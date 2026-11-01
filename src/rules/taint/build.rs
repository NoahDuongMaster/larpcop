//! Building a taint rule from its configuration: patterns compiled per
//! language and indexed by node kind, regexes, source texts.

use super::{TaintRule, argv, mapping, outputs, pathobj, routes, scan, typed};
use crate::config::TaintConfig;
use crate::rules::Level;
use anyhow::{Context, Result};
use ast_grep_core::Pattern;
use ast_grep_language::SupportLang;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

impl TaintRule {
    pub fn new(cfg: &TaintConfig, typed: typed::Typed, root: PathBuf) -> Result<Self> {
        let compile = |lang: SupportLang, list: &[String]| -> Result<Vec<scan::Compiled>> {
            list.iter()
                .flat_map(|p| crate::rules::pattern_fixes::variants(p))
                .flat_map(crate::rules::pattern_fixes::compound)
                .map(|p| {
                    let compiled = pattern(&p, lang)
                        .with_context(|| format!("taint `{}`: pattern `{p}`", cfg.id))?;
                    Ok((compiled, scan::needle(&p), scan::specificity(&p)))
                })
                .collect()
        };
        let mut langs = Vec::new();
        for name in &cfg.languages {
            let lang = SupportLang::from_str(name)
                .map_err(|_| anyhow::anyhow!("taint `{}`: unknown language `{name}`", cfg.id))?;
            langs.push((
                lang,
                scan::Indexed::new([
                    compile(lang, &cfg.sources)?,
                    compile(lang, &cfg.sinks)?,
                    compile(lang, &cfg.sanitizers)?,
                    compile(lang, &cfg.guards)?,
                    compile(lang, &cfg.rejects)?,
                ]),
            ));
        }
        // Kotlin code calls Java classes of the same project: a Kotlin rule
        // summarizes them, without reporting on Java files itself.
        let mut companions = Vec::new();
        let declared: Vec<SupportLang> = langs.iter().map(|(l, _)| *l).collect();
        if declared.contains(&SupportLang::Kotlin) && !declared.contains(&SupportLang::Java) {
            let java = SupportLang::Java;
            let lenient = |list: &[String]| -> Vec<scan::Compiled> {
                list.iter()
                    .flat_map(|p| java_forms(p))
                    .filter_map(|p| {
                        Some((
                            pattern(&p, java).ok()?,
                            scan::needle(&p),
                            scan::specificity(&p),
                        ))
                    })
                    .collect()
            };
            langs.push((
                java,
                scan::Indexed::new([
                    lenient(&cfg.sources),
                    lenient(&cfg.sinks),
                    lenient(&cfg.sanitizers),
                    lenient(&cfg.guards),
                    lenient(&cfg.rejects),
                ]),
            ));
            companions.push(java);
        }
        Ok(Self {
            id: cfg.id.clone(),
            level: cfg.severity.unwrap_or(Level::Error),
            message: cfg.message.clone(),
            note: cfg.note.clone(),
            sink_arg: cfg.sink_arg.clone(),
            sanitizer_names: cfg
                .sanitizer_names
                .as_deref()
                .map(regex::Regex::new)
                .transpose()
                .with_context(|| format!("taint `{}`: sanitizer_names", cfg.id))?,
            unless: cfg
                .unless
                .iter()
                .map(|u| regex::Regex::new(u))
                .collect::<Result<_, _>>()
                .with_context(|| format!("taint `{}`: unless", cfg.id))?,
            safe_prefix: cfg
                .safe_prefix
                .as_deref()
                .map(regex::Regex::new)
                .transpose()
                .with_context(|| format!("taint `{}`: safe_prefix", cfg.id))?,
            source_texts: cfg
                .sources
                .iter()
                .map(|s| s.split_whitespace().collect())
                .collect(),
            source_names: cfg.source_names.iter().cloned().collect(),
            param_types: cfg.param_types.clone(),
            param_decorators: cfg.param_decorators.clone(),
            resolver_args: cfg.resolver_args,
            escape_contexts: cfg.escape_contexts,
            own_serialization_safe: cfg.own_serialization_safe,
            html_fragments: cfg.html_fragments,
            path_objects: cfg
                .path_objects
                .as_ref()
                .map(|p| -> Result<_> {
                    let re = |s: &str| {
                        regex::Regex::new(s)
                            .with_context(|| format!("taint `{}`: path_objects", cfg.id))
                    };
                    Ok(pathobj::PathObjects {
                        types: re(&p.types)?,
                        uses: re(&p.uses)?,
                    })
                })
                .transpose()?,
            fixed_routes: routes::FixedRoutes {
                sources: cfg
                    .fixed_route_sources
                    .iter()
                    .map(|s| s.split_whitespace().collect())
                    .collect(),
                prefixed: Default::default(),
            },
            shell_argv: cfg
                .shell_argv
                .as_ref()
                .map(|a| -> Result<_> {
                    let re = |s: &str| {
                        regex::Regex::new(s)
                            .with_context(|| format!("taint `{}`: shell_argv", cfg.id))
                    };
                    Ok(argv::ShellArgv {
                        calls: re(&a.calls)?,
                        vectors: outputs::parse(&a.vectors)?,
                        shells: re(&a.shells)?,
                        flags: re(&a.flags)?,
                    })
                })
                .transpose()?,
            writes: std::sync::Arc::new(
                outputs::Writes::new(&cfg.source_writes, &cfg.copies)
                    .with_context(|| format!("taint `{}`: source_writes/copies", cfg.id))?,
            ),
            cleaners: std::sync::Arc::new(mapping::Cleaners::new(
                &cfg.sanitizers,
                cfg.sanitizer_names
                    .as_deref()
                    .map(regex::Regex::new)
                    .transpose()
                    .with_context(|| format!("taint `{}`: sanitizer_names", cfg.id))?,
            )),
            handler_classes: cfg
                .handler_classes
                .as_deref()
                .map(regex::Regex::new)
                .transpose()
                .with_context(|| format!("taint `{}`: handler_classes", cfg.id))?,
            input_types: cfg
                .input_types
                .as_deref()
                .map(regex::Regex::new)
                .transpose()
                .with_context(|| format!("taint `{}`: input_types", cfg.id))?,
            exclude: crate::files::globset(&cfg.exclude)?,
            handler_decorators: cfg
                .handler_decorators
                .as_deref()
                .map(regex::Regex::new)
                .transpose()
                .with_context(|| format!("taint `{}`: handler_decorators", cfg.id))?,
            typed,
            responds: cfg
                .response_returns
                .as_ref()
                .map(|r| super::responds::Responds::new(&cfg.id, r))
                .transpose()?,
            langs,
            companions,
            root,
            imported: Mutex::default(),
            reach: Mutex::default(),
        })
    }
}

/// Go calls written alone (`db.Query($X)`) need a function body as context.
pub(super) fn pattern(p: &str, lang: SupportLang) -> Result<Pattern> {
    if let Some((context, selector)) = crate::rules::pattern_fixes::context_in(p, lang) {
        return Ok(Pattern::contextual(&context, &selector, lang)?);
    }
    Ok(Pattern::try_new(p, lang)?)
}

/// A Kotlin pattern as Java writes it: `File($X)` is `new File($X)` there.
fn java_forms(p: &str) -> Vec<String> {
    let constructor = p.starts_with(char::is_uppercase)
        && p.split('(')
            .next()
            .is_some_and(|c| c.chars().all(|c| c.is_alphanumeric() || c == '_'));
    if constructor {
        vec![p.to_string(), format!("new {p}")]
    } else {
        vec![p.to_string()]
    }
}

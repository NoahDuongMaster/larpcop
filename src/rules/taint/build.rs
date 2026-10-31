//! Building a taint rule from its configuration: patterns compiled per
//! language and indexed by node kind, regexes, source texts.

use super::{TaintRule, scan, typed};
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
            exclude: crate::files::globset(&cfg.exclude)?,
            handler_decorators: cfg
                .handler_decorators
                .as_deref()
                .map(regex::Regex::new)
                .transpose()
                .with_context(|| format!("taint `{}`: handler_decorators", cfg.id))?,
            typed,
            langs,
            root,
            imported: Mutex::default(),
        })
    }
}

/// Go calls written alone (`db.Query($X)`) need a function body as context.
pub(super) fn pattern(p: &str, lang: SupportLang) -> Result<Pattern> {
    if lang == SupportLang::Go
        && let Some((context, selector)) = crate::rules::pattern_fixes::context(p)
    {
        return Ok(Pattern::contextual(&context, &selector, lang)?);
    }
    Ok(Pattern::try_new(p, lang)?)
}

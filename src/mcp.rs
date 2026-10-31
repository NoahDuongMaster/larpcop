//! `larpcop mcp`: an MCP server (stdio) so agents can ask for the rules that
//! apply to the file they are about to touch, validate code before writing it,
//! and run fixes — instead of loading every rule of every stack into context.

use crate::context::Ctx;
use crate::files::Scope;
use crate::report;
use anyhow::Result;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use std::fmt::Write;
use std::path::PathBuf;

pub struct Server {
    start: PathBuf,
    extends: Vec<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct PathArg {
    /// File path, relative to the project root or absolute.
    path: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ContentArg {
    /// File the content is meant for (decides which rules apply).
    path: String,
    /// The complete file content you intend to write.
    content: String,
}

#[derive(Deserialize, schemars::JsonSchema, Default)]
pub struct PathsArg {
    /// Files or directories; empty = every uncommitted change.
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct RuleArg {
    /// Rule id, e.g. `no-explicit-any`.
    id: String,
}

type Reply = Result<CallToolResult, ErrorData>;

fn text(s: String) -> Reply {
    Ok(CallToolResult::success(vec![ContentBlock::text(s)]))
}

fn failed(e: anyhow::Error) -> ErrorData {
    ErrorData::internal_error(format!("{e:#}"), None)
}

#[tool_router]
impl Server {
    #[tool(
        description = "Rules enforced on one file (by its language and path), with how to comply. Call before writing or editing a file."
    )]
    fn rules_for(&self, Parameters(PathArg { path }): Parameters<PathArg>) -> Reply {
        let ctx = self.ctx().map_err(failed)?;
        let (cfg, engine) = ctx.load().map_err(failed)?;
        let rel = self.rel(&ctx, &path);
        let rules = engine.rules_for(&rel);
        let mut out = format!("{} rule(s) apply to {rel}:\n", rules.len());
        for r in rules {
            let lock = cfg.locked.get(&r.id).map_or("", |_| " [locked]");
            let _ = writeln!(
                out,
                "\n- {} ({}){lock}: {}",
                r.id,
                r.level.as_str(),
                r.message
            );
            if let Some(note) = &r.note {
                let _ = writeln!(out, "  how to comply: {note}");
            }
        }
        text(out)
    }

    #[tool(
        description = "Check content before writing it to a file. Returns the violations it would introduce; write only clean content."
    )]
    fn check_content(&self, Parameters(arg): Parameters<ContentArg>) -> Reply {
        let ctx = self.ctx().map_err(failed)?;
        let path = ctx.root.join(self.rel(&ctx, &arg.path));
        let outcome = ctx.check_content(&path, &arg.content).map_err(failed)?;
        text(report::text(&outcome))
    }

    #[tool(
        description = "Check files on disk (default: every uncommitted change) against all enforced rules."
    )]
    fn check(&self, Parameters(PathsArg { paths }): Parameters<PathsArg>) -> Reply {
        let ctx = self.ctx().map_err(failed)?;
        let outcome = ctx.check(&self.scope(&ctx, paths)).map_err(failed)?;
        text(report::text(&outcome))
    }

    #[tool(description = "Apply the automatic fixes rules provide, then report what is left.")]
    fn fix(&self, Parameters(PathsArg { paths }): Parameters<PathsArg>) -> Reply {
        let ctx = self.ctx().map_err(failed)?;
        let (cfg, engine) = ctx.load().map_err(failed)?;
        let scope = self.scope(&ctx, paths);
        let exclude = crate::files::globset(&cfg.exclude).map_err(failed)?;
        let sources = crate::files::collect(&cfg.root, &scope, &exclude).map_err(failed)?;
        let mut out = String::new();
        for (rel, content, n) in engine.fix(&sources) {
            std::fs::write(cfg.root.join(&rel), content).map_err(|e| failed(e.into()))?;
            let _ = writeln!(out, "fixed {rel} ({n} fix(es))");
        }
        let outcome = ctx.check(&scope).map_err(failed)?;
        text(out + &report::text(&outcome))
    }

    #[tool(
        description = "Explain one rule: what it forbids, how to comply, and valid/invalid examples."
    )]
    fn explain_rule(&self, Parameters(RuleArg { id }): Parameters<RuleArg>) -> Reply {
        let ctx = self.ctx().map_err(failed)?;
        let (cfg, engine) = ctx.load().map_err(failed)?;
        let Some(rule) = engine.rules().into_iter().find(|r| r.id == id) else {
            return Err(ErrorData::invalid_params(format!("no rule `{id}`"), None));
        };
        let mut out = format!(
            "{} ({}, {}): {}\n",
            rule.id,
            rule.level.as_str(),
            rule.scope,
            rule.message
        );
        if let Some(note) = rule.note {
            let _ = writeln!(out, "How to comply: {note}");
        }
        out += &crate::rules::testing::examples(&cfg.rule_dirs, &id);
        text(out)
    }
}

#[tool_handler]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("larpcop", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Coding rules enforced on this repository by pre-commit and CI. Call rules_for before \
editing a file and check_content before writing it; violating code cannot be committed.",
            )
    }
}

impl Server {
    fn ctx(&self) -> Result<Ctx> {
        Ctx::new(&self.start, self.extends.clone(), false)
    }

    fn rel(&self, ctx: &Ctx, path: &str) -> String {
        let p = PathBuf::from(path);
        let abs = if p.is_absolute() { p } else { ctx.root.join(p) };
        crate::files::rel_of_new(&ctx.root, &abs).unwrap_or_else(|| path.to_string())
    }

    fn scope(&self, ctx: &Ctx, paths: Vec<String>) -> Scope {
        if paths.is_empty() {
            return Scope::Changed;
        }
        Scope::Paths(paths.iter().map(|p| ctx.root.join(p)).collect())
    }
}

pub fn serve(start: PathBuf, extends: Vec<String>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let service = Server { start, extends }
            .serve(rmcp::transport::stdio())
            .await?;
        service.waiting().await?;
        Ok(())
    })
}

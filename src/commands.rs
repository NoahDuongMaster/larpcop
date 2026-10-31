//! Command handlers. Exit codes: 0 ok, 1 violations/failures, 3 internal error.

use crate::baseline::{self, Baseline};
use crate::cli::{Cli, Cmd};
use crate::context::Ctx;
use crate::files::{self, Scope};
use crate::report::{self, Format};
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use std::fs;

pub fn run(cli: Cli) -> Result<u8> {
    let g = cli.global;
    let ctx = || Ctx::new(&g.dir, g.extends.clone(), g.refresh);
    match cli.cmd {
        Cmd::Check {
            scope,
            format,
            output,
        } => {
            let outcome = ctx()?.check(&scope.scope())?;
            for spec in &output {
                let (fmt, path) = spec
                    .split_once('=')
                    .with_context(|| format!("--output expects FORMAT=FILE, got `{spec}`"))?;
                let fmt = Format::from_str(fmt, true)
                    .map_err(|e| anyhow::anyhow!("--output {spec}: {e}"))?;
                fs::write(path, report::render(&outcome, fmt))
                    .with_context(|| format!("writing {path}"))?;
            }
            print!("{}", report::render(&outcome, format));
            Ok(u8::from(outcome.errors() > 0))
        }
        Cmd::Fix { scope, dry_run } => fix(&ctx()?, scope.scope(), dry_run),
        Cmd::Baseline { prune } => {
            let ctx = ctx()?;
            let (cfg, engine) = ctx.load()?;
            let now = ctx.raw(&cfg, &engine, &Scope::All)?.violations;
            let next = match (prune, Baseline::load(&cfg.root, false)?) {
                (true, Some(known)) => known.prune(&now),
                (true, None) => bail!("no {} to prune", baseline::FILE),
                (false, _) => Baseline::of(&now),
            };
            next.write(&cfg.root)?;
            println!(
                "agentkit: {} now holds {} known violation(s).",
                baseline::FILE,
                next.len()
            );
            Ok(0)
        }
        Cmd::Test { require_all } => {
            let (cfg, _) = ctx()?.load()?;
            let report = crate::rules::testing::run(&cfg.rule_dirs)?;
            print!("{}", report.text);
            if !report.untested.is_empty() {
                println!("untested rule(s): {}", report.untested.join(", "));
            }
            let failed = report.failures > 0 || (require_all && !report.untested.is_empty());
            println!(
                "agentkit: {}",
                if failed {
                    "✗ rule tests failed"
                } else {
                    "✓ rule tests passed"
                }
            );
            Ok(u8::from(failed))
        }
        Cmd::Rules => rules(&ctx()?),
        Cmd::Sync { check } => sync(&ctx()?, check),
        Cmd::Install { force } => {
            let path = crate::install::install(&ctx()?.root, force)?;
            println!("agentkit: installed {}", path.display());
            Ok(0)
        }
        Cmd::Hook { agent } => {
            let code = crate::hook::run(agent, g.extends, g.refresh)?;
            Ok(u8::try_from(code).unwrap_or(1))
        }
    }
}

fn fix(ctx: &Ctx, scope: Scope, dry_run: bool) -> Result<u8> {
    if matches!(scope, Scope::Staged) {
        bail!("`fix --staged` would edit the worktree, not the index; use --changed");
    }
    let (cfg, engine) = ctx.load()?;
    let exclude = files::globset(&cfg.exclude)?;
    let sources = files::collect(&cfg.root, &scope, &exclude)?;
    let fixed = engine.fix(&sources);
    for (rel, text, n) in &fixed {
        if !dry_run {
            fs::write(cfg.root.join(rel), text).with_context(|| format!("writing {rel}"))?;
        }
        println!(
            "{} {rel} ({n} fix(es))",
            if dry_run { "would fix" } else { "fixed" }
        );
    }
    if dry_run {
        return Ok(u8::from(!fixed.is_empty()));
    }
    let outcome = ctx.check(&scope)?;
    print!("{}", report::render(&outcome, Format::Text));
    Ok(u8::from(outcome.errors() > 0))
}

fn rules(ctx: &Ctx) -> Result<u8> {
    let (cfg, engine) = ctx.load()?;
    println!(
        "root: {}\nsources: {}\n",
        cfg.root.display(),
        cfg.sources.join(" → ")
    );
    for r in engine.rules() {
        let lock = cfg
            .locked
            .get(&r.id)
            .map_or(String::new(), |by| format!("  [locked by {by}]"));
        println!(
            "{:<24} {:<7} {:<22} {}{lock}",
            r.id,
            r.level.as_str(),
            r.scope,
            r.message
        );
    }
    Ok(0)
}

fn sync(ctx: &Ctx, check: bool) -> Result<u8> {
    let (cfg, engine) = ctx.load()?;
    let changed = crate::sync::run(&cfg, &engine.rules(), check)?;
    for path in &changed {
        let verb = if check { "out of date:" } else { "updated:" };
        println!("{verb} {}", path.display());
    }
    if check && !changed.is_empty() {
        eprintln!(
            "agentkit: generated files are stale; run `agentkit sync` and commit the result."
        );
        return Ok(1);
    }
    if changed.is_empty() {
        println!("agentkit: generated files are up to date.");
    }
    Ok(0)
}

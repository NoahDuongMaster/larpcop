//! `larpcop rules` and `larpcop stats`: what the rules are, and what they did.

use crate::context::Ctx;
use crate::files::Scope;
use anyhow::Result;
use std::path::PathBuf;

pub fn rules(ctx: &Ctx, for_path: Option<PathBuf>, json: bool) -> Result<u8> {
    let (cfg, engine) = ctx.load()?;
    let infos = match &for_path {
        Some(path) => {
            // Root-relative, `/`-separated, as the rules see paths.
            let rel = path
                .strip_prefix(&cfg.root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let mut found = engine.rules_for(&rel);
            found.sort_by(|a, b| a.id.cmp(&b.id));
            found
        }
        None => engine.rules(),
    };
    if json {
        let rows: Vec<_> = infos
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "level": r.level.as_str(),
                    "languages": r.scope,
                    "message": r.message,
                    "note": r.note,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(0);
    }
    if for_path.is_none() {
        println!(
            "root: {}\nsources: {}\n",
            cfg.root.display(),
            cfg.sources.join(" → ")
        );
    }
    for r in &infos {
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

pub fn stats(ctx: &Ctx, scope: Scope, top: usize, json: bool) -> Result<u8> {
    let (cfg, engine) = ctx.load()?;
    let (outcome, sources) = ctx.raw(&cfg, &engine, &scope)?;
    let summary = crate::stats::collect(&engine, &sources, &outcome.violations);
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print!("{}", crate::stats::render(&summary, top));
    }
    Ok(0)
}

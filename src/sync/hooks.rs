//! Merges larpcop's hook entries into agents' JSON config files, keeping
//! every user-defined setting and hook untouched.

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};

/// Every generated entry runs `larpcop hook <agent>`; that prefix identifies ours.
const OURS: &str = "larpcop hook ";

pub fn parse(current: Option<&str>) -> Result<Value> {
    let doc = match current {
        Some(c) if !c.trim().is_empty() => serde_json::from_str(c).context("invalid JSON")?,
        _ => json!({}),
    };
    anyhow::ensure!(doc.is_object(), "must be a JSON object");
    Ok(doc)
}

pub fn render(doc: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(doc)? + "\n")
}

fn is_ours(hook: &Value) -> bool {
    hook.get("command")
        .and_then(Value::as_str)
        .is_some_and(|c| c.starts_with(OURS))
}

fn event_list<'a>(doc: &'a mut Value, event: &str) -> Result<&'a mut Vec<Value>> {
    let hooks = doc
        .as_object_mut()
        .context("must be a JSON object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    hooks
        .as_object_mut()
        .context("`hooks` must be an object")?
        .entry(event)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .with_context(|| format!("`hooks.{event}` must be an array"))
}

/// Claude Code / Codex / Gemini CLI shape:
/// `hooks.<Event> = [{ matcher?, hooks: [{ type: "command", command, timeout }] }]`.
pub fn merge_grouped(
    doc: &mut Value,
    events: &[(&str, Option<&str>)],
    handler: &Value,
) -> Result<()> {
    for (event, matcher) in events {
        let groups = event_list(doc, event)?;
        for group in groups.iter_mut() {
            if let Some(list) = group.get_mut("hooks").and_then(Value::as_array_mut) {
                list.retain(|h| !is_ours(h));
            }
        }
        groups.retain(|g| {
            g.get("hooks")
                .and_then(Value::as_array)
                .is_none_or(|l| !l.is_empty())
        });
        let mut group = Map::new();
        if let Some(m) = matcher {
            group.insert("matcher".into(), json!(m));
        }
        group.insert("hooks".into(), json!([handler]));
        groups.push(Value::Object(group));
    }
    Ok(())
}

/// Cursor shape: `hooks.<event> = [{ command, matcher?, timeout, ... }]`.
pub fn merge_flat(doc: &mut Value, entries: &[(&str, Value)]) -> Result<()> {
    for (event, entry) in entries {
        let list = event_list(doc, event)?;
        list.retain(|h| !is_ours(h));
        list.push(entry.clone());
    }
    Ok(())
}

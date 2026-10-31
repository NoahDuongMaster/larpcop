//! Encodes a verdict in each agent's hook protocol.
//!
//! Claude Code, Codex and Gemini CLI share the convention "exit 2, reason on
//! stderr" for every event we use (block a tool, feed back after an edit,
//! continue instead of stopping). Cursor's native protocol is JSON on stdout.

use super::Agent;
use super::event::Event;
use serde_json::json;

pub enum Verdict {
    Allow,
    /// Message for the model: why it is blocked / what it must fix.
    Block(String),
}

pub const BLOCK_EXIT: i32 = 2;

/// Prints the agent-specific response and returns the process exit code.
pub fn emit(agent: Agent, event: &Event, hook_event: &str, verdict: &Verdict) -> i32 {
    match agent {
        Agent::ClaudeCode | Agent::Codex | Agent::Gemini => match verdict {
            Verdict::Allow => 0,
            Verdict::Block(message) => {
                eprintln!("{message}");
                BLOCK_EXIT
            }
        },
        Agent::Cursor => {
            println!("{}", cursor_response(event, hook_event, verdict));
            0
        }
    }
}

/// Cursor treats invalid or missing JSON from permission hooks as a deny, so
/// pre-tool hooks always answer explicitly, even when allowing.
fn cursor_response(event: &Event, hook_event: &str, verdict: &Verdict) -> serde_json::Value {
    let is_permission_hook = hook_event == "preToolUse" || hook_event.starts_with("before");
    match (verdict, event) {
        (Verdict::Block(msg), Event::Shell(_) | Event::BeforeEdit(_)) => json!({
            "permission": "deny",
            "user_message": "agentkit: blocked by enforced coding rules",
            "agent_message": msg,
        }),
        (Verdict::Block(msg), Event::AfterEdit(_)) => json!({ "additional_context": msg }),
        (Verdict::Block(msg), Event::Stop { .. }) => json!({ "followup_message": msg }),
        _ if is_permission_hook => json!({ "permission": "allow" }),
        _ => json!({}),
    }
}

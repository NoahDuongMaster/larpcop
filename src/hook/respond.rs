//! Encodes a verdict in each agent's hook protocol.
//!
//! Claude Code, Codex, Gemini CLI and Factory Droid share the convention "exit 2,
//! reason on stderr" for every event we use (block a tool, feed back after an
//! edit, continue instead of stopping). Cursor and Copilot CLI answer in JSON on
//! stdout; Kiro blocks tools with exit 2 but continues a turn through JSON.

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
    let Verdict::Block(message) = verdict else {
        if agent == Agent::Cursor {
            println!("{}", cursor_response(event, hook_event, verdict));
        }
        return 0;
    };
    match (agent, event) {
        (Agent::Cursor, _) => println!("{}", cursor_response(event, hook_event, verdict)),
        (Agent::Copilot, _) => println!("{}", copilot_response(event, message)),
        (Agent::Kiro, Event::Stop { .. }) => {
            println!("{}", json!({ "decision": "block", "reason": message }));
        }
        _ => {
            eprintln!("{message}");
            return BLOCK_EXIT;
        }
    }
    0
}

/// Copilot CLI parses stdout only on exit 0 (exit 2 on Stop is a mere warning).
fn copilot_response(event: &Event, message: &str) -> serde_json::Value {
    match event {
        Event::AfterEdit(_) => json!({ "additionalContext": message }),
        Event::Stop { .. } => json!({ "decision": "block", "reason": message }),
        _ => json!({ "permissionDecision": "deny", "permissionDecisionReason": message }),
    }
}

/// Cursor treats invalid or missing JSON from permission hooks as a deny, so
/// pre-tool hooks always answer explicitly, even when allowing.
fn cursor_response(event: &Event, hook_event: &str, verdict: &Verdict) -> serde_json::Value {
    let is_permission_hook = hook_event == "preToolUse" || hook_event.starts_with("before");
    match (verdict, event) {
        (Verdict::Block(msg), Event::Shell(_) | Event::BeforeEdit(_) | Event::Proposed(..)) => {
            json!({
                "permission": "deny",
                "user_message": "larpcop: blocked by enforced coding rules",
                "agent_message": msg,
            })
        }
        (Verdict::Block(msg), Event::AfterEdit(_)) => json!({ "additional_context": msg }),
        (Verdict::Block(msg), Event::Stop { .. }) => json!({ "followup_message": msg }),
        _ if is_permission_hook => json!({ "permission": "allow" }),
        _ => json!({}),
    }
}

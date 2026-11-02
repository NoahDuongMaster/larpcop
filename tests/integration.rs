//! Single integration-test crate: Cargo links one binary instead of sixteen,
//! and the test harness runs every module on the same thread pool.

mod common;

#[path = "suite/adapters.rs"]
mod adapters;
#[path = "suite/agents.rs"]
mod agents;
#[path = "suite/ai.rs"]
mod ai;
#[path = "suite/check.rs"]
mod check;
#[path = "suite/dashboard.rs"]
mod dashboard;
#[path = "suite/deps_age.rs"]
mod deps_age;
#[path = "suite/deps_approval.rs"]
mod deps_approval;
#[path = "suite/foundation.rs"]
mod foundation;
#[path = "suite/hooks.rs"]
mod hooks;
#[path = "suite/mcp.rs"]
mod mcp;
#[path = "suite/quality.rs"]
mod quality;
#[path = "suite/security.rs"]
mod security;
#[path = "suite/shell_hook.rs"]
mod shell_hook;
#[path = "suite/stats.rs"]
mod stats;
#[path = "suite/sync_install.rs"]
mod sync_install;
#[path = "suite/types.rs"]
mod types;

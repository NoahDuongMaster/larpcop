mod ai;
mod baseline;
mod cli;
mod commands;
mod config;
mod context;
mod dashboard;
mod deps;
mod files;
mod hook;
mod install;
mod lsp;
mod mcp;
mod org;
mod report;
mod rules;
mod shell;
mod shell_ast;
mod sync;
mod types;

use clap::Parser;
use std::process::ExitCode;

/// Exit 3 on internal failure: distinct from 1 (violations) and from 2, which
/// agent hook protocols reserve for "block and show the model".
fn main() -> ExitCode {
    let result = commands::run(cli::Cli::parse());
    // Language servers started for type queries are child processes: stop them.
    types::shutdown();
    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("agentkit: error: {err:#}");
            ExitCode::from(3)
        }
    }
}

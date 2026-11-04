//! One run of the model's CLI: the prompt on its stdin, the answer from its
//! stdout, and a deadline, so a model that hangs does not hang larpcop with it.

use anyhow::{Context, Result, anyhow, bail};
use std::env::VarError;
use std::io::{Read, Write};
use std::process::{Child, Output};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const TIMEOUT_VAR: &str = "LARPCOP_LLM_TIMEOUT_SECS";
/// A review of a large change can think for minutes, but not forever.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// How often a running model is checked on.
const POLL: Duration = Duration::from_millis(20);

/// How long the model may take: `LARPCOP_LLM_TIMEOUT_SECS` seconds, else ten minutes.
pub(super) fn timeout() -> Result<Duration> {
    timeout_from(std::env::var(TIMEOUT_VAR))
}

fn timeout_from(var: Result<String, VarError>) -> Result<Duration> {
    let text = match var {
        Ok(text) => text,
        Err(VarError::NotPresent) => return Ok(DEFAULT_TIMEOUT),
        Err(e) => return Err(e).context(TIMEOUT_VAR),
    };
    let secs = text
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|secs| *secs > 0)
        .with_context(|| {
            format!("{TIMEOUT_VAR} must be a whole number of seconds, not `{text}`")
        })?;
    Ok(Duration::from_secs(secs))
}

/// What `child` printed, once it exits with `prompt` on its stdin. Past `timeout`
/// it is killed and that is an error: `name` says which model.
pub(super) fn run(mut child: Child, prompt: &str, timeout: Duration, name: &str) -> Result<Output> {
    let mut stdin = child.stdin.take().context("stdin")?;
    let prompt = prompt.as_bytes().to_vec();
    // One thread per pipe: a model that starts answering before it has read the
    // whole prompt would fill the stdout pipe while we still fill its stdin, and
    // both sides would wait for each other. Detached, so that a model killed at
    // the deadline cannot hold us up through a child of its own that keeps a pipe.
    let sent = std::thread::spawn(move || stdin.write_all(&prompt));
    let stdout = drain(child.stdout.take().context("stdout")?);
    let stderr = drain(child.stderr.take().context("stderr")?);
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("waiting for `{name}`"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().with_context(|| format!("stopping `{name}`"))?;
            child.wait().with_context(|| format!("stopping `{name}`"))?;
            bail!(
                "`{name}` gave no answer within {timeout:?} and was stopped (set {TIMEOUT_VAR} \
to allow more seconds)"
            );
        }
        std::thread::sleep(POLL);
    };
    let (stdout, stderr) = (collect(stdout)?, collect(stderr)?);
    // A model that failed is reported by its own words, before a prompt it did not read.
    if status.success() {
        sent.join()
            .map_err(|_| anyhow!("the thread sending the prompt panicked"))?
            .with_context(|| format!("sending the prompt to `{name}`"))?;
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn drain(mut pipe: impl Read + Send + 'static) -> JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn collect(reader: JoinHandle<std::io::Result<Vec<u8>>>) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow!("the thread reading the model's output panicked"))?
        .context("reading the model's output")
}

#[cfg(test)]
mod tests;

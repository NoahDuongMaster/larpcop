//! The model runner against fake models (shell one-liners).

use super::*;
use crate::ai::Llm;
use std::ffi::OsString;

fn model(script: &str, timeout: Duration) -> Llm {
    let sh = crate::shell::posix_shell().to_string_lossy().into_owned();
    Llm {
        argv: vec![sh, "-c".into(), script.into()],
        cache: None,
        timeout,
    }
}

const LONG: Duration = Duration::from_secs(60);

#[test]
fn a_prompt_larger_than_the_pipe_buffers_goes_in_and_the_answer_comes_out() {
    let prompt = "lorem ipsum dolor sit amet\n".repeat(50_000);
    let answer = model("cat", LONG).ask(&prompt, false).unwrap();
    assert_eq!(answer, prompt);
}

#[test]
fn a_model_that_hangs_is_killed_at_the_deadline() {
    let started = Instant::now();
    let err = model("sleep 30", Duration::from_millis(300))
        .ask("hi", false)
        .unwrap_err();
    let took = started.elapsed();
    let said = format!("{err:#}");
    assert!(said.contains("gave no answer within 300ms"), "{said}");
    assert!(said.contains("LARPCOP_LLM_TIMEOUT_SECS"), "{said}");
    assert!(took < Duration::from_secs(10), "{took:?}");
}

/// `sh` forks `sleep`; killing `sh` leaves `sleep` holding the output pipes.
#[test]
fn a_child_of_the_model_that_keeps_the_pipes_open_does_not_hold_us_up() {
    let started = Instant::now();
    let err = model("sleep 5; echo late", Duration::from_millis(300))
        .ask("hi", false)
        .unwrap_err();
    assert!(err.to_string().contains("gave no answer"), "{err:#}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_model_that_fails_is_reported_by_its_own_words() {
    let err = model("echo boom >&2; exit 3", LONG)
        .ask("hi", false)
        .unwrap_err();
    let said = err.to_string();
    assert!(said.contains("failed") && said.contains("boom"), "{said}");
}

#[test]
fn the_timeout_is_ten_minutes_unless_set_to_a_positive_number_of_seconds() {
    let set = |v: &str| timeout_from(Ok(v.to_string()));
    assert_eq!(
        timeout_from(Err(VarError::NotPresent)).unwrap(),
        Duration::from_secs(600)
    );
    assert_eq!(set("30").unwrap(), Duration::from_secs(30));
    assert_eq!(set(" 5 ").unwrap(), Duration::from_secs(5));
    for bad in ["0", "-1", "soon", "1.5", ""] {
        let err = set(bad).unwrap_err().to_string();
        assert!(
            err.contains("LARPCOP_LLM_TIMEOUT_SECS") && err.contains(&format!("`{bad}`")),
            "{bad}: {err}"
        );
    }
    let not_unicode = VarError::NotUnicode(OsString::from("x"));
    assert!(timeout_from(Err(not_unicode)).is_err());
}

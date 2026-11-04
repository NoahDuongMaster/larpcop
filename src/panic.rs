//! Panics become errors at the edges: one bad file must not kill a language
//! server or the MCP server, and a hook or CI run must end with the documented
//! exit code (3) rather than a core dump. The default panic hook still prints
//! the message and location, which is what a bug report needs.

use anyhow::{Result, anyhow};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// The text a panic carried.
pub fn message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no message".into())
}

/// Runs `f`; a panic inside it comes back as an error.
pub fn contain<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|p| {
        Err(anyhow!(
            "internal error (a bug in larpcop): {}",
            message(&*p)
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::contain;

    #[test]
    fn a_panic_becomes_an_error_with_its_message() {
        let from_str = contain::<()>(|| panic!("boom"));
        assert!(format!("{:#}", from_str.unwrap_err()).contains("boom"));
        let n = 7;
        let from_string = contain::<()>(|| panic!("bad {n}"));
        assert!(format!("{:#}", from_string.unwrap_err()).contains("bad 7"));
        assert_eq!(contain(|| Ok(1)).unwrap(), 1);
    }

    #[test]
    fn a_panic_in_a_rayon_worker_reaches_the_caller_as_an_error() {
        use rayon::prelude::*;
        let r = contain(|| {
            (0..64)
                .into_par_iter()
                .for_each(|i| assert!(i != 40, "worker failed"));
            Ok(())
        });
        assert!(format!("{:#}", r.unwrap_err()).contains("worker failed"));
    }
}

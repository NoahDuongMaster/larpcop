//! What the OSV.dev and deps.dev clients share: connection pools sized for the
//! fan-out, bounded retries of transient failures, and the fan-out itself.

use anyhow::Result;
use rayon::prelude::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ureq::http::Response;

/// Requests in flight at once, and idle connections kept per host: lookups wait
/// on the network, not the CPU, but deps.dev throttles clients that open many
/// connections at once.
pub(super) const CONCURRENCY: usize = 12;

/// Tries per request: the first one plus two retries.
const ATTEMPTS: u32 = 3;
const BASE_DELAY: Duration = Duration::from_millis(250);

pub(super) fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .max_idle_connections(CONCURRENCY)
        .max_idle_connections_per_host(CONCURRENCY)
        .user_agent(concat!("larpcop/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Status and body of a request, retried when the server throttles (429), fails
/// (5xx) or the connection breaks. Timeouts are not retried: they already waited
/// as long as the caller allows. After the last try the failure is returned as is,
/// so callers keep failing closed.
pub(super) fn fetch(
    request: impl Fn() -> Result<Response<ureq::Body>, ureq::Error>,
) -> Result<(u16, String)> {
    retrying(ATTEMPTS, BASE_DELAY, request)
}

fn retrying(
    attempts: u32,
    base: Duration,
    request: impl Fn() -> Result<Response<ureq::Body>, ureq::Error>,
) -> Result<(u16, String)> {
    let mut attempt = 1;
    loop {
        let outcome = request().and_then(|mut resp| {
            let status = resp.status().as_u16();
            Ok((status, resp.body_mut().read_to_string()?))
        });
        let transient = match &outcome {
            Ok((status, _)) => *status == 429 || (500..600).contains(status),
            Err(e) => matches!(e, ureq::Error::Io(_) | ureq::Error::ConnectionFailed),
        };
        if !transient || attempt >= attempts {
            return Ok(outcome?);
        }
        // Exponential, with up to 100 ms of jitter so parallel retries do not
        // arrive together again.
        let jitter = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::from(d.subsec_nanos() % 100));
        std::thread::sleep(base * 2u32.pow(attempt - 1) + Duration::from_millis(jitter));
        attempt += 1;
    }
}

/// `f` over `items` on up to `threads` threads, results in order; the first
/// error wins. One item (or none) is not worth a pool.
pub(super) fn par_map<T: Sync, R: Send>(
    threads: usize,
    items: &[T],
    f: impl Fn(&T) -> Result<R> + Sync + Send,
) -> Result<Vec<R>> {
    if items.len() < 2 {
        return items.iter().map(f).collect();
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads.min(items.len()))
        .build()?;
    pool.install(|| items.par_iter().map(f).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::fake;

    const TINY: Duration = Duration::from_millis(1);

    fn get(agent: &ureq::Agent, url: &str, attempts: u32) -> Result<(u16, String)> {
        retrying(attempts, TINY, || agent.get(url).call())
    }

    #[test]
    fn throttling_and_server_errors_are_retried_a_bounded_number_of_times() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let server =
            fake::serve(
                move |_| match calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                    0 => fake::reply(429, ""),
                    1 => fake::reply(503, ""),
                    _ => fake::reply(200, "ok"),
                },
            );
        let agent = agent(Duration::from_secs(5));
        let url = format!("{}/x", server.url);
        assert_eq!(get(&agent, &url, 3).unwrap(), (200, "ok".to_string()));
        assert_eq!(server.requests().len(), 3);

        let always = fake::serve(|_| fake::reply(503, "down"));
        let url = format!("{}/x", always.url);
        assert_eq!(
            get(&agent, &url, 3).unwrap(),
            (503, "down".to_string()),
            "the last answer is returned for the caller to fail on"
        );
        assert_eq!(always.requests().len(), 3);
    }

    #[test]
    fn client_errors_and_unreachable_hosts() {
        let server = fake::serve(|_| fake::reply(404, ""));
        let agent = agent(Duration::from_secs(5));
        let url = format!("{}/x", server.url);
        assert_eq!(get(&agent, &url, 3).unwrap().0, 404);
        assert_eq!(
            server.requests().len(),
            1,
            "a 404 is an answer, not a failure"
        );

        // Nothing listens on the discard port: the connection error is retried,
        // then reported.
        let err = get(&agent, "http://127.0.0.1:9/x", 2).unwrap_err();
        // "Connection refused" on Unix, "actively refused it" on Windows.
        assert!(format!("{err:#}").contains("refused"), "{err:#}");
    }

    #[test]
    fn fan_out_keeps_order_and_reports_the_first_error() {
        let items: Vec<u32> = (0..50).collect();
        let doubled = par_map(4, &items, |n| Ok(n * 2)).unwrap();
        assert_eq!(doubled, (0..50).map(|n| n * 2).collect::<Vec<_>>());
        let failed = par_map(4, &items, |n| {
            anyhow::ensure!(*n != 7, "seven");
            Ok(*n)
        });
        assert_eq!(failed.unwrap_err().to_string(), "seven");
    }
}

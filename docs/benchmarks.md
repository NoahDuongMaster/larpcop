# Benchmarks

The results of larpcop on deliberately vulnerable projects and public test suites, with the first-run scores and how the numbers were measured.

[Back to the README](../README.md)

## Results

The benchmark lives in [`bench/`](../bench) and is re-run with `bench/run.sh`. It covers 22 suites, counted from the sections of `run.sh` that write a result page. Each suite has an answer key taken from the project's own documentation, comments or labels, and larpcop runs with the `standards/recommended` rule set. The suites, their pinned versions, their answer keys and the scoring are described in [bench/README.md](../bench/README.md#suites).

Line suites report the lines found out of the lines the key lists. Category suites report TPR − FPR: the share of vulnerable cases reported minus the share of safe cases reported, averaged over vulnerability categories. A score of 0% means as many wrong reports as right ones, and +100% means every vulnerable case found with no safe case flagged. See [how scores are computed](../bench/README.md#how-scores-are-computed).

| Suite | larpcop |
|---|---|
| Juice Shop: vulnerable lines found | 11/27 (8/27 without `validate-request-input`) |
| Juice Shop: time | 6.63 s |
| NodeGoat: lines found | 12/14 |
| DVNA: lines found | 12/14 |
| DVPWA (Python): lines found | 4/4 |
| DVWS-Node (REST, GraphQL, SOAP): lines found | 13/15 |
| GoVWA (Go): lines found | 4/4 |
| OWASP Benchmark Java (2,740 cases, TPR − FPR score): time / score | 12.9 s / +91.9% |
| OWASP Benchmark Python (1,230 cases, TPR − FPR score): time / score | 2.5 s / +70.6% |
| NIST Juliet C# (1,443 web cases, TPR − FPR score): time / score | 5.0 s / +99.2% |
| NIST Juliet Java (1,665 servlet cases, TPR − FPR score) | +96.4% |
| NIST Juliet Java stored XSS (148 cases, data read from a database; held-out) | +75.0% (every CWE80/83 case; CWE81 `sendError` is deliberately skipped) |
| NIST Juliet C# stored XSS (148 cases, data read from a database; held-out) | +100.0% |
| NIST Juliet C (6,080 OS command and format string cases): time / score | 21.7 s / +100.0% |
| RailsGoat (Ruby): lines found | 13/14 |
| java-sec-code (Java/Spring, 76 endpoints, TPR − FPR score) | +84.6% |
| VulnerableApp (Java/Spring, 97 handlers, TPR − FPR score) | +88.1% |
| DVWA (PHP, TPR − FPR score) | +80.0% |
| XVWA (PHP, 19 bugs according to the project's README): lines found | 17/19 |
| WackoPicko (PHP, 14 bugs according to its README): lines found | 11/14 |
| NIST SARD PHP (20,856 cases with data from the request, 8 vulnerability types; TPR − FPR score): time / score | 23.6 s / +56.4% |
| vulnerable-node `sast/seeds` (scored with the project's script) | 11/12, 1 false positive (0 if generic rules are removed) |
| DSVW (Python, 15 sink lines) | 13/15, several credited from a neighbouring line; first run 1 line |

NodeGoat and DVNA each have one vulnerable-dependency line in their key. `dependency-vulnerability` finds those lines by querying the OSV database over the network, so those two suites need network access when scored. The counts above include them; without the rule each drops to 11/14.

## Timings

The times are the median of three runs of `larpcop check`, measured with larpcop 0.3.0 on a Darwin arm64 machine with 8 CPUs ([`bench/results/timing.txt`](../bench/results/timing.txt)), so they do not include the speed-ups made since. Those speed-ups were checked against a binary from before them: the findings were identical, field by field, on 11 of the suites (NodeGoat, DVNA, DVPWA, GoVWA, WackoPicko, DVWS-Node, vulnerable-node, XVWA, RailsGoat, java-sec-code and Juice Shop).

The clock runs around the larpcop process only, and a run that crashes is recorded as `FAILED` instead of a time. `bench/scripts/scale.sh` times a full check of `django/django` and `rails/rails` separately ([`bench/results/scale.md`](../bench/results/scale.md)).

## First run and after adding rules

Juice Shop was the development set. Every other suite was a held-out check on its first run and was then used to add rules, so its figure in the table above is no longer held-out. The exceptions are the two stored XSS suites, which were not tuned after their first run. The first-run results were:

| Suite | First run |
|---|---|
| Juice Shop (development set) | 5/27 |
| NodeGoat | 8/14 |
| DVNA | 5/14 |
| vulnerable-node `sast/seeds` | 10/12 with 1 false positive |
| DVPWA | 1/4 |
| DVWS-Node | 10/15 |
| GoVWA | 0/4 |
| OWASP Benchmark Java | +37.5% |
| DVWA | +40.0% |
| Juliet C# | +43.9% |
| RailsGoat | 10/14 |
| java-sec-code | +6.6% |
| VulnerableApp | +7.2% |
| OWASP Benchmark Python | +39.8% |
| Juliet Java | +68.6% |
| Juliet C | +84.7% |
| SARD PHP | +5.3% (16.9 s) |
| XVWA | 12/19 |
| WackoPicko | 9/14 |

The held-out method and every missed line are in [bench/README.md](../bench/README.md#first-runs-and-later-changes) and its [known misses](../bench/README.md#known-misses). Each suite has its own page in [`bench/results/`](../bench/results).

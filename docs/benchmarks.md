# Benchmarks

The public benchmark of larpcop against Semgrep OSS and gitleaks on deliberately vulnerable projects, with the first-run results for comparison.

[Back to the README](../README.md)

## Results

The benchmark lives in [`bench/`](../bench) and is re-run with `bench/run.sh`. The timings below were measured with larpcop 0.3.0, Semgrep 1.183.0 and gitleaks 8.30.1 on a Darwin arm64 machine with 8 CPUs ([`bench/results/timing.txt`](../bench/results/timing.txt)), so they do not include the speed-ups made since. Those speed-ups were checked against a binary from before them: the findings were identical, field by field, on 11 of the suites (NodeGoat, DVNA, DVPWA, GoVWA, WackoPicko, DVWS-Node, vulnerable-node, XVWA, RailsGoat, java-sec-code and Juice Shop). It covers twenty-two deliberately vulnerable suites, and each suite has an answer key from the project itself.

| | larpcop | Semgrep OSS (`p/default`) | gitleaks |
|---|---|---|---|
| Juice Shop: time (gitleaks scans secrets only) | 6.63 s | 33.75 s | 4.76 s |
| Juice Shop: vulnerable lines found | **11/27** | 6/27 | - |
| NodeGoat: lines found | **12/14** | 4/14 | - |
| DVNA: lines found | **12/14** | 7/14 | - |
| DVPWA (Python): lines found | **4/4** | 2/4 | - |
| DVWS-Node (REST, GraphQL, SOAP): lines found | **13/15** | 7/15 | - |
| GoVWA (Go): lines found | 4/4 | 4/4 | - |
| OWASP Benchmark Java (2,740 cases, TPR − FPR score): time / score | **12.9 s / +91.9%** | 45.8 s / +34.9% | - |
| OWASP Benchmark Python (1,230 cases, TPR − FPR score): time / score | **2.5 s / +70.6%** | 8.1 s / −0.8% (`p/python`), +6.9% (`p/default`) | - |
| NIST Juliet C# (1,443 web cases, TPR − FPR score): time / score | **5.0 s / +99.2%** | 16.1 s / +0.8% | - |
| NIST Juliet Java (1,665 servlet cases, TPR − FPR score) | **+96.4%** (first run +68.6%) | +22.4% (`p/java` +33.0%) | - |
| NIST Juliet Java stored XSS (148 cases, data read from a database; held-out) | **+75.0%** (every CWE80/83 case; CWE81 `sendError` is deliberately skipped) | +0.0% | - |
| NIST Juliet C# stored XSS (148 cases, data read from a database; held-out) | **+100.0%** | +0.0% | - |
| NIST Juliet C (6,080 OS command and format string cases): time / score | **21.7 s / +100.0%** (first run, held-out: +84.7%) | 32.5 s / +0.0% | - |
| Kotlin: labelled tests from the Semgrep rules repo (9 vulnerable cases, 3 clean cases) | **+88.9%** (first run +55.6%) | - (Semgrep's own tests) | - |
| RailsGoat (Ruby): lines found | **13/14** | 9/14 | - |
| java-sec-code (Java/Spring, 76 endpoints, TPR − FPR score) | **+84.6%** | +20.8% | - |
| VulnerableApp (Java/Spring, 97 handlers, TPR − FPR score) | **+88.1%** | +16.5% | - |
| DVWA (PHP, TPR − FPR score) | **+80.0%** | +3.3% | - |
| XVWA (PHP, 19 bugs according to the project's README): lines found | **17/19** | 5/19 | - |
| WackoPicko (PHP, 14 bugs according to its README): lines found | **11/14** | 1/14 | - |
| NIST SARD PHP (20,856 cases with data from the request, 8 vulnerability types; TPR − FPR score): time / score | **23.6 s / +56.4%** (first run, held-out: 16.9 s / +5.3%) | 98.1 s / +0.1% | - |
| vulnerable-node `sast/seeds` (scored with the project's script) | **11/12**, 1 false positive (0 if generic rules are removed) | 10/12, 1 false positive (8/12 if generic rules are removed) | - |
| Secrets | identical to gitleaks | - | 69 + 3 |

## First run and after adding rules

Each suite was a validation set on its first run, and was then used to add rules. The first-run results were: NodeGoat 8/14, DVNA 5/14 (Semgrep 7/14), vulnerable-node 10/12 with 1 false positive, DVPWA 1/4 (Semgrep 2/4), DVWS-Node 10/15 (Semgrep 7/15), GoVWA 0/4 (Semgrep 4/4), OWASP Benchmark Java +37.5% (Semgrep +34.9%), DVWA +40.0% (Semgrep +3.3%), Juliet C# +43.9% (Semgrep +0.8%), RailsGoat 10/14 (Semgrep 9/14), java-sec-code +6.6% (Semgrep +20.8%), VulnerableApp +7.2% (Semgrep +16.5%), OWASP Benchmark Python +39.8% (Semgrep +6.9%), Juliet Java +68.6% (Semgrep +22.4%, `p/java` +33.0%), Juliet C +84.7% (Semgrep +0.0%), SARD PHP +5.3% (Semgrep +0.1%).

The order in which the suites were run and every missed line are in [bench/README.md](../bench/README.md), which is in Vietnamese.

# larpcop benchmark

This directory measures larpcop's security rules on deliberately vulnerable projects and public test suites. Every suite has an answer key: the lines, endpoints or test cases known to contain a bug. `run.sh` fetches each suite at a pinned version, runs larpcop with the `standards/recommended` rule set and scores the findings against the key. The scored output is committed in [`results/`](results). A summary table is in [docs/benchmarks.md](../docs/benchmarks.md).

- [`run.sh`](run.sh) fetches the suites, runs larpcop, scores and writes `results/`.
- [`scripts/`](scripts) holds the scorers (`score.py`, `owasp_benchmark.py`, `juliet.py`, `sard_php.py`, `dvwa.py`, `java_sec_code.py`, `seeds.py`), the timing helper `time_it.py` and `scale.sh`.
- [`truth/`](truth) holds the answer keys written for this benchmark (`*-truth.json`) and the scripts that generate some of them (`java_sec_code_truth.py`, `java_endpoints.py`, `vulnerableapp_truth.py`).
- [`results/`](results) holds one page per suite and [`timing.txt`](results/timing.txt).

## Running it

You need `git`, `python3`, `node` (the vulnerable-node scorer is a Node script), `curl`, `unzip` and a release build of larpcop. The run clones the projects and downloads the NIST archives, so it needs network access.

```sh
cargo build --release
bench/run.sh                         # uses target/release/larpcop
bench/run.sh /path/to/larpcop        # another binary
BENCH_WORK=/data/bench bench/run.sh  # another working directory
```

`BENCH_WORK` is where checkouts and archives are kept. It defaults to `${TMPDIR:-/tmp}/larpcop-bench`. Existing checkouts are reused, so only the first run clones. A run overwrites the pages in `results/`. The raw JSON reports it writes next to them are ignored by git.

For each suite the script checks out the pinned commit (or unpacks the selected cases from the NIST archive), writes a `.larpcop.yaml` that extends `standards/recommended`, runs `larpcop check --format json` and passes the report to the suite's scorer. The scoring run uses the full set, including `dependency-vulnerability`, which queries OSV.dev. The timing runs of the application suites disable that rule, so the clock does not include advisory lookups.

Timings are the median wall time of three runs. `scripts/time_it.py` starts the clock around the larpcop process only. A run that exits with a code other than 0 or 1 (1 means findings were reported) stops the benchmark and is recorded as `FAILED(exit N)`, so a crash cannot show up as a fast run. The first line of `timing.txt` records the larpcop version, the operating system and the CPU count.

`scripts/scale.sh` is separate from `run.sh`. It times a full check of two large real repositories, `django/django` (`a05e16a`) and `rails/rails` (`d0f264a`), and counts the findings. Nobody wrote these for a benchmark, so there is no answer key. See [`results/scale.md`](results/scale.md).

## How scores are computed

Only security rules count. The code-quality rules in the recommended set (complexity, function length and similar) are ignored.

Line-scored suites give a list of vulnerable lines. A line is found when a larpcop security finding covers it, give or take 3 lines, in the same file. The class of the finding is not compared with the listed bug; each result page shows which rules matched, so a reader can judge. A finding at a call site also credits a sink line in another file when the finding's note names that line. The score is lines found over lines listed. These suites measure recall only: a finding on any other line is neither rewarded nor penalised.

The vulnerable-node seeds use the project's own scorer, `sast/tests/score.js`. A seed (one file, one bug) counts as found when the report names its file, and two clean files measure false positives. The seeds are scored twice: with every security finding, and without the generic per-file checks (`validate-request-input`), which credit a file without naming its bug.

Category-scored suites label safe code as well. Cases are grouped by vulnerability category. For each category, TPR is the share of vulnerable cases with a finding of that category, FPR is the share of safe cases with one, and the category score is TPR − FPR. The suite score is the mean over categories, from −100% to +100%. Reporting every case scores 0 in a category, and so does reporting none. How a case is labelled and located depends on the suite:

- OWASP Benchmark: the project's expected-results file; a case is reported when a finding of its category falls in its file, as in the project's own scorecard. Policy rules, which forbid a construct whatever reaches it, count as findings of their category (for example `java-no-sql-concat` for SQL injection).
- Juliet: code in a `bad*` method or `*_bad` file is vulnerable, code in `good*` is not. The stored XSS suites count `java-taint-stored-xss` and `cs-taint-stored-xss`, and Juliet C counts `c-taint-shell` and `c-taint-format`.
- SARD PHP: each file is labelled bad or good as a whole by the suite's manifest. larpcop is counted through its `php-taint-*` rules, not through policy rules.
- DVWA: in each module `low`, `medium` and `high` are vulnerable and `impossible` is the fixed version.
- java-sec-code and VulnerableApp: a case is an endpoint or handler, and it is reported when a finding of its category lies in its line range. A call-site finding of a flow into a helper counts.

## Suites

There are 22 suites, one for each result page that `run.sh` writes. Names link to the result page.

### Line-scored

| Suite | Source, pinned | Answer key | Found | First run |
|---|---|---|---|---|
| [Juice Shop](results/juice-shop.md) | OWASP Juice Shop `v20.3.0` (Express, Angular) | `// vuln-code-snippet vuln-line` comments placed by the Juice Shop maintainers: 27 lines, excluding `test/` and `data/static/codefixes/` | 11/27 (8/27 without `validate-request-input`) | 5/27 |
| [NodeGoat](results/NodeGoat.md) | OWASP NodeGoat `c5cb68a` (Express, MongoDB) | [`nodegoat-truth.json`](truth/nodegoat-truth.json): 14 lines from the NodeGoat tutorial | 12/14 | 8/14 |
| [DVNA](results/dvna.md) | appsecco/dvna `9ba473a` (Express, Sequelize, EJS) | [`dvna-truth.json`](truth/dvna-truth.json): 14 lines from the project's `docs/solution/*.md` | 12/14 | 5/14 |
| [DVPWA](results/dvpwa.md) | anxolerd/dvpwa `a1d8f89` (Python, aiohttp, Jinja2) | [`dvpwa-truth.json`](truth/dvpwa-truth.json): 4 lines from the Vulnerabilities section of the README | 4/4 | 1/4 |
| [GoVWA](results/govwa.md) | 0c34/govwa `4058f79` (Go, net/http, html/template) | [`govwa-truth.json`](truth/govwa-truth.json): 4 lines the project marks with its own comments in `vulnerability/sqli` and `vulnerability/xss`. IDOR and client-side auth are logic bugs, and the XXE module is an empty file | 4/4 | 0/4 |
| [DVWS-Node](results/dvws-node.md) | snoopysecurity/dvws-node `e83689c` (Express, MongoDB, MySQL, GraphQL, SOAP and XML-RPC) | [`dvws-truth.json`](truth/dvws-truth.json): 15 lines from `CHALLENGES.md`, one for each challenge whose bug sits on a single line. IDOR, CORS, rate limiting and other design flaws are left out | 13/15 (13/15 without `validate-request-input`) | 10/15 (9/15 without) |
| [RailsGoat](results/railsgoat.md) | OWASP/railsgoat `f5951f1` (Ruby on Rails) | [`railsgoat-truth.json`](truth/railsgoat-truth.json): 14 lines from the RailsGoat wiki | 13/14 | 10/14 |
| [XVWA](results/php-apps.md) | s4n7h0/xvwa `fb30fa5` (plain PHP) | [`xvwa-truth.json`](truth/xvwa-truth.json): the 19 bugs the README lists, one module each | 17/19 (16 of the listed kind) | 12/19 (11 of the listed kind) |
| [WackoPicko](results/php-apps.md) | adamdoupe/WackoPicko `cabc1b3` (plain PHP) | [`wackopicko-truth.json`](truth/wackopicko-truth.json): the 14 bugs the README lists. The admin password lives in the database dump, not in code, and is not counted | 11/14 | 9/14 |
| [DSVW](results/dsvw.md) | stamparm/DSVW `9ca3c9a` (Python, 98 lines in one file) | [`dsvw-truth.json`](truth/dsvw-truth.json): 15 sink lines, written from the app's own table of cases before any rule ran on it | 13/15, several credited from a neighbouring line (see [DSVW](#dsvw)) | 1 line |

One of the 17 XVWA lines, the CSRF one, is credited through a finding of a different kind one line away. The other 16 are found by a finding of the kind the README names.

### File-scored

| Suite | Source, pinned | Answer key | Found | First run |
|---|---|---|---|---|
| [vulnerable-node seeds](results/seeds.md) | cr0hn/vulnerable-node `d68f2a3`, directory `sast/seeds/` | The project's `sast/ground-truth.yaml`: 12 files with one bug each and 2 clean files | 11/12, 1 false positive (11/12, 0 false positives without the generic per-file checks) | 10/12, 1 false positive (6/12 without) |

### Category-scored

| Suite | Source, pinned | Cases and labels | Score | First run |
|---|---|---|---|---|
| [OWASP Benchmark Java](results/owasp-benchmark.md) | OWASP-Benchmark/BenchmarkJava `f40c618` | 2,740 cases, labelled by the project | +91.9% | +37.5% |
| [OWASP Benchmark Python](results/owasp-benchmark-python.md) | OWASP-Benchmark/BenchmarkPython `f129148` | 1,230 cases, labelled in `expectedresults-0.1.csv` | +70.6% | +39.8% |
| [DVWA](results/dvwa.md) | digininja/DVWA `a1978a2` (PHP) | 8 modules (SQL injection, blind SQL injection, command injection, file inclusion, upload, reflected XSS, stored XSS, open redirect) at 4 levels each | +80.0% | +40.0% |
| [Juliet C#](results/juliet-cs.md) | NIST SARD Juliet C# 1.3 (2020-08-01 archive) | 1,443 cases whose data comes from an HTTP request (`QueryString`, `Params`, `Cookies`), in 10 CWEs: SQL injection, OS command, relative and absolute path traversal, open redirect, three kinds of XSS, LDAP, XPath | +99.2% | +43.9% |
| [Juliet Java](results/juliet-java.md) | NIST SARD Juliet Java 1.3 (2017-10-01 archive) | 1,665 servlet cases (`getParameter`, `getCookies`, `getQueryString`) in the same 10 CWEs | +96.4% | +68.6% |
| [Juliet Java stored XSS](results/juliet-java-stored.md) | Same archive | 148 XSS cases (CWE80, 81, 83) whose data is read from a database row | +75.0% | +75.0% (no good code flagged) |
| [Juliet C# stored XSS](results/juliet-cs-stored.md) | Same C# archive | 148 XSS cases whose data is read from a database row | +100.0% | +100.0% (148 of 148, no good code flagged) |
| [Juliet C](results/juliet-c.md) | NIST SARD Juliet C/C++ 1.3 (2017-10-01 archive) | 6,080 `.c` cases: OS command injection (CWE78, 3,800) and format string (CWE134, 2,280), with data from the console, the environment, files and sockets | +100.0% | +84.7% (format +87%, shell +83%, no good code flagged) |
| [SARD PHP](results/sard-php.md) | NIST SARD PHP Vulnerability Test Suite #103 (2015-10-27), sha256 `3407473fc2cfa38eea9216b8a7f22559b656f20ba5f2eb3b6992010265780f8c` | 20,856 of the 42,212 cases, those whose data comes from the request, in 8 vulnerability types (XSS, SQL, XPath, LDAP, redirect, file inclusion, OS command, `eval`) | +56.4% | +5.3% (took 16.9 s) |
| [java-sec-code](results/java-sec-code.md) | JoyChou93/java-sec-code `4711f4e` (Java, Spring) | [`java-sec-code-truth.json`](truth/java-sec-code-truth.json): 76 endpoints, labelled from the project's routes (`/vuln`, `/sec`) and comments | +84.6% | +6.6% |
| [VulnerableApp](results/vulnerableapp.md) | SasanLabs/VulnerableApp `9f45cd5` (Java, Spring) | [`vulnerableapp-truth.json`](truth/vulnerableapp-truth.json): 97 handlers, labelled by the project's `Variant.SECURE` | +88.1% | +7.2% |

The Juliet stored XSS suites have the same first-run and current score because nothing was changed after their first run.

### Timings

Median of three runs of `larpcop check`, larpcop 0.3.0 on a Darwin arm64 machine with 8 CPUs. [`timing.txt`](results/timing.txt) lists the first five rows. A re-run of `run.sh` writes there the times of all application suites and of the two OWASP Benchmark editions; it does not time the Juliet and SARD PHP suites.

| Suite | Time |
|---|---|
| Juice Shop | 6.63 s |
| NodeGoat | 3.25 s |
| DVNA | 1.21 s |
| DVPWA | 2.59 s |
| DVWS-Node | 1.94 s |
| GoVWA | 1.57 s |
| OWASP Benchmark Java | 12.9 s |
| OWASP Benchmark Python | 2.5 s |
| Juliet C# | 5.0 s |
| Juliet C | 21.7 s |
| SARD PHP | 23.6 s |

The Juice Shop time includes 9 vendored library files (three.js and others, 39,500 lines) that the project commits although they match its `.gitignore`. larpcop checks tracked files even when they are ignored. `run.sh` times the application suites with `dependency-vulnerability` disabled. The committed `timing.txt` was taken before that, with the rule enabled, so NodeGoat's time there is mostly the wait for advisory lookups on the 1,480 packages in its `package-lock.json`.

## First runs and later changes

Each suite ran first as a held-out check, then served to improve larpcop. Both numbers are listed above so that the gap is visible.

- Juice Shop was the development set, used while the first rules were written. Its first run is not a held-out number.
- Every other suite was a held-out check on its first run: the rules under test had been committed before the suite was scored. For RailsGoat, java-sec-code, VulnerableApp, OWASP Benchmark Python, the Juliet and SARD PHP suites, XVWA, WackoPicko and DSVW, the answer key or case selection and the scorer were committed as well, before any run.
- After a first run, the misses and false positives were analysed and rules or engine changes followed. The current score of those suites is a regression check, not a held-out number.
- Juliet Java stored XSS and Juliet C# stored XSS were not tuned after their first run, so their scores are held-out numbers.
- The current scores show only that none of the suites has regressed. Judging a new rule needs a suite nobody has looked at yet.

First runs fell short for a few recurring reasons:

- Request sources that a framework exposes in its own way: aiohttp, Starlette and Tornado request objects, NestJS decorators, FastAPI and Flask handler parameters, GraphQL resolver arguments, Spring meta-annotations, Python `request.cookies` and headers.
- Flows the engine did not follow across files and classes: same-package Java and C# classes, Java imports from other packages, methods of imported classes, Go methods by receiver, PHP files pulled in with `require`, C files in the same directory, call chains of four or five files, static fields and globals of another class or file, data passed through serialization, calls through a base class.
- Flows the engine did not follow inside a construct: Ruby scopes and calls without parentheses, C pointers that alias one variable, function pointers, Python `match`/`case`, PHP files that mix HTML and code.
- Rules that did not exist yet: XSS in Go, XXE and server-side template injection in Java, LDAP and XPath injection in several languages, JWT `alg: none`, SQL assembled in a variable before it reaches `execute`.
- Guards and sanitizers read wrongly: `is_numeric` and `ctype_digit` are checks, not cleaners; `startsWith` guards a path only once it is resolved; an escaper protects only the sink it is made for.
- Sink names that were too broad: `RegExp.prototype.exec` read as `child_process.exec`, `stream.write(a + b)` as XSS, `dict.get(x)` as SSRF. Sinks are now declared by name (`cp.exec`, `res.send`, `session.get`).
- A clean assignment inside an `if` branch clearing a variable for the whole function, as if it always ran. An assignment that runs on only some paths (inside an `if`, loop, `try` or `switch`) can now taint a variable but not clean it.

## Reading a result page

A line-scored page has one row per answer-key line with the larpcop rules that reported it, or a dash when none did. Below the table it gives the number of lines found and the count of security findings per rule, including findings on lines the key does not list.

A category-scored page has one row per category with TPR, FPR and score, and the average. Many pages have a first-run section and a section for the current state, which is marked as not held-out. The remarks below the tables list what changed between the two and what is still wrong.

`seeds.md` gives the project's scorer output for both counting modes. `php-apps.md` is a write-up of XVWA and WackoPicko together; `run.sh` writes their line tables to `xvwa.md` and `WackoPicko.md`. `timing.txt` holds the timings.

## Known misses

What larpcop does not report, and why. The result pages have the rest.

- Juice Shop, 16 of 27 lines: logic, authorization and configuration bugs with no syntactic shape, such as an exposed admin route, a redirect allowlist built on `includes`, a rate limit that trusts `X-Forwarded-For` and chatbot prompt injection. `larpcop review` aims at this kind of bug but is not counted because its answers are not deterministic.
- NodeGoat: a weak password policy (`session.js:144`) and a password stored in plain text (`user-dao.js:25`, an assignment rather than a comparison; the comparison at `user-dao.js:61` is found).
- DVNA: an API that returns every user record (`appHandler.js:207`) and an admin route with no authorization check (`routes/app.js:42`).
- DVWS-Node: XXE in a hand-written entity expander (`vulnerable-xml.js:81`, no XML parser is involved) and SSRF through an XML-RPC method parameter (`xml-rpc/server.js:29`; the `xmlrpc` library is not a declared request source).
- vulnerable-node seeds: NoSQL injection in a function that takes the filter as a parameter, with no request source in the file. The one false positive, `clean-escaped.js`, comes from a generic per-file check.
- RailsGoat: CSRF protection turned off. larpcop reports it at the class declaration (line 2), and the answer key lists the commented-out `protect_from_forgery` (line 9), which is outside the 3-line window, so it counts as missed.
- XVWA: an IDOR and a `delete` with no admin check.
- WackoPicko: forceful browsing, a page that needs no login and a coupon that can be reused.
- DVWA: the file-inclusion levels only assign `$file` at the top level of a file that `fi/index.php` requires through a path chosen at run time, and variables that a required file sets are not followed into the file that requires it. The stored-XSS levels write the guestbook row that a shared `dvwaGuestbook()` prints; `php-taint-stored-xss` reports it there (`dvwaPage.inc.php:625`), not in the per-level files the scorer credits. That rule was written after DVWA had been scored, so it is not a held-out result.
- OWASP Benchmark: SQL injection scores +11% on the Java edition because `java-no-sql-concat`, a policy rule, reports SQL built by concatenation whatever is concatenated. On the Python edition `py-no-shell-true`, `py-no-eval` and `py-no-ldap-interpolation` do the same for their constructs, and command injection, code injection and LDAP injection score 0%.
- Juliet Java and Juliet Java stored XSS: `response.sendError(404, data)` (CWE81: 111 cases in the first suite, and all 37 misses in the stored suite) is deliberately not an XSS sink, because Tomcat and Jetty escape the message on their error pages.
- Juliet C#: every case is found. The 12 cases flagged in good code are `GoodG2B` of flow 75 in SQL and XPath, where Juliet 1.3 reads the same request data as the bad code, so they are real injections labelled good.
- SARD PHP: most remaining misses are cases whose label contradicts the code. 768 bad cases check and copy a `$sanitized` that is never assigned, 272 only print a literal, the `span_Style` cases print the constant `checked_data` rather than request data, 48 good cases sanitize `$tained` (a typo) while the raw `$tainted` reaches `system()`, and 1,328 good cases use an escape function that does not protect the sink they reach (`addslashes` for XPath, shell and paths, `htmlspecialchars` for LDAP).
- java-sec-code: the 5 SSRF `/sec` endpoints rely on a runtime socket hook (`SecurityUtil.startSSRFHook()`), so statically they look like the vulnerable ones. The 3 MyBatis endpoints are found in the mapper files, outside the endpoint, and the scorer does not count them.
- VulnerableApp: SQL levels 3 and 4 strip quotes and then concatenate, and `java-no-sql-concat` forbids the concatenation itself.

### DSVW

DSVW is a 98-line Python file. Its answer key lists 15 lines. With the standard 3-line window larpcop finds 13 of them, but the score overstates what it detects. No `py-taint-*` rule reports anything on the file; all 13 credits come from policy rules, and several are neighbouring-line credits of a different class. The reflected XSS at line 25, for example, is credited by the SQL rule at line 22 and by the deserialization rule at line 27. Lines 55 (template injection) and 70 (open redirect) have no finding.

On the first run the only hit was `exec(program)` at line 49, reported by `py-taint-shell`. The current run reports line 49 through `py-no-eval`.

DSVW reads all of its input through one dict built at the top of `do_GET`:

```python
params = dict((match.group("parameter"), urllib.parse.unquote(...re.findall(...)))
              for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)([^&]+)", query))
```

Every sink then uses `params["id"]`, `params["domain"]` and so on. The source is `self.path`, the idiom of `BaseHTTPRequestHandler`, and it is not one of the Python sources larpcop knows (`request.args`, `sys.argv`, `input()` and similar). That one missing source explains the taint misses, so this is a gap in the rules, not in the taint walk.

Declaring `self.path` and `self.headers` of `BaseHTTPRequestHandler` as sources would close it. The answer key has since been seen, so a score taken after that change would no longer be held-out. The gap is recorded as a measurement, and the fix belongs on a file whose key is still unknown.

DSVW stays useful as a small regression check: its lines are known and a run takes under a second.

## Caveats

- The current scores of most suites are not held-out numbers; see [First runs and later changes](#first-runs-and-later-changes).
- Two answer-key lines are vulnerable dependencies: NodeGoat `package-lock.json:6742` (marked 0.3.5) and DVNA `package.json:25` (mathjs 3.10.1). Only `dependency-vulnerability` finds them, and it queries the OSV database over the network. These two suites therefore need network access, and their results can change as advisories are published. With the rule off those two lines count as missed (11/14 each).
- Line matching does not compare the class of the finding with the class of the listed bug. XVWA states both counts for this reason.
- The recommended set includes GitHub Actions and Terraform rules, so finding totals on the result pages include their findings (`gha-unpinned-action`, `tf-open-ingress` and others).
- larpcop parses files that contain syntax errors, so it also reports in the snippet files under Juice Shop's `data/static/codefixes/`. Those files are not in the answer key.
- Angular's `[innerHTML]` binding is not reported as XSS, because Angular sanitizes it; the real bug in Juice Shop is `bypassSecurityTrust*`. Sequelize filters (`where:`, `include:`) are not reported as NoSQL injection, because Sequelize does not accept operators from JSON.
- Answer keys are small. With 14 lines, one line moves a score by 7 points, so the large suites (OWASP Benchmark, Juliet, SARD PHP) are the steadier measure.

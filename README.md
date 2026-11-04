<p align="center">
  <img src="assets/jimothy.svg" width="180" alt="Jimothy, larpcop's mascot: a round raccoon in a police cap">
</p>

<h1 align="center">larpcop</h1>

<p align="center">
  <b>Your agent says "done, all tests pass." larpcop asks for the receipt.</b>
</p>

<p align="center">
  <a href="https://github.com/NoahDuongMaster/larpcop/actions/workflows/ci.yml"><img src="https://github.com/NoahDuongMaster/larpcop/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/NoahDuongMaster/larpcop/releases/latest"><img src="https://img.shields.io/github/v/release/NoahDuongMaster/larpcop" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0">
</p>

<p align="center">
  <b>English</b> · <a href="README.vi.md">Tiếng Việt</a> · <a href="README.zh-CN.md">简体中文</a>
</p>

> **larp** /lɑːrp/ *(verb, 2026 slang)*: to act out something you did not actually do.
> *"I followed the rules and ran the tests."* (It did not run the tests.)

larpcop makes every coding agent (Claude Code, Codex, Gemini CLI, Cursor, Copilot CLI, Factory Droid, Kiro) and every human follow the same rules, on any stack. It is one Rust binary. Rules are matched with [ast-grep](https://ast-grep.github.io) (tree-sitter, 25+ languages), so the verdict is the same on every run. There is no model in the gate and no vibes in the exit code.

The mascot is Jimothy, the round Seattle raccoon who got famous in July 2026, redrawn here in a police cap.

## See it work

An agent writes a file. larpcop checks it right after the edit and sends the errors back to the agent:

```text
larpcop: the file you just edited breaks enforced rules. Fix them now.

src/app.ts
  1:1     error   secrets  Found a Stripe Access Token ... (gitleaks rule `stripe-access-token`)
          │ const API_KEY="***";
          └ fix: Remove it from the code and load it from the environment or a secret manager.
  2:24    error   no-explicit-any  `any` disables type checking.
          │ export function run(x: any) {
          └ fix: Use a precise type, a generic, or `unknown` narrowed with a type guard or schema.
  4:3     error   no-suppression-comment  Suppression comment: it hides a check instead of fixing what it found.
          │ // @ts-ignore
  5:10    error   no-eval  `eval` / `new Function` executes strings as code.
          │ return eval(x);
```

Then the agent tries the classic:

```text
$ git commit --no-verify -m "it works, trust me"
larpcop: blocked: skipping git hooks (`--no-verify` / `git commit -n`) is not allowed.
```

Both outputs come from the v0.3.0 release binary, trimmed for length.

## Why a gate and not a prompt

A prompt can only ask. Only a deterministic check can refuse. So larpcop sits at the points every agent has to pass through:

| Layer | What runs | Can the agent skip it? |
|---|---|---|
| CI ([`enforce.yml`](.github/workflows/enforce.yml) or an org ruleset) | `larpcop check --since origin/<base>` | No |
| Git pre-commit (`larpcop install`) | `larpcop check --staged` (the staged content, not the working tree) | With `--no-verify`, and then CI catches it |
| Agent hooks (`larpcop hook <agent>`) | Blocks bypasses, reports errors right after each edit, refuses to finish while errors remain | Agents without hooks skip it, and still hit git and CI |
| `AGENTS.md` (`larpcop sync`) | Generated guidelines and a rule table | It is a suggestion, so yes |

Hooks shorten the feedback loop. Git and CI are what make the rules binding. [More on the enforcement model](docs/agents.md).

## Install

Each release ships binaries for macOS (arm64, x64), Linux (arm64, x64) and Windows (x64), 5 to 9 MB compressed.

```sh
# macOS and Linux
curl -LsSf https://github.com/NoahDuongMaster/larpcop/releases/latest/download/larpcop-installer.sh | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/NoahDuongMaster/larpcop/releases/latest/download/larpcop-installer.ps1 | iex"
```

The installers put the binary in `~/.local/bin`. To build from source, clone the repo and run `cargo build --release`. There is no crates.io or npm package yet, and the Homebrew formula is attached to the release but not published.

## Quick start

```sh
cd your-repo
cat > .larpcop.yaml <<'EOF'
extends:
  - https://github.com/NoahDuongMaster/larpcop.git#v0.3.0//standards/recommended
EOF
larpcop install   # git pre-commit hook
larpcop sync      # AGENTS.md plus hook files for every agent
larpcop check     # see what it finds
```

`recommended` is the rule set maintained in this repo (see below). Your company can keep its own standards in a separate repo and pin them by tag. A repo cannot opt out of the standards CI enforces, and rules marked `locked` cannot be disabled or overridden. [Configuration](docs/configuration.md).

## What it catches

- **Structure, not spelling.** Rules are ast-grep patterns. Codex once dodged the first version of the `no-console` rule with `globalThis["console"]["log"](x)`. The rule now matches the structure, and the message tells the agent that rewording the same thing still counts as a violation. [Rules](docs/rules.md).
- **Injection across functions and files.** Taint analysis follows data from sources to sinks through assignments, calls, imports, callbacks and class fields. 99 taint rules cover SQL, shell, XSS, SSRF, path traversal, open redirect, deserialization and more. [Taint](docs/taint.md).
- **Secrets.** 222 [gitleaks](https://github.com/gitleaks/gitleaks) detectors are embedded in the binary. Matches print redacted. [Security](docs/security.md).
- **Dependencies.** Known malware and known vulnerabilities (OSV.dev) block; `recommended` turns that on at `high`. Two more gates are opt-in: a minimum release age for every new version (14 days is the usual setting) and a human approving each new direct dependency. The hook stops `npm i some-evil-package` before its install script runs. [Dependencies](docs/dependencies.md).
- **Code quality.** Function length, cyclomatic complexity, a baseline for legacy code, SARIF and GitLab reports, a single sticky PR comment, an LSP server, and an HTML dashboard.
- **Review by a model, never as a gate.** `larpcop review` and `larpcop learn` use whatever CLI you already have (`claude -p`, `codex exec`, `gemini`, `ollama`). They only warn. `learn` turns a standard written in words into deterministic rules. [AI review](docs/ai-review.md).
- **A tool the agent can ask.** `larpcop mcp` gives agents `rules_for`, `check_content`, `check`, `fix` and `explain_rule`, so they can check a draft before they write it.
- **Rollout.** `larpcop org setup <owner>` opens one PR per repository. `larpcop sync --managed` writes machine-level policy files that users cannot switch off. [Organization](docs/organization.md).

The `recommended` set has 93 ast-grep rule files, 99 taint rules, 6 text rules, the secrets detectors and the vulnerability check.

## Agents

| Agent | Before a tool runs | After an edit | When it tries to stop |
|---|---|---|---|
| Claude Code | yes | yes | yes |
| Codex | yes | yes | yes |
| Gemini CLI | yes | yes | yes |
| Cursor | yes | yes | yes |
| Copilot CLI | yes | yes | yes |
| Factory Droid | yes | yes | yes |
| Kiro | yes, and it checks the content about to be written | not available (Kiro does not return PostToolUse output to the model) | yes |

The stop hook blocks once. If the agent still stops (to ask a human, for example), it is allowed to, and the violating code still cannot be committed or merged.

Claude Code and Codex were run for real. Kiro's payloads were recorded from a real `kiro-cli`. Cursor's come from the `cursor-agent` source. Gemini CLI, Copilot CLI and Factory Droid follow the vendors' hook references and have not been run with the real agent. Details and per-agent notes: [Agents](docs/agents.md).

## Benchmarks

Detection against deliberately vulnerable projects, scored against each project's own list of known bugs.

| Suite | larpcop |
|---|---|
| Juice Shop, vulnerable lines found | 11/27 |
| NodeGoat | 12/14 |
| DVNA | 12/14 |
| OWASP Benchmark Java (2,740 cases, TPR − FPR) | +91.9% |
| NIST Juliet C# (1,443 web cases, TPR − FPR) | +99.2% |
| NIST SARD PHP (20,856 cases, TPR − FPR) | +56.4% |

Read these with one caveat in mind. Every suite was a held-out check on its first run, then was used to write more rules. The first-run numbers are lower and are listed next to the final ones, with the list of suites, the method and the misses, in [Benchmarks](docs/benchmarks.md). Re-run it with `bench/run.sh`.

## Where it falls short

- **Logic and authorization bugs** (IDOR, a missing admin check, returning too much data) have no common syntactic shape. On three of the benchmark suites, no SAST tool caught them. `larpcop review` aims at them but can only warn.
- **CSRF** has no general rule. A state-changing `GET` handler differs from a correct one only by a missing token check, and a missing call is true of every file. The bundled rules only flag an explicit opt-out, for example Rails without `protect_from_forgery`, Spring's `.disable()` and Django's `@csrf_exempt`.
- **Taint is an approximation.** The list of what it follows and what it does not is in [Taint](docs/taint.md).
- **Advisory-based checks** cannot know about a malicious release nobody has reported yet. The release-age gate, if you turn it on, covers most of that gap.
- **Files an agent writes through a shell script** are checked after the command runs, not before. Pre-commit and CI still apply.

## FAQ

**My agent will just pass `--no-verify`.**
It can try. The hook reads shell commands with a real parser, so `bash -c 'rm .larpcop.yaml'`, `--no-ver""ify` and `sudo env SKIP=all git commit` are all blocked. If something slips through, CI checks the pull request anyway.

**Why not put the rules in `AGENTS.md` and trust the agent?**
Agents read it the way people read terms of service. larpcop does generate an `AGENTS.md`, because it helps. It is not what enforces anything.

**Does it send my code to a model?**
Only if you run `larpcop review` or `larpcop learn`, and only to the CLI you configured. `check`, the hooks and the default CI workflow never call a model (the workflow's `review` step is off unless you turn it on). Dependency checks call deps.dev and OSV.dev.

**Who is Jimothy?**
A round raccoon, very famous in Seattle in July 2026. Now on duty.

## Documentation

| Page | Covers |
|---|---|
| [Configuration](docs/configuration.md) | Standards, `extends`, `locked`, commands, exit codes, baseline, environment variables |
| [Rules](docs/rules.md) | Writing rules, `metadata.resolve`, fixes and fixtures, the `recommended` set, quality reports |
| [Security](docs/security.md) | The four layers, text rules, secrets |
| [Taint](docs/taint.md) | The `taint:` reference, guards, type-aware sinks, limits |
| [Dependencies](docs/dependencies.md) | Approval, release age, vulnerabilities and malware |
| [AI review](docs/ai-review.md) | `review` and `learn` |
| [Agents](docs/agents.md) | Enforcement model, per-agent hooks, MCP server |
| [Organization](docs/organization.md) | Dashboard, managed policy, `org`, CI workflow, releases |
| [Benchmarks](docs/benchmarks.md) | Full results |
| [Verification](docs/verification.md) | What the tests cover and what was run for real |

## Development

```sh
cargo fmt --check && cargo clippy --all-targets && cargo test
cargo run -- check   # larpcop checks its own source with its own rules
```

Files stay under 300 lines, errors are never swallowed, and the repo's own `AGENTS.md` lists the rest.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in larpcop, as defined in the Apache-2.0 license, is dual licensed as above, without any additional terms or conditions.

The secrets detectors (`assets/gitleaks.toml`) come from [gitleaks](https://github.com/gitleaks/gitleaks), MIT licensed. The license text is in [`assets/gitleaks.LICENSE`](assets/gitleaks.LICENSE).

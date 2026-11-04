# Verification

What larpcop's tests cover, and what was run for real on GitHub, with real agents, real lockfiles and real dependency data.

[Back to the README](../README.md)

## CI matrix

[`ci.yml`](../.github/workflows/ci.yml) has two jobs. The `lint` job runs `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` on ubuntu and macOS only. The `test` job runs on ubuntu, macOS and Windows, and runs `cargo test`, `cargo run -- check` and `cargo run -- sync --check`. The three type-query tests (tsserver, gopls, rust-analyzer) run only on ubuntu and macOS: the LSP client has no Windows-specific code, and rust-analyzer on a Windows runner takes about 40 s for the first request.

## What the tests cover

`cargo test` covers these categories:

- **Unit:** the guard, shell lookup, and paths in Codex patches. Reading real lockfiles from npm 11, pnpm 11, uv 0.11, cargo 1.98, bun 1.4 and bundler, along with yarn v1/Berry, Poetry, go.mod, NuGet, Gradle, Composer, pom.xml and csproj, and the private-registry, git and workspace entries that must be skipped. Manifests. Detection of install commands. Gate setup for 4 package managers.
- **Dashboard:** open and baselined counts per rule, the debt trend over git history, and a page that contains no scripts.
- **AI (the model is faked with shell scripts):** review reports only changed lines, drops unknown rules and caches answers. `learn` sends a failing rule back together with the error, keeps only rules that pass their tests, and the rules it writes run like normal rules.
- **Security:** taint through variables, destructuring, sanitizers and reassignment (TS, Python, Go, Rust), through function calls and imports, callbacks and guards. `sink_types` through the real typescript-language-server, gopls and rust-analyzer (across files). Secrets are masked when printed. With a fake OSV: malware is always blocked, vulnerabilities block only new versions, blocking follows the threshold, and the hook blocks install commands.
- **Integration:** check, locked, git extends by tag, staged, `--changed`/`--since`, linter delegation, the github format, prevention of rule evasion, the hooks of all 7 agents (Claude Code, Codex, Gemini CLI, Cursor, Copilot CLI, Factory Droid and Kiro), idempotent sync, drift detection, CRLF, and a real pre-commit. For dependencies: version age (through the cache and through a fake deps.dev server), the merge-base of a PR, the security-patch exception, the package manager gate, approval of new dependencies (including monorepos), the hook that blocks install commands, and a lock that can only be tightened.

## Runs on GitHub

On real GitHub (repo `NoahDuongMaster/larpcop`):

- [`ci.yml`](../.github/workflows/ci.yml) runs on ubuntu, macOS and **Windows**: the `lint` job (`cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`) on ubuntu and macOS only, and the `test` job (`cargo test`, `cargo run -- check` and `cargo run -- sync --check`) on all three. The Windows test run also covers a linter executed through Git's `sh.exe`, extends from `file:///C:/…`, CRLF and a real pre-commit.
- Release `v0.3.0`: [release.yml](../.github/workflows/release.yml) builds 5 targets. The installer was installed for real into `~/.local/bin` the way the Install section of the [README](../README.md#install) describes.
- The CI gate, tried with PR #1 (closed, not merged):
  - The violating commit was blocked by the pre-commit hook on the local machine; it was pushed with `--no-verify`.
  - `enforce` downloaded the binary from the release, **failed**, and put `no-explicit-any` / `no-console` annotations on the exact lines in the PR.
  - Pushing a fix turned every check green.

## Real agent runs

Real agents were also run in a demo repo:

- **Claude Code**:
  - With AGENTS.md: it complied on its own and refused `--no-verify`.
  - Without AGENTS.md: it wrote `console.log`, and the Stop hook forced it to delete it itself.
  - When the user told it to use `any`, the agent stopped and asked the person. Pre-commit blocked the violating file; when the person used `--no-verify`, CI still caught it.
- **Codex** (no AGENTS.md, told to use `any` and `--no-verify`):
  - `--no-verify` was blocked.
  - The after-edit hook caught `any`, and Codex switched to `unknown`.
  - The first time, Codex got around the console rule with `globalThis["console"]`. After the rule was fixed, a second run made Codex delete `console.log` outright.
- **Claude Code with dependency rules**: two sessions were asked to "use package `slugify`, install with npm", one with AGENTS.md and one with only the hook:
  - In both, the hook blocked `npm install slugify` *before* the command ran. Nothing was installed, no file was created, and the agent stopped to ask a person for approval (total $0.43).
  - This run exposed a bug: `2>&1` in `npm install slugify 2>&1 | tail -5` was read as a package name. It was fixed, with a regression test.

## Real lockfiles

Lockfiles produced by real tools, taken from public repos (the dev machine has no composer, dotnet or gradle):

- `composer.lock` of symfony/demo: all 153/153 packages were read, and it has 4 real OSV advisories (`league/commonmark`, `symfony/http-foundation`, `symfony/yaml`).
- `packages.lock.json` of dorssel/usbipd-win: all 40 packages were read (46 entries, duplicated across target frameworks).
- `gradle.lockfile` of Netflix/maestro: all 100 lines were read, with 11 OSV advisories.

## Real dependency data

- `typescript@next` (published 2 hours earlier) was blocked together with its 7 platform binaries. Each error carried a suggestion of `7.0.2`; the 8 deps.dev lookups took 0.58 s in total.
- larpcop's own `Cargo.lock` had 3 new crates blocked, 9 to 13 days old; they were downgraded to exactly the suggested versions. 2 other crates were let through because they are RUSTSEC patch versions.

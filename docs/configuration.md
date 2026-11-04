# Configuration and commands

This page covers the standards and project config files, the order in which config is applied, the full command list, exit codes, baselines, environment variables and Windows specifics.

[Back to the README](../README.md)

## Standards and project config

### Standards repo

Company standards live in a separate repo, tagged with versions. See [examples/standards](../examples/standards) for an example.

```yaml
# larpcop.yaml
max_lines: { max: 300, exclude: ["**/*.test.*"] }
rule_dirs: [rules]              # ast-grep YAML rules, any language
guidelines: guidelines.md       # prose, inlined into AGENTS.md
exclude: ["**/node_modules/**"]
linters:                        # delegate to each stack's own tool (optional)
  - { id: eslint, run: "npx eslint --max-warnings 0 {files}", include: ["**/*.{ts,tsx}"] }
locked: [max-lines, no-explicit-any]   # repos cannot disable or override these
```

### Project config

A repo that uses those standards, for example [examples/demo-app](../examples/demo-app):

```yaml
# .larpcop.yaml
extends:
  - https://github.com/<org>/standards.git#v1.0.0   # or a local path
rule_dirs: [team-rules]
disable: [py-no-print]          # only rules that are not locked can be disabled
```

### Order of application

Config is applied in this order: `--extends` / `LARPCOP_EXTENDS` (forced in by CI), then the `extends` chain, then `.larpcop.yaml`. CI always passes `--extends`, so deleting the config in the repo does not escape the standards. The same standards URL is applied only once, and the version that CI pins wins.

### Differences from the ast-grep CLI

There are two deliberate differences from the ast-grep CLI:

- The `ast-grep-ignore` comment is not supported. Every exception must go through config, so that it is visible in review and is blocked for locked rules.
- A rule written for `TypeScript` does not apply to `.tsx` files. `.tsx` files need their own rule with `language: Tsx`.

## Commands

```sh
larpcop check [paths…] [--staged | --changed | --since REF] [--jobs N] [--format text|json|github|sarif|gitlab|markdown] [--output FORMAT=FILE]
                               # --jobs (or LARPCOP_JOBS): number of threads, so the machine stays usable when checking a whole repo
larpcop fix [paths…] [--changed | --since REF] [--dry-run]   # apply the rules' `fix:`, then check again
larpcop baseline [--prune]    # record existing violations; --prune only removes entries that have been fixed
larpcop test [STANDARDS_DIR] [--require-all]  # run the fixtures in rule-tests/ (valid, invalid, fixed)
larpcop metrics [paths…] [--top N] [--json]    # complexity, function size
larpcop review [--staged | --changed | --since REF]  # `llm` rules, scored by a model (warning)
larpcop learn "<standard>" | --reviews N       # generate ast-grep rules + tests from a description / review comments
larpcop dashboard [--org OWNER] [--json]       # HTML page: violations, baseline debt, hotspots, repos with the gate
larpcop lsp | larpcop mcp    # language server / MCP server (stdio)
larpcop org status|setup …    # status and rollout on GitHub
larpcop rules [--for PATH] [--json]   # effective rules; --for: only the rules that apply to one file
larpcop stats [paths…] [--top N] [--json]   # which rule catches what, which rules apply but catch nothing, which rules do not apply
larpcop sync [--check]        # AGENTS.md + hook files for every agent (see the agent table in agents.md)
larpcop install [--force]     # git pre-commit hook (respects core.hooksPath, monorepos)
larpcop hook <claude-code|codex|gemini|cursor>   # entrypoint for the agent hooks (reads stdin)
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | Violations at error level |
| `3` | Internal or config error |

Code `2` is not used, because the agent hook protocol reserves it for "block and tell the model". As a result, a broken config never blocks the agent.

### Baseline

To apply a new rule to an old codebase without fixing everything at once, someone runs `larpcop baseline` and commits `.larpcop-baseline.json`. `check` hides exactly the recorded violations and still reports every new one.

- Entries match by rule, file and **line content**, not by line number. Editing elsewhere in the file does not bring an old violation back, and adding another identical violation is still caught (entries are counted by number of occurrences).
- Agents cannot run `larpcop baseline` and cannot edit the baseline file (the hook blocks both). `larpcop baseline --prune` is allowed, because it only removes entries that have been fixed.
- For a locked rule, the repo's baseline must not grow. With `--changed`, `--staged` or `--since`, an increase in the number of entries of a locked rule compared with the base is an error. The first recording (the rule has no entries yet) is still allowed, so that an org can roll out a new rule.

## Environment variables

Variables used by larpcop and by its installer.

| Variable | Meaning |
|---|---|
| `LARPCOP_EXTENDS` | Same as `--extends`. Standards that CI forces onto the repo; applied first, before the `extends` chain and `.larpcop.yaml`. |
| `LARPCOP_JOBS` | Number of threads, same as `--jobs`. Keeps the machine usable when checking a whole repo. |
| `LARPCOP_SHELL` | POSIX shell used to run the `run:` command of a linter, and also a string-form `llm.command` or `LARPCOP_LLM`. Checked first in the shell lookup order (see [Windows](#windows)). |
| `LARPCOP_CACHE_DIR` | Overrides the per-OS directory where larpcop keeps its cache (see [Windows](#windows)). Besides the standards checkouts, that directory also holds the `llm` answer cache, the deps.dev release dates and the OSV query cache. |
| `LARPCOP_LLM` | Model command used by `llm` rules, run through the shell. When it is set and not blank, it takes precedence over `llm.command`. When neither is set, larpcop uses `claude -p`, or `codex exec -` if `claude` is not found. |
| `LARPCOP_LLM_TIMEOUT_SECS` | Maximum run time of one model call, in whole seconds (greater than 0; any other value is an error). The default is 10 minutes, after which the call is stopped. |
| `LARPCOP_DEBUG_TYPES` | When set to any value (the docs use `1`), prints to stderr the answer of the language server for each type query. |
| `LARPCOP_DEPS_API` | Base URL of the deps.dev API used for release dates. The default is `https://api.deps.dev/v3`. |
| `LARPCOP_OSV_API` | Base URL of the OSV.dev API used for vulnerabilities and malware. The default is `https://api.osv.dev/v1`. |
| `LARPCOP_PACKAGIST_API` | Base URL of the Packagist API used for Composer packages. The default is `https://repo.packagist.org`. |
| `LARPCOP_GITHUB_TOKEN` | A token variable of the installer. It does not work for a private repo, because GitHub does not allow private assets to be downloaded through `releases/download` URLs (tried). |
| `LARPCOP_DOWNLOAD_URL` | Points the installer at a local directory instead of GitHub releases. The value is a `file://` URL of a directory that holds `larpcop-installer.sh` and the release archives (`*.tar.xz` and `*.tar.xz.sha256`), for example fetched with `gh release download`. |

## Windows

- The `run:` command of a linter always runs under a POSIX shell, so one config works on every OS. Shell lookup order: the `LARPCOP_SHELL` variable, then the `sh.exe` that ships with Git for Windows (found through `git --exec-path`), then `sh` in PATH.
- The standards cache uses the standard directory of each OS: `%LOCALAPPDATA%` on Windows, `~/Library/Caches` on macOS, XDG on Linux. It can be overridden with `LARPCOP_CACHE_DIR`.
- Paths are normalised with `dunce`, so the `\\?\C:\...` form does not appear.
- CRLF files caused by `autocrlf` do not count as drift, and the generated AGENTS.md always uses LF.

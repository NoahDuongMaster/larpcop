# Agents and enforcement

How larpcop enforces rules on coding agents: the enforcement layers, the shell command guard, the per-agent adapters and hooks, and the MCP server.

[Back to the README](../README.md)

## Enforcement model

A prompt only suggests. Only a deterministic gate can enforce, so larpcop blocks at the points every agent has to pass through:

| Layer | Mechanism | Does every agent pass through it? | Can it be bypassed? |
|---|---|---|---|
| CI ([`enforce.yml`](../.github/workflows/enforce.yml) + org ruleset) | `larpcop check --since origin/<base>` | Yes | No |
| Git pre-commit (`larpcop install`) | `larpcop check --staged` (checks the staged content, not the working tree) | Yes | `--no-verify`, but CI catches it again |
| Agent hook (`larpcop hook <agent>`) | Blocks bypass attempts, returns errors right after each file edit, blocks stopping while errors remain | Agents that have hooks | - |
| `AGENTS.md` (`larpcop sync`) | Instructions plus an auto-generated rule table | Every agent reads it | Advisory only |

Agent hooks only shorten the feedback loop. An agent without hooks is still blocked at git and in CI.

## Shell command guard

The hook parses commands with tree-sitter-bash. Quotes, pipes, `&&`/`;`/`&`, redirects, `bash -c '…'`, `eval` and `sudo`/`env` are all resolved structurally. As a result, `bash -c 'rm .larpcop.yaml'`, `--no-ver""ify`, `git push --no-veri` and `sudo env SKIP=all git commit` are blocked, while `cp .larpcop.yaml /tmp/bak`, `git config --get core.hooksPath` and `echo 'never rm .larpcop.yaml' > notes.txt` are not.

## Agent adapters

`larpcop sync` generates all the files below. Every adapter shares one decision core; each agent differs only in how it parses the payload and how it replies.

By default `sync` generates files for every agent; `agents: [claude-code, kiro]` in `.larpcop.yaml` limits the set. `sync` also registers the `larpcop mcp` MCP server for Claude Code (`.mcp.json`), Cursor (`.cursor/mcp.json`), Kiro (`.kiro/settings/mcp.json`) and Gemini (`mcpServers`).

| Agent | Generated files | Reads rules from | Before a tool runs | After a file edit | When the turn ends |
|---|---|---|---|---|---|
| Claude Code | `.claude/settings.json`, `CLAUDE.md` (`@AGENTS.md`) | AGENTS.md (import) | `PreToolUse` Bash/Edit/Write | `PostToolUse` | `Stop` |
| Codex | `.codex/hooks.json` | AGENTS.md (native) | `PreToolUse` Bash/`apply_patch` | `PostToolUse` `apply_patch` (the path comes from the patch header) | `Stop` |
| Gemini CLI | `.gemini/settings.json` (adds `context.fileName: AGENTS.md`) | AGENTS.md | `BeforeTool` `run_shell_command`/`write_file`/`replace` | `AfterTool` | `AfterAgent` |
| Cursor | `.cursor/hooks.json` (native JSON, `loop_limit: 1`) | AGENTS.md (native) | `preToolUse` Shell/Write/Delete | `postToolUse` -> `additional_context` | `stop` -> `followup_message` |
| Copilot CLI | `.github/hooks/larpcop.json` (PascalCase event names, Claude-style payload) | AGENTS.md (native) | `PreToolUse` -> `permissionDecision: deny` | `PostToolUse` -> `additionalContext` | `Stop` -> `decision: block` |
| Factory Droid | `.factory/hooks.json` | AGENTS.md (native) | `PreToolUse` Execute/Create/Edit/ApplyPatch | `PostToolUse` | `Stop` |
| Kiro (CLI V3, IDE 1.0) | `.kiro/hooks/larpcop.json` | AGENTS.md | `PreToolUse` `shell` + the **content about to be written** by `write` | (Kiro does not pass PostToolUse output to the model) | `Stop` -> `decision: block` |

### What the hooks do

- **Before a tool runs**, the hook blocks `--no-verify`, `git commit -n`, `core.hooksPath`, `HUSKY=0`, `LEFTHOOK=0` and `SKIP=`. It also blocks writes to `.git/hooks`, `.larpcop.yaml`, rule files, and the hook file of any agent. Install commands for packages that have not been approved (`npm i`, `pnpm add`, `yarn add`, `bun add`, `pip install`, `uv add`, `poetry add`, `cargo add`, `go get`) are blocked before they run, that is, before the package's install scripts can run. See [dependencies](dependencies.md).
- **After a file edit**, the hook checks exactly the files that were just edited and returns the errors to the model.
- **When the turn ends**, the hook checks all uncommitted changes and blocks **once**. If the agent still stops (for example to ask the person because the user's instruction conflicts with a rule), it is allowed to stop; the violating code still cannot be committed or merged. Blocking a second time or more only causes a loop: in a real Claude Code run, the same block was seen 8 times in a row until max-turns ran out. If the user presses stop (Cursor `status: aborted`), the hook never blocks.

### Notes per agent

- **Cursor** also loads the hooks in `.claude/settings.json` by default. The Claude adapter recognizes a payload with `cursor_version` and skips it, so Cursor does not get two replies.
- **Codex** runs project hooks only after each developer trusts them once through `/hooks`. To enforce at the organization level, ship them as managed hooks through `requirements.toml` (`allow_managed_hooks_only = true`).
- **Claude Code** can also be enforced at the organization level through [managed settings](https://docs.anthropic.com/en/docs/claude-code/settings) (MDM).
- **Cursor Enterprise** has team-level and enterprise-level hooks.
- **Kiro** does not pass `PostToolUse` output to the model, so the adapter checks the **content about to be written** at `PreToolUse` (`fs_write` takes `text`; `str_replace` rebuilds the file after the replacement). It blocks only when the write *increases* the number of violations of a rule; a partial fix to a file that was already broken is still written. Kiro does not report an "already blocked once" flag, so the adapter remembers it by `session_id`.
- **Copilot CLI** also reads `.claude/settings.json`, so the hook may run twice; both runs block the same thing. Copilot treats exit 2 at `Stop` as only a warning, so the Copilot adapter blocks the end of a turn by exiting 0 and printing `{"decision": "block", "reason": ...}` as JSON.

### Payload schema sources

- Codex: measured from a real `codex exec` 0.163.
- Claude Code: recorded from a real run.
- Cursor: read from the source of `cursor-agent` 2026.10.22. Write sends `{file_path, content}`, Shell sends `{command, cwd}`.
- Gemini: follows the official hooks reference.
- Kiro: recorded from a real `kiro-cli` 2.37 `--v3` (`fs_write {path,text}`, `str_replace {path,oldStr,newStr}`, `execute_bash {command}`, Stop has no loop flag).
- Copilot CLI, Factory Droid: follow the official hooks reference (no real agent run yet).

### MCP server

`larpcop mcp` (stdio, official `rmcp` SDK) gives agents 5 tools:

| Tool | What it does |
|---|---|
| `rules_for(path)` | Only the rules that apply to that file (by language and glob), with how to comply. The agent does not have to load the rules of every stack into its context. |
| `check_content(path, content)` | Checks content **before it is written**: returns the violations it would add. |
| `check(paths?)` | Checks files on disk (default: all uncommitted changes). |
| `fix(paths?)` | Applies the rules' `fix:` and reports what remains. |
| `explain_rule(id)` | What the rule forbids, how to comply, and correct and incorrect examples taken from the fixtures. |

Tested with Claude Code (`claude -p`): the agent called `rules_for` on its own for `src/report.ts` and `tools/sum.py`, called `check_content` for both drafts, and only then wrote the files. The result was clean on the first try.

## Limitations

- **Cursor and Gemini have not been run with real agents.** Cursor needs `cursor-agent login` (through the browser); Gemini CLI was not installed and logged in on the test machine. The adapters are tested against the payload schemas above.
- **Files that agents write through the shell.** `cat > f <<EOF`, `tee`, `echo … > f`, `cp`/`mv`/`install`, and `sed -i` with only substitution commands (`s/…/…/`, dry-run on a copy) have their content checked *before* the command runs. Scripts the agent writes itself, Makefiles, or `sed` with other commands cannot be seen in advance. The hook checks the files the command changed right after it runs, then again when the turn ends, at pre-commit and in CI.

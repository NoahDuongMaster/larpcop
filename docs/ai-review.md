# AI review and rule learning

This page describes `larpcop review` and `larpcop learn`, which replace CodeRabbit/Bugbot and Packmind, and how to configure the model command they use.

[Back to the README](../README.md)

## Model command

The model is the CLI that the team already uses (`claude -p`, `codex exec -`, `gemini`, `ollama run …`). larpcop sends the prompt through stdin and reads stdout, so it holds no API key and does not depend on the SDK of any vendor.

- If `llm.command` is not set, larpcop uses `claude -p`, and if that is not available, `codex exec -`.
- The command can be changed with the variable `LARPCOP_LLM`.
- One model call runs for at most 10 minutes and is then stopped. Change this with `LARPCOP_LLM_TIMEOUT_SECS` (a number of seconds, greater than 0).

## Configuration

```yaml
llm:
  command: claude -p --model sonnet     # string: run through sh; array: run directly
  rules:
    - id: thin-controllers
      files: ["src/controllers/**"]
      prompt: Controllers only parse the request, call one service function and map the result. They never touch the database directly.
```

## larpcop review

`larpcop review [--staged | --changed | --since REF]` grades the `llm` rules. It makes one call per file (4 files run in parallel) and sends only the files that a rule applies to. On a diff, the changed lines are marked and only those lines are reported.

- The result is always a warning: the model is not deterministic, while a gate must be.
- Answers are cached by the content of the prompt, so running again on code that has not changed gives the same result and costs nothing. Use `--no-cache` to ask again.
- It has all the formats that `check` has (`--format markdown` for PR comments, `sarif`…).

## larpcop learn

`larpcop learn "<standard written in words>"` or `larpcop learn --reviews 50` turns a standard into deterministic ast-grep rules. With `--reviews`, the standard comes from the review comments of recent PRs, read through `gh`.

- The model only proposes. A rule is kept when it parses and passes the valid and invalid examples that the model itself wrote.
- A rule that fails is sent back to the model with the exact error (3 rounds by default).
- A rule that passes is written to `.larpcop/rules/`, with its fixtures in `.larpcop/rule-tests/`. larpcop also reports the number of places in the repo that currently violate it, so you can decide whether to fix them or add them to the baseline.

This is the way to gradually turn the "soft" rules of AI review into hard rules.

## Runs on a real model

These were run for real with `claude -p --model sonnet` on a demo Express repo:

- `review --changed`: a new controller function that called `db.user.findUnique` was reported on exactly line 9, with a suggestion to move it to a service (8.6 s).
- `learn "Never import moment; use date-fns. No default exports, only named exports. Never await inside a loop; collect the promises and use Promise.all."` produced 3 rules, all of which passed in the first round (22 s). Each rule had 7 to 8 examples, including near-miss cases that must stay valid: an `await` inside an arrow function that sits in a loop is not counted. After the 3 rules were added to the repo, `larpcop check` caught exactly the 3 existing violations.

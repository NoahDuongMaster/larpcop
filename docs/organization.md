# Organization rollout

How to roll larpcop out across a company: the dashboard, machine-level managed policies, the `larpcop org` commands, the reusable CI workflow, releases and the binary size.

[Back to the README](../README.md)

## Dashboard

**`larpcop dashboard [--org OWNER] [--out FILE] [--json]`** generates a single HTML file with no scripts and no external resources, so it can be attached to a CI artifact, published on GitHub Pages or opened straight from disk. The page contains:

- the number of open violations and the number of baselined violations, per rule;
- baseline debt over time, computed from the git history of `.larpcop-baseline.json`;
- the most complex functions;
- with `--org`: which repos have a config, which repos have run the CI gate, and the most recent run.

`--json` outputs the same data for other dashboards to use.

## Company-wide rollout

### Managed policy on dev machines

`larpcop sync --managed --extends <URL#tag> --out <DIR>` generates machine-level policy files for 5 agents. The files call `larpcop` by absolute path and enforce the company's standards on *every* repo, including repos that have no `.larpcop.yaml`. Users cannot turn it off.

| Agent | macOS | Linux | Windows |
|---|---|---|---|
| Claude Code | `/Library/Application Support/ClaudeCode/managed-settings.json` | `/etc/claude-code/managed-settings.json` | `C:\Program Files\ClaudeCode\managed-settings.json` |
| Codex | `/etc/codex/requirements.toml` (`[features] hooks = true`, `managed_dir`) | same as macOS | `C:\ProgramData\OpenAI\Codex\requirements.toml` |
| Gemini CLI | `/Library/Application Support/GeminiCli/settings.json` | `/etc/gemini-cli/settings.json` | `C:\ProgramData\gemini-cli\settings.json` |
| Cursor | `/Library/Application Support/Cursor/hooks.json` | `/etc/cursor/hooks.json` | `C:\ProgramData\Cursor\hooks.json` |
| Copilot CLI | `/etc/github-copilot/policy.d/larpcop.json` | same as macOS | `C:\ProgramData\GitHub\Copilot\policy.d\larpcop.json` |

`--out /` installs the files directly (needs root); `--out pkgroot` creates a directory tree to package for MDM. Kiro and Factory Droid have no machine-level file (dashboard / per user). The paths come from each vendor's managed settings docs. They have not been installed on a real machine yet because that needs root.

### GitHub repositories

```sh
larpcop org status <owner> [--standards URL#tag] [--json]
larpcop org setup  <owner> --standards URL#tag [--repos a,b] [--workflow-ref vX] [--dry-run]
```

- With 1000 repos or more (the limit of `gh repo list`), both `status` and `setup` report an error instead of silently handling only part of them.
- `status` lists each repo (not archived, not a fork): whether it has `.larpcop.yaml`, which standards it extends and which tag it pins, whether a workflow calls the gate, how the most recent run went, and whether a setup PR is open. It exits with 1 if any repo still has no gate. Measured on a real account: 57 repos in about 22 seconds.
- `setup` opens **one PR per repo**. The PR contains `.larpcop.yaml`, the workflow `.github/workflows/larpcop.yml` and every agent file that `sync` generates from the repo's existing content, so the PR passes `sync --check` right away. Running it again skips repos that already have the gate or a PR, and reuses the branch if the previous run stopped midway.
- Writing files under `.github/workflows` needs a token with the `workflow` scope. Without the scope the PR is still opened, and the workflow content is placed in the PR description so it can be added by hand (`gh auth refresh -s workflow` makes the next run add it automatically).
- Tested on two throwaway repos (standards + app): the PR opened, the PR branch passed `sync --check` and `check`, and running again did not create a duplicate PR.
- It uses the `gh` CLI, so it stores no token and works with SSO and GitHub Enterprise.

## CI

[`enforce.yml`](../.github/workflows/enforce.yml) is a reusable workflow. Each repo calls it, or an org ruleset requires it:

```yaml
jobs:
  larpcop:
    permissions:
      contents: read
      pull-requests: write   # comment on the PR; also add security-events: write if sarif is enabled
    uses: NoahDuongMaster/larpcop/.github/workflows/enforce.yml@v0.3.1
    with:
      standards: https://github.com/<org>/standards.git#v1.0.0
    secrets:
      larpcop-token: ${{ secrets.LARPCOP_TOKEN }}   # only needed when the standards repo (or a fork of larpcop) is private
```

`permissions` must be declared in the calling job: a reusable workflow cannot have more permissions than the job that calls it, and a repo's default token usually has read-only permissions. If a permission is missing, the gate still runs and still blocks. Only the comment on the PR cannot be posted, and the workflow shows a warning that names the missing permission.

The workflow checks only the files that a PR changes, so old technical debt does not block the PR and new debt cannot get in. It also runs `sync --check` to make sure the generated agent files always match the rules. By default it installs the latest larpcop release (`larpcop-version` pins another tag). This repo uses the same workflow on itself through [`self-enforce.yml`](../.github/workflows/self-enforce.yml), with `larpcop-from-source: true`, so its own PRs are checked by the code they change instead of the last release.

## Releases and distribution

The release pipeline uses [`dist`](https://opensource.axo.dev/cargo-dist/) ([release.yml](../.github/workflows/release.yml), [dist-workspace.toml](../dist-workspace.toml)). Pushing a `v*` tag makes CI build 5 targets and create a GitHub Release.

The shell and PowerShell installers download the binary from GitHub Releases. The repository is public, so they work for anyone. For a private fork, developers and CI fetch the binaries with `gh release download` (it needs a logged-in `gh` with read access to the repo). The `larpcop-token` secret in the CI workflow is likewise needed only when the standards repo or a fork of larpcop is private.

After the release exists, [`publish-npm.yml`](../.github/workflows/publish-npm.yml) publishes the npm package that `dist` builds (`publish-jobs` in `dist-workspace.toml`):

- to [npmjs.com](https://www.npmjs.com/package/larpcop) as `larpcop`, with [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC, so the repository holds no npm token). npm checks the name of the workflow that calls the publish job, so the trusted publisher is set up for `release.yml`:

  ```sh
  npm trust github larpcop --repo NoahDuongMaster/larpcop --file release.yml --allow-publish
  ```

- to [GitHub Packages](https://github.com/NoahDuongMaster/larpcop/pkgs/npm/larpcop) as `@noahduongmaster/larpcop`, with the job's `GITHUB_TOKEN`. This fills the Packages box on the repository page. GitHub's npm registry asks for a token even to install a public package, so the install instructions in the README use npmjs.com.

The package downloads the binary of its own version from the GitHub release when it is installed. To publish an older release to GitHub Packages, run the `publish-npm` workflow by hand with its tag; npmjs.com is published by `release.yml` only. Version 0.3.1 was published to npmjs.com by hand, before the pipeline existed.

There is no Homebrew formula. To publish one with every release, add `"homebrew"` to `installers`, set `publish-jobs = ["homebrew", "./publish-npm"]` and add the `HOMEBREW_TAP_TOKEN` secret.

## Binary size

The v0.3.0 Linux x64 binary is 61,693,312 bytes (about 59 MiB) on disk, and the compressed release archives are 5 to 9 MiB. The current release build is about 57 MB. Most of it is the parse tables of the grammars: kotlin, c-sharp, swift and scala alone took 8 to 12 MB each (measured when the binary was about 50 MB). This is data, not code, so code optimizations do not help:

- `opt-level = "z"` was measured (also when the binary was about 50 MB) at 49.9 MB versus 49.3 MB, so it is not smaller, and it is about 25 times slower (0.75 s versus 0.03 s for the same `check` run).
- ast-grep-language does not allow disabling individual languages (its source code has no `cfg(feature)`), so cutting grammars would need a fork. It is not worth doing.

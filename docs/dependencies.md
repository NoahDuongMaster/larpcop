# Dependencies

This page covers the dependency gates: approval of new dependencies, the minimum release age, and the vulnerability and malware check, plus the known limitations.

[Back to the README](../README.md)

## Approval and release age

A dependency is code that nobody on the team wrote, and agents install packages very readily. There are two rules:

```yaml
dependencies:
  min_release_age: 14        # dependency-release-age
  require_approval: true     # dependency-approval
  approved: [left-pad, "npm:@acme/*", "cargo:serde"]   # [ecosystem:]glob
  exempt: ["npm:@acme/*"]    # packages on a private registry: no public release date
```

### Approval

**`dependency-approval`**: a new direct dependency must be listed in `approved`. "New" means not yet present in any manifest at the base commit, so adding `react` to a new package in a monorepo that already uses `react` does not count. An agent cannot edit `.larpcop.yaml`, so one `approved` line is one human approval and is visible in review.

Manifests that can be read: `package.json`, `Cargo.toml`, `pyproject.toml` (PEP 621, dependency-groups, Poetry), `requirements*.txt`, `go.mod`, `Gemfile`, `composer.json`, `*.csproj`/`*.fsproj`, `pom.xml`, `build.gradle(.kts)` and `gradle/libs.versions.toml`.

### Release age

**`dependency-release-age`** runs in three places:

1. **Lockfile** (pre-commit, CI, and the hook that runs when an agent turn ends). Every version that this change adds or switches to, transitive dependencies included, must be at least `N` days old.
   - The release date comes from [deps.dev](https://deps.dev), a common API for npm, PyPI, crates.io, Go, RubyGems, NuGet and Maven (Composer uses the Packagist API). It is cached on disk, because a release date never changes.
   - Only versions that are *new in the change* are looked up, so a PR usually costs only a few requests.
   - Lockfiles that can be read: `package-lock.json` (v2/v3), `pnpm-lock.yaml` (v5 to v9), `yarn.lock` (v1 and Berry), `bun.lock`, `Cargo.lock`, `uv.lock`, `poetry.lock`, `go.mod`, `Gemfile.lock`, `packages.lock.json` (NuGet), `gradle.lockfile`, `composer.lock`, and hard-pinned versions in `pom.xml` and `*.csproj`.
   - When it blocks, the message includes a concrete version to pin, for example: *"Use typescript@7.0.2 (published 2026-07-08)"*.
2. **Package manager**. npm, pnpm, yarn Berry and bun can refuse a version that is too new at install time, on the developer machine, *before* any install script runs. A lockfile can only be seen after the install has happened, so a repo must turn this feature on:

   | Package manager | File | Setting for 14 days |
   |---|---|---|
   | npm | `.npmrc` | `min-release-age=14` |
   | pnpm | `pnpm-workspace.yaml` | `minimumReleaseAge: 20160` |
   | yarn ≥ Berry | `.yarnrc.yml` | `npmMinimalAgeGate: "14d"` |
   | bun | `bunfig.toml` | `[install] minimumReleaseAge = 1209600` |
   | uv ≥ 0.9 | `pyproject.toml` (`[tool.uv]`) or `uv.toml` | `exclude-newer = "14 days"` |

   Tested for real: npm 11.19 with `min-release-age=14`, asked for `typescript@next`, picked `7.0.2` by itself. pnpm 11.2 picked the dev build `20261017`, exactly 14 days old. pip has no repo-wide setting for this, so when `min_release_age` is set, the agent hook requires every `pip install` to carry `--uploaded-prior-to` with an absolute date at least that many days in the past. The `PIP_UPLOADED_PRIOR_TO` variable with such a date, or `--no-index`, also satisfies the hook.
3. **Agent hook**.
   - It blocks commands that *loosen* the gate (`--min-release-age=0`, `npm config set min-release-age …`, `npm_config_min_release_age=…`, `uv … --exclude-newer "1 day"`, `UV_EXCLUDE_NEWER=…`). The value is actually read, so a *stricter* setting (`--exclude-newer "30 days"`) still passes.
   - Package managers with no native gate (Cargo, Go, Poetry, Bundler, RubyGems, Composer, NuGet, and Yarn 1, recognised by the absence of `.yarnrc.yml`) and tool runners that run a package immediately (`npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx`, `pipx run`, `cargo install`): the hook asks the registry **which version** the command would download, and blocks the command before it runs if that version is not old enough. Where an install runs dependency code right away (`bundle install`, `poetry update`), the resolve-only form (`bundle lock`, `poetry lock`) is required, so that the lockfile is checked first.
   - When the lockfile contains a version that fails the check, every command that could run project or dependency code (`npm test`, `make`, `node script.js`…) is blocked. Blocking is the default; only read-only and file-moving commands (`git`, `ls`, `cat`, `grep`, `sed`, `cp`…) can run, so that the lockfile can be fixed.

### Fail closed and the security-fix exception

A version that is not on deps.dev, or that cannot be looked up because of a network error, is blocked (fail closed).

**The exception is a security fix.** A version that is too new is still let through, as a warning, if the newest old-enough version of the same release line has an advisory and the new version does not. This uses the `advisoryKeys` field of deps.dev. Without the exception, the rule would force a downgrade to the vulnerable version. The larpcop repo itself hit this case with `rustls-webpki` 0.103.16 and `webpki-roots` 1.0.11, because the earlier old-enough versions were affected by RUSTSEC-2026-0382 and RUSTSEC-2026-0381.

### Locked rules

Both rules are locked in the sample standards. A locked rule can only be *tightened*. Raising the number of days or adding to `approved` is allowed. Lowering the number of days, turning off `require_approval` or adding to `exempt` is rejected.

## Vulnerabilities and malware

This is the fourth of the four security layers (the other three are described in [security.md](security.md)). The rule is `dependency-vulnerability`, with data from [OSV.dev](https://osv.dev): GitHub Advisory, RustSec, PyPA, Go, and the OpenSSF malicious package source.

```yaml
dependencies:
  vulnerabilities: high     # low | moderate | high | critical
```

- A package reported as **malware** (`MAL-…`) is always blocked, in every lockfile and in every PR, including PRs that do not touch a lockfile: malware is often discovered after it is already in the repo.
- A vulnerability at the chosen severity or above blocks the version *that this change brings in*. `larpcop check` without a scope checks everything. The message also names the patched version.
- The hook blocks install commands **before they run**: a package name that is flagged as malware (`npm i aaa-evil`), or a pinned version with a vulnerability (`npm i lodash@4.17.15`). If OSV cannot be reached, the install command is blocked too (fail closed), the same as for the lockfile.
- Severity comes from the advisory's own rating. If there is none, it is computed from the CVSS 3/4 vector (the `cvss` crate).
- OSV's answers for lockfile checks are kept in a 15-minute cache (`<cache>/osv-query/`, per package@version), so running `check` again right after does not ask OSV again about the same package versions. Install commands **never** read this cache, and errors or incomplete responses are not stored. As a result, in a lockfile check, a malware report that OSV publishes while a pin's answer is cached is only seen once that entry expires, not immediately.

Run against real data, with a lockfile containing `lodash@4.17.15`, `local-commander-agent@0.3.52` and `zod@3.23.8`:

- `local-commander-agent` (MAL-2026-18425, reported the same day) is blocked, even when run with `--changed` and the change does not touch the lockfile.
- `lodash@4.17.15`: 3 advisories of High severity (command injection, prototype pollution, code injection through `_.template`), each with a patched version (`4.17.19`, `4.17.21`, `4.18.0`).
- `zod@3.23.8`: 1 High advisory (GHSA-mrhx-c7xc-m3w5).
- The hook blocks `npm i local-commander-agent`, `npm i lodash@4.17.15` and `npm i zod@3.23.8`. It lets `npm i lodash` through (not pinned, so npm installs the latest version).

## Limitations

- **A hijacked trusted package.** A minimum age of 14 days blocks malicious versions that are detected within 14 days (most of them: OSV records malware with a median delay of about 20 hours). A malicious version that stays around longer without anyone reporting it is unknown to any advisory-based tool.
- **Dependencies.** The version-age rule needs network access to deps.dev and fails closed when a lookup is not possible. A package on a private registry must be declared in `exempt`.
- **No reachability in SCA.** An advisory in a lockfile is reported even when the package is only an indirect dependency that nobody imports. There is no "is it imported" step, because the name in the lockfile (`PyYAML`, `PyJWT`, `@scope/pkg`) cannot be reliably derived from the `import` statement (`yaml`, `jwt`, `@scope/pkg/sub`) for every ecosystem. A wrong "not used" claim is worse than saying nothing.

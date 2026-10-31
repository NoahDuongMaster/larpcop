# agentkit

Ép mọi coding agent (Claude Code, Codex, Gemini CLI, Cursor…) và cả người tuân theo cùng một bộ rule, trên mọi stack.
Một binary Rust duy nhất, rule engine là [ast-grep](https://ast-grep.github.io) (tree-sitter, 25+ ngôn ngữ).

## Mô hình thực thi

Prompt chỉ *gợi ý*. Chỉ có cổng kiểm tra tất định mới *ép* được, nên agentkit chặn ở những điểm mà mọi agent bắt buộc phải đi qua:

| Tầng | Cơ chế | Agent nào cũng phải qua? | Bypass được? |
|---|---|---|---|
| CI ([`enforce.yml`](.github/workflows/enforce.yml) + org ruleset) | `agentkit check --since origin/<base>` | ✅ | ❌ |
| Git pre-commit (`agentkit install`) | `agentkit check --staged` (kiểm nội dung staged, không phải working tree) | ✅ | `--no-verify` → CI bắt lại |
| Hook của agent (`agentkit hook <agent>`) | Chặn bypass, phản hồi lỗi ngay sau mỗi lần sửa file, chặn kết thúc khi còn lỗi | Agent có hook | — |
| `AGENTS.md` (`agentkit sync`) | Hướng dẫn + bảng rule sinh tự động | Mọi agent đều đọc | Chỉ là gợi ý |

Hook của agent chỉ để rút ngắn vòng phản hồi. Agent không có hook vẫn bị chặn ở git và CI.

## Cài đặt

Mỗi release có binary cho macOS (arm64, x64), Linux (arm64, x64) và Windows (x64), dạng nén khoảng 4 MB. Có installer shell, PowerShell, công thức Homebrew và package npm `@noahduongmaster/agentkit`. Binary được cài vào `~/.local/bin`.

Repo hiện **private**, nên dùng GitHub CLI (`gh`, cần đăng nhập và có quyền đọc repo) để tải installer cùng các bản build về một thư mục, rồi trỏ installer vào thư mục đó. Lệnh sau đã chạy thật trên macOS:

```sh
d=$(mktemp -d)
gh release download --repo NoahDuongMaster/agentkit --dir "$d" \
  --pattern 'agentkit-installer.sh' --pattern '*.tar.xz' --pattern '*.tar.xz.sha256'
AGENTKIT_DOWNLOAD_URL="file://$d" sh "$d/agentkit-installer.sh"
```

Trên Windows: `gh release download --repo NoahDuongMaster/agentkit --pattern '*windows-msvc.zip'`, giải nén rồi đặt `agentkit.exe` vào một thư mục có trong PATH.

`AGENTKIT_GITHUB_TOKEN` của installer **không** dùng được cho repo private, vì GitHub không cho tải asset private qua URL `releases/download` (đã thử). Khi repo chuyển sang public thì chỉ cần:

```sh
curl -LsSf https://github.com/NoahDuongMaster/agentkit/releases/latest/download/agentkit-installer.sh | sh
```

## Cấu hình

Standards của công ty (một repo riêng, gắn tag phiên bản), ví dụ [examples/standards](examples/standards):

```yaml
# agentkit.yaml
max_lines: { max: 300, exclude: ["**/*.test.*"] }
rule_dirs: [rules]              # rule ast-grep YAML, mọi ngôn ngữ
guidelines: guidelines.md       # văn xuôi, được inline vào AGENTS.md
exclude: ["**/node_modules/**"]
linters:                        # uỷ quyền cho tool riêng của từng stack (tùy chọn)
  - { id: eslint, run: "npx eslint --max-warnings 0 {files}", include: ["**/*.{ts,tsx}"] }
locked: [max-lines, no-explicit-any]   # repo không được disable/override
```

Repo, ví dụ [examples/demo-app](examples/demo-app):

```yaml
# .agentkit.yaml
extends:
  - https://github.com/<org>/standards.git#v1.0.0   # hoặc đường dẫn local
rule_dirs: [team-rules]
disable: [py-no-print]          # chỉ được disable rule không bị lock
```

Thứ tự áp dụng: `--extends` / `AGENTKIT_EXTENDS` (CI ép vào) → chuỗi `extends` → `.agentkit.yaml`. Vì CI luôn truyền `--extends`, xoá config trong repo cũng không thoát được standards. Cùng một URL standards chỉ áp dụng một lần, và phiên bản CI pin sẽ thắng.

Có hai điểm cố ý khác với ast-grep CLI:

- Không hỗ trợ comment `ast-grep-ignore`. Mọi ngoại lệ phải đi qua config, để hiện rõ khi review và bị chặn với rule đã lock.
- Rule viết cho `TypeScript` không áp dụng cho file `.tsx`. File `.tsx` cần rule riêng với `language: Tsx`.

### Viết rule theo ý nghĩa, không theo một cách viết

Agent sẽ tìm khe hở. Khi chạy Codex thật, nó né rule `console.$METHOD(...)` bằng cách viết `globalThis["console"]["log"](x)`, và rule đó vẫn báo sạch. Rule phải bắt được *cấu trúc* đó dưới mọi cách viết: identifier, truy cập qua property, truy cập bằng key tính toán. Xem `no-console` trong [rules/typescript.yml](examples/standards/rules/typescript.yml) và test hồi quy `no_console_cannot_be_dodged`. Thông điệp gửi cho agent cũng nói rõ rằng viết lại để né rule vẫn bị tính là vi phạm.

## Dependency

Dependency là code không ai trong team viết, và agent cài package rất dễ dãi. Có hai rule:

```yaml
dependencies:
  min_release_age: 14        # dependency-release-age
  require_approval: true     # dependency-approval
  approved: [left-pad, "npm:@acme/*", "cargo:serde"]   # [hệ sinh thái:]glob
  exempt: ["npm:@acme/*"]    # package ở registry riêng: không có ngày phát hành công khai
```

**`dependency-approval`**: dependency trực tiếp mới phải nằm trong `approved`. "Mới" nghĩa là chưa có trong bất kỳ manifest nào ở commit gốc, nên thêm `react` vào một package mới trong monorepo đã dùng `react` thì không tính. Agent không sửa được `.agentkit.yaml`, nên một dòng `approved` là một lần người duyệt và hiện rõ khi review. Đọc được `package.json`, `Cargo.toml`, `pyproject.toml` (PEP 621, dependency-groups, Poetry), `requirements*.txt` và `go.mod`.

**`dependency-release-age`** chạy ở ba chỗ:

1. **Lockfile** (pre-commit, CI, hook kết thúc lượt): mọi phiên bản, kể cả dependency bắc cầu, mà thay đổi này thêm vào hoặc đổi sang phải đủ `N` ngày tuổi. Ngày phát hành lấy từ [deps.dev](https://deps.dev), một API chung cho npm, PyPI, crates.io và Go, và được cache trên đĩa vì ngày phát hành không bao giờ đổi. Chỉ phiên bản *mới trong thay đổi* mới được tra, nên PR thường chỉ mất vài request. Lockfile đọc được: `package-lock.json` (v2/v3), `pnpm-lock.yaml` (v5–v9), `yarn.lock` (v1 và Berry), `Cargo.lock`, `uv.lock`, `poetry.lock` và `go.mod`. Khi chặn, thông báo đưa luôn một phiên bản cụ thể để pin, ví dụ: *"Use typescript@7.0.2 (published 2026-07-08)"*.
2. **Package manager**: npm, pnpm, yarn Berry và bun tự chặn được bản quá mới ngay lúc cài, trên máy dev, *trước khi* install script chạy. Lockfile chỉ thấy được sau khi đã cài, nên repo bắt buộc phải bật tính năng này:

   | Package manager | File | Thiết lập cho 14 ngày |
   |---|---|---|
   | npm | `.npmrc` | `min-release-age=14` |
   | pnpm | `pnpm-workspace.yaml` | `minimumReleaseAge: 20160` |
   | yarn ≥ Berry | `.yarnrc.yml` | `npmMinimalAgeGate: "14d"` |
   | bun | `bunfig.toml` | `[install] minimumReleaseAge = 1209600` |

   Đã chạy thật: npm 11.19 với `min-release-age=14`, khi được yêu cầu `typescript@next` thì tự chọn `7.0.2`. pnpm 11.2 chọn bản dev `20261017`, đúng 14 ngày tuổi.
3. **Hook của agent**: chặn mọi lệnh ghi đè gate (`--min-release-age=0`, `npm config set min-release-age …`, `npm_config_min_release_age=…`).

Phiên bản không có trên deps.dev hoặc không tra được vì lỗi mạng đều bị chặn (fail closed). **Ngoại lệ là bản vá bảo mật**: một bản quá mới vẫn được cho qua, ở mức warning, nếu bản đủ tuổi mới nhất cùng dòng có advisory còn bản mới thì không, theo trường `advisoryKeys` của deps.dev. Không có ngoại lệ này thì rule sẽ ép hạ về bản có lỗ hổng: chính repo agentkit gặp trường hợp này với `rustls-webpki` 0.103.16 và `webpki-roots` 1.0.11, vì bản đủ tuổi trước đó dính RUSTSEC-2026-0382 và RUSTSEC-2026-0381.

Cả hai rule được lock trong standards mẫu. Một rule đã lock chỉ được *siết thêm*: tăng số ngày hoặc thêm `approved` thì được; giảm số ngày, tắt `require_approval` hoặc thêm `exempt` thì bị từ chối.

## Lệnh

```sh
agentkit check [paths…] [--staged | --changed | --since REF] [--format text|json|github] [--output FORMAT=FILE]
agentkit fix [paths…] [--changed | --since REF] [--dry-run]   # áp `fix:` của rule rồi check lại
agentkit baseline [--prune]    # ghi nhận vi phạm cũ; --prune chỉ xoá entry đã sửa
agentkit test [--require-all]  # chạy fixture trong rule-tests/ (valid, invalid, fixed)
agentkit rules                 # rule hiệu lực, nguồn, rule nào bị lock
agentkit sync [--check]        # AGENTS.md + file hook cho mọi agent (xem bảng dưới)
agentkit install [--force]     # git pre-commit hook (tôn trọng core.hooksPath, monorepo)
agentkit hook <claude-code|codex|gemini|cursor>   # entrypoint cho hook của agent (đọc stdin)
```

Exit code: `0` sạch, `1` có vi phạm mức error, `3` lỗi nội bộ/config. Không dùng `2`, vì giao thức hook của agent dành nó cho nghĩa "chặn và báo cho model". Nhờ vậy config hỏng không bao giờ chặn agent.

### Baseline

Để áp rule mới lên codebase cũ mà không phải sửa hết ngay: người chạy `agentkit baseline`, commit `.agentkit-baseline.json`. `check` ẩn đúng các vi phạm đã ghi nhận và vẫn báo mọi vi phạm mới.

- Entry khớp theo rule, file và **nội dung dòng**, không theo số dòng: sửa chỗ khác trong file không làm vi phạm cũ hiện lại, còn viết thêm một vi phạm giống hệt thì vẫn bị bắt (đếm theo số lần).
- Agent không chạy được `agentkit baseline` và không sửa được file baseline (hook chặn). `agentkit baseline --prune` thì được, vì nó chỉ xoá entry đã sửa.
- Với rule bị lock, baseline của repo không được phình ra: ở `--changed`/`--staged`/`--since`, số entry của rule lock tăng so với base là lỗi. Lần ghi nhận đầu tiên (rule chưa có entry nào) vẫn được phép, để org triển khai rule mới.

### Fix và test rule

Rule ast-grep có `fix:` thì vi phạm kèm gợi ý `agentkit fix <file>`. Fix lặp tối đa 5 lượt, bỏ qua các sửa đè lên nhau trong cùng lượt.

`agentkit test` đọc fixture theo định dạng của ast-grep (`rule-tests/<id>-test.yml` với `valid`/`invalid`), thêm `fixed: [{before, after}]` để kiểm `fix:`. `--require-all` làm CI fail khi có rule chưa có fixture.

### Guard đọc lệnh shell bằng parser

Hook phân tích lệnh bằng tree-sitter-bash: quote, pipe, `&&`/`;`/`&`, redirect, `bash -c '…'`, `eval`, `sudo`/`env` đều được giải theo cấu trúc. Nhờ vậy `bash -c 'rm .agentkit.yaml'`, `--no-ver""ify`, `git push --no-veri`, `sudo env SKIP=all git commit` bị chặn, còn `cp .agentkit.yaml /tmp/bak`, `git config --get core.hooksPath` hay `echo 'never rm .agentkit.yaml' > notes.txt` thì không.

## Adapter agent

`agentkit sync` sinh ra tất cả các file dưới đây. Mọi adapter dùng chung một lõi quyết định; mỗi agent chỉ khác ở cách parse payload và cách trả lời.

| Agent | File sinh ra | Đọc rule từ | Trước khi chạy tool | Sau khi sửa file | Khi kết thúc lượt |
|---|---|---|---|---|---|
| Claude Code | `.claude/settings.json`, `CLAUDE.md` (`@AGENTS.md`) | AGENTS.md (import) | `PreToolUse` Bash/Edit/Write | `PostToolUse` | `Stop` |
| Codex | `.codex/hooks.json` | AGENTS.md (native) | `PreToolUse` Bash/`apply_patch` | `PostToolUse` `apply_patch` (path lấy từ header của patch) | `Stop` |
| Gemini CLI | `.gemini/settings.json` (thêm `context.fileName: AGENTS.md`) | AGENTS.md | `BeforeTool` `run_shell_command`/`write_file`/`replace` | `AfterTool` | `AfterAgent` |
| Cursor | `.cursor/hooks.json` (JSON native, `loop_limit: 1`) | AGENTS.md (native) | `preToolUse` Shell/Write/Delete | `postToolUse` → `additional_context` | `stop` → `followup_message` |

Các hook làm những việc sau:

- **Trước tool** chặn: `--no-verify`, `git commit -n`, `core.hooksPath`, `HUSKY=0`, `LEFTHOOK=0`, `SKIP=`; ghi vào `.git/hooks`, `.agentkit.yaml`, file rule, hoặc file hook của bất kỳ agent nào. Lệnh cài package chưa được duyệt (`npm i`, `pnpm add`, `yarn add`, `bun add`, `pip install`, `uv add`, `poetry add`, `cargo add`, `go get`) bị chặn trước khi chạy, tức là trước khi install script của package kịp chạy. Xem [Dependency](#dependency).
- **Sau khi sửa** kiểm đúng các file vừa sửa và trả lỗi về cho model.
- **Kết thúc lượt** kiểm mọi thay đổi chưa commit và chặn **một lần**. Nếu agent vẫn dừng (ví dụ để hỏi người khi lệnh của user mâu thuẫn với rule) thì cho dừng; code vi phạm vẫn không commit hay merge được. Chặn lần hai trở đi chỉ gây loop: khi chạy Claude Code thật đã thấy 8 lần chặn y hệt nhau cho tới khi hết max-turns. Nếu user bấm dừng (Cursor `status: aborted`) thì không bao giờ chặn.

Một số lưu ý riêng cho từng agent:

- **Cursor** mặc định nạp luôn hook trong `.claude/settings.json`. Adapter Claude nhận ra payload có `cursor_version` và tự bỏ qua, để không bị phản hồi hai lần.
- **Codex** chỉ chạy hook của project sau khi từng dev trust một lần qua `/hooks`. Muốn ép ở cấp tổ chức thì phát hành dưới dạng managed hooks qua `requirements.toml` (`allow_managed_hooks_only = true`).
- **Claude Code** cũng có thể ép ở cấp tổ chức qua [managed settings](https://docs.anthropic.com/en/docs/claude-code/settings) (MDM).
- **Cursor Enterprise** có hook cấp team và enterprise.

Nguồn của schema payload:

- Codex: đo từ `codex exec` 0.163 thật.
- Claude Code: chạy thật.
- Cursor: đọc từ mã nguồn `cursor-agent` 2026.10.22. Write gửi `{file_path, content}`, Shell gửi `{command, cwd}`.
- Gemini: theo hooks reference chính thức.

## CI

[`enforce.yml`](.github/workflows/enforce.yml) là reusable workflow. Mỗi repo gọi nó, hoặc org ruleset bắt buộc nó:

```yaml
jobs:
  agentkit:
    uses: NoahDuongMaster/agentkit/.github/workflows/enforce.yml@v0.1.0
    with:
      standards: https://github.com/<org>/standards.git#v1.0.0
    secrets:
      agentkit-token: ${{ secrets.AGENTKIT_TOKEN }}   # chỉ cần khi agentkit/standards private
```

Workflow này chỉ kiểm các file mà PR thay đổi, nên nợ kỹ thuật cũ không chặn PR, còn nợ mới không lọt vào được. Nó cũng chạy `sync --check` để đảm bảo các file agent sinh ra luôn khớp với rule. Repo này tự dùng chính workflow đó qua [`self-enforce.yml`](.github/workflows/self-enforce.yml).

## Phân phối khi repo private

Pipeline release dùng [`dist`](https://opensource.axo.dev/cargo-dist/) ([release.yml](.github/workflows/release.yml), [dist-workspace.toml](dist-workspace.toml)). Đẩy tag `v*` là CI tự build cho 5 target và tạo GitHub Release.

Installer shell/PowerShell, Homebrew và npm đều tải binary từ GitHub Releases, nên **chỉ chạy được cho mọi người khi repo public**. Khi repo còn private:

- Dev và CI dùng `gh release download` (cần đăng nhập `gh` và có quyền đọc repo).
- Công thức Homebrew (`agentkit.rb`) và tarball npm được đính kèm trong release nhưng **chưa publish**.

Khi chọn được nơi công khai (public repo, tap `homebrew-tap`, npm scope), chỉ cần thêm `publish-jobs = ["homebrew", "npm"]` cùng hai secret `HOMEBREW_TAP_TOKEN` và `NPM_TOKEN`.

## Kích thước binary

Binary nặng 47 MB trên đĩa, nhưng chỉ khoảng **4 MB khi tải về** (`tar.xz`). Phần lớn là bảng parse của grammar: riêng kotlin, c-sharp, swift, scala mỗi cái 8–12 MB. Đây là dữ liệu, không phải code, nên các cách tối ưu code không giúp được:

- `opt-level = "z"` đã đo cho ra 49.9 MB so với 49.3 MB, tức không nhỏ đi, mà lại chậm hơn khoảng 25 lần (0.75s so với 0.03s cho cùng một lần `check`).
- ast-grep-language không cho tắt từng ngôn ngữ (mã nguồn không có `cfg(feature)`), nên muốn cắt bớt grammar thì phải fork. Không đáng làm.

## Windows

- Lệnh `run:` của linter luôn chạy bằng shell POSIX, nên một config dùng được trên mọi OS. Thứ tự tìm shell: biến `AGENTKIT_SHELL`, rồi `sh.exe` đi kèm Git for Windows (tìm qua `git --exec-path`), rồi `sh` trong PATH.
- Cache standards dùng thư mục chuẩn của từng OS: `%LOCALAPPDATA%` trên Windows, `~/Library/Caches` trên macOS, XDG trên Linux. Có thể ghi đè bằng `AGENTKIT_CACHE_DIR`.
- Path được chuẩn hoá bằng `dunce`, không bị dạng `\\?\C:\...`.
- File CRLF do `autocrlf` không bị tính là drift, và AGENTS.md sinh ra luôn dùng LF.
- [`ci.yml`](.github/workflows/ci.yml) chạy fmt, clippy và toàn bộ test trên ubuntu, macOS và Windows.

## Đã kiểm chứng

`cargo test` có 47 test:

- Unit: guard, tìm shell, path trong patch Codex; đọc lockfile thật của npm 11, pnpm 11, uv 0.11, cargo 1.98 (kèm yarn v1/Berry, Poetry, go.mod, và các entry registry riêng/git/workspace phải bị bỏ qua); manifest; nhận diện lệnh cài; thiết lập gate của 4 package manager.
- Integration: check, locked, git extends theo tag, staged, `--changed`/`--since`, linter delegation, format github, chống né rule, hook của 4 agent, sync idempotent, phát hiện drift, CRLF, pre-commit thật; dependency: tuổi phiên bản (qua cache và qua một server deps.dev giả), merge-base của PR, ngoại lệ bản vá bảo mật, gate package manager, duyệt dependency mới (cả monorepo), hook chặn lệnh cài, lock chỉ được siết thêm.

Trên GitHub thật (repo private `NoahDuongMaster/agentkit`):

- [`ci.yml`](.github/workflows/ci.yml) xanh trên ubuntu, macOS và **Windows**: fmt, clippy `-D warnings`, 29/29 test. Trên Windows có cả linter chạy qua `sh.exe` của Git, extends từ `file:///C:/…`, CRLF và pre-commit thật.
- Release `v0.1.0`: [release.yml](.github/workflows/release.yml) build 5 target. Installer đã được cài thật vào `~/.local/bin` theo cách ở mục [Cài đặt](#cài-đặt).
- Cổng CI, thử bằng PR #1 (đã đóng, không merge):
  - Commit vi phạm bị pre-commit chặn ở máy local; được đẩy lên bằng `--no-verify`.
  - `enforce` tải binary từ release, **fail** và gắn annotation `no-explicit-any` / `no-console` vào đúng dòng trong PR.
  - Push bản sửa thì mọi check chuyển xanh.

Ngoài ra đã chạy agent thật trong repo demo:

- **Claude Code**:
  - Có AGENTS.md: tự tuân thủ và từ chối `--no-verify`.
  - Không có AGENTS.md: viết `console.log`, Stop hook buộc nó tự xoá.
  - User ra lệnh dùng `any`: agent dừng lại hỏi người. Pre-commit chặn file vi phạm; khi người dùng `--no-verify` thì CI vẫn bắt được.
- **Codex** (không có AGENTS.md, được bảo dùng `any` và `--no-verify`):
  - `--no-verify` bị chặn.
  - Hook sau khi sửa file bắt được `any`, Codex đổi sang `unknown`.
  - Lần đầu Codex né rule console bằng `globalThis["console"]`. Sau khi sửa rule, chạy lại thì Codex xoá hẳn `console.log`.
- **Claude Code với dependency rules**: hai phiên được yêu cầu "dùng package `slugify`, cài bằng npm", một phiên có AGENTS.md, một phiên chỉ có hook:
  - Cả hai đều bị hook chặn `npm install slugify` *trước khi* lệnh chạy. Không có gì được cài, không file nào bị tạo, và agent dừng lại hỏi người duyệt (tổng cộng $0.43).
  - Lần chạy này lộ ra bug: `2>&1` trong `npm install slugify 2>&1 | tail -5` bị đọc thành tên package. Đã sửa, kèm test hồi quy.
- **Dependency với dữ liệu thật**:
  - `typescript@next` (phát hành cách đó 2 giờ) bị chặn cùng 7 binary nền tảng của nó. Mỗi lỗi kèm gợi ý `7.0.2`; 8 lần tra deps.dev hết 0,58 giây.
  - Chính `Cargo.lock` của agentkit bị chặn 3 crate mới 9–13 ngày tuổi; đã hạ theo đúng phiên bản được gợi ý. 2 crate khác được cho qua vì là bản vá RUSTSEC.

## Giới hạn

- **Cursor và Gemini chưa chạy agent thật.** Cursor cần đăng nhập `cursor-agent login` (qua trình duyệt); Gemini CLI chưa được cài hay đăng nhập trên máy dev. Adapter được test bằng đúng schema payload ở trên.
- **File agent ghi bằng shell** (ví dụ `cat > f <<EOF`) không đi qua hook "sau khi sửa". Chúng vẫn bị bắt ở hook kết thúc lượt, ở pre-commit và ở CI.
- **Repo private** khiến installer `curl | sh`, Homebrew và npm chưa dùng được cho người ngoài (xem [Phân phối khi repo private](#phân-phối-khi-repo-private)). Repo khác muốn gọi `enforce.yml` thì cần quyền truy cập Actions; mục này đã được bật sẵn cho các repo cùng owner `NoahDuongMaster` (`access_level: user`). Repo gọi vẫn phải truyền secret `agentkit-token` để tải binary.
- **Chi phí CI**: GitHub Actions của repo private tính phút chạy, với runner macOS nhân 10 và Windows nhân 2. Repo public thì miễn phí.
- **Dependency**:
  - Rule tuổi phiên bản cần mạng tới deps.dev và fail closed khi không tra được. Package ở registry riêng phải được khai trong `exempt`.
  - uv, Poetry, Cargo và Go không có thiết lập tuổi tối thiểu dạng tương đối (uv `exclude-newer` chỉ nhận một ngày cố định). Với các hệ sinh thái này, bản quá mới của một package *đã duyệt* vẫn cài được lên máy dev, rồi mới bị chặn ở lượt kết thúc, pre-commit và CI. Yarn 1 cũng không có gate.
  - `bun.lock` chưa được đọc phiên bản; chỉ kiểm thiết lập `bunfig.toml`. Maven, Gradle, NuGet, RubyGems và Composer chưa hỗ trợ.
  - Hook chỉ nhận ra lệnh cài gõ trực tiếp. Cài qua script hay Makefile thì không thấy trước, nhưng vẫn bị bắt ở lockfile và manifest.
  - Bộ standards mẫu bật dependency rules từ bản sau `v0.1.0`. Workflow `self-enforce` tải binary bản release mới nhất, nên PR chỉ dùng được các khóa `dependencies` sau khi có release mới.

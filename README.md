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

Repo hiện **private**, nên phải tải bằng GitHub CLI đã đăng nhập:

```sh
gh release download --repo NoahDuongMaster/agentkit --pattern 'agentkit-installer.sh' -O - \
  | AGENTKIT_INSTALLER_GITHUB_BASE_URL=… sh   # xem mục "Phân phối khi repo private"
```

Khi repo chuyển sang public thì chỉ cần:

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

## Lệnh

```sh
agentkit check [paths…] [--staged | --changed | --since REF] [--format text|json|github]
agentkit rules                 # rule hiệu lực, nguồn, rule nào bị lock
agentkit sync [--check]        # AGENTS.md + file hook cho mọi agent (xem bảng dưới)
agentkit install [--force]     # git pre-commit hook (tôn trọng core.hooksPath, monorepo)
agentkit hook <claude-code|codex|gemini|cursor>   # entrypoint cho hook của agent (đọc stdin)
```

Exit code: `0` sạch, `1` có vi phạm mức error, `3` lỗi nội bộ/config. Không dùng `2`, vì giao thức hook của agent dành nó cho nghĩa "chặn và báo cho model". Nhờ vậy config hỏng không bao giờ chặn agent.

## Adapter agent

`agentkit sync` sinh ra tất cả các file dưới đây. Mọi adapter dùng chung một lõi quyết định; mỗi agent chỉ khác ở cách parse payload và cách trả lời.

| Agent | File sinh ra | Đọc rule từ | Trước khi chạy tool | Sau khi sửa file | Khi kết thúc lượt |
|---|---|---|---|---|---|
| Claude Code | `.claude/settings.json`, `CLAUDE.md` (`@AGENTS.md`) | AGENTS.md (import) | `PreToolUse` Bash/Edit/Write | `PostToolUse` | `Stop` |
| Codex | `.codex/hooks.json` | AGENTS.md (native) | `PreToolUse` Bash/`apply_patch` | `PostToolUse` `apply_patch` (path lấy từ header của patch) | `Stop` |
| Gemini CLI | `.gemini/settings.json` (thêm `context.fileName: AGENTS.md`) | AGENTS.md | `BeforeTool` `run_shell_command`/`write_file`/`replace` | `AfterTool` | `AfterAgent` |
| Cursor | `.cursor/hooks.json` (JSON native, `loop_limit: 1`) | AGENTS.md (native) | `preToolUse` Shell/Write/Delete | `postToolUse` → `additional_context` | `stop` → `followup_message` |

Các hook làm những việc sau:

- **Trước tool** chặn: `--no-verify`, `git commit -n`, `core.hooksPath`, `HUSKY=0`, `LEFTHOOK=0`, `SKIP=`; ghi vào `.git/hooks`, `.agentkit.yaml`, file rule, hoặc file hook của bất kỳ agent nào.
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

`cargo test` có 29 test:

- Unit: guard, tìm shell, path trong patch Codex.
- Integration: check, locked, git extends theo tag, staged, `--changed`/`--since`, linter delegation, format github, chống né rule, hook của 4 agent, sync idempotent, phát hiện drift, CRLF, pre-commit thật.

Ngoài ra đã chạy agent thật trong repo demo:

- **Claude Code**:
  - Có AGENTS.md: tự tuân thủ và từ chối `--no-verify`.
  - Không có AGENTS.md: viết `console.log`, Stop hook buộc nó tự xoá.
  - User ra lệnh dùng `any`: agent dừng lại hỏi người. Pre-commit chặn file vi phạm; khi người dùng `--no-verify` thì CI vẫn bắt được.
- **Codex** (không có AGENTS.md, được bảo dùng `any` và `--no-verify`):
  - `--no-verify` bị chặn.
  - Hook sau khi sửa file bắt được `any`, Codex đổi sang `unknown`.
  - Lần đầu Codex né rule console bằng `globalThis["console"]`. Sau khi sửa rule, chạy lại thì Codex xoá hẳn `console.log`.

## Giới hạn

- **Cursor và Gemini chưa chạy agent thật.** Cursor cần đăng nhập `cursor-agent login` (qua trình duyệt); Gemini CLI chưa được cài hay đăng nhập trên máy dev. Adapter được test bằng đúng schema payload ở trên.
- **File agent ghi bằng shell** (ví dụ `cat > f <<EOF`) không đi qua hook "sau khi sửa". Chúng vẫn bị bắt ở hook kết thúc lượt, ở pre-commit và ở CI.

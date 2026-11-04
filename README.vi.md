<p align="center">
  <img src="assets/jimothy.svg" width="180" alt="Jimothy, linh vật của larpcop: chú gấu mèo tròn đội mũ cảnh sát">
</p>

<h1 align="center">larpcop</h1>

<p align="center">
  <b>Agent báo "xong, test pass hết rồi." larpcop trả lời: "Cho xin cái bill."</b>
</p>

<p align="center">
  <a href="https://github.com/NoahDuongMaster/larpcop/actions/workflows/ci.yml"><img src="https://github.com/NoahDuongMaster/larpcop/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/NoahDuongMaster/larpcop/releases/latest"><img src="https://img.shields.io/github/v/release/NoahDuongMaster/larpcop" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0">
</p>

<p align="center">
  <a href="README.md">English</a> · <b>Tiếng Việt</b> · <a href="README.zh-CN.md">简体中文</a>
</p>

> **larp** /lɑːrp/ *(động từ, tiếng lóng 2026)*: làm màu, diễn như thể đã làm một việc mà thật ra chưa hề làm.
> *"Dạ em tuân thủ rule và chạy test đủ rồi sếp."* (Test thì chưa chạy cái nào.)

larpcop ép mọi coding agent (Claude Code, Codex, Gemini CLI, Cursor, Copilot CLI, Factory Droid, Kiro) và cả người viết code phải tuân theo cùng một bộ rule, trên mọi stack. Tất cả nằm trong một binary Rust duy nhất. Rule được khớp bằng [ast-grep](https://ast-grep.github.io) (tree-sitter, 25+ ngôn ngữ), nên lần nào chạy cũng ra cùng một kết luận. Cổng kiểm tra không chứa model nào, exit code cũng không có chỗ cho vibe.

Linh vật là Jimothy, chú gấu mèo tròn vo ở Seattle nổi tiếng hồi tháng 7/2026, ở đây được vẽ lại và đội mũ cảnh sát.

## Demo

Agent ghi một file. Ngay sau lần sửa đó, larpcop kiểm tra và gửi lỗi ngược lại cho agent:

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

Rồi agent thử chiêu kinh điển:

```text
$ git commit --no-verify -m "it works, trust me"
larpcop: blocked: skipping git hooks (`--no-verify` / `git commit -n`) is not allowed.
```

Cả hai đoạn output đều lấy từ binary của bản release v0.3.0, đã cắt bớt cho gọn.

## Vì sao cần cổng kiểm tra thay vì prompt

Prompt chỉ đề nghị được. Chỉ một phép kiểm tra tất định mới từ chối được. Nên larpcop đứng ở những điểm mà agent nào cũng phải đi qua:

| Tầng | Chạy gì | Agent có bỏ qua được không? |
|---|---|---|
| CI ([`enforce.yml`](.github/workflows/enforce.yml) hoặc org ruleset) | `larpcop check --since origin/<base>` | Không |
| Git pre-commit (`larpcop install`) | `larpcop check --staged` (nội dung đã staged, không phải working tree) | Được, bằng `--no-verify`; khi đó CI sẽ bắt lại |
| Hook của agent (`larpcop hook <agent>`) | Chặn các cách lách, báo lỗi ngay sau mỗi lần sửa, không cho kết thúc khi vẫn còn lỗi | Agent không có hook thì bỏ qua được, nhưng vẫn bị chặn ở git và CI |
| `AGENTS.md` (`larpcop sync`) | Hướng dẫn và bảng rule được sinh tự động | Được, vì đây chỉ là gợi ý |

Hook rút ngắn vòng phản hồi. Git và CI mới là chỗ rule trở nên bắt buộc. [Chi tiết về mô hình thực thi](docs/agents.md).

## Cài đặt

Mỗi bản release có sẵn binary cho macOS (arm64, x64), Linux (arm64, x64) và Windows (x64), dung lượng nén từ 5 đến 9 MB.

```sh
# macOS and Linux
curl -LsSf https://github.com/NoahDuongMaster/larpcop/releases/latest/download/larpcop-installer.sh | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/NoahDuongMaster/larpcop/releases/latest/download/larpcop-installer.ps1 | iex"
```

Installer đặt binary vào `~/.local/bin`. Muốn build từ source thì clone repo rồi chạy `cargo build --release`. Hiện chưa có package trên crates.io, npm hay Homebrew.

## Bắt đầu nhanh

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

`recommended` là bộ rule do chính repo này duy trì (xem bên dưới). Công ty có thể giữ standards riêng trong một repo khác và pin theo tag. Repo không thể từ chối standards mà CI ép áp dụng, và rule đánh dấu `locked` thì không thể bị disable hay override. [Cấu hình](docs/configuration.md).

## Bắt được những gì

- **Khớp theo cấu trúc, không theo mặt chữ.** Rule là các pattern của ast-grep. Codex từng lách bản đầu tiên của rule `no-console` bằng `globalThis["console"]["log"](x)`. Giờ rule khớp theo cấu trúc, và thông báo nói thẳng với agent rằng viết lại cùng một thứ theo cách khác vẫn bị tính là vi phạm. [Rule](docs/rules.md).
- **Injection xuyên hàm và xuyên file.** Taint analysis lần theo dữ liệu từ source đến sink qua phép gán, lời gọi hàm, import, callback và field của class. Có 99 rule taint cho SQL, shell, XSS, SSRF, path traversal, open redirect, deserialization và nhiều loại khác. [Taint](docs/taint.md).
- **Secrets.** Binary nhúng sẵn 222 detector của [gitleaks](https://github.com/gitleaks/gitleaks). Giá trị tìm thấy được in ra ở dạng đã che. [Bảo mật](docs/security.md).
- **Dependency.** Mã độc đã biết và lỗ hổng đã biết (OSV.dev) đều bị chặn; `recommended` bật chặn từ mức `high`. Hai cổng nữa là tuỳ chọn: tuổi phiên bản tối thiểu cho mỗi phiên bản mới (thường đặt 14 ngày) và một người duyệt từng dependency trực tiếp mới. Hook chặn `npm i some-evil-package` trước khi install script của nó kịp chạy. [Dependency](docs/dependencies.md).
- **Chất lượng code.** Độ dài hàm, cyclomatic complexity, baseline cho code cũ, báo cáo SARIF và GitLab, một comment PR duy nhất được cập nhật tại chỗ, LSP server và dashboard HTML.
- **Review bằng model, không bao giờ làm cổng chặn.** `larpcop review` và `larpcop learn` dùng bất kỳ CLI nào máy đã có sẵn (`claude -p`, `codex exec`, `gemini`, `ollama`). Chúng chỉ cảnh báo. `learn` biến một chuẩn viết bằng lời thành các rule tất định. [AI review](docs/ai-review.md).
- **Một tool để agent hỏi.** `larpcop mcp` cung cấp cho agent các tool `rules_for`, `check_content`, `check`, `fix` và `explain_rule`, để agent kiểm bản nháp trước khi ghi file.
- **Triển khai.** `larpcop org setup <owner>` mở một PR cho mỗi repo. `larpcop sync --managed` ghi các file policy cấp máy mà người dùng không tắt được. [Tổ chức](docs/organization.md).

Bộ `recommended` gồm 93 file rule ast-grep, 99 rule taint, 6 rule text, các detector secrets và phần kiểm tra lỗ hổng.

## Các agent

| Agent | Trước khi chạy tool | Sau khi sửa file | Khi định dừng |
|---|---|---|---|
| Claude Code | có | có | có |
| Codex | có | có | có |
| Gemini CLI | có | có | có |
| Cursor | có | có | có |
| Copilot CLI | có | có | có |
| Factory Droid | có | có | có |
| Kiro | có, và kiểm tra cả nội dung sắp được ghi | không có (Kiro không trả output của PostToolUse về cho model) | có |

Stop hook chỉ chặn một lần. Nếu agent vẫn dừng (ví dụ để hỏi người), thì cứ để nó dừng, và code vi phạm vẫn không commit hay merge được.

Claude Code và Codex đã được chạy thật. Payload của Kiro được ghi lại từ một `kiro-cli` thật. Payload của Cursor lấy từ mã nguồn `cursor-agent`. Gemini CLI, Copilot CLI và Factory Droid làm theo hooks reference của từng hãng và chưa chạy với agent thật. Chi tiết và ghi chú riêng cho từng agent: [Agent](docs/agents.md).

## Benchmark

Kết quả phát hiện trên các dự án cố ý có lỗ hổng, chấm theo danh sách lỗi đã biết của chính từng dự án.

| Bộ test | larpcop |
|---|---|
| Juice Shop, số dòng lỗ hổng tìm thấy | 11/27 |
| NodeGoat | 12/14 |
| DVNA | 12/14 |
| OWASP Benchmark Java (2.740 ca, TPR − FPR) | +91,9% |
| NIST Juliet C# (1.443 ca web, TPR − FPR) | +99,2% |
| NIST SARD PHP (20.856 ca, TPR − FPR) | +56,4% |

Có một lưu ý khi đọc các con số này. Mỗi bộ test ở lần chạy đầu là một bài kiểm tra held-out, rồi sau đó được dùng để viết thêm rule. Số của lần chạy đầu thấp hơn, và được liệt kê cạnh số cuối cùng trong [Benchmark](docs/benchmarks.md), cùng với danh sách các bộ test, phương pháp và các lỗi bị sót. Chạy lại bằng `bench/run.sh`.

## Giới hạn

- **Lỗi logic và phân quyền** (IDOR, thiếu kiểm tra quyền admin, trả về thừa dữ liệu) không có dạng cú pháp chung. Trên ba bộ benchmark, không công cụ SAST nào bắt được chúng. `larpcop review` nhắm vào loại này nhưng chỉ cảnh báo được.
- **CSRF** không có rule tổng quát. Một handler `GET` làm thay đổi trạng thái chỉ khác handler đúng ở chỗ thiếu bước kiểm tra token, mà thiếu một lời gọi hàm thì file nào cũng thoả. Các rule đi kèm chỉ bắt chỗ tắt CSRF một cách tường minh, ví dụ Rails thiếu `protect_from_forgery`, `.disable()` của Spring và `@csrf_exempt` của Django.
- **Taint chỉ là xấp xỉ.** Danh sách những gì nó theo được và những gì không theo được nằm trong [Taint](docs/taint.md).
- **Các phép kiểm dựa trên advisory** không thể biết về một bản release độc hại mà chưa ai báo cáo. Cổng tuổi phiên bản, nếu bật, lấp được phần lớn khoảng hở đó.
- **File mà agent ghi qua shell script** chỉ được kiểm sau khi lệnh đã chạy, không kiểm trước được. Pre-commit và CI vẫn áp dụng.

## Câu hỏi thường gặp

**Thế agent cứ thêm `--no-verify` thì sao?**
Thử thì không ai cấm. Hook đọc lệnh shell bằng một parser thật, nên `bash -c 'rm .larpcop.yaml'`, `--no-ver""ify` và `sudo env SKIP=all git commit` đều bị chặn. Nếu có gì lọt qua, CI vẫn kiểm tra pull request.

**Sao không ghi rule vào `AGENTS.md` rồi tin agent?**
Agent đọc file đó giống cách người ta đọc điều khoản sử dụng: kéo xuống cuối rồi bấm "Tôi đã đọc và đồng ý". Vì có ích nên larpcop vẫn sinh ra một file `AGENTS.md`, nhưng file đó không ép buộc được gì.

**Code có bị gửi cho model không?**
Chỉ khi chạy `larpcop review` hoặc `larpcop learn`, và chỉ gửi tới CLI đã được cấu hình. `check`, các hook và CI workflow mặc định không bao giờ gọi model (bước `review` của workflow ở trạng thái tắt, trừ khi bật lên). Các phép kiểm tra dependency có gọi tới deps.dev và OSV.dev.

**Jimothy là ai?**
Một chú gấu mèo tròn vo, nổi như cồn ở Seattle hồi tháng 7/2026. Giờ đang trong ca trực.

## Tài liệu

Các trang tham khảo dưới đây chỉ có bản tiếng Anh.

| Trang | Nội dung |
|---|---|
| [Cấu hình](docs/configuration.md) | Standards, `extends`, `locked`, các lệnh, exit code, baseline, biến môi trường |
| [Rule](docs/rules.md) | Cách viết rule, `metadata.resolve`, fix và fixture, bộ `recommended`, báo cáo chất lượng |
| [Bảo mật](docs/security.md) | Bốn lớp, rule text, secrets |
| [Taint](docs/taint.md) | Tham chiếu `taint:`, guard, sink có xét kiểu, các giới hạn |
| [Dependency](docs/dependencies.md) | Duyệt dependency, tuổi phiên bản, lỗ hổng và mã độc |
| [AI review](docs/ai-review.md) | `review` và `learn` |
| [Agent](docs/agents.md) | Mô hình thực thi, hook cho từng agent, MCP server |
| [Tổ chức](docs/organization.md) | Dashboard, managed policy, `org`, CI workflow, release |
| [Benchmark](docs/benchmarks.md) | Kết quả đầy đủ |
| [Kiểm chứng](docs/verification.md) | Các test bao phủ những gì và những gì đã được chạy thật |

## Phát triển

```sh
cargo fmt --check && cargo clippy --all-targets && cargo test
cargo run -- check   # larpcop checks its own source with its own rules
```

File giữ dưới 300 dòng, không nuốt lỗi, và `AGENTS.md` của chính repo liệt kê phần còn lại.

## Giấy phép

Dùng theo một trong hai giấy phép [Apache-2.0](LICENSE-APACHE) hoặc [MIT](LICENSE-MIT), tuỳ bạn chọn.

Trừ khi bạn nêu rõ điều khác, mọi đóng góp mà bạn chủ động gửi vào larpcop, theo nghĩa của giấy phép Apache-2.0, đều được cấp phép kép như trên, không kèm điều khoản hay điều kiện bổ sung nào.

Bộ detector secrets (`assets/gitleaks.toml`) lấy từ [gitleaks](https://github.com/gitleaks/gitleaks), theo giấy phép MIT. Nguyên văn giấy phép nằm trong [`assets/gitleaks.LICENSE`](assets/gitleaks.LICENSE).

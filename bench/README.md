# Benchmark: agentkit vs Semgrep OSS vs gitleaks

Chạy lại được bằng một lệnh: `bench/run.sh` (cần git, python3, semgrep, gitleaks và một bản build release của agentkit). Kết quả thô nằm trong [`results/`](results): `juice-shop.md`, `NodeGoat.md`, `timing.txt`; các file JSON không được commit.

## Đối tượng và cách chấm

| | Juice Shop | NodeGoat |
|---|---|---|
| Mã nguồn | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) tag `v20.3.0` (Express + Angular) | [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) commit `c5cb68a` (Express + MongoDB) |
| Đáp án | Comment `// vuln-code-snippet vuln-line <challenge>` do chính nhóm Juice Shop đặt: 27 dòng (bỏ `test/` và `data/static/codefixes/`) | [`nodegoat-truth.json`](nodegoat-truth.json): 14 dòng theo tutorial OWASP Top 10 của NodeGoat, viết ra **trước khi** chạy bất kỳ công cụ nào |
| Vai trò | Bộ dùng để phát triển: một số rule được thêm sau khi đã thấy chỗ hổng | **Bộ kiểm chứng**: không rule nào được thêm hay sửa sau khi chạy |

- **Một dòng tính là tìm thấy** khi có finding của công cụ phủ dòng đó, chấp nhận lệch ±3 dòng, áp dụng như nhau cho mọi công cụ.
- **Công cụ**:
  - agentkit với bộ [`standards/recommended`](../standards/recommended); chỉ tính rule bảo mật.
  - Semgrep OSS 1.183.0 với gói `p/default` (1073 rule), tải về một lần trước khi đo.
  - gitleaks 8.30.1, chỉ để so phần secrets.
- **Thời gian**: trung vị của 3 lần chạy trên MacBook arm64 8 nhân.

## Kết quả (31/10/2026)

| | agentkit | Semgrep OSS | gitleaks |
|---|---|---|---|
| Juice Shop: thời gian | **3,58 s** | 34,91 s | 5,37 s |
| Juice Shop: dòng tìm thấy (/27) | **11** (8 nếu không tính `validate-request-input`) | 6 | – |
| NodeGoat: thời gian | **3,26 s** | 10,06 s | 0,23 s |
| NodeGoat: dòng tìm thấy (/14) | **8** (6 nếu không tính `validate-request-input`) | 4 | – |
| Secrets (so với gitleaks) | 69/69 và 3/3 trùng khớp | – | 69 và 3 |

agentkit chạy cả bộ `recommended` (ast-grep, taint, secrets, metric, lỗ hổng dependency). Thời gian NodeGoat gần như toàn bộ là chờ mạng: OSV được hỏi về cả 1.480 package trong `package-lock.json` (khoảng 3 s cho một request querybatch từ máy đo); chi tiết advisory được cache theo trường `modified` của OSV nên chỉ tải lại khi advisory bị sửa. Lần chạy đầu, chưa có cache, mất 7,8 s.

### Juice Shop

- **SQL injection** (`routes/login.ts:34`, `routes/search.ts:23`): cả hai đều bắt được. agentkit bắt bằng hai lớp độc lập: quy ước `no-sql-interpolation` và `taint-sql`.
- **XSS qua `bypassSecurityTrustHtml`** (2 dòng): chỉ agentkit (`no-bypass-security-trust`).
- **Directory listing** (4 dòng): cả hai.
- **NoSQL injection / forged review** (`routes/updateProductReviews.ts`, 3 dòng): chỉ agentkit, nhờ quy ước `validate-request-input`. Quy ước này cấm cách viết gây ra lỗi chứ không truy vết lỗi, nên báo mọi chỗ dùng input chưa validate: 236 chỗ ở Juice Shop. Repo cũ dùng `baseline` để chỉ chặn code mới.
- **16 dòng không công cụ nào bắt được**: lỗi logic, phân quyền, cấu hình (route admin lộ, allowlist redirect dùng `includes`, rate limit tin `X-Forwarded-For`, prompt injection chatbot…). SAST cú pháp không với tới loại này; rule `llm` (`agentkit review`) làm cho loại này nhưng không được tính vì không tất định.

### NodeGoat (bộ kiểm chứng)

| Dòng | Lỗ hổng | agentkit | Semgrep OSS |
|---|---|---|---|
| `contributions.js:32–34` | Server-side JS injection (`eval` của `req.body`) | ✓ `no-eval` | ✓ `eval-detected` |
| `allocations-dao.js:78` | NoSQL injection (`$where`) | ✓ `no-mongo-where` | – |
| `index.js:72` | Open redirect (`req.query.url`) | ✓ `taint-redirect` | ✓ `express-open-redirect` |
| `package-lock.json:6742` | Dependency có lỗ hổng (`marked@0.3.5`) | ✓ `dependency-vulnerability` | – (cần Semgrep Supply Chain, bản trả phí) |
| `allocations.js:18`, `research.js:16` | IDOR, SSRF | ✓ chỉ qua quy ước `validate-request-input` | – |
| `session.js:64`, `profile.js:59`, `user-dao.js:25/61`, `session.js:144`, `server.js:137` | Log injection, ReDoS, mật khẩu plain text, chính sách mật khẩu yếu, tắt autoescape | – | – |

Bộ này cho thấy chỗ trống thật: ReDoS, log injection và tắt template autoescape chưa có rule. Chúng **không** được thêm sau khi xem kết quả, để bộ này còn giá trị kiểm chứng; nếu thêm thì phải đo trên một bộ thứ ba (ví dụ DVNA).

### Phạm vi khác nhau

- Cả hai có rule GitHub Actions và Terraform. agentkit trước đây bỏ qua thư mục ẩn khi quét toàn repo, nên không thấy `.github/workflows`; benchmark lộ ra lỗi này và đã sửa.
- Semgrep báo lỗi cú pháp và bỏ qua các file snippet trong `data/static/codefixes/` của Juice Shop. tree-sitter chịu lỗi nên agentkit vẫn đọc được, vì vậy có thêm finding ở đó (ví dụ 28 trên 34 lần `no-directory-listing`).

**Secrets**: agentkit nhúng nguyên bộ rule của gitleaks và giải mã base64/JWT như gitleaks, nên kết quả trùng khớp hoàn toàn. Các lần chạy trước lộ ra 3 bug đã sửa: công thức entropy (đếm ký tự, chia cho số byte), gộp finding `generic-*` nằm trong finding cụ thể hơn, và secret nằm trong payload JWT.

## Những gì đã thay đổi vì benchmark

Juice Shop lần đầu: agentkit **5/27**, Semgrep 6/27. Sau đó bộ `recommended` được thêm các rule dưới đây, đều là mẫu lỗ hổng phổ biến nhưng được thêm *sau khi* đã thấy chỗ hổng:

- `no-bypass-security-trust` (Angular), `no-directory-listing` (`serve-index`): đưa kết quả lên 11/27.
- `no-weak-hash`, `py-no-weak-hash`, `no-mongo-where`, `taint-redirect`: không đổi điểm Juice Shop. `no-mongo-where` và `taint-redirect` bắt được 2 dòng của NodeGoat, bộ mà chúng chưa từng thấy.

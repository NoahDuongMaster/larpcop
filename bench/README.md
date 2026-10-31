# Benchmark: agentkit vs Semgrep OSS vs gitleaks

Chạy lại được bằng một lệnh: `bench/run.sh` (cần git, python3, semgrep, gitleaks và một bản build release của agentkit). Kết quả thô nằm trong [`results/`](results): `score.md`, `timing.txt`; các file JSON không được commit.

## Đối tượng và cách chấm

- **Mã nguồn**: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) tag `v20.3.0`, ứng dụng Express + Angular được cố ý viết với lỗ hổng.
- **Đáp án**: các comment `// vuln-code-snippet vuln-line <challenge>` mà chính nhóm Juice Shop đặt vào dòng có lỗ hổng cho phần coding challenge. Có 27 dòng (bỏ qua `test/` và `data/static/codefixes/`). Đáp án do bên thứ ba viết, không phải do agentkit chọn.
- **Một dòng tính là tìm thấy** khi có finding của công cụ phủ dòng đó, chấp nhận lệch ±3 dòng. Cửa sổ này áp dụng như nhau cho cả hai công cụ.
- **Công cụ**:
  - agentkit với bộ [`standards/recommended`](../standards/recommended); chỉ tính các rule bảo mật, phần chất lượng code bỏ ra.
  - Semgrep OSS 1.183.0 với gói `p/default` (1073 rule), tải về một lần trước khi đo.
  - gitleaks 8.30.1, chỉ để so phần secrets.
- **Thời gian**: trung vị của 3 lần chạy trên MacBook arm64 8 nhân.

## Kết quả (31/10/2026)

| | agentkit | Semgrep OSS | gitleaks |
|---|---|---|---|
| Thời gian quét toàn repo | **2,91 s** | 33,44 s | 4,60 s |
| Dòng lỗ hổng tìm thấy (/27) | **11** | 6 | – |
| … không tính rule quy ước `validate-request-input` | **8** | 6 | – |
| Secrets (so với gitleaks) | 68/69 trùng khớp | – | 69 |

agentkit chạy cả bộ `recommended` (26 rule ast-grep, 4 rule taint, secrets, metric), nhanh hơn Semgrep **11,5 lần** và còn nhanh hơn gitleaks, dù đã gồm luôn phần secrets.

Theo từng loại:

- **SQL injection** (`routes/login.ts:34`, `routes/search.ts:23`): cả hai đều bắt được. agentkit bắt bằng hai lớp độc lập: quy ước `no-sql-interpolation` và `taint-sql`.
- **XSS qua `bypassSecurityTrustHtml`** (2 dòng): chỉ agentkit bắt được (`no-bypass-security-trust`).
- **Directory listing** (4 dòng): cả hai đều bắt được.
- **NoSQL injection / forged review** (`routes/updateProductReviews.ts`, 3 dòng): chỉ agentkit, nhờ quy ước `validate-request-input` (`req.body.id` được dùng mà không qua schema). Quy ước này không phải truy vết lỗi; nó cấm cách viết gây ra lỗi, nên sẽ báo mọi chỗ dùng input chưa validate. Ở Juice Shop là 236 chỗ (125 trong `routes/`). Repo cũ nên dùng `baseline` để chỉ chặn code mới.
- **16 dòng không công cụ nào bắt được**: lỗi logic, phân quyền và cấu hình (route admin lộ, allowlist redirect dùng `includes`, rate limit tin `X-Forwarded-For`, prompt injection chatbot…). Đây là phần mà SAST cú pháp không với tới; rule `llm` (`agentkit review`) được làm cho loại này, nhưng không được tính vào benchmark vì không tất định.

Phạm vi khác nhau, nói rõ để không so lệch:

- Semgrep có rule cho Terraform (17 finding) và GitHub Actions (13 finding), tức 30 trong 68; agentkit chưa có rule cho hai loại này.
- Semgrep báo lỗi cú pháp và bỏ qua các file snippet trong `data/static/codefixes/`. tree-sitter chịu lỗi nên agentkit vẫn đọc được, vì vậy agentkit có thêm finding ở đó (ví dụ 28 trên 34 lần `no-directory-listing`).
- Ngoài `test/` và `codefixes/`: agentkit có 41 finding bảo mật nếu không tính `validate-request-input` (185 nếu tính). Semgrep có 53, trong đó phần lớn là Terraform và GitHub Actions.

**Secrets**: agentkit nhúng nguyên bộ rule của gitleaks. Kết quả trùng khớp với gitleaks 68/69. Finding duy nhất bị lệch nằm trong payload của một JWT: gitleaks giải mã base64 rồi quét tiếp phần bên trong, agentkit chưa làm việc này. Lần chạy đầu lệch 5 finding, lộ ra 2 bug đã sửa: entropy phải tính theo đúng công thức của gitleaks (đếm ký tự, chia cho số byte), và finding `generic-*` nằm trong một finding cụ thể hơn trên cùng dòng thì phải gộp làm một.

## Những gì đã thay đổi vì benchmark

Lần chạy đầu: agentkit tìm được **5/27**, Semgrep 6/27. Sau đó bộ `recommended` được thêm các rule dưới đây. Đây đều là các mẫu lỗ hổng phổ biến, không viết riêng cho Juice Shop, nhưng chúng được thêm *sau khi* đã thấy chỗ hổng:

- `no-bypass-security-trust` (Angular), `no-directory-listing` (`serve-index`): nhờ hai rule này mà kết quả lên 11/27.
- `no-weak-hash`, `py-no-weak-hash`, `no-mongo-where`, `taint-redirect`: không thay đổi điểm trên 27 dòng.

Muốn kiểm chứng không thiên vị thì cần một bộ đáp án thứ hai mà các rule chưa từng nhìn thấy. Hướng tiếp theo là dùng NodeGoat hoặc DVNA.

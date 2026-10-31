# Benchmark: larpcop vs Semgrep OSS vs gitleaks

Chạy lại được bằng một lệnh: `bench/run.sh` (cần git, python3, node, semgrep, gitleaks và một bản build release của larpcop). Kết quả thô nằm trong [`results/`](results): `juice-shop.md`, `NodeGoat.md`, `dvna.md`, `seeds.md`, `timing.txt`; các file JSON không được commit.

## Đối tượng và cách chấm

| | Mã nguồn | Đáp án |
|---|---|---|
| Juice Shop | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) `v20.3.0` (Express + Angular) | Comment `// vuln-code-snippet vuln-line` do chính nhóm Juice Shop đặt: 27 dòng (bỏ `test/` và `data/static/codefixes/`) |
| NodeGoat | [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) `c5cb68a` (Express + MongoDB) | [`nodegoat-truth.json`](nodegoat-truth.json): 14 dòng theo tutorial của NodeGoat |
| DVNA | [appsecco/dvna](https://github.com/appsecco/dvna) `9ba473a` (Express + Sequelize + EJS) | [`dvna-truth.json`](dvna-truth.json): 14 dòng theo `docs/solution/*.md` của DVNA |
| vulnerable-node | [cr0hn/vulnerable-node](https://github.com/cr0hn/vulnerable-node) `d68f2a3`, thư mục `sast/seeds/` | Do chính dự án viết (`sast/ground-truth.yaml`) và chấm bằng script của dự án (`sast/tests/score.js`): 12 file, mỗi file một lỗ hổng, cộng 2 file sạch để đo báo nhầm |

- **Một dòng tính là tìm thấy** khi có finding của công cụ phủ dòng đó, chấp nhận lệch ±3 dòng, áp dụng như nhau cho mọi công cụ. Với vulnerable-node, một file tính là tìm thấy khi công cụ báo bất kỳ finding nào trong file (cách chấm của dự án); cột thứ hai bỏ các rule báo cho mọi handler Express bất kể lỗi (`validate-request-input` của larpcop, kiểm middleware CSRF của Semgrep).
- **Công cụ**: larpcop với bộ [`standards/recommended`](../standards/recommended), chỉ tính rule bảo mật; Semgrep OSS 1.183.0 với gói `p/default` (1073 rule), tải về một lần trước khi đo; gitleaks 8.30.1, chỉ để so phần secrets.
- **Thời gian**: trung vị của 3 lần chạy trên MacBook arm64 8 nhân.

## Bộ nào còn là bộ kiểm chứng

Một bộ chỉ đo được độ tổng quát khi rule chưa được viết sau khi xem đáp án của nó. Thứ tự đã diễn ra:

1. **Juice Shop** là bộ phát triển: lần đầu larpcop 5/27, Semgrep 6/27; `no-bypass-security-trust`, `no-directory-listing`, `no-weak-hash`, `no-mongo-where`, `taint-redirect` được thêm sau đó.
2. **NodeGoat** được chấm lần đầu khi chưa ai xem đáp án: larpcop **8/14**, Semgrep 4/14. Bốn chỗ trống (ReDoS, log injection, tắt autoescape, so mật khẩu plain text) sau đó có rule, nên NodeGoat không còn là bộ kiểm chứng.
3. **DVNA** đo bốn rule đó: chúng không bắt thêm dòng nào (DVNA không có các lỗi này). Lần chạy đầu: larpcop **5/14**, Semgrep **7/14**. Các chỗ trống (secret của session viết cứng, XXE, deserialization, `mathjs.eval`, output không escape trong template EJS) sau đó có rule, nên DVNA cũng hết là bộ kiểm chứng.
4. **vulnerable-node** đo các rule của bước 3, lần đầu: larpcop 10/12 file, 1 báo nhầm (6/12 nếu bỏ rule chung chung), Semgrep 10/12, 1 báo nhầm (8/12). Các chỗ trống (XSS qua `res.send`, path traversal, SSRF, ReDoS, prototype pollution) và báo nhầm (redirect đã được kiểm bằng `startsWith`) sau đó được xử lý bằng rule taint mới, `guards` và `safe_prefix`.

Kết quả dưới đây là sau bước 4: chỉ có ý nghĩa *không thụt lùi* trên cả bốn bộ. Rule mới cần một bộ thứ năm chưa ai nhìn.

## Kết quả (01/11/2026)

| | larpcop | Semgrep OSS | gitleaks |
|---|---|---|---|
| Juice Shop: thời gian | **5,00 s** | 33,34 s | 4,83 s |
| Juice Shop: dòng tìm thấy (/27) | **11** (8 nếu không tính `validate-request-input`) | 6 | – |
| NodeGoat: thời gian | **3,12 s** | 9,82 s | 0,21 s |
| NodeGoat: dòng tìm thấy (/14) | **12** | 4 | – |
| DVNA: thời gian | **1,12 s** | 9,51 s | 0,23 s |
| DVNA: dòng tìm thấy (/14) | **12** | 7 | – |
| vulnerable-node seeds (/12 file, báo nhầm trên 2 file sạch) | **11**, 1 báo nhầm (11 và 0 báo nhầm nếu bỏ rule chung chung) | 10, 1 báo nhầm (8 và 1 báo nhầm nếu bỏ rule chung chung) | – |
| Secrets (so với gitleaks) | 69/69 và 3/3 trùng khớp | – | 69 và 3 |

larpcop chạy cả bộ `recommended` (ast-grep, 16 rule taint, rule template, secrets, metric, lỗ hổng dependency). So với 3,58 s ở bản 0.2.1, Juice Shop chậm hơn vì thêm 12 rule taint và taint xuyên hàm; mỗi rule quét cây cú pháp một lần cho mọi pattern và mỗi phạm vi chỉ duyệt một lần cho mọi tham số và mọi vòng summary. Thời gian NodeGoat gần như toàn bộ là chờ mạng: OSV được hỏi về 1.480 package trong `package-lock.json`.

### Những gì không công cụ nào bắt được

- Juice Shop: 16 dòng lỗi logic, phân quyền, cấu hình (route admin lộ, allowlist redirect dùng `includes`, rate limit tin `X-Forwarded-For`, prompt injection chatbot…).
- NodeGoat: chính sách mật khẩu yếu (`session.js:144`), mật khẩu lưu plain text (`user-dao.js:25`, phép gán chứ không phải phép so sánh).
- DVNA: API trả mọi bản ghi user (`appHandler.js:207`), route admin không kiểm quyền (`routes/app.js:42`).
- vulnerable-node: NoSQL injection trong một hàm nhận filter làm tham số, không có nguồn request nào trong file.

SAST cú pháp không với tới lỗi logic và phân quyền; rule `llm` (`larpcop review`) nhắm vào loại này nhưng không được tính vì không tất định.

### Phạm vi khác nhau

- Cả hai có rule GitHub Actions và Terraform. larpcop trước đây bỏ qua thư mục ẩn khi quét toàn repo, nên không thấy `.github/workflows`; benchmark lộ ra lỗi này và đã sửa.
- Semgrep báo lỗi cú pháp và bỏ qua các file snippet trong `data/static/codefixes/` của Juice Shop. tree-sitter chịu lỗi nên larpcop vẫn đọc được, vì vậy có thêm finding ở đó.
- `[innerHTML]` của Angular không bị tính là XSS: Angular tự sanitize binding này; lỗ hổng thật nằm ở `bypassSecurityTrust*`.
- Filter của Sequelize (`where:`, `include:`) không bị tính là NoSQL injection: Sequelize không nhận operator từ JSON.

**Secrets**: larpcop nhúng nguyên bộ rule của gitleaks và giải mã base64/JWT như gitleaks, nên kết quả trùng khớp hoàn toàn. Các lần chạy trước lộ ra 3 bug đã sửa: công thức entropy, gộp finding `generic-*` nằm trong finding cụ thể hơn, và secret nằm trong payload JWT.

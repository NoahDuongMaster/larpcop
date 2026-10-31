# Benchmark: larpcop vs Semgrep OSS vs gitleaks

Chạy lại được bằng một lệnh: `bench/run.sh` (cần git, python3, node, semgrep, gitleaks và một bản build release của larpcop). Kết quả thô nằm trong [`results/`](results): `juice-shop.md`, `NodeGoat.md`, `dvna.md`, `dvpwa.md`, `dvws-node.md`, `govwa.md`, `seeds.md`, `timing.txt`; các file JSON không được commit.

## Đối tượng và cách chấm

| | Mã nguồn | Đáp án |
|---|---|---|
| Juice Shop | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) `v20.3.0` (Express + Angular) | Comment `// vuln-code-snippet vuln-line` do chính nhóm Juice Shop đặt: 27 dòng (bỏ `test/` và `data/static/codefixes/`) |
| NodeGoat | [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) `c5cb68a` (Express + MongoDB) | [`nodegoat-truth.json`](nodegoat-truth.json): 14 dòng theo tutorial của NodeGoat |
| DVNA | [appsecco/dvna](https://github.com/appsecco/dvna) `9ba473a` (Express + Sequelize + EJS) | [`dvna-truth.json`](dvna-truth.json): 14 dòng theo `docs/solution/*.md` của DVNA |
| DVPWA | [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) `a1d8f89` (Python, aiohttp + Jinja2) | [`dvpwa-truth.json`](dvpwa-truth.json): 4 dòng theo mục *Vulnerabilities* trong README của DVPWA |
| GoVWA | [0c34/govwa](https://github.com/0c34/govwa) `4058f79` (Go, net/http + html/template) | [`govwa-truth.json`](govwa-truth.json): 4 dòng theo comment đánh dấu lỗ hổng của chính dự án trong `vulnerability/sqli` và `vulnerability/xss` (IDOR và client-side auth là lỗi logic; module XXE là file rỗng) |
| DVWS-Node | [snoopysecurity/dvws-node](https://github.com/snoopysecurity/dvws-node) `e83689c` (Express + MongoDB + MySQL + GraphQL + SOAP/XML-RPC) | [`dvws-truth.json`](dvws-truth.json): 15 dòng theo `CHALLENGES.md`, mỗi challenge mà lỗi nằm ở một dòng code (bỏ IDOR, CORS, rate limit… là lỗi thiết kế) |
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

5. **DVPWA** là bộ Python đầu tiên, đo mọi rule Python tới lúc đó, lần đầu: larpcop **1/4**, Semgrep **2/4**. Chỗ trống lộ ra ba điểm yếu chung: SQL được dựng bằng `%` ở một biến rồi mới truyền vào `execute`, `md5` gọi trực tiếp sau `from hashlib import md5`, và nguồn request của aiohttp/Starlette/Tornado chưa được khai. Thêm vào đó, taint chưa theo được qua method của class được import (`Student.create(...)`). Cả bốn đã được sửa.

6. **DVWS-Node** đo mọi rule tới bước 5, kể cả session fixation, taint qua decorator của NestJS và tham số handler của FastAPI/Flask (hai thứ này đã được thử trên mẫu thật `nestjs/nest/sample` và `fastapi/full-stack-fastapi-template` để đếm báo nhầm, không phải trên bộ có đáp án). Lần đầu: larpcop **10/15** (9/15 nếu bỏ `validate-request-input`), Semgrep **7/15**. Chỗ trống lộ ra: JWT chấp nhận `alg: none`, filter LDAP ghép chuỗi, file `.env` có secret được commit dù nằm trong `.gitignore` (larpcop bỏ qua file đã track nhưng bị ignore: một bug), tham số của resolver GraphQL không được coi là dữ liệu request, và `fsPromise.writeFile` không phải sink vì chỉ có `fs.*`/`fsp.*`. Lần chạy đó cũng lộ ra báo nhầm: `RegExp.prototype.exec` bị tính là `child_process.exec`, `stream.write(a + b)` là XSS, `dict.get(x)` là SSRF; sink giờ khai theo tên (`cp.exec`, `res.send`, `session.get`). Tất cả đã được sửa, nên DVWS-Node cũng hết là bộ kiểm chứng.

7. **GoVWA** là bộ Go đầu tiên, đo 5 rule taint Go vừa viết (SQL, shell, path, SSRF, redirect) cùng `go-no-sql-sprintf`. Lần đầu: larpcop **0/4**, Semgrep **4/4**. Lần chạy lộ ra bốn điểm yếu chung của phần Go: không có rule XSS nào (`template.HTML(x)`), `go-no-sql-sprintf` chỉ bắt `fmt.Sprintf` nằm ngay trong `db.Query(...)` chứ không bắt khi câu SQL được dựng trước ở một biến, method Go (`func (p *Profile) Load()`) không có summary theo kiểu receiver nên taint không qua được `p.Load(uid)` ở file khác cùng package, và pattern nguồn `$C.Query(k)` của gin trùng với sink `db.Query(sql)`. Cả bốn đã được sửa (`go-taint-xss`, `go-no-unsafe-template-type`, SQL dựng ở bất kỳ đâu, method theo receiver, sink nằm trong nguồn thì không tính). Chạy thử trên `pocketbase/pocketbase` (Go thật, không phải bộ có đáp án) lộ thêm báo nhầm: `stmt.Exec(args)` của prepared statement, `resp.Body` của response bị coi là nguồn; đã sửa.

8. **OWASP Benchmark (Java)** đo 8 rule taint Java và 5 rule cú pháp Java vừa viết, chấm như scorecard của chính dự án (mỗi hạng mục: tỉ lệ bắt đúng − tỉ lệ báo nhầm, rồi lấy trung bình). Lần đầu: larpcop **+37,5%**, Semgrep `p/default` +34,9%, `p/java` +17,7%. Lần chạy lộ ra một điểm yếu chung của taint: phép gán sạch nằm trong nhánh `if` (`if (param == null) param = "";`) xoá taint như thể nó luôn chạy. Giờ phép gán chỉ chạy trên một số đường (trong `if`, vòng lặp, `try`, `switch`) có thể làm bẩn nhưng không làm sạch một biến: **+44,0%**. Báo nhầm còn lại phần lớn là các ca cố ý của Benchmark mà taint không có hằng số và chỉ số collection không phân biệt được (`(7*18)+num > 200 ? "safe" : param`, `list.remove(0); list.get(1)`), và rule quy ước `java-no-sql-concat` báo mọi câu SQL ghép chuỗi, kể cả khi giá trị ghép vào là an toàn.

9. **DVWA (PHP)** đo 8 rule taint PHP và 3 rule cú pháp PHP vừa viết. Đáp án lấy từ cấu trúc của chính DVWA: trong mỗi module, `source/low.php`, `medium.php`, `high.php` có lỗ hổng theo thiết kế, `impossible.php` là bản đã sửa (8 module: SQLi, SQLi blind, command injection, file inclusion, upload, XSS phản chiếu, XSS lưu trữ, open redirect). Lần đầu: larpcop **+40,0%**, Semgrep **+3,3%**. Báo nhầm trên các bản `impossible.php` lộ ra: `is_numeric`/`ctype_digit` là phép kiểm (guard) chứ không phải hàm làm sạch, giá trị qua `md5()` là an toàn, `$_SERVER['SERVER_PROTOCOL']` không do client đặt (chỉ các khoá `HTTP_*`, `REQUEST_URI`, `QUERY_STRING`, `PHP_SELF`… là nguồn), hàm trong file được `require` không có summary, và một phép gán sạch trong nhánh `if` không làm sạch được biến cho phần còn lại của chính nhánh đó. Sau khi sửa: **+60,0%**. XSS ở DVWA nằm ở `index.php` dùng chung cho mọi mức (file nguồn chỉ dựng chuỗi `$html`), nên không công cụ nào bắt được theo file.

10. **NIST Juliet C# 1.3** đo 9 rule taint C# (thêm `cs-taint-ldap`, `cs-taint-xpath` và các tên `HttpRequest`/`HttpResponse` cổ điển trước khi chạy). Chỉ lấy 1.443 ca có dữ liệu đến từ request HTTP (`QueryString`, `Params`, `Cookies`) ở 10 CWE: SQLi, lệnh OS, path traversal tương đối/tuyệt đối, open redirect, ba loại XSS, LDAP, XPath. Đáp án là nhãn của chính Juliet: mã trong method `Bad*` (hay file `*_bad.cs`) có lỗ hổng, mã trong `Good*` thì không. Lần đầu: larpcop **+43,9%**, Semgrep `p/default` và `p/csharp` cùng **+0,8%** (Semgrep bắt 67% ca SQL nhưng báo cả 61% bản đã sửa). Các ca bị sót lộ ra những chỗ engine chưa theo được: luồng qua nhiều file (Java/C# không có `import` cho class cùng namespace), `(new Helper()).Run(x)`, `cmd.CommandText += …`, `List.Add`/`AddLast`/`Dictionary`, field của class viết không có `this.`. Sau khi sửa engine, cộng sanitizer `SecurityElement.Escape` và sink `StatusDescription`: **+86,5%**, không còn báo nhầm. Còn sót: chuỗi gọi qua hơn 2 file (biến thể 53, 54), field static của class khác (68), dữ liệu qua serialize (75), gọi qua lớp cơ sở ảo (81).

Kết quả dưới đây là sau bước 10: chỉ có ý nghĩa *không thụt lùi* trên cả mười bộ. Rule mới cần một bộ chưa ai nhìn.

## Kết quả (01/11/2026)

| | larpcop | Semgrep OSS | gitleaks |
|---|---|---|---|
| Juice Shop: thời gian | 6,63 s | 33,75 s | **4,76 s** |
| Juice Shop: dòng tìm thấy (/27) | **11** (8 nếu không tính `validate-request-input`) | 6 | – |
| NodeGoat: thời gian | 3,25 s | 10,64 s | **0,21 s** |
| NodeGoat: dòng tìm thấy (/14) | **12** | 4 | – |
| DVNA: thời gian | 1,21 s | 10,12 s | **0,24 s** |
| DVNA: dòng tìm thấy (/14) | **12** | 7 | – |
| DVPWA: thời gian | 2,59 s | 26,01 s | **0,21 s** |
| DVPWA: dòng tìm thấy (/4) | **4** | 2 | – |
| DVWS-Node: thời gian | 1,94 s | 11,14 s | **0,27 s** |
| DVWS-Node: dòng tìm thấy (/15) | **13** (cả 13 khi bỏ `validate-request-input`) | 7 | – |
| GoVWA: thời gian | 1,57 s | – | – |
| GoVWA: dòng tìm thấy (/4) | **4** (lần đầu 0) | 4 | – |
| OWASP Benchmark Java: thời gian | **7,11 s** | 48,6 s (`p/default`), 54,9 s (`p/java`) | 49,8 s |
| DVWA (PHP): điểm trung bình (TPR − FPR) | **+60,0%** (lần đầu +40,0%) | +3,3% | – |
| Juliet C# (1.443 ca web): thời gian | **4,96 s** | 16,1 s (`p/default`) | – |
| Juliet C# (1.443 ca web): điểm trung bình (TPR − FPR) | **+86,5%** (lần đầu +43,9%) | +0,8% (`p/default`, `p/csharp`) | – |
| OWASP Benchmark Java: điểm trung bình (TPR − FPR) | **+46,2%** (lần đầu +37,5%) | +34,9% (`p/default`), +17,7% (`p/java`) | – |
| vulnerable-node seeds (/12 file, báo nhầm trên 2 file sạch) | **11**, 1 báo nhầm (11 và 0 báo nhầm nếu bỏ rule chung chung) | 10, 1 báo nhầm (8 và 1 báo nhầm nếu bỏ rule chung chung) | – |
| Secrets (so với gitleaks) | 69/69 và 3/3 trùng khớp | – | 69 và 3 |

larpcop chạy cả bộ `recommended` (ast-grep, 16 rule taint, rule template, secrets, metric, lỗ hổng dependency). Mọi rule taint dùng chung một lần parse và một lần duyệt cây cho mỗi file; mỗi rule chỉ thử pattern của nó trên các node đúng loại. Juice Shop chậm hơn bản 0.3.0 (5,00 s) vì giờ đọc cả 9 file thư viện (three.js…, 39.500 dòng) mà Juice Shop commit dù có trong `.gitignore`: file đã track thì vẫn được kiểm. Thời gian NodeGoat gần như toàn bộ là chờ mạng: OSV được hỏi về 1.480 package trong `package-lock.json`.

### Những gì không công cụ nào bắt được

- Juice Shop: 16 dòng lỗi logic, phân quyền, cấu hình (route admin lộ, allowlist redirect dùng `includes`, rate limit tin `X-Forwarded-For`, prompt injection chatbot…).
- NodeGoat: chính sách mật khẩu yếu (`session.js:144`), mật khẩu lưu plain text (`user-dao.js:25`, phép gán chứ không phải phép so sánh).
- DVNA: API trả mọi bản ghi user (`appHandler.js:207`), route admin không kiểm quyền (`routes/app.js:42`).
- DVWS-Node: XXE trong bộ mở rộng entity tự viết (`vulnerable-xml.js:81`, không dùng parser XML nào), SSRF qua tham số của method XML-RPC (`xml-rpc/server.js:29`, thư viện `xmlrpc` không phải nguồn đã khai).
- vulnerable-node: NoSQL injection trong một hàm nhận filter làm tham số, không có nguồn request nào trong file.

SAST cú pháp không với tới lỗi logic và phân quyền; rule `llm` (`larpcop review`) nhắm vào loại này nhưng không được tính vì không tất định.

### Phạm vi khác nhau

- Cả hai có rule GitHub Actions và Terraform. larpcop trước đây bỏ qua thư mục ẩn khi quét toàn repo, nên không thấy `.github/workflows`; benchmark lộ ra lỗi này và đã sửa.
- Semgrep báo lỗi cú pháp và bỏ qua các file snippet trong `data/static/codefixes/` của Juice Shop. tree-sitter chịu lỗi nên larpcop vẫn đọc được, vì vậy có thêm finding ở đó.
- `[innerHTML]` của Angular không bị tính là XSS: Angular tự sanitize binding này; lỗ hổng thật nằm ở `bypassSecurityTrust*`.
- Filter của Sequelize (`where:`, `include:`) không bị tính là NoSQL injection: Sequelize không nhận operator từ JSON.

**Secrets**: larpcop nhúng nguyên bộ rule của gitleaks và giải mã base64/JWT như gitleaks, nên kết quả trùng khớp hoàn toàn. Các lần chạy trước lộ ra 3 bug đã sửa: công thức entropy, gộp finding `generic-*` nằm trong finding cụ thể hơn, và secret nằm trong payload JWT.

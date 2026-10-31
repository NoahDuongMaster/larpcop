<p align="center"><img src="assets/jimothy.svg" width="180" alt="Jimothy, linh vật của larpcop: chú gấu mèo tròn đội mũ cảnh sát"></p>

# larpcop

> *larp* (slang 2026): làm màu, giả vờ. Agent hay báo "đã tuân thủ rule, đã chạy test" khi chưa hề làm; larpcop là cổng kiểm tra không tin lời báo cáo. Linh vật là **Jimothy**, chú gấu mèo tròn vo ở Seattle nổi tiếng tháng 7/2026, ở đây được vẽ lại và đội mũ cảnh sát ([`assets/jimothy.svg`](assets/jimothy.svg)).

Ép mọi coding agent (Claude Code, Codex, Gemini CLI, Cursor…) và cả người tuân theo cùng một bộ rule, trên mọi stack.
Một binary Rust duy nhất, rule engine là [ast-grep](https://ast-grep.github.io) (tree-sitter, 25+ ngôn ngữ).

## Mô hình thực thi

Prompt chỉ *gợi ý*. Chỉ có cổng kiểm tra tất định mới *ép* được, nên larpcop chặn ở những điểm mà mọi agent bắt buộc phải đi qua:

| Tầng | Cơ chế | Agent nào cũng phải qua? | Bypass được? |
|---|---|---|---|
| CI ([`enforce.yml`](.github/workflows/enforce.yml) + org ruleset) | `larpcop check --since origin/<base>` | ✅ | ❌ |
| Git pre-commit (`larpcop install`) | `larpcop check --staged` (kiểm nội dung staged, không phải working tree) | ✅ | `--no-verify` → CI bắt lại |
| Hook của agent (`larpcop hook <agent>`) | Chặn bypass, phản hồi lỗi ngay sau mỗi lần sửa file, chặn kết thúc khi còn lỗi | Agent có hook | — |
| `AGENTS.md` (`larpcop sync`) | Hướng dẫn + bảng rule sinh tự động | Mọi agent đều đọc | Chỉ là gợi ý |

Hook của agent chỉ để rút ngắn vòng phản hồi. Agent không có hook vẫn bị chặn ở git và CI.

## Cài đặt

Mỗi release có binary cho macOS (arm64, x64), Linux (arm64, x64) và Windows (x64), dạng nén khoảng 4 MB. Có installer shell, PowerShell, công thức Homebrew và package npm `larpcop`. Binary được cài vào `~/.local/bin`.

Repo hiện **private**, nên dùng GitHub CLI (`gh`, cần đăng nhập và có quyền đọc repo) để tải installer cùng các bản build về một thư mục, rồi trỏ installer vào thư mục đó. Lệnh sau đã chạy thật trên macOS:

```sh
d=$(mktemp -d)
gh release download --repo NoahDuongMaster/larpcop --dir "$d" \
  --pattern 'larpcop-installer.sh' --pattern '*.tar.xz' --pattern '*.tar.xz.sha256'
LARPCOP_DOWNLOAD_URL="file://$d" sh "$d/larpcop-installer.sh"
```

Trên Windows: `gh release download --repo NoahDuongMaster/larpcop --pattern '*windows-msvc.zip'`, giải nén rồi đặt `larpcop.exe` vào một thư mục có trong PATH.

`LARPCOP_GITHUB_TOKEN` của installer **không** dùng được cho repo private, vì GitHub không cho tải asset private qua URL `releases/download` (đã thử). Khi repo chuyển sang public thì chỉ cần:

```sh
curl -LsSf https://github.com/NoahDuongMaster/larpcop/releases/latest/download/larpcop-installer.sh | sh
```

## Cấu hình

Standards của công ty (một repo riêng, gắn tag phiên bản), ví dụ [examples/standards](examples/standards):

```yaml
# larpcop.yaml
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
# .larpcop.yaml
extends:
  - https://github.com/<org>/standards.git#v1.0.0   # hoặc đường dẫn local
rule_dirs: [team-rules]
disable: [py-no-print]          # chỉ được disable rule không bị lock
```

Thứ tự áp dụng: `--extends` / `LARPCOP_EXTENDS` (CI ép vào) → chuỗi `extends` → `.larpcop.yaml`. Vì CI luôn truyền `--extends`, xoá config trong repo cũng không thoát được standards. Cùng một URL standards chỉ áp dụng một lần, và phiên bản CI pin sẽ thắng.

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

**`dependency-approval`**: dependency trực tiếp mới phải nằm trong `approved`. "Mới" nghĩa là chưa có trong bất kỳ manifest nào ở commit gốc, nên thêm `react` vào một package mới trong monorepo đã dùng `react` thì không tính. Agent không sửa được `.larpcop.yaml`, nên một dòng `approved` là một lần người duyệt và hiện rõ khi review. Đọc được `package.json`, `Cargo.toml`, `pyproject.toml` (PEP 621, dependency-groups, Poetry), `requirements*.txt`, `go.mod`, `Gemfile`, `composer.json`, `*.csproj`/`*.fsproj`, `pom.xml`, `build.gradle(.kts)` và `gradle/libs.versions.toml`.

**`dependency-release-age`** chạy ở ba chỗ:

1. **Lockfile** (pre-commit, CI, hook kết thúc lượt): mọi phiên bản, kể cả dependency bắc cầu, mà thay đổi này thêm vào hoặc đổi sang phải đủ `N` ngày tuổi. Ngày phát hành lấy từ [deps.dev](https://deps.dev), một API chung cho npm, PyPI, crates.io, Go, RubyGems, NuGet và Maven (Composer thì lấy từ API của Packagist), và được cache trên đĩa vì ngày phát hành không bao giờ đổi. Chỉ phiên bản *mới trong thay đổi* mới được tra, nên PR thường chỉ mất vài request. Lockfile đọc được: `package-lock.json` (v2/v3), `pnpm-lock.yaml` (v5–v9), `yarn.lock` (v1 và Berry), `bun.lock`, `Cargo.lock`, `uv.lock`, `poetry.lock`, `go.mod`, `Gemfile.lock`, `packages.lock.json` (NuGet), `gradle.lockfile`, `composer.lock`, cùng các phiên bản pin cứng trong `pom.xml` và `*.csproj`. Khi chặn, thông báo đưa luôn một phiên bản cụ thể để pin, ví dụ: *"Use typescript@7.0.2 (published 2026-07-08)"*.
2. **Package manager**: npm, pnpm, yarn Berry và bun tự chặn được bản quá mới ngay lúc cài, trên máy dev, *trước khi* install script chạy. Lockfile chỉ thấy được sau khi đã cài, nên repo bắt buộc phải bật tính năng này:

   | Package manager | File | Thiết lập cho 14 ngày |
   |---|---|---|
   | npm | `.npmrc` | `min-release-age=14` |
   | pnpm | `pnpm-workspace.yaml` | `minimumReleaseAge: 20160` |
   | yarn ≥ Berry | `.yarnrc.yml` | `npmMinimalAgeGate: "14d"` |
   | bun | `bunfig.toml` | `[install] minimumReleaseAge = 1209600` |
   | uv ≥ 0.9 | `pyproject.toml` (`[tool.uv]`) hoặc `uv.toml` | `exclude-newer = "14 days"` |

   Đã chạy thật: npm 11.19 với `min-release-age=14`, khi được yêu cầu `typescript@next` thì tự chọn `7.0.2`. pnpm 11.2 chọn bản dev `20261017`, đúng 14 ngày tuổi. `pip install` phải kèm `--uploaded-prior-to`.
3. **Hook của agent**:
   - Chặn lệnh *nới* gate (`--min-release-age=0`, `npm config set min-release-age …`, `npm_config_min_release_age=…`, `uv … --exclude-newer "1 day"`, `UV_EXCLUDE_NEWER=…`). Giá trị được đọc thật, nên thiết lập *chặt hơn* (`--exclude-newer "30 days"`) vẫn qua.
   - Package manager không có gate gốc (Cargo, Go, Poetry, Bundler, RubyGems, Composer, NuGet, Yarn 1, nhận ra vì không có `.yarnrc.yml`) và tool runner chạy package ngay (`npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx`, `pipx run`, `cargo install`): hook hỏi registry xem lệnh sẽ tải **phiên bản nào** và chặn nếu chưa đủ tuổi, trước khi lệnh chạy. Chỗ nào cài xong là chạy code dependency ngay (`bundle install`, `poetry update`) thì bắt buộc dạng chỉ resolve (`bundle lock`, `poetry lock`) để lockfile qua kiểm trước.
   - Khi lockfile đang chứa phiên bản không qua kiểm, mọi lệnh có thể chạy code dự án hay dependency bị chặn (`npm test`, `make`, `node script.js`…), mặc định là chặn; chỉ các lệnh chỉ đọc/di chuyển file (`git`, `ls`, `cat`, `grep`, `sed`, `cp`…) được chạy để sửa lockfile.

Phiên bản không có trên deps.dev hoặc không tra được vì lỗi mạng đều bị chặn (fail closed). **Ngoại lệ là bản vá bảo mật**: một bản quá mới vẫn được cho qua, ở mức warning, nếu bản đủ tuổi mới nhất cùng dòng có advisory còn bản mới thì không, theo trường `advisoryKeys` của deps.dev. Không có ngoại lệ này thì rule sẽ ép hạ về bản có lỗ hổng: chính repo larpcop gặp trường hợp này với `rustls-webpki` 0.103.16 và `webpki-roots` 1.0.11, vì bản đủ tuổi trước đó dính RUSTSEC-2026-0382 và RUSTSEC-2026-0381.

Cả hai rule được lock trong standards mẫu. Một rule đã lock chỉ được *siết thêm*: tăng số ngày hoặc thêm `approved` thì được; giảm số ngày, tắt `require_approval` hoặc thêm `exempt` thì bị từ chối.

## Bảo mật (thay Semgrep/Snyk)

Bốn lớp, xếp theo mức chắc chắn. Lớp đầu tất định 100%, các lớp sau bắt phần còn lại.

**1. Quy ước cú pháp (bộ `recommended`).** Không đi truy vết lỗi mà cấm luôn cách viết dẫn tới lỗi: SQL chỉ qua tham số, lệnh shell chỉ qua mảng tham số, dữ liệu request chỉ được dùng sau khi qua schema (`validate-request-input`: `req.body`, `req.query`, `req.params`, `request.json()` phải nằm trong `X.parse(…)`/`safeParse`/`validate`…). Khi đó lỗi không viết ra được ngay từ đầu, và ast-grep bắt đúng 100%, cùng một kết quả ở mọi lần chạy.

**2. Taint xuyên hàm và xuyên file.** Theo dữ liệu từ `sources` tới đối số của `sinks` qua các phép gán theo thứ tự dòng code; đi qua `sanitizers` thì sạch, gán lại giá trị sạch thì hết taint, destructuring cũng được theo. Mỗi hàm có một *summary* (tham số nào tới sink, tham số nào được trả về, hàm có trả về dữ liệu nguồn không), nên dữ liệu được theo qua lời gọi hàm trong cùng file, qua `import`/`require`/alias của tsconfig, `from … import` của Python và các package trong cùng module Go; callback và closure thấy các biến bẩn mà chúng bắt được; method được biết dưới tên `Class.method` (cả khi class được import), và `obj.method(…)` với `obj` chưa rõ kiểu dùng method duy nhất mang tên đó; field mà một method gán dữ liệu bẩn (`this.term = req.query.q`, `self.term = …`) là bẩn trong mọi method khác của class đó. Pattern viết bằng cú pháp ast-grep:

```yaml
taint:
  - id: taint-sql
    languages: [TypeScript, Tsx, JavaScript]
    message: Request data reaches a SQL query.
    sources: ["req.query", "req.body", "req.params"]
    sinks: ["$DB.query($SQL)", "$DB.query($SQL, $$$REST)"]
    sink_arg: SQL                 # chỉ đối số này phải sạch
    sanitizers: ["Number($X)", "$S.parse($X)"]
    guards: ["$U.startsWith($P)", "$L.includes($U)"]   # if (!ok(x)) return …; → x sạch phía sau
    safe_prefix: '^/[^/\\]'                          # "/products/" + id: phần đầu cố định là an toàn
    param_decorators: [Body, Query]                   # NestJS: @Body() dto là dữ liệu request
    handler_decorators: '^\w+\.(get|post|route)\('     # Python: mọi tham số của hàm route
    resolver_args: true                               # GraphQL: (parent, args) => …
```

`guards` là phép kiểm trong điều kiện `if`: sau một nhánh `return`/`throw`, hoặc bên trong nhánh chạy khi phép kiểm đúng, biến được kiểm là sạch. `safe_prefix` là regex trên phần chuỗi cố định ở đầu đối số được ghép (`res.redirect("/p/" + id)` không thể dẫn ra ngoài site); nó cũng quyết định một guard `x.startsWith("…")` có đáng tin không. `exclude` là glob của file rule không báo (bộ `recommended` bỏ file test: `res.end('poking ' + req.params.user)` trong test của Express không phải lỗ hổng); hàm trong các file đó vẫn được dùng khi file khác gọi tới.

Bộ `recommended` có sẵn 30 rule taint: SQL, shell, open redirect, code injection (`eval`, `vm`, `mathjs.eval`), XSS phản chiếu (`res.send` của chuỗi HTML, `innerHTML`), path traversal, SSRF, NoSQL injection (MongoDB/Mongoose; filter của Sequelize thì không), regex injection, log injection cho JS/TS; SQL, path traversal, SSRF, SSTI (`render_template_string`), code injection/deserialization, log injection cho Python (nguồn của Flask, Django, FastAPI/Starlette, aiohttp, Tornado); SQL, shell, path traversal, SSRF, open redirect, XSS (`template.HTML`, ghi thẳng vào `ResponseWriter`) cho Go (net/http, gin, echo, chi, gorilla/mux); SQL (JDBC, JdbcTemplate, JPA), lệnh OS, path traversal, XSS, LDAP, XPath, open redirect, trust boundary cho Java (Servlet, Spring với `@RequestParam`/`@PathVariable`/`@RequestBody`…). Phép gán chỉ chạy trên một số đường (trong `if`, vòng lặp, `try`) có thể làm bẩn nhưng không làm sạch biến: `if (p == null) p = "";` không xoá taint của `p`. Dữ liệu request không qua `req.query` cũng được tính: tham số có decorator của NestJS (`@Body()`, `@Query()`; trừ khi qua `ParseIntPipe`…) tham số của hàm route khai bằng decorator (FastAPI, Flask; trừ `int`/`UUID`… mà framework đã kiểm, và `Depends(...)`), và đối số của resolver GraphQL (`(parent, args) => …`, `def resolve_x(root, info, id)`). Sink được khai theo tên đối tượng (`cp.exec`, `res.send`, `session.get`), vì `$X.exec` cũng khớp `RegExp.prototype.exec` và `$X.get` khớp `dict.get`. Lớp 1 bắt ``db.query(`…${id}`)`` ngay tại chỗ gọi; lớp 2 bắt trường hợp lớp 1 không thấy, khi chuỗi SQL được dựng ở biến hoặc ở hàm khác:

```ts
const name = req.query.name as string;
const sql = "SELECT * FROM users WHERE name = '" + name + "'";
res.json(await db.query(sql));          // taint-sql
```

**Kiểu** thì hỏi language server của chính dự án (typescript-language-server, pyright, gopls, rust-analyzer) thay vì tự viết type checker. `sink_types` yêu cầu metavariable của sink phải có kiểu khớp regex:

```yaml
    sinks: ["$DB.query($SQL)"]
    sink_arg: SQL
    sink_types: { DB: "\\bPool\\b" }   # pool.query(sql) bị bắt; searchIndex.query(text) thì không
```

Chỉ hỏi server về các ứng viên mà lớp cú pháp đã tìm thấy, mỗi vị trí một lần, nên chỉ trả giá khi có ứng viên (chạy thử: 1,9 s với tsserver, 0,5 s với pyright, 0,7 s với gopls, 6 s với rust-analyzer vì phải nạp workspace; larpcop chờ rust-analyzer báo xong qua `experimental/serverStatus`). Server không có, không khởi động được, hoặc không trả lời thì finding vẫn giữ nguyên, tức là fail closed. Lệnh chạy server đổi được bằng `language_servers: { typescript: [...] }`; `LARPCOP_DEBUG_TYPES=1` in ra câu trả lời của server. Test chạy với cả bốn server thật, cả trong CI.

**Template và file không có grammar.** Rule `text:` là regex trên file theo glob (template, HTML, config):

```yaml
text:
  - id: no-unescaped-template-output
    files: ["**/*.ejs", "**/*.hbs", "**/*.njk", "**/*.html", "**/*.vue"]
    regex: '<%-[^%]*%>|\{\{\{|\|\s*safe\b|\bv-html\s*='
    not: '^<%-\s*include\b'          # match nào khớp `not` thì bỏ qua
    message: Template output written without HTML escaping (XSS).
```

Bộ `recommended` có 4 rule loại này: output không escape (EJS `<%-`, Handlebars `{{{`, Jinja/Nunjucks `|safe` và `autoescape false`, Blade `{!!`, ERB `raw`/`html_safe`, Svelte `{@html}`, Vue `v-html`, Razor `Html.Raw`), Pug `!=`/`!{}`, `innerHTML`/`document.write` trong script của template, và secret thật trong file `.env` được commit (giá trị mẫu như `changeme`, `${VAR}` thì bỏ qua).

**3. Secrets.** `secrets: {}` bật 222 detector của [gitleaks](https://github.com/gitleaks/gitleaks) (MIT, nhúng nguyên `gitleaks.toml` vào binary, kèm license trong `assets/`): lọc theo keyword, regex, entropy, allowlist theo đúng ngữ nghĩa của gitleaks. Kết quả in ra đã che, chỉ giữ 4 ký tự đầu (`ghp_…[redacted]`). `exclude` để bỏ qua fixture có khoá giả; rule bị lock thì không thêm `exclude` được. Hook cũng chặn agent ghi secret vào file.

**4. Lỗ hổng và mã độc trong dependency** (`dependency-vulnerability`, dữ liệu [OSV.dev](https://osv.dev): GitHub Advisory, RustSec, PyPA, Go, và nguồn mã độc của OpenSSF):

```yaml
dependencies:
  vulnerabilities: high     # low | moderate | high | critical
```

- Package bị báo là **mã độc** (`MAL-…`) luôn bị chặn, ở mọi lockfile và trong mọi PR, kể cả PR không đụng tới lockfile: mã độc thường được phát hiện sau khi đã vào repo.
- Lỗ hổng từ mức đã chọn trở lên chặn phiên bản *mà thay đổi này đưa vào*. `larpcop check` không giới hạn phạm vi thì kiểm toàn bộ. Thông báo nêu luôn phiên bản đã vá.
- Hook chặn lệnh cài **trước khi chạy**: tên package dính mã độc (`npm i aaa-evil`), hoặc phiên bản pin dính lỗ hổng (`npm i lodash@4.17.15`). Không gọi được OSV thì lệnh cài cũng bị chặn (fail closed), giống phần lockfile.
- Mức nghiêm trọng lấy theo đánh giá của advisory, nếu không có thì tính từ vector CVSS 3/4 (crate `cvss`).

Đã chạy với dữ liệu thật (lockfile gồm `lodash@4.17.15`, `local-commander-agent@0.3.52`, `zod@3.23.8`):

- `local-commander-agent` (MAL-2026-18425, được báo cáo trong ngày) bị chặn, kể cả khi chạy `--changed` mà thay đổi không đụng tới lockfile.
- `lodash@4.17.15`: 3 advisory mức High (command injection, prototype pollution, code injection qua `_.template`), mỗi cái kèm bản vá (`4.17.19`, `4.17.21`, `4.18.0`).
- `zod@3.23.8`: 1 advisory High (GHSA-mrhx-c7xc-m3w5).
- Hook chặn `npm i local-commander-agent`, `npm i lodash@4.17.15` và `npm i zod@3.23.8`; cho qua `npm i lodash` (không pin, npm cài bản mới nhất).

## AI review và học rule (thay CodeRabbit/Bugbot, Packmind)

Model là CLI mà team đang dùng (`claude -p`, `codex exec -`, `gemini`, `ollama run …`). larpcop gửi prompt qua stdin và đọc stdout, nên không giữ API key và không phụ thuộc SDK của hãng nào. Không khai `llm.command` thì tự dùng `claude -p`, nếu không có thì `codex exec -`. Có thể đổi bằng biến `LARPCOP_LLM`.

```yaml
llm:
  command: claude -p --model sonnet     # chuỗi: chạy qua sh; mảng: chạy thẳng
  rules:
    - id: thin-controllers
      files: ["src/controllers/**"]
      prompt: Controllers only parse the request, call one service function and map the result. They never touch the database directly.
```

**`larpcop review [--staged | --changed | --since REF]`** chấm các rule `llm`, mỗi file một lần gọi (chạy song song 4 file), chỉ gửi những file mà rule áp dụng. Trên một diff, các dòng đã đổi được đánh dấu và chỉ những dòng đó được báo. Kết quả **luôn là warning**: model không tất định, còn cổng chặn thì phải tất định. Câu trả lời được cache theo nội dung prompt, nên chạy lại trên code không đổi sẽ ra cùng kết quả và không tốn tiền (`--no-cache` để hỏi lại). Có đủ các format như `check` (`--format markdown` cho comment PR, `sarif`…).

**`larpcop learn "<chuẩn viết bằng lời>"`** hoặc **`larpcop learn --reviews 50`** (lấy từ review comment của các PR gần đây, qua `gh`) biến chuẩn thành rule ast-grep tất định. Model chỉ đề xuất; một rule được giữ lại khi parse được và pass các ví dụ valid/invalid do chính model viết. Rule fail được gửi lại cho model kèm lỗi chính xác (mặc định 3 vòng). Rule đạt được ghi vào `.larpcop/rules/` cùng fixture trong `.larpcop/rule-tests/`, kèm số chỗ trong repo đang vi phạm để quyết định sửa hay baseline. Đây là cách chuyển dần các rule "mềm" của AI review thành rule cứng.

Đã chạy thật với `claude -p --model sonnet` trên một repo Express demo:

- `review --changed`: một hàm controller mới gọi `db.user.findUnique` bị báo đúng dòng 9, kèm gợi ý chuyển sang service (8,6 giây).
- `learn "Never import moment; use date-fns. No default exports, only named exports. Never await inside a loop; collect the promises and use Promise.all."` cho ra 3 rule đều pass ngay vòng đầu (22 giây). Có 7–8 ví dụ mỗi rule, gồm cả trường hợp gần giống mà phải hợp lệ: `await` trong arrow function nằm trong vòng lặp thì không bị tính. Gắn 3 rule vào repo thì `larpcop check` bắt đúng 3 chỗ vi phạm có sẵn.

## Dashboard và benchmark

**`larpcop dashboard [--org OWNER] [--out FILE] [--json]`** tạo một file HTML duy nhất, không có script và không tải tài nguyên ngoài, nên có thể đính vào artifact của CI, đưa lên GitHub Pages hoặc mở thẳng từ đĩa. Trang gồm:

- số vi phạm còn mở và số đã baseline theo từng rule;
- nợ baseline theo thời gian, tính từ lịch sử git của `.larpcop-baseline.json`;
- các hàm phức tạp nhất;
- với `--org`: repo nào có config, repo nào đã chạy cổng CI, và lần chạy gần nhất.

`--json` xuất cùng dữ liệu đó cho dashboard khác dùng.

**Benchmark công khai**: [`bench/`](bench) (chạy lại bằng `bench/run.sh`), trên tám bộ cố ý có lỗ hổng, mỗi bộ có đáp án từ chính dự án đó:

| | larpcop | Semgrep OSS (`p/default`) | gitleaks |
|---|---|---|---|
| Juice Shop: thời gian (gitleaks chỉ quét secrets) | 6,63 s | 33,75 s | 4,76 s |
| Juice Shop: dòng lỗ hổng tìm thấy | **11/27** | 6/27 | – |
| NodeGoat: dòng tìm thấy | **12/14** | 4/14 | – |
| DVNA: dòng tìm thấy | **12/14** | 7/14 | – |
| DVPWA (Python): dòng tìm thấy | **4/4** | 2/4 | – |
| DVWS-Node (REST, GraphQL, SOAP): dòng tìm thấy | **13/15** | 7/15 | – |
| GoVWA (Go): dòng tìm thấy | 4/4 | 4/4 | – |
| OWASP Benchmark Java (2.740 ca, điểm TPR − FPR): thời gian / điểm | **7,1 s / +44,0%** | 48,6 s / +34,9% | – |
| vulnerable-node `sast/seeds` (chấm bằng script của dự án) | **11/12**, 1 báo nhầm (0 nếu bỏ rule chung chung) | 10/12, 1 báo nhầm (8/12 nếu bỏ rule chung chung) | – |
| Secrets | trùng khớp hoàn toàn với gitleaks | – | 69 + 3 |

Mỗi bộ từng là bộ kiểm chứng ở lần chạy đầu, rồi được dùng để thêm rule: NodeGoat lần đầu 8/14, DVNA 5/14 (Semgrep 7/14), vulnerable-node 10/12 với 1 báo nhầm, DVPWA 1/4 (Semgrep 2/4), DVWS-Node 10/15 (Semgrep 7/15), GoVWA 0/4 (Semgrep 4/4), OWASP Benchmark Java +37,5% (Semgrep +34,9%). Thứ tự đó và từng dòng bị bỏ sót nằm trong [bench/README.md](bench/README.md).

## Lệnh

```sh
larpcop check [paths…] [--staged | --changed | --since REF] [--format text|json|github|sarif|gitlab|markdown] [--output FORMAT=FILE]
larpcop fix [paths…] [--changed | --since REF] [--dry-run]   # áp `fix:` của rule rồi check lại
larpcop baseline [--prune]    # ghi nhận vi phạm cũ; --prune chỉ xoá entry đã sửa
larpcop test [STANDARDS_DIR] [--require-all]  # chạy fixture trong rule-tests/ (valid, invalid, fixed)
larpcop metrics [paths…] [--top N] [--json]    # độ phức tạp, kích thước hàm
larpcop review [--changed | --since REF]       # rule `llm`, chấm bằng model (warning)
larpcop learn "<chuẩn>" | --reviews N          # sinh rule ast-grep + test từ lời / review comment
larpcop dashboard [--org OWNER] [--json]       # trang HTML: vi phạm, nợ baseline, hotspot, repo có gate
larpcop lsp | larpcop mcp    # language server / MCP server (stdio)
larpcop org status|setup …    # trạng thái và triển khai trên GitHub
larpcop rules                 # rule hiệu lực, nguồn, rule nào bị lock
larpcop sync [--check]        # AGENTS.md + file hook cho mọi agent (xem bảng dưới)
larpcop install [--force]     # git pre-commit hook (tôn trọng core.hooksPath, monorepo)
larpcop hook <claude-code|codex|gemini|cursor>   # entrypoint cho hook của agent (đọc stdin)
```

Exit code: `0` sạch, `1` có vi phạm mức error, `3` lỗi nội bộ/config. Không dùng `2`, vì giao thức hook của agent dành nó cho nghĩa "chặn và báo cho model". Nhờ vậy config hỏng không bao giờ chặn agent.

### Baseline

Để áp rule mới lên codebase cũ mà không phải sửa hết ngay: người chạy `larpcop baseline`, commit `.larpcop-baseline.json`. `check` ẩn đúng các vi phạm đã ghi nhận và vẫn báo mọi vi phạm mới.

- Entry khớp theo rule, file và **nội dung dòng**, không theo số dòng: sửa chỗ khác trong file không làm vi phạm cũ hiện lại, còn viết thêm một vi phạm giống hệt thì vẫn bị bắt (đếm theo số lần).
- Agent không chạy được `larpcop baseline` và không sửa được file baseline (hook chặn). `larpcop baseline --prune` thì được, vì nó chỉ xoá entry đã sửa.
- Với rule bị lock, baseline của repo không được phình ra: ở `--changed`/`--staged`/`--since`, số entry của rule lock tăng so với base là lỗi. Lần ghi nhận đầu tiên (rule chưa có entry nào) vẫn được phép, để org triển khai rule mới.

### Fix và test rule

Rule ast-grep có `fix:` thì vi phạm kèm gợi ý `larpcop fix <file>`. Fix lặp tối đa 5 lượt, bỏ qua các sửa đè lên nhau trong cùng lượt.

`larpcop test` đọc fixture theo định dạng của ast-grep (`rule-tests/<id>-test.yml` với `valid`/`invalid`), thêm `fixed: [{before, after}]` để kiểm `fix:`. Rule taint và rule `text:` dùng cùng định dạng: mỗi đoạn được kiểm như một file của từng ngôn ngữ của rule (rule `text:` thì khai `file: views/page.ejs`). `--require-all` làm CI fail khi có rule, của bất kỳ loại nào, chưa có fixture.

### Guard đọc lệnh shell bằng parser

Hook phân tích lệnh bằng tree-sitter-bash: quote, pipe, `&&`/`;`/`&`, redirect, `bash -c '…'`, `eval`, `sudo`/`env` đều được giải theo cấu trúc. Nhờ vậy `bash -c 'rm .larpcop.yaml'`, `--no-ver""ify`, `git push --no-veri`, `sudo env SKIP=all git commit` bị chặn, còn `cp .larpcop.yaml /tmp/bak`, `git config --get core.hooksPath` hay `echo 'never rm .larpcop.yaml' > notes.txt` thì không.

## Bộ rule chính thức `recommended`

[`standards/recommended`](standards/recommended) là bộ rule do larpcop duy trì, version theo tag của repo:

```yaml
extends:
  - https://github.com/NoahDuongMaster/larpcop.git#v0.3.0//standards/recommended
```

(`URL#tag//thư-mục` lấy một thư mục con của repo standards.) Bộ này có 59 rule ast-grep, 30 rule taint, 4 rule `text:`, cùng secrets và `dependency-vulnerability`. Rule bảo mật và metric độ dài/độ phức tạp không áp lên file test (`test/`, `tests/`, `*.spec.*`, `test_*.py`, `tests.py`…); rule chất lượng (`no-explicit-any`, `no-console`, `no-empty-catch`…) thì vẫn áp: chạy thử trên repo `expressjs/express`, test của Express chiếm 96/129 finding `validate-request-input` và 118/120 finding `function-length`. File minified (dòng trung bình trên 300 byte, như `prism.js` hay `jquery-3.2.1-min.js` được commit vào repo) chỉ được quét secrets, vì secret có thể nằm trong bundle; method Go được biết theo kiểu receiver (`Profile.Load`), method Rust theo kiểu của `impl`. Mọi rule kèm fixture, và `larpcop test standards/recommended --require-all` chạy trong `cargo test`:

- **Biến lỗi bảo mật thành quy ước cú pháp** (không cần taint): SQL chỉ qua tham số (`no-sql-interpolation`, `py-no-sql-interpolation`, `go-no-sql-sprintf`; chuỗi có dạng câu SQL mà được ghép hay format ở bất kỳ đâu cũng bị bắt, không chỉ trong lời gọi `query`), lệnh shell chỉ qua mảng tham số (`no-shell-interpolation`, `py-no-shell-true`), không `eval`/`new Function`/`exec`, không gán HTML từ biến vào `innerHTML`, không `dangerouslySetInnerHTML` hay `bypassSecurityTrust*` (Angular), không `serve-index`, không MD5/SHA-1, không `$where` của MongoDB, input của request phải qua schema (`validate-request-input`), không tắt kiểm chứng chỉ TLS (`py-no-tls-verify-off`, `go-no-insecure-tls`), `yaml.safe_load` (có auto-fix), regex có lượng từ lồng nhau (ReDoS), tắt autoescape của template, so sánh mật khẩu dạng plain text, secret của session/JWT viết cứng, XML bật external entity (XXE), thư viện deserialize chạy được code (`node-serialize`, `pickle`), hàm merge đệ quy không chặn `__proto__` (prototype pollution), ghi user vào session phía server mà không cấp session id mới (session fixation: `req.session.regenerate`, `new_session` của aiohttp).
- **Không tắt kiểm tra**: `@ts-ignore`, `@ts-expect-error`, `eslint-disable`, `biome-ignore` là vi phạm; `any`, catch rỗng, `debugger` (có auto-fix).
- **Kích thước và độ phức tạp**: hàm tối đa 80 dòng, độ phức tạp vòng (McCabe) tối đa 15, file tối đa 500 dòng.

Rule cho JavaScript/TypeScript được sinh cho cả TypeScript, Tsx và JavaScript dưới **cùng một id** (`scripts/gen-recommended.py`), nên `disable`/`locked` một id là áp cho cả ba.

## Chất lượng code (thay Sonar/Codacy)

- **Metric** — `larpcop metrics [--top N] [--json]`: số dòng, số hàm, độ phức tạp vòng của từng hàm (đếm trên cây tree-sitter, mọi ngôn ngữ ast-grep đọc được; hàm lồng nhau tính riêng). Trên chính repo này: 60 file, 813 hàm, trung bình 1,91. Ép bằng config:
  ```yaml
  metrics:
    max_complexity: 15        # rule `complexity`
    max_function_lines: 80    # rule `function-length`
  ```
- **Báo cáo cho CI** — `--format sarif|gitlab|markdown`, hoặc ghi nhiều định dạng cùng lúc bằng `--output FORMAT=FILE`. SARIF đã kiểm với schema SARIF 2.1.0 chính thức (0 lỗi); có `partialFingerprints` ổn định khi code dịch dòng. GitLab Code Quality có fingerprint riêng cho từng issue.
- **Comment PR** — workflow `enforce.yml` ghi `larpcop-report.md` và giữ **một** comment trên PR, sửa lại sau mỗi lần push (`comment: true`, mặc định). `sarif: true` đẩy kết quả lên GitHub code scanning.
- **LSP** — `larpcop lsp`: diagnostic ngay khi gõ (kể cả buffer chưa lưu), và code action "apply rule fixes". Đã chạy trong Neovim 0.12 thật: hiện đúng `no-sql-interpolation` và `no-debugger`, có code action. Lần chạy đó lộ bug: request sai định dạng làm server thoát; nay trả lỗi `InvalidParams` và chạy tiếp (có test hồi quy).

## Adapter agent

`larpcop sync` sinh ra tất cả các file dưới đây. Mọi adapter dùng chung một lõi quyết định; mỗi agent chỉ khác ở cách parse payload và cách trả lời.

Mặc định sinh cho mọi agent; `agents: [claude-code, kiro]` trong `.larpcop.yaml` giới hạn lại. `sync` cũng đăng ký MCP server `larpcop mcp` cho Claude Code (`.mcp.json`), Cursor (`.cursor/mcp.json`), Kiro (`.kiro/settings/mcp.json`) và Gemini (`mcpServers`).

| Agent | File sinh ra | Đọc rule từ | Trước khi chạy tool | Sau khi sửa file | Khi kết thúc lượt |
|---|---|---|---|---|---|
| Claude Code | `.claude/settings.json`, `CLAUDE.md` (`@AGENTS.md`) | AGENTS.md (import) | `PreToolUse` Bash/Edit/Write | `PostToolUse` | `Stop` |
| Codex | `.codex/hooks.json` | AGENTS.md (native) | `PreToolUse` Bash/`apply_patch` | `PostToolUse` `apply_patch` (path lấy từ header của patch) | `Stop` |
| Gemini CLI | `.gemini/settings.json` (thêm `context.fileName: AGENTS.md`) | AGENTS.md | `BeforeTool` `run_shell_command`/`write_file`/`replace` | `AfterTool` | `AfterAgent` |
| Cursor | `.cursor/hooks.json` (JSON native, `loop_limit: 1`) | AGENTS.md (native) | `preToolUse` Shell/Write/Delete | `postToolUse` → `additional_context` | `stop` → `followup_message` |
| Copilot CLI | `.github/hooks/larpcop.json` (event PascalCase → payload kiểu Claude) | AGENTS.md (native) | `PreToolUse` → `permissionDecision: deny` | `PostToolUse` → `additionalContext` | `Stop` → `decision: block` |
| Factory Droid | `.factory/hooks.json` | AGENTS.md (native) | `PreToolUse` Execute/Create/Edit/ApplyPatch | `PostToolUse` | `Stop` |
| Kiro (CLI V3, IDE 1.0) | `.kiro/hooks/larpcop.json` | AGENTS.md | `PreToolUse` `shell` + **nội dung sắp ghi** của `write` | (Kiro không đưa output PostToolUse cho model) | `Stop` → `decision: block` |

Các hook làm những việc sau:

- **Trước tool** chặn: `--no-verify`, `git commit -n`, `core.hooksPath`, `HUSKY=0`, `LEFTHOOK=0`, `SKIP=`; ghi vào `.git/hooks`, `.larpcop.yaml`, file rule, hoặc file hook của bất kỳ agent nào. Lệnh cài package chưa được duyệt (`npm i`, `pnpm add`, `yarn add`, `bun add`, `pip install`, `uv add`, `poetry add`, `cargo add`, `go get`) bị chặn trước khi chạy, tức là trước khi install script của package kịp chạy. Xem [Dependency](#dependency).
- **Sau khi sửa** kiểm đúng các file vừa sửa và trả lỗi về cho model.
- **Kết thúc lượt** kiểm mọi thay đổi chưa commit và chặn **một lần**. Nếu agent vẫn dừng (ví dụ để hỏi người khi lệnh của user mâu thuẫn với rule) thì cho dừng; code vi phạm vẫn không commit hay merge được. Chặn lần hai trở đi chỉ gây loop: khi chạy Claude Code thật đã thấy 8 lần chặn y hệt nhau cho tới khi hết max-turns. Nếu user bấm dừng (Cursor `status: aborted`) thì không bao giờ chặn.

Một số lưu ý riêng cho từng agent:

- **Cursor** mặc định nạp luôn hook trong `.claude/settings.json`. Adapter Claude nhận ra payload có `cursor_version` và tự bỏ qua, để không bị phản hồi hai lần.
- **Codex** chỉ chạy hook của project sau khi từng dev trust một lần qua `/hooks`. Muốn ép ở cấp tổ chức thì phát hành dưới dạng managed hooks qua `requirements.toml` (`allow_managed_hooks_only = true`).
- **Claude Code** cũng có thể ép ở cấp tổ chức qua [managed settings](https://docs.anthropic.com/en/docs/claude-code/settings) (MDM).
- **Cursor Enterprise** có hook cấp team và enterprise.
- **Kiro** không trả output của `PostToolUse` cho model, nên adapter kiểm **nội dung sắp ghi** ngay ở `PreToolUse` (`fs_write` lấy `text`, `str_replace` dựng lại file sau khi thay). Chỉ chặn khi lần ghi *làm tăng* số vi phạm của một rule; sửa dở một file vốn đã lỗi vẫn được ghi. Kiro không báo cờ "đã bị chặn một lần", nên adapter tự nhớ theo `session_id`.
- **Copilot CLI** đọc cả `.claude/settings.json`, nên hook có thể chạy hai lần; cả hai đều chặn cùng một thứ. Chỉ adapter Copilot làm được việc chặn kết thúc lượt, vì Copilot coi exit 2 ở Stop là cảnh báo.

Nguồn của schema payload:

- Codex: đo từ `codex exec` 0.163 thật.
- Claude Code: chạy thật.
- Cursor: đọc từ mã nguồn `cursor-agent` 2026.10.22. Write gửi `{file_path, content}`, Shell gửi `{command, cwd}`.
- Gemini: theo hooks reference chính thức.
- Kiro: ghi lại từ `kiro-cli` 2.37 `--v3` thật (`fs_write {path,text}`, `str_replace {path,oldStr,newStr}`, `execute_bash {command}`, Stop không có cờ lặp).
- Copilot CLI, Factory Droid: theo hooks reference chính thức (chưa chạy agent thật).

### MCP server

`larpcop mcp` (stdio, SDK chính thức `rmcp`) cho agent 5 tool:

| Tool | Làm gì |
|---|---|
| `rules_for(path)` | Chỉ các rule áp cho file đó (theo ngôn ngữ và glob), kèm cách tuân thủ. Agent không phải nạp rule của mọi stack vào context. |
| `check_content(path, content)` | Kiểm nội dung **trước khi ghi**: trả về các vi phạm nó sẽ thêm vào. |
| `check(paths?)` | Kiểm file trên đĩa (mặc định: mọi thay đổi chưa commit). |
| `fix(paths?)` | Áp `fix:` của rule rồi báo phần còn lại. |
| `explain_rule(id)` | Rule cấm gì, cách tuân thủ, ví dụ đúng/sai lấy từ fixture. |

Chạy thật với Claude Code (`claude -p`, $0.25): agent tự gọi `rules_for` cho `src/report.ts` và `tools/sum.py`, gọi `check_content` cho cả hai bản nháp, rồi mới ghi; kết quả sạch ngay lần đầu. Lần chạy đó lộ một bug (file trong thư mục chưa tồn tại bị bỏ qua), đã sửa kèm test.

## Triển khai toàn công ty

**Managed policy trên máy dev.** `larpcop sync --managed --extends <URL#tag> --out <DIR>` sinh file policy cấp máy cho 5 agent, gọi `larpcop` bằng đường dẫn tuyệt đối và ép standards của công ty lên *mọi* repo, kể cả repo chưa có `.larpcop.yaml`. User không tắt được.

| Agent | macOS | Linux | Windows |
|---|---|---|---|
| Claude Code | `/Library/Application Support/ClaudeCode/managed-settings.json` | `/etc/claude-code/managed-settings.json` | `C:\Program Files\ClaudeCode\managed-settings.json` |
| Codex | `/etc/codex/requirements.toml` (`[features] hooks = true`, `managed_dir`) | như macOS | `C:\ProgramData\OpenAI\Codex\requirements.toml` |
| Gemini CLI | `/Library/Application Support/GeminiCli/settings.json` | `/etc/gemini-cli/settings.json` | `C:\ProgramData\gemini-cli\settings.json` |
| Cursor | `/Library/Application Support/Cursor/hooks.json` | `/etc/cursor/hooks.json` | `C:\ProgramData\Cursor\hooks.json` |
| Copilot CLI | `/etc/github-copilot/policy.d/larpcop.json` | như macOS | `C:\ProgramData\GitHub\Copilot\policy.d\larpcop.json` |

`--out /` cài thẳng (cần root); `--out pkgroot` tạo cây thư mục để đóng gói cho MDM. Kiro và Factory Droid không có file cấp máy (dashboard / theo user). Đường dẫn lấy từ docs managed settings của từng hãng; chưa cài thử lên máy thật vì cần quyền root.

**Repo trên GitHub.**

```sh
larpcop org status <owner> [--standards URL#tag] [--json]
larpcop org setup  <owner> --standards URL#tag [--repos a,b] [--workflow-ref vX] [--dry-run]
```

- `status` liệt kê từng repo (không archived, không fork): có `.larpcop.yaml` không, extends standards nào và pin tag nào, có workflow gọi gate không, lần chạy gần nhất ra sao, có PR setup đang mở không. Exit 1 nếu còn repo chưa có gate. Đo trên tài khoản thật: 57 repo trong khoảng 22 giây.
- `setup` mở **một PR mỗi repo** gồm `.larpcop.yaml`, workflow `.github/workflows/larpcop.yml` và mọi file agent mà `sync` sinh ra từ nội dung hiện có của repo, nên PR qua được `sync --check` ngay. Chạy lại thì bỏ qua repo đã có gate hoặc đã có PR, và dùng lại nhánh nếu lần trước dừng giữa chừng.
- Ghi file trong `.github/workflows` cần token có scope `workflow`. Thiếu scope thì PR vẫn được mở, và nội dung workflow nằm trong mô tả PR để thêm tay (`gh auth refresh -s workflow` để lần sau tự thêm).
- Đã chạy thật trên hai repo sandbox private (standards + app): PR mở được, nhánh PR qua `sync --check` và `check`, chạy lại không tạo PR trùng. Hai repo sandbox đã xoá sau khi thử.
- Dùng `gh` CLI nên không lưu token, chạy được với SSO và GitHub Enterprise.

## CI

[`enforce.yml`](.github/workflows/enforce.yml) là reusable workflow. Mỗi repo gọi nó, hoặc org ruleset bắt buộc nó:

```yaml
jobs:
  larpcop:
    permissions:
      contents: read
      pull-requests: write   # comment trên PR; thêm security-events: write nếu bật sarif
    uses: NoahDuongMaster/larpcop/.github/workflows/enforce.yml@v0.3.0
    with:
      standards: https://github.com/<org>/standards.git#v1.0.0
    secrets:
      larpcop-token: ${{ secrets.LARPCOP_TOKEN }}   # chỉ cần khi larpcop/standards private
```

`permissions` phải khai ở job gọi: reusable workflow không được có quyền vượt quá job gọi nó, mà token mặc định của repo thường chỉ có quyền đọc. Thiếu quyền thì gate vẫn chạy và vẫn chặn, chỉ có comment trên PR là không đăng được; workflow sẽ hiện một warning nói rõ quyền còn thiếu. Lỗi này được phát hiện khi thử bản v0.2.0 trên PR thật.

Workflow này chỉ kiểm các file mà PR thay đổi, nên nợ kỹ thuật cũ không chặn PR, còn nợ mới không lọt vào được. Nó cũng chạy `sync --check` để đảm bảo các file agent sinh ra luôn khớp với rule. Repo này tự dùng chính workflow đó qua [`self-enforce.yml`](.github/workflows/self-enforce.yml).

## Phân phối khi repo private

Pipeline release dùng [`dist`](https://opensource.axo.dev/cargo-dist/) ([release.yml](.github/workflows/release.yml), [dist-workspace.toml](dist-workspace.toml)). Đẩy tag `v*` là CI tự build cho 5 target và tạo GitHub Release.

Installer shell/PowerShell, Homebrew và npm đều tải binary từ GitHub Releases, nên **chỉ chạy được cho mọi người khi repo public**. Khi repo còn private:

- Dev và CI dùng `gh release download` (cần đăng nhập `gh` và có quyền đọc repo).
- Công thức Homebrew (`larpcop.rb`) và tarball npm được đính kèm trong release nhưng **chưa publish**.

Khi chọn được nơi công khai (public repo, tap `homebrew-tap`, npm scope), chỉ cần thêm `publish-jobs = ["homebrew", "npm"]` cùng hai secret `HOMEBREW_TAP_TOKEN` và `NPM_TOKEN`.

## Kích thước binary

Binary nặng 47 MB trên đĩa, nhưng chỉ khoảng **4 MB khi tải về** (`tar.xz`). Phần lớn là bảng parse của grammar: riêng kotlin, c-sharp, swift, scala mỗi cái 8–12 MB. Đây là dữ liệu, không phải code, nên các cách tối ưu code không giúp được:

- `opt-level = "z"` đã đo cho ra 49.9 MB so với 49.3 MB, tức không nhỏ đi, mà lại chậm hơn khoảng 25 lần (0.75s so với 0.03s cho cùng một lần `check`).
- ast-grep-language không cho tắt từng ngôn ngữ (mã nguồn không có `cfg(feature)`), nên muốn cắt bớt grammar thì phải fork. Không đáng làm.

## Windows

- Lệnh `run:` của linter luôn chạy bằng shell POSIX, nên một config dùng được trên mọi OS. Thứ tự tìm shell: biến `LARPCOP_SHELL`, rồi `sh.exe` đi kèm Git for Windows (tìm qua `git --exec-path`), rồi `sh` trong PATH.
- Cache standards dùng thư mục chuẩn của từng OS: `%LOCALAPPDATA%` trên Windows, `~/Library/Caches` trên macOS, XDG trên Linux. Có thể ghi đè bằng `LARPCOP_CACHE_DIR`.
- Path được chuẩn hoá bằng `dunce`, không bị dạng `\\?\C:\...`.
- File CRLF do `autocrlf` không bị tính là drift, và AGENTS.md sinh ra luôn dùng LF.
- [`ci.yml`](.github/workflows/ci.yml) chạy fmt, clippy và toàn bộ test trên ubuntu, macOS và Windows.

## Đã kiểm chứng

`cargo test` có 116 test:

- Unit: guard, tìm shell, path trong patch Codex; đọc lockfile thật của npm 11, pnpm 11, uv 0.11, cargo 1.98, bun 1.4, bundler (kèm yarn v1/Berry, Poetry, go.mod, NuGet, Gradle, Composer, pom.xml, csproj, và các entry registry riêng/git/workspace phải bị bỏ qua); manifest; nhận diện lệnh cài; thiết lập gate của 4 package manager.
- Dashboard: số mở/baseline theo rule, xu hướng nợ qua lịch sử git, trang không có script.
- AI (model giả bằng shell script): review chỉ báo dòng đã đổi, bỏ rule lạ, cache câu trả lời; learn gửi lại rule fail kèm lỗi, chỉ giữ rule pass test, rule ghi ra chạy được như rule thường.
- Bảo mật: taint qua biến/destructuring/sanitizer/gán lại (TS, Python, Go, Rust), qua lời gọi hàm và import, callback, guard; `sink_types` qua typescript-language-server, gopls và rust-analyzer thật (xuyên file); secrets bị che khi in ra; OSV giả: mã độc luôn chặn, lỗ hổng chỉ chặn bản mới, theo ngưỡng, hook chặn lệnh cài.
- Integration: check, locked, git extends theo tag, staged, `--changed`/`--since`, linter delegation, format github, chống né rule, hook của 4 agent, sync idempotent, phát hiện drift, CRLF, pre-commit thật; dependency: tuổi phiên bản (qua cache và qua một server deps.dev giả), merge-base của PR, ngoại lệ bản vá bảo mật, gate package manager, duyệt dependency mới (cả monorepo), hook chặn lệnh cài, lock chỉ được siết thêm.

Trên GitHub thật (repo private `NoahDuongMaster/larpcop`):

- [`ci.yml`](.github/workflows/ci.yml) xanh trên ubuntu, macOS và **Windows**: fmt, clippy `-D warnings`, 29/29 test. Trên Windows có cả linter chạy qua `sh.exe` của Git, extends từ `file:///C:/…`, CRLF và pre-commit thật.
- Release `v0.3.0`: [release.yml](.github/workflows/release.yml) build 5 target. Installer đã được cài thật vào `~/.local/bin` theo cách ở mục [Cài đặt](#cài-đặt).
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
- **Lockfile do công cụ thật sinh ra**, lấy từ repo công khai (máy dev không có composer, dotnet hay gradle): `composer.lock` của symfony/demo đọc đủ 153/153 package và có 4 advisory OSV thật (`league/commonmark`, `symfony/http-foundation`, `symfony/yaml`); `packages.lock.json` của dorssel/usbipd-win đọc đủ 40 package (46 entry, trùng giữa các target framework); `gradle.lockfile` của Netflix/maestro đọc đủ 100 dòng, 11 advisory OSV.
- **Dependency với dữ liệu thật**:
  - `typescript@next` (phát hành cách đó 2 giờ) bị chặn cùng 7 binary nền tảng của nó. Mỗi lỗi kèm gợi ý `7.0.2`; 8 lần tra deps.dev hết 0,58 giây.
  - Chính `Cargo.lock` của larpcop bị chặn 3 crate mới 9–13 ngày tuổi; đã hạ theo đúng phiên bản được gợi ý. 2 crate khác được cho qua vì là bản vá RUSTSEC.

## Giới hạn

- **Lỗi logic và phân quyền** (IDOR, thiếu kiểm quyền admin, trả thừa dữ liệu) không có dạng cú pháp chung: trên ba bộ benchmark, đây là phần không công cụ SAST nào bắt được. Rule `llm` (`larpcop review`) nhắm vào loại này nhưng chỉ cho warning, vì model không tất định; `larpcop learn` chuyển dần các nhận xét lặp lại thành rule tất định.
- **Taint là xấp xỉ**: field của chính object (`this.x`, `self.x`) được theo giữa các method của một class, field của object khác thì không; import chỉ được theo 2 tầng (collection thì có: `push`, `set`, `append`, `Object.assign`…); giá trị trả về từ hàm không có summary (thư viện) được coi là bẩn nếu đối số bẩn. `guards` không phân biệt chiều của phép kiểm và không hiểu cấu trúc `&&`/`||` của điều kiện (`startsWith` với chuỗi cố định thì chỉ được tính khi chuỗi đó là phần đầu an toàn theo `safe_prefix`: `startsWith("/")` có, `startsWith("http")` không). Language server cần dự án đã cài đủ dependency mới trả lời đúng kiểu.
- **Package uy tín bị chiếm quyền**: tuổi tối thiểu 14 ngày chặn được bản độc bị phát hiện trong 14 ngày (phần lớn: OSV ghi nhận mã độc với độ trễ trung vị khoảng 20 giờ). Bản độc tồn tại lâu hơn mà chưa ai báo thì không công cụ dựa trên advisory nào biết.
- **Cursor và Gemini chưa chạy agent thật.** Cursor cần đăng nhập `cursor-agent login` (qua trình duyệt); Gemini CLI chưa được cài hay đăng nhập trên máy dev. Adapter được test bằng đúng schema payload ở trên.
- **File agent ghi bằng shell**: `cat > f <<EOF`, `tee`, `echo … > f`, `cp`/`mv`/`install` và `sed -i` chỉ gồm lệnh thay thế (`s/…/…/`, chạy thử trên bản sao) được kiểm nội dung *trước khi* lệnh chạy. Script tự viết, Makefile hay `sed` có lệnh khác thì không thấy trước được; hook kiểm các file mà lệnh đã đổi ngay sau khi lệnh chạy, rồi lại ở lượt kết thúc, pre-commit và CI.
- **Repo private** khiến installer `curl | sh`, Homebrew và npm chưa dùng được cho người ngoài (xem [Phân phối khi repo private](#phân-phối-khi-repo-private)). Repo khác muốn gọi `enforce.yml` thì cần quyền truy cập Actions; mục này đã được bật sẵn cho các repo cùng owner `NoahDuongMaster` (`access_level: user`). Repo gọi vẫn phải truyền secret `larpcop-token` để tải binary.
- **Chi phí CI**: GitHub Actions của repo private tính phút chạy, với runner macOS nhân 10 và Windows nhân 2. Repo public thì miễn phí.
- **Dependency**: rule tuổi phiên bản cần mạng tới deps.dev và fail closed khi không tra được; package ở registry riêng phải được khai trong `exempt`.

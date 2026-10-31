| Line | Vulnerability | larpcop | Semgrep OSS |
|---|---|---|---|
| `app/controllers/users_controller.rb:29` | A1 SQL injection (where with interpolated params[:user][:id]) | `rb-taint-sql` | `tainted-sql-string` |
| `app/models/analytics.rb:3` | A1 SQL injection (select("#{col}"), col from admin_controller custom fields) | `rb-taint-sql` | – |
| `app/models/benefits.rb:15` | A1 command injection (system cp with the uploaded file name) | `rb-taint-shell` | – |
| `app/controllers/sessions_controller.rb:26` | A10 open redirect (redirect_to params[:url]) | `rb-taint-redirect` | `avoid-redirect`, `check-redirect-to` |
| `app/controllers/benefit_forms_controller.rb:12` | Extras constantize (params[:type].constantize) | `rb-taint-code`, `rb-taint-path` | `check-send-file`, `check-unsafe-reflection` |
| `app/controllers/benefit_forms_controller.rb:13` | Path traversal (send_file of params[:name]) | `rb-taint-code`, `rb-taint-path` | `check-send-file`, `check-unsafe-reflection` |
| `app/controllers/password_resets_controller.rb:6` | Extras RCE (Marshal.load of params[:user]) | `rb-taint-deserialization` | `bad-deserialization` |
| `app/controllers/users_controller.rb:50` | Extras mass assignment (permit!) | `rb-no-permit-all` | – |
| `app/models/user.rb:45` | A6 insecure password storage (MD5) | `rb-no-weak-hash` | `weak-hashes-md5` |
| `app/models/user.rb:55` | A6 insecure password storage (MD5) | `rb-no-weak-hash` | `weak-hashes-md5` |
| `app/views/layouts/shared/_header.html.erb:47` | A3 stored XSS (first_name.html_safe in ERB) | `no-unescaped-template-output` | `avoid-html-safe` |
| `app/controllers/application_controller.rb:9` | A8 CSRF (protect_from_forgery commented out) | – | `missing-csrf-protection` |
| `config/initializers/session_store.rb:4` | A2 session cookie without HttpOnly (httponly: false) | `rb-no-cookie-httponly-off` | – |
| `config/initializers/html_entities.rb:2` | A5 HTML entities not escaped in JSON | `rb-no-json-html-escape-off` | – |

- larpcop: 13/14 lines; 37 security findings: no-unescaped-template-output 6, rb-no-weak-hash 5, rb-taint-code 4, gha-unpinned-action 2, no-inner-html 2, no-regex-redos 2, rb-taint-sql 2, rb-taint-path 2, no-eval 1, rb-csrf-off 1, rb-taint-shell 1, rb-taint-deserialization 1, rb-no-html-safe-interpolation 1, rb-taint-xss 1, rb-taint-redirect 1, rb-no-permit-all 1, no-inner-html-in-templates 1, rb-no-json-html-escape-off 1, secrets 1, rb-no-cookie-httponly-off 1
- Semgrep OSS: 9/14 lines; 44 security findings: detect-non-literal-regexp 6, weak-hashes-md5 6, avoid-html-safe 5, detailed-exceptions 4, check-unscoped-find 3, check-unsafe-reflection 3, github-actions-mutable-action-tag 2, var-in-href 2, detected-generic-api-key 1, raw-html-concat 1, eval-detected 1, weak-hashes-sha1 1, missing-csrf-protection 1, check-send-file 1, bad-deserialization 1, avoid-redirect 1, check-redirect-to 1, tainted-sql-string 1, model-attr-accessible 1, unquoted-attribute 1, avoid-raw 1

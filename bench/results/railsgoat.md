# RailsGoat

[OWASP/railsgoat](https://github.com/OWASP/railsgoat) `f5951f1`: Ruby on Rails.

Answer key: `bench/truth/railsgoat-truth.json`, 14 lines taken from the project's wiki, written after the Ruby rules were committed and before any tool ran on the application. A line counts as found when a larpcop security finding lies within three lines of it in the same file. Engine changes (scopes as methods, calls without parentheses, implicit returns), a `select` sink without receiver and three configuration rules were added after the first run, so the result is not a held-out number.

| Line | Vulnerability | larpcop |
|---|---|---|
| `app/controllers/users_controller.rb:29` | A1 SQL injection (where with interpolated params[:user][:id]) | `rb-taint-sql` |
| `app/models/analytics.rb:3` | A1 SQL injection (select("#{col}"), col from admin_controller custom fields) | `rb-taint-sql` |
| `app/models/benefits.rb:15` | A1 command injection (system cp with the uploaded file name) | `rb-taint-shell` |
| `app/controllers/sessions_controller.rb:26` | A10 open redirect (redirect_to params[:url]) | `rb-taint-redirect` |
| `app/controllers/benefit_forms_controller.rb:12` | Extras constantize (params[:type].constantize) | `rb-taint-code`, `rb-taint-path` |
| `app/controllers/benefit_forms_controller.rb:13` | Path traversal (send_file of params[:name]) | `rb-taint-code`, `rb-taint-path` |
| `app/controllers/password_resets_controller.rb:6` | Extras RCE (Marshal.load of params[:user]) | `rb-taint-deserialization` |
| `app/controllers/users_controller.rb:50` | Extras mass assignment (permit!) | `rb-no-permit-all` |
| `app/models/user.rb:45` | A6 insecure password storage (MD5) | `rb-no-weak-hash` |
| `app/models/user.rb:55` | A6 insecure password storage (MD5) | `rb-no-weak-hash` |
| `app/views/layouts/shared/_header.html.erb:47` | A3 stored XSS (first_name.html_safe in ERB) | `no-unescaped-template-output` |
| `app/controllers/application_controller.rb:9` | A8 CSRF (protect_from_forgery commented out) | – |
| `config/initializers/session_store.rb:4` | A2 session cookie without HttpOnly (httponly: false) | `rb-no-cookie-httponly-off` |
| `config/initializers/html_entities.rb:2` | A5 HTML entities not escaped in JSON | `rb-no-json-html-escape-off` |

- larpcop: 13/14 lines; 37 security findings: no-unescaped-template-output 6, rb-no-weak-hash 5, rb-taint-code 4, gha-unpinned-action 2, no-inner-html 2, no-regex-redos 2, rb-taint-sql 2, rb-taint-path 2, no-eval 1, rb-csrf-off 1, rb-taint-shell 1, rb-taint-deserialization 1, rb-no-html-safe-interpolation 1, rb-taint-xss 1, rb-taint-redirect 1, rb-no-permit-all 1, no-inner-html-in-templates 1, rb-no-json-html-escape-off 1, secrets 1, rb-no-cookie-httponly-off 1

Missed: A8 CSRF (`app/controllers/application_controller.rb:9`). `rb-csrf-off` reports it at the class declaration (line 2), while the answer key lists the commented-out `protect_from_forgery` at line 9, so the line counts as missed.

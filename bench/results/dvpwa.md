| Line | Vulnerability | larpcop | Semgrep OSS |
|---|---|---|---|
| `sqli/dao/student.py:43` | SQL injection (student name % formatted into INSERT) | `py-no-sql-interpolation` | `formatted-sql-query`, `sqlalchemy-execute-raw-query` |
| `sqli/app.py:35` | Stored XSS (Jinja2 autoescape=False) | `py-no-template-autoescape-off` | – |
| `sqli/dao/user.py:41` | Passwords stored as unsalted md5 | `py-no-weak-hash` | `md5-used-as-password` |
| `sqli/views.py:42` | Session fixation (session id not rotated on login) | `py-no-session-fixation` | – |

- larpcop: 4/4 lines; 37 security findings: dependency-vulnerability 29, no-inner-html 2, py-no-template-autoescape-off 1, py-no-sql-interpolation 1, py-no-weak-hash 1, no-eval 1, py-no-session-fixation 1, py-taint-sql 1
- Semgrep OSS: 2/4 lines; 9 security findings: unsafe-formatstring 3, no-new-privileges 1, writable-filesystem-service 1, formatted-sql-query 1, sqlalchemy-execute-raw-query 1, md5-used-as-password 1, detect-non-literal-regexp 1

Secrets vs gitleaks: 0 identical findings; 0 only in gitleaks, 0 only in larpcop.

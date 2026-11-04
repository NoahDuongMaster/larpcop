# DVPWA

[anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) `a1d8f89`: Python, aiohttp and Jinja2.

Answer key: `bench/truth/dvpwa-truth.json`, 4 lines taken from the Vulnerabilities section of the project's README. A line counts as found when a larpcop security finding lies within three lines of it in the same file. The Python rules were adjusted after the first run on this suite (SQL built with `%` in a variable before `execute`, `md5` imported by name, aiohttp request sources, taint through methods of imported classes), so the result is not a held-out number.

| Line | Vulnerability | larpcop |
|---|---|---|
| `sqli/dao/student.py:43` | SQL injection (student name % formatted into INSERT) | `py-no-sql-interpolation` |
| `sqli/app.py:35` | Stored XSS (Jinja2 autoescape=False) | `py-no-template-autoescape-off` |
| `sqli/dao/user.py:41` | Passwords stored as unsalted md5 | `py-no-weak-hash` |
| `sqli/views.py:42` | Session fixation (session id not rotated on login) | `py-no-session-fixation` |

- larpcop: 4/4 lines; 37 security findings: dependency-vulnerability 29, no-inner-html 2, py-no-template-autoescape-off 1, py-no-sql-interpolation 1, py-no-weak-hash 1, no-eval 1, py-no-session-fixation 1, py-taint-sql 1

Missed: none.

| Line | Vulnerability | larpcop |
|---|---|---|
| `dsvw.py:22` | SQL injection (?id= concatenated into the query) | `py-no-sql-interpolation` |
| `dsvw.py:25` | reflected XSS (?v= substituted into the page) | `py-no-sql-interpolation`, `py-no-unsafe-deserialization` |
| `dsvw.py:27` | insecure deserialization (pickle.loads of ?object=) | `py-no-unsafe-deserialization` |
| `dsvw.py:29` | path traversal / SSRF (?path= opened or fetched) | `py-no-shell-true`, `py-no-unsafe-deserialization` |
| `dsvw.py:31` | command injection (nslookup of ?domain= through a shell) | `py-no-shell-true`, `py-no-xml-external-entities` |
| `dsvw.py:33` | XXE (external entities resolved on ?xml=) | `py-no-shell-true`, `py-no-xml-external-entities` |
| `dsvw.py:35` | XPath injection (?name= inside the xpath expression) | `py-no-xml-external-entities` |
| `dsvw.py:42` | SQL injection (?comment= concatenated into the INSERT) | `py-no-sql-interpolation` |
| `dsvw.py:46` | stored XSS (stored comments rendered into the page) | `py-no-eval` |
| `dsvw.py:48` | file inclusion (?include= opened or fetched) | `py-no-eval` |
| `dsvw.py:49` | code execution (exec of the included program) | `py-no-eval` |
| `dsvw.py:55` | server-side template injection (?tmpl= formatted) | – |
| `dsvw.py:59` | JSONP XSS (?callback= wrapped around the JSON) | `py-no-sql-interpolation` |
| `dsvw.py:61` | SQL injection (login username and password concatenated) | `py-no-sql-interpolation` |
| `dsvw.py:70` | open redirect (Location header from ?redir=) | – |

- larpcop: 13/15 lines; 13 security findings: gha-unpinned-action 4, py-no-sql-interpolation 3, py-no-xml-external-entities 3, py-no-unsafe-deserialization 1, py-no-shell-true 1, py-no-eval 1

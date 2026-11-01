## First run (held-out)

NIST Juliet C# 1.3, the 1,443 cases whose data comes from an HTTP request (`QueryString`, `Params`, `Cookies`), scored from Juliet's own `Bad*`/`Good*` labels (`bench/juliet.py`). The rules and the case selection were committed before any tool ran. larpcop scored **+43.9%** on the first run; Semgrep `p/default` and `p/csharp` scored +0.8% (their columns below are from that run). The per-category larpcop table of the first run was not kept (commit 0e1dc01 records the average).

## Now (not a held-out number: the suite has been used to fix the engine)

| Category (cases) | larpcop: found / good flagged / score | Semgrep (jcs-semgrep-default): found / good flagged / score | Semgrep (jcs-semgrep-csharp): found / good flagged / score |
|---|---|---|---|
| ldap (111) | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 16% / 16% / **+0%** |
| path (222) | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| redirect (111) | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| shell (111) | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| sql (333) | 100% / 3% / **+97%** | 67% / 61% / **+5%** | 67% / 61% / **+5%** |
| xpath (111) | 100% / 3% / **+97%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xss (444) | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| **average** | **+99.2%** | **+0.8%** | **+0.8%** |

Every case is found. Fixed since the first run, among others: serialized data (flow 75, `BinaryFormatter.Serialize(ms, data)` then `ms.ToArray()`), a static field of another class read by the callee (flow 68), `Base b = new Good()` resolved to the class it was built as (flow 81). The "good flagged" cases are flow 75's `GoodG2B` in SQL and XPath (12): in Juliet C# 1.3 that method reads `req.Params.Get(...)`/the cookie/query string, the bad source, and passes it to the bad sink, so these are real injections labeled good.

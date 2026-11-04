# NIST Juliet C# 1.3: web cases

The 1,443 cases of Juliet C# 1.3 whose data comes from an HTTP request (`QueryString`, `Params`, `Cookies`), scored from Juliet's own `Bad*`/`Good*` labels with `bench/scripts/juliet.py`. The rules and the case selection were committed before any tool ran.

## First run

larpcop scored **+43.9%**. The per-category table of the first run was not kept.

## Current

The engine was adjusted after the first run using this suite's misses, so these numbers are not held-out.

| Category (cases) | larpcop: found / good flagged / score |
|---|---|
| ldap (111) | 100% / 0% / **+100%** |
| path (222) | 100% / 0% / **+100%** |
| redirect (111) | 100% / 0% / **+100%** |
| shell (111) | 100% / 0% / **+100%** |
| sql (333) | 100% / 3% / **+97%** |
| xpath (111) | 100% / 3% / **+97%** |
| xss (444) | 100% / 0% / **+100%** |
| **average** | **+99.2%** |

Every case is found. Cases that needed engine changes after the first run, among others: serialized data (flow 75, `BinaryFormatter.Serialize(ms, data)` then `ms.ToArray()`), a static field of another class read by the callee (flow 68), `Base b = new Good()` resolved to the class it was built as (flow 81). The "good flagged" cases are flow 75's `GoodG2B` in SQL and XPath (12): in Juliet C# 1.3 that method reads `req.Params.Get(...)`/the cookie/query string, the bad source, and passes it to the bad sink, so these are real injections labeled good.

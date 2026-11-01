# NIST Juliet Java 1.3: servlet test cases

1,665 test cases whose data comes from `request.getParameter`, `getCookies` or `getQueryString`, in the 10 CWEs of the C# bench (SQL, OS command, relative/absolute path, open redirect, XSS ×3, LDAP, XPath). Juliet labels by construction: `bad*` methods are vulnerable, `good*` are not. Scored with `juliet.py` (found rate − good-code flagged rate per category), committed with the case selection (ae4baa8) before any tool ran.

## First run (larpcop ae4baa8)

| Category (cases) | larpcop: found / good flagged / score | Semgrep p/default: found / good flagged / score | Semgrep p/java: found / good flagged / score |
|---|---|---|---|
| ldap (111) | 89% / 0% / **+89%** | 100% / 92% / **+8%** | 59% / 11% / **+49%** |
| path (222) | 59% / 0% / **+59%** | 59% / 11% / **+49%** | 59% / 11% / **+49%** |
| redirect (111) | 89% / 0% / **+89%** | 16% / 16% / **+0%** | 16% / 16% / **+0%** |
| shell (111) | 89% / 0% / **+89%** | 59% / 11% / **+49%** | 59% / 11% / **+49%** |
| sql (555) | 86% / 0% / **+86%** | 95% / 81% / **+15%** | 76% / 27% / **+49%** |
| xpath (111) | 89% / 89% / **+0%** | 49% / 49% / **+0%** | 49% / 49% / **+0%** |
| xss (444) | 67% / 0% / **+67%** | 36% / 0% / **+36%** | 36% / 0% / **+36%** |
| **average** | **+68.6%** | **+22.4%** | **+33.0%** |

## After the fixes (not a held-out number)

| Category (cases) | larpcop: found / good flagged / score | Semgrep p/default: found / good flagged / score | Semgrep p/java: found / good flagged / score |
|---|---|---|---|
| ldap (111) | 95% / 0% / **+95%** | 100% / 92% / **+8%** | 59% / 11% / **+49%** |
| path (222) | 95% / 0% / **+95%** | 59% / 11% / **+49%** | 59% / 11% / **+49%** |
| redirect (111) | 95% / 0% / **+95%** | 16% / 16% / **+0%** | 16% / 16% / **+0%** |
| shell (111) | 95% / 0% / **+95%** | 59% / 11% / **+49%** | 59% / 11% / **+49%** |
| sql (555) | 95% / 0% / **+95%** | 95% / 81% / **+15%** | 76% / 27% / **+49%** |
| xpath (111) | 95% / 0% / **+95%** | 49% / 49% / **+0%** | 49% / 49% / **+0%** |
| xss (444) | 71% / 0% / **+71%** | 36% / 0% / **+36%** | 36% / 0% / **+36%** |
| **average** | **+91.2%** | **+22.4%** | **+33.0%** |

Fixed: a literal `startsWith` is a path guard only on a resolved path (`getCanonicalPath()`, `normalize()`); Juliet's `getQueryString` parsing (`token.startsWith("id=")`) cleaned the value. `StringEscapeUtils.escapeXml` and ESAPI `encodeForXPath` are XPath sanitizers. A call on an object built in the same function (`Base b = new Bad(); b.action(x)`) uses the class it was built as.

Chains of 4–5 files (flows 53, 54) are found since imports are followed 4 deep, past the second level only into files that lead to a source or sink (halo 39 s → 44 s instead of 102 s summarizing everything).

Still missed: data in a static field of another class (68) and through serialization (75); `response.sendError(404, data)` (CWE81, 111 cases) is not an XSS sink: Tomcat and Jetty escape the message on their error pages.

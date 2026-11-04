# NIST Juliet Java 1.3: servlet test cases

1,665 test cases whose data comes from `request.getParameter`, `getCookies` or `getQueryString`, in 10 CWEs (SQL injection, OS command injection, relative and absolute path traversal, open redirect, XSS ×3, LDAP injection, XPath injection). Juliet labels by construction: `bad*` methods are vulnerable, `good*` are not. Scored with `bench/scripts/juliet.py` (found rate − good-code flagged rate per category). The scorer was committed with the case selection before any tool ran.

## First run

| Category (cases) | larpcop: found / good flagged / score |
|---|---|
| ldap (111) | 89% / 0% / **+89%** |
| path (222) | 59% / 0% / **+59%** |
| redirect (111) | 89% / 0% / **+89%** |
| shell (111) | 89% / 0% / **+89%** |
| sql (555) | 86% / 0% / **+86%** |
| xpath (111) | 89% / 89% / **+0%** |
| xss (444) | 67% / 0% / **+67%** |
| **average** | **+68.6%** |

## Current

The engine was adjusted after the first run using this suite's misses, so these numbers are not held-out.

| Category (cases) | larpcop: found / good flagged / score |
|---|---|
| ldap (111) | 100% / 0% / **+100%** |
| path (222) | 100% / 0% / **+100%** |
| redirect (111) | 100% / 0% / **+100%** |
| shell (111) | 100% / 0% / **+100%** |
| sql (555) | 100% / 0% / **+100%** |
| xpath (111) | 100% / 0% / **+100%** |
| xss (444) | 75% / 0% / **+75%** |
| **average** | **+96.4%** |

What the adjustments covered: a literal `startsWith` is a path guard only on a resolved path (`getCanonicalPath()`, `normalize()`); without that distinction, Juliet's `getQueryString` parsing (`token.startsWith("id=")`) cleaned the value. `StringEscapeUtils.escapeXml` and ESAPI `encodeForXPath` are XPath sanitizers. A call on an object built in the same function (`Base b = new Bad(); b.action(x)`) uses the class it was built as.

Chains of 4–5 files (flows 53, 54) are found because imports are followed 4 deep, and past the second level only into files that lead to a source or sink. On the halo repository this costs 39 s → 44 s, against 102 s if every file were summarized.

Serialized data (flow 75) is followed: a stream write (`out.writeObject(data)`) taints the stream and the stream it was built around (`new ObjectOutputStream(bytes)`), so `bytes.toByteArray()` carries it into the other class, where `readObject()` returns it.

A static field of another class read by the callee (flow 68) is an input of that method: the call is reported where the caller holds the field tainted (`data = request.getParameter(...)` before `new B().badSink()`), not where it set a constant.

Missed: `response.sendError(404, data)` (CWE81, 111 cases) is not an XSS sink: Tomcat and Jetty escape the message on their error pages.

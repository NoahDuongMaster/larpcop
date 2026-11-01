# OWASP Benchmark for Python (OWASP-Benchmark/BenchmarkPython f129148)

1,230 test cases, each labelled vulnerable or not by the project (`expectedresults-0.1.csv`). Scored with `owasp_benchmark.py`, as the Java edition: per category, TPR − FPR. The Python rules measured (py-taint-ldap, py-taint-xpath, py-taint-trust-boundary, py-no-insecure-random, py-no-insecure-cookie, XXE via xml.sax features) and the scorer's Python mapping were committed (31c1118) before any tool ran on it. Policy rules count as findings of their category (`py-no-shell-true` for cmdi, `py-no-eval` for codeinj), as `java-no-sql-concat` does on the Java edition: they report the construct whatever its input, so the safe cases that use it are false positives here.

## First run (larpcop 31c1118)

| Category | larpcop TPR / FPR / score | Semgrep (p/default) TPR / FPR / score | Semgrep (p/python) TPR / FPR / score |
|---|---|---|---|
| cmdi | 54% / 100% / **-46%** | 54% / 100% / **-46%** | 54% / 100% / **-46%** |
| codeinj | 100% / 100% / **+0%** | 100% / 100% / **+0%** | 0% / 0% / **+0%** |
| deserialization | 94% / 25% / **+69%** | 100% / 33% / **+67%** | 50% / 17% / **+33%** |
| hash | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| ldapi | 100% / 100% / **+0%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| pathtraver | 35% / 9% / **+27%** | 3% / 2% / **+1%** | 3% / 2% / **+1%** |
| redirect | 85% / 38% / **+47%** | 8% / 5% / **+3%** | 0% / 0% / **+0%** |
| securecookie | 100% / 0% / **+100%** | 100% / 100% / **+0%** | 0% / 0% / **+0%** |
| sqli | 100% / 0% / **+100%** | 100% / 0% / **+100%** | 0% / 0% / **+0%** |
| trustbound | 22% / 11% / **+12%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| weakrand | 78% / 0% / **+78%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xpathi | 25% / 11% / **+14%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xss | 0% / 9% / **-9%** | 0% / 28% / **-28%** | 0% / 0% / **+0%** |
| xxe | 100% / 35% / **+65%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| **average** | **+39.8%** | **+6.9%** | **-0.8%** |

## After the fixes (not a held-out number)

| Category | larpcop TPR / FPR / score | Semgrep (p/default) TPR / FPR / score | Semgrep (p/python) TPR / FPR / score |
|---|---|---|---|
| cmdi | 54% / 100% / **-46%** | 54% / 100% / **-46%** | 54% / 100% / **-46%** |
| codeinj | 100% / 100% / **+0%** | 100% / 100% / **+0%** | 0% / 0% / **+0%** |
| deserialization | 100% / 19% / **+81%** | 100% / 33% / **+67%** | 50% / 17% / **+33%** |
| hash | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| ldapi | 100% / 100% / **+0%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| pathtraver | 78% / 10% / **+69%** | 3% / 2% / **+1%** | 3% / 2% / **+1%** |
| redirect | 92% / 38% / **+54%** | 8% / 5% / **+3%** | 0% / 0% / **+0%** |
| securecookie | 100% / 0% / **+100%** | 100% / 100% / **+0%** | 0% / 0% / **+0%** |
| sqli | 100% / 0% / **+100%** | 100% / 0% / **+100%** | 0% / 0% / **+0%** |
| trustbound | 100% / 32% / **+68%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| weakrand | 78% / 0% / **+78%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xpathi | 80% / 23% / **+57%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xss | 100% / 36% / **+64%** | 0% / 28% / **-28%** | 0% / 0% / **+0%** |
| xxe | 100% / 35% / **+65%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| **average** | **+56.4%** | **+6.9%** | **-0.8%** |

Fixed: Python `match`/`case` was not a branch; a returned string built with `+=` and f-strings was not an HTML response; `request.cookies`, `headers`, `data`, `files`, `self.request.*` were not sources; `codecs.open`, `os.path.exists` and other file functions were not path sinks; `elementpath.select` was not an XPath sink; the project's only `get` hid `request.GET.get('q')`; a method of a lowercase class (`request_wrapper.get_form_parameter`) was not summarized; map entries under literal keys were one taint; branches decided by known values (`if 7 * 42 - num > 200`, `match "ABC"[0]`, Java `switch` on `"ABC".charAt(1)`) counted both sides. The last also took OWASP Benchmark Java from +52.6% to +72.6%; lists read by position in straight-line code (`add("safe"); add(param); remove(0); get(1)`), escapers called through a chain (`org.owasp.esapi.ESAPI.encoder().encodeForHTML`) and Java classes named in full without an import (`new org.owasp.benchmark.helpers.SeparateClassRequest(request)`) took it to +86.8%.

Still wrong: a list changed in a branch or passed to a function is one whole; a `configparser` section; an argument list built with `append` (`args.append('sh'); args.append('-c'); args.append(cmd)`): only list literals are read; the policy rules `py-no-shell-true`, `py-no-eval`, `py-no-ldap-interpolation` report safe cases by design.

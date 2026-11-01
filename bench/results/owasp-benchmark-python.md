# OWASP Benchmark for Python (OWASP-Benchmark/BenchmarkPython f129148)

1,230 test cases, each labelled vulnerable or not by the project (`expectedresults-0.1.csv`). Scored with `owasp_benchmark.py`, as the Java edition: per category, TPR − FPR. The Python rules measured (py-taint-ldap, py-taint-xpath, py-taint-trust-boundary, py-no-insecure-random, py-no-insecure-cookie, XXE via xml.sax features) and the scorer's Python mapping were committed (31c1118) before any tool ran on it. Policy rules count as findings of their category (`py-no-shell-true` for cmdi, `py-no-eval` for codeinj), as `java-no-sql-concat` does on the Java edition: they report the construct whatever its input, so the safe cases that use it are false positives here.

## First run (larpcop 31c1118)

| Category | larpcop TPR / FPR / score | Semgrep (p/default) TPR / FPR / score | Semgrep (p/python) TPR / FPR / score |
|---|---|---|---|
| cmdi | 100% / 100% / **+0%** | 54% / 100% / **-46%** | 54% / 100% / **-46%** |
| codeinj | 100% / 100% / **+0%** | 100% / 100% / **+0%** | 0% / 0% / **+0%** |
| deserialization | 100% / 19% / **+81%** | 100% / 33% / **+67%** | 50% / 17% / **+33%** |
| hash | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| ldapi | 100% / 100% / **+0%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| pathtraver | 100% / 0% / **+100%** | 3% / 2% / **+1%** | 3% / 2% / **+1%** |
| redirect | 100% / 33% / **+67%** | 8% / 5% / **+3%** | 0% / 0% / **+0%** |
| securecookie | 100% / 0% / **+100%** | 100% / 100% / **+0%** | 0% / 0% / **+0%** |
| sqli | 100% / 0% / **+100%** | 100% / 0% / **+100%** | 0% / 0% / **+0%** |
| trustbound | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| weakrand | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xpathi | 100% / 14% / **+86%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xss | 100% / 10% / **+90%** | 0% / 28% / **-28%** | 0% / 0% / **+0%** |
| xxe | 100% / 35% / **+65%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| **average** | **+70.6%** | **+6.9%** | **-0.8%** |

## After the fixes (not a held-out number)

| Category | larpcop TPR / FPR / score | Semgrep (p/default) TPR / FPR / score | Semgrep (p/python) TPR / FPR / score |
|---|---|---|---|
| cmdi | 100% / 100% / **+0%** | 54% / 100% / **-46%** | 54% / 100% / **-46%** |
| codeinj | 100% / 100% / **+0%** | 100% / 100% / **+0%** | 0% / 0% / **+0%** |
| deserialization | 100% / 19% / **+81%** | 100% / 33% / **+67%** | 50% / 17% / **+33%** |
| hash | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| ldapi | 100% / 100% / **+0%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| pathtraver | 100% / 0% / **+100%** | 3% / 2% / **+1%** | 3% / 2% / **+1%** |
| redirect | 100% / 33% / **+67%** | 8% / 5% / **+3%** | 0% / 0% / **+0%** |
| securecookie | 100% / 0% / **+100%** | 100% / 100% / **+0%** | 0% / 0% / **+0%** |
| sqli | 100% / 0% / **+100%** | 100% / 0% / **+100%** | 0% / 0% / **+0%** |
| trustbound | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| weakrand | 100% / 0% / **+100%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xpathi | 100% / 14% / **+86%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| xss | 100% / 10% / **+90%** | 0% / 28% / **-28%** | 0% / 0% / **+0%** |
| xxe | 100% / 35% / **+65%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| **average** | **+70.6%** | **+6.9%** | **-0.8%** |

Fixed: Python `match`/`case` was not a branch; a returned string built with `+=` and f-strings was not an HTML response; `request.cookies`, `headers`, `data`, `files`, `self.request.*` were not sources; `codecs.open`, `os.path.exists` and other file functions were not path sinks; `elementpath.select` was not an XPath sink; the project's only `get` hid `request.GET.get('q')`; a method of a lowercase class (`request_wrapper.get_form_parameter`) was not summarized; map entries under literal keys were one taint; branches decided by known values (`if 7 * 42 - num > 200`, `match "ABC"[0]`, Java `switch` on `"ABC".charAt(1)`) counted both sides. The last also took OWASP Benchmark Java from +52.6% to +72.6%; lists read by position in straight-line code (`add("safe"); add(param); remove(0); get(1)`), escapers called through a chain (`org.owasp.esapi.ESAPI.encoder().encodeForHTML`) and Java classes named in full without an import (`new org.owasp.benchmark.helpers.SeparateClassRequest(request)`) took it to +86.8%.

Fixed later: a `configparser` value read under its two keys (`conf.get('s', 'keyA')`) is that entry only, not the whole parser. A query written into a `StringIO` (`strIO.write(bar)`, then `strIO.getvalue()`) carries what was written (xpathi 80% → 100% found).

Fixed later still: an argument list built with `append` in `if`/`else` branches (`args.append('sh'); args.append('-c'); args.append(cmd)`) is read every way it can come out (cmdi 54% → 100% found); `request.path` in a handler whose route has no variables is that route, not request data; a path joined with `/` (`p = base / name`) and then used (`p.exists()`, `p.read_text()`) is a path sink (pathtraver 78% → 100%); `random.normalvariate` and the other `*variate` functions are insecure randomness (weakrand 78% → 100%).

Still wrong: a list changed in a branch other than by `append`, or passed to a function, is one whole; the policy rules `py-no-shell-true`, `py-no-eval`, `py-no-ldap-interpolation` report safe cases by design.

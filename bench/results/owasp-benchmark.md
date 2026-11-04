# OWASP Benchmark for Java 1.2 (OWASP-Benchmark/BenchmarkJava f40c618)

2,740 test cases, scored like the project's scorecard: per category, true positive rate − false positive rate, then the average. The rules were written before the first run.

## First run

The first run scored **+37.5%**. A first change to the engine (assignments inside a branch can no longer clean a variable) gave the table below (**+44.0%**).

| Category | larpcop TPR / FPR / score |
|---|---|
| cmdi | 83% / 58% / **+26%** |
| crypto | 75% / 0% / **+75%** |
| hash | 69% / 0% / **+69%** |
| ldapi | 85% / 47% / **+38%** |
| pathtraver | 82% / 61% / **+20%** |
| securecookie | 100% / 0% / **+100%** |
| sqli | 99% / 97% / **+2%** |
| trustbound | 82% / 67% / **+14%** |
| weakrand | 100% / 0% / **+100%** |
| xpathi | 80% / 65% / **+15%** |
| xss | 81% / 56% / **+25%** |
| **average** | **+44.0%** |

## Current

The engine was adjusted after the first run using this benchmark's misses, so these numbers are not held-out.

| Category | larpcop TPR / FPR / score |
|---|---|
| cmdi | 100% / 0% / **+100%** |
| crypto | 100% / 0% / **+100%** |
| hash | 100% / 0% / **+100%** |
| ldapi | 100% / 0% / **+100%** |
| pathtraver | 100% / 0% / **+100%** |
| securecookie | 100% / 0% / **+100%** |
| sqli | 100% / 89% / **+11%** |
| trustbound | 100% / 0% / **+100%** |
| weakrand | 100% / 0% / **+100%** |
| xpathi | 100% / 0% / **+100%** |
| xss | 100% / 0% / **+100%** |
| **average** | **+91.9%** |

Remaining errors: sqli's false positives are `java-no-sql-concat`, a policy rule that reports SQL built by concatenation whatever is concatenated. The hash and crypto rules follow the algorithm to its value (`getProperty("hashAlg1", "SHA512")` is MD5 in `benchmark.properties`, a file the repository commits although its `.gitignore` lists it).

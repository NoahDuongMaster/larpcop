## First run (held-out)

OWASP Benchmark Java 1.2 (2,740 cases), scored like the project's scorecard (per category: true positive rate − false positive rate). The rules were written before the first run; the first run scored **+37.5%**. The same commit (731b7f4) made assignments inside a branch unable to clean a variable, which gave the table below (**+44.0%**).

| Category | larpcop TPR / FPR / score | Semgrep (bj-semgrep-default) TPR / FPR / score | Semgrep (bj-semgrep-java) TPR / FPR / score |
|---|---|---|---|
| cmdi | 83% / 58% / **+26%** | 93% / 87% / **+6%** | 89% / 77% / **+12%** |
| crypto | 75% / 0% / **+75%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| hash | 69% / 0% / **+69%** | 69% / 0% / **+69%** | 69% / 0% / **+69%** |
| ldapi | 85% / 47% / **+38%** | 96% / 88% / **+9%** | 96% / 88% / **+9%** |
| pathtraver | 82% / 61% / **+20%** | 90% / 79% / **+12%** | 90% / 79% / **+12%** |
| securecookie | 100% / 0% / **+100%** | 100% / 0% / **+100%** | 0% / 0% / **+0%** |
| sqli | 99% / 97% / **+2%** | 93% / 73% / **+20%** | 86% / 62% / **+24%** |
| trustbound | 82% / 67% / **+14%** | 52% / 42% / **+10%** | 52% / 42% / **+10%** |
| weakrand | 100% / 0% / **+100%** | 100% / 0% / **+100%** | 0% / 0% / **+0%** |
| xpathi | 80% / 65% / **+15%** | 93% / 65% / **+28%** | 93% / 65% / **+28%** |
| xss | 81% / 56% / **+25%** | 82% / 52% / **+30%** | 82% / 52% / **+30%** |
| **average** | **+44.0%** | **+34.9%** | **+17.7%** |

## Now (not a held-out number: the benchmark has been used to fix the engine)

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

Left: sqli's false positives are `java-no-sql-concat`, a policy rule that reports SQL built by concatenation whatever is concatenated. Fixed since: hash and crypto rules follow the algorithm to its value (`getProperty("hashAlg1", "SHA512")` is MD5 in `benchmark.properties`, a file the repo commits although its `.gitignore` lists it).

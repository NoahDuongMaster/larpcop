| Category | larpcop TPR / FPR / score | Semgrep (bj-semgrep-default) TPR / FPR / score | Semgrep (bj-semgrep-java) TPR / FPR / score |
|---|---|---|---|
| cmdi | 91% / 61% / **+30%** | 93% / 87% / **+6%** | 89% / 77% / **+12%** |
| crypto | 75% / 0% / **+75%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| hash | 69% / 0% / **+69%** | 69% / 0% / **+69%** | 69% / 0% / **+69%** |
| ldapi | 89% / 53% / **+36%** | 96% / 88% / **+9%** | 96% / 88% / **+9%** |
| pathtraver | 89% / 62% / **+26%** | 90% / 79% / **+12%** | 90% / 79% / **+12%** |
| securecookie | 100% / 0% / **+100%** | 100% / 0% / **+100%** | 0% / 0% / **+0%** |
| sqli | 100% / 97% / **+3%** | 93% / 73% / **+20%** | 86% / 62% / **+24%** |
| trustbound | 87% / 74% / **+12%** | 52% / 42% / **+10%** | 52% / 42% / **+10%** |
| weakrand | 100% / 0% / **+100%** | 100% / 0% / **+100%** | 0% / 0% / **+0%** |
| xpathi | 93% / 70% / **+23%** | 93% / 65% / **+28%** | 93% / 65% / **+28%** |
| xss | 89% / 56% / **+34%** | 82% / 52% / **+30%** | 82% / 52% / **+30%** |
| **average** | **+46.2%** | **+34.9%** | **+17.7%** |

## Now (not a held-out number: the benchmark has been used to fix the engine)

| Category | larpcop TPR / FPR / score |
|---|---|
| cmdi | 100% / 0% / **+100%** |
| crypto | 75% / 0% / **+75%** |
| hash | 69% / 0% / **+69%** |
| ldapi | 100% / 0% / **+100%** |
| pathtraver | 100% / 0% / **+100%** |
| securecookie | 100% / 0% / **+100%** |
| sqli | 100% / 89% / **+11%** |
| trustbound | 100% / 0% / **+100%** |
| weakrand | 100% / 0% / **+100%** |
| xpathi | 100% / 0% / **+100%** |
| xss | 100% / 0% / **+100%** |
| **average** | **+86.8%** |

Left: sqli's false positives are `java-no-sql-concat`, a policy rule that reports SQL built by concatenation whatever is concatenated; hash and crypto misses read the algorithm from `benchmark.properties` at run time (`getProperty("hashAlg1", "SHA512")` is MD5 there).

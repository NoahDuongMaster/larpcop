# java-sec-code (JoyChou93/java-sec-code 4711f4e)

Java, Spring. 76 endpoints, labelled from the project's routes (`/vuln` vs `/sec`) and comments (`bench/truth/java-sec-code-truth.json`, committed before any tool ran). An endpoint is reported when a finding of its category lies inside it. Score per category = TPR − FPR.

## First run (before rules were added for this suite)

| category (vuln/safe) | larpcop |
|---|---|
| code (5/2) | 4/5 TP, 1/2 FP (+30%) |
| deserialization (5/2) | 0/5 TP, 0/2 FP (+0%) |
| path (1/1) | 1/1 TP, 1/1 FP (+0%) |
| redirect (3/2) | 1/3 TP, 1/2 FP (-17%) |
| shell (4/1) | 4/4 TP, 1/1 FP (+0%) |
| sql (5/5) | 2/5 TP, 0/5 FP (+40%) |
| ssrf (8/9) | 1/8 TP, 0/9 FP (+12%) |
| ssti (1/0) | 0/1 TP, 0/0 FP (+0%) |
| xss (2/1) | 0/2 TP, 0/1 FP (+0%) |
| xxe (11/8) | 0/11 TP, 0/8 FP (+0%) |
| **average** | **+6.6%** |
| **total** | 13/45 TP, 4/31 FP |

## Current

Rules and engine were adjusted after the first run using this suite's misses, so these numbers are not held-out.

| category (vuln/safe) | larpcop |
|---|---|
| code (5/2) | 5/5 TP, 0/2 FP (+100%) |
| deserialization (5/2) | 4/5 TP, 0/2 FP (+80%) |
| path (1/1) | 1/1 TP, 0/1 FP (+100%) |
| redirect (3/2) | 3/3 TP, 0/2 FP (+100%) |
| shell (4/1) | 4/4 TP, 0/1 FP (+100%) |
| sql (5/5) | 2/5 TP, 0/5 FP (+40%) |
| ssrf (8/9) | 8/8 TP, 5/9 FP (+44%) |
| ssti (1/0) | 1/1 TP, 0/0 FP (+100%) |
| xss (2/1) | 2/2 TP, 0/1 FP (+100%) |
| xxe (11/8) | 9/11 TP, 0/8 FP (+82%) |
| **average** | **+84.6%** |
| **total** | 39/45 TP, 5/31 FP |

The 5 SSRF `/sec` endpoints rely on a runtime socket hook (`SecurityUtil.startSSRFHook()`); statically they are the same calls as the vulnerable ones. SQL: the 3 MyBatis endpoints are found in the mapper files (`mybatis-sql-interpolation`, `java-no-mybatis-sql-interpolation`), outside the endpoint, so this scorer does not count them.

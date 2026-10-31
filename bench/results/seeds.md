| Tool | All security findings | Without per-file generic checks |
|---|---|---|
| larpcop | TP: 11/12   FN: 1   FP: 1 · missed: sast/seeds/nosql-operator.js · false positives: sast/seeds/clean-escaped.js · TPR = 0.92   FPR = 0.08 | TP: 11/12   FN: 1   FP: 0 · missed: sast/seeds/nosql-operator.js · TPR = 0.92   FPR = 0.00 |
| Semgrep OSS | TP: 10/12   FN: 2   FP: 1 · missed: sast/seeds/nosql-operator.js, sast/seeds/prototype-pollution.js · false positives: sast/seeds/clean-escaped.js · TPR = 0.83   FPR = 0.09 | TP: 8/12   FN: 4   FP: 1 · missed: sast/seeds/nosql-operator.js, sast/seeds/ssrf-fetch.js, sast/seeds/prototype-pollution.js, sast/seeds/open-redirect.js · false positives: sast/seeds/clean-escaped.js · TPR = 0.67   FPR = 0.11 |

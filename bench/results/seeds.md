# vulnerable-node: SAST seeds

[cr0hn/vulnerable-node](https://github.com/cr0hn/vulnerable-node) `d68f2a3`: JavaScript. Only `sast/seeds/` is scanned: one vulnerability per file, plus clean control files.

Scoring uses the project's own scorer, `sast/tests/score.js`, which counts a seed as found when a report names its file. larpcop is scored twice: with every security finding, and without the findings that any request handler or Express file gets regardless of the bug (`validate-request-input`), because those credit a file without naming its vulnerability.

| Tool | All security findings | Without per-file generic checks |
|---|---|---|
| larpcop | TP: 11/12   FN: 1   FP: 1 · missed: sast/seeds/nosql-operator.js · false positives: sast/seeds/clean-escaped.js · TPR = 0.92   FPR = 0.08 | TP: 11/12   FN: 1   FP: 0 · missed: sast/seeds/nosql-operator.js · TPR = 0.92   FPR = 0.00 |

Missed in both columns: `sast/seeds/nosql-operator.js`. The one false positive in the first column, `sast/seeds/clean-escaped.js`, comes from the per-file generic check and disappears in the second column.

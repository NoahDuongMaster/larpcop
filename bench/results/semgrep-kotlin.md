# Kotlin: Semgrep's labeled Kotlin rule tests

Four Kotlin test files of the Semgrep rules repository (semgrep/semgrep-rules at
16b9e6d, `kotlin/lang/security/`), whose authors labeled each case line
`// ruleid:` (should be reported) or `// ok:` (should not). The selection and
the scorer (`bench/semgrep_kotlin.py`) were committed (aaafc72) before any tool
ran on these files. The cookie tests are left out: Semgrep flags a cookie
missing `setSecure(true)`, larpcop's rules an explicit `false`.

larpcop only: these are Semgrep's own rule tests, so Semgrep passes them by
construction.

## First run (held-out)

| File (rule) | found | flagged wrongly |
|---|---|---|
| use-of-md5.kt (`kt-no-weak-hash`) | 1/2 | 0/1 |
| use-of-sha1.kt (`kt-no-weak-hash`) | 2/3 | 0/0 |
| ecb-cipher.kt (`kt-no-weak-cipher`) | 2/2 | 0/1 |
| command-injection-formatted-runtime-call.kt (`kt-taint-shell`) | 0/2 | 0/1 |
| **total** | 5/9 (56%) | 0/3 (0%) |

score (TPR - FPR): **+55.6%**

Missed: Apache Commons `DigestUtils.getMd5Digest()` / `getSha1Digest()`;
`r.exec("/bin/sh -c some_tool" + input)` and
`r.loadLibrary(String.format("%s.dll", input))`, where `input` is a parameter
of a function no request handler calls.

## After fixes (not held-out)

| File (rule) | found | flagged wrongly |
|---|---|---|
| use-of-md5.kt (`kt-no-weak-hash`) | 2/2 | 0/1 |
| use-of-sha1.kt (`kt-no-weak-hash`) | 3/3 | 0/0 |
| ecb-cipher.kt (`kt-no-weak-cipher`) | 2/2 | 0/1 |
| command-injection-formatted-runtime-call.kt (`kt-taint-shell`, `kt-no-shell-string`) | 1/2 | 0/1 |
| **total** | 8/9 (89%) | 0/3 (0%) |

score (TPR - FPR): **+88.9%**

Fixed: the weak-hash rules (Java and Kotlin) know Commons Codec / Spring
`DigestUtils` (`md5Hex`, `getSha1Digest`, `md5DigestAsHex`…) and Guava
`Hashing.md5()` / `sha1()`. New policy rules `java-no-shell-string` /
`kt-no-shell-string`: `Runtime.exec` of a string that starts with a shell
(`sh -c …`, `cmd /c …`) built from values. `exec("ls " + dir)` is not one:
without a shell, `Runtime.exec(String)` only splits on spaces. `loadLibrary` /
`System.load` are sinks of the `*-taint-shell` rules.

Still missed, by design: `loadLibrary` of a parameter that no request data
reaches. larpcop reports a parameter where a caller passes request data.

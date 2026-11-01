# VulnerableApp (SasanLabs/VulnerableApp 9f45cd5)

97 handlers in categories a SAST tool can check, labelled by the project (`variant = Variant.SECURE` safe, the default UNSECURE vulnerable); truth committed before any tool ran (4b055e8). Scored like java-sec-code: a finding of the handler's category inside it. Score per category = TPR − FPR.

## First run (larpcop e913760)

| category (vuln/safe) | larpcop | semgrep-default | semgrep-java |
|---|---|---|---|
| deserialization (3/1) | 0/3 TP, 0/1 FP (+0%) | 0/3 TP, 0/1 FP (+0%) | 0/3 TP, 0/1 FP (+0%) |
| ldap (4/2) | 0/4 TP, 0/2 FP (+0%) | 0/4 TP, 0/2 FP (+0%) | 0/4 TP, 0/2 FP (+0%) |
| path (12/3) | 0/12 TP, 1/3 FP (-33%) | 0/12 TP, 1/3 FP (-33%) | 0/12 TP, 1/3 FP (-33%) |
| redirect (9/3) | 0/9 TP, 0/3 FP (+0%) | 0/9 TP, 0/3 FP (+0%) | 0/9 TP, 0/3 FP (+0%) |
| shell (5/1) | 5/5 TP, 1/1 FP (+0%) | 0/5 TP, 0/1 FP (+0%) | 0/5 TP, 0/1 FP (+0%) |
| sql (8/11) | 8/8 TP, 2/11 FP (+82%) | 8/8 TP, 2/11 FP (+82%) | 8/8 TP, 2/11 FP (+82%) |
| ssrf (6/1) | 5/6 TP, 1/1 FP (-17%) | 4/6 TP, 0/1 FP (+67%) | 4/6 TP, 0/1 FP (+67%) |
| xss (14/7) | 0/14 TP, 0/7 FP (+0%) | 0/14 TP, 0/7 FP (+0%) | 0/14 TP, 0/7 FP (+0%) |
| xxe (3/4) | 1/3 TP, 0/4 FP (+33%) | 1/3 TP, 0/4 FP (+33%) | 1/3 TP, 0/4 FP (+33%) |
| **average** | **+7.2%** | **+16.5%** | **+16.5%** |
| **total** | 19/64 TP, 5/33 FP | 13/64 TP, 3/33 FP | 13/64 TP, 3/33 FP |

## After the fixes (not a held-out number)

| category (vuln/safe) | larpcop |
|---|---|
| deserialization (3/1) | 0/3 TP, 0/1 FP (+0%) |
| ldap (4/2) | 4/4 TP, 0/2 FP (+100%) |
| path (12/3) | 11/12 TP, 1/3 FP (+58%) |
| redirect (9/3) | 9/9 TP, 1/3 FP (+67%) |
| shell (5/1) | 5/5 TP, 1/1 FP (+0%) |
| sql (8/11) | 8/8 TP, 2/11 FP (+82%) |
| ssrf (6/1) | 6/6 TP, 0/1 FP (+100%) |
| xss (14/7) | 5/14 TP, 0/7 FP (+36%) |
| xxe (3/4) | 3/3 TP, 0/4 FP (+100%) |
| **average** | **+60.3%** |
| **total** | 51/64 TP, 5/33 FP |

Still wrong: a check in a lambda kept in a variable, or with several branches (`Supplier<Boolean> validator = () -> { … }`), and method references (`WHITELISTED_URLS::contains`) are not read; a lambda check `!name.contains("..")` counts as a guard, as it does in an `if`. Stored XSS through the database (6 handlers): the database is not a source. HTML-escaped input in an unquoted attribute (`<img src=%s>`): escaping is not judged by context. Jackson `readValue` behind a project util: `java-no-jackson-default-typing` reports the mapper's configuration, outside the handlers. SQL levels 3/4 concatenate after stripping quotes; `java-no-sql-concat` forbids the concatenation itself. Fixed since the first write-up: JAXB `Unmarshaller.unmarshal(stream)` is XXE; external general entities off without parameter entities off is not a fix.

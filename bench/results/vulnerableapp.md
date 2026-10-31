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

| category (vuln/safe) | larpcop | semgrep-default | semgrep-java |
|---|---|---|---|
| deserialization (3/1) | 0/3 TP, 0/1 FP (+0%) | 0/3 TP, 0/1 FP (+0%) | 0/3 TP, 0/1 FP (+0%) |
| ldap (4/2) | 4/4 TP, 0/2 FP (+100%) | 0/4 TP, 0/2 FP (+0%) | 0/4 TP, 0/2 FP (+0%) |
| path (12/3) | 12/12 TP, 3/3 FP (+0%) | 0/12 TP, 1/3 FP (-33%) | 0/12 TP, 1/3 FP (-33%) |
| redirect (9/3) | 9/9 TP, 1/3 FP (+67%) | 0/9 TP, 0/3 FP (+0%) | 0/9 TP, 0/3 FP (+0%) |
| shell (5/1) | 5/5 TP, 1/1 FP (+0%) | 0/5 TP, 0/1 FP (+0%) | 0/5 TP, 0/1 FP (+0%) |
| sql (8/11) | 8/8 TP, 2/11 FP (+82%) | 8/8 TP, 2/11 FP (+82%) | 8/8 TP, 2/11 FP (+82%) |
| ssrf (6/1) | 6/6 TP, 0/1 FP (+100%) | 4/6 TP, 0/1 FP (+67%) | 4/6 TP, 0/1 FP (+67%) |
| xss (14/7) | 5/14 TP, 0/7 FP (+36%) | 0/14 TP, 0/7 FP (+0%) | 0/14 TP, 0/7 FP (+0%) |
| xxe (3/4) | 1/3 TP, 0/4 FP (+33%) | 1/3 TP, 0/4 FP (+33%) | 1/3 TP, 0/4 FP (+33%) |
| **average** | **+46.4%** | **+16.5%** | **+16.5%** |
| **total** | 50/64 TP, 7/33 FP | 13/64 TP, 3/33 FP | 13/64 TP, 3/33 FP |

Still wrong: validation passed as a lambda or method reference to the helper that reads the file / runs the command / redirects (`readFile(() -> ALLOWED.contains(f), f)`, `WHITELISTED_URLS::contains`): 5 secure handlers reported. Stored XSS through the database (6 handlers): the database is not a source. HTML-escaped input in an unquoted attribute (`<img src=%s>`): escaping is not judged by context. Jackson polymorphic `readValue` behind a project util: `java-no-jackson-default-typing` reports the mapper's configuration, outside the handlers. JAXB `Unmarshaller.unmarshal` (XXE level 1): no rule. SQL levels 3/4 concatenate after stripping quotes; `java-no-sql-concat` forbids the concatenation itself.

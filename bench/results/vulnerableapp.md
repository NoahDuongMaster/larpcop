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
| path (12/3) | 11/12 TP, 0/3 FP (+92%) |
| redirect (9/3) | 9/9 TP, 0/3 FP (+100%) |
| shell (5/1) | 5/5 TP, 0/1 FP (+100%) |
| sql (8/11) | 8/8 TP, 2/11 FP (+82%) |
| ssrf (6/1) | 6/6 TP, 0/1 FP (+100%) |
| xss (14/7) | 14/14 TP, 1/7 FP (+86%) |
| xxe (3/4) | 3/3 TP, 0/4 FP (+100%) |
| **average** | **+84.4%** |
| **total** | 60/64 TP, 3/33 FP |

Spring Data repositories are sources of `java-taint-stored-xss`: the reading methods (`find*`, `get*`, `stream*`…) of a field, local or parameter declared as a `*Repository`/`*Dao`, so the 6 stored XSS handlers (`postRepository.findByLevelIdentifier(level).forEach(post -> posts.append(…))`) are found. That needed Java callbacks to receive the elements of the list they run over (`list.forEach(p -> …)` named its receiver differently from JS), and what a callback writes into the names it captures (`posts`) to hold after it. SECURE levels 7 and 9 pass an escaping lambda into the shared helper (`post -> StringEscapeUtils.escapeHtml4(post)`), which the helper applies with `function.apply(…)`: a function that runs one of its parameters gets a summary per such parameter with those calls clean, used when the argument is a function that always returns clean data. Level 8 is still reported: it rejects `<` and `>` before saving, so what the database holds for that level was checked when it was written, which no reading of the handler can tell.

Still wrong: a lambda check `!name.contains("..")` counts as a guard, as it does in an `if`. Jackson `readValue` behind a project util: `java-no-jackson-default-typing` reports the mapper's configuration, outside the handlers. SQL levels 3/4 concatenate after stripping quotes; `java-no-sql-concat` forbids the concatenation itself. Fixed since the first write-up: a check on a normalized path built from the input (`Paths.get(BASE + fileName).normalize().startsWith(base)`, in a lambda) proves the input; HTML escaping is judged by where the value lands (`<img src=%s>` with `escapeHtml4` is reported, 3 handlers); JAXB `Unmarshaller.unmarshal(stream)` is XXE; external general entities off without parameter entities off is not a fix.

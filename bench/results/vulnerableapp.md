# VulnerableApp (SasanLabs/VulnerableApp 9f45cd5)

Java, Spring. 97 handlers in categories a static analyzer can check, labelled by the project (`variant = Variant.SECURE` is safe, the default UNSECURE is vulnerable); the answer key (`bench/truth/vulnerableapp-truth.json`) was committed before any tool ran. Scored like java-sec-code: a finding of the handler's category inside it. Score per category = TPR − FPR.

## First run (before rules were added for this suite)

| category (vuln/safe) | larpcop |
|---|---|
| deserialization (3/1) | 0/3 TP, 0/1 FP (+0%) |
| ldap (4/2) | 0/4 TP, 0/2 FP (+0%) |
| path (12/3) | 0/12 TP, 1/3 FP (-33%) |
| redirect (9/3) | 0/9 TP, 0/3 FP (+0%) |
| shell (5/1) | 5/5 TP, 1/1 FP (+0%) |
| sql (8/11) | 8/8 TP, 2/11 FP (+82%) |
| ssrf (6/1) | 5/6 TP, 1/1 FP (-17%) |
| xss (14/7) | 0/14 TP, 0/7 FP (+0%) |
| xxe (3/4) | 1/3 TP, 0/4 FP (+33%) |
| **average** | **+7.2%** |
| **total** | 19/64 TP, 5/33 FP |

## Current

Rules and engine were adjusted after the first run using this suite's misses, so these numbers are not held-out.

| category (vuln/safe) | larpcop |
|---|---|
| deserialization (3/1) | 1/3 TP, 0/1 FP (+33%) |
| ldap (4/2) | 4/4 TP, 0/2 FP (+100%) |
| path (12/3) | 11/12 TP, 0/3 FP (+92%) |
| redirect (9/3) | 9/9 TP, 0/3 FP (+100%) |
| shell (5/1) | 5/5 TP, 0/1 FP (+100%) |
| sql (8/11) | 8/8 TP, 2/11 FP (+82%) |
| ssrf (6/1) | 6/6 TP, 0/1 FP (+100%) |
| xss (14/7) | 14/14 TP, 1/7 FP (+86%) |
| xxe (3/4) | 3/3 TP, 0/4 FP (+100%) |
| **average** | **+88.1%** |
| **total** | 61/64 TP, 3/33 FP |

Stored XSS: Spring Data repositories are sources of `java-taint-stored-xss`, namely the reading methods (`find*`, `get*`, `stream*`…) of a field, local or parameter declared as a `*Repository`/`*Dao`. With that, the 6 stored XSS handlers (`postRepository.findByLevelIdentifier(level).forEach(post -> posts.append(…))`) are found. This relies on Java callbacks receiving the elements of the list they run over (`list.forEach(p -> …)`) and on what a callback writes into the names it captures (`posts`) holding after it. SECURE levels 7 and 9 pass an escaping lambda into the shared helper (`post -> StringEscapeUtils.escapeHtml4(post)`), which the helper applies with `function.apply(…)`: a function that runs one of its parameters gets a summary per such parameter with those calls clean, used when the argument is a function that always returns clean data. Level 8 is reported as vulnerable: it rejects `<` and `>` before saving, so what the database holds was checked when it was written, which reading the handler cannot show.

Other behaviour the numbers depend on:

- Jackson `readValue` behind a project util is a sink of `java-taint-deserialization` when that mapper turns default typing on in its file (`sink_configured`: the initializer, the factory method it calls, calls made on the name), so level 4 (`POLYMORPHIC_MAPPER`, built by `createPolymorphicMapper()` with `activateDefaultTyping(LaissezFaireSubTypeValidator…)`) is found.
- A check on a normalized path built from the input (`Paths.get(BASE + fileName).normalize().startsWith(base)`, in a lambda) proves the input.
- HTML escaping is judged by where the value lands: `<img src=%s>` with `escapeHtml4` is reported (3 handlers).
- JAXB `Unmarshaller.unmarshal(stream)` is XXE; external general entities off without parameter entities off is not a fix.

Remaining errors:

- A lambda check `!name.contains("..")` counts as a guard, as it does in an `if`.
- SQL levels 3 and 4 concatenate after stripping quotes; `java-no-sql-concat` forbids the concatenation itself.
- Deserialization levels 1 and 2 bind the JSON to one fixed class (`TYPED_MAPPER.readValue(json, UserPreferences.class)`): no class the sender names is built, and the flaw is trusting an unsigned cookie (an authorization question), which no sink models.

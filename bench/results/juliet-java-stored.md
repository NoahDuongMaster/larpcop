# NIST Juliet Java 1.3: stored XSS

The XSS cases of Juliet Java (CWE80, CWE81, CWE83) whose data comes from a
database row (`_Servlet_database_`: `statement.executeQuery(…)`, then
`resultSet.getString(1)`), scored with `juliet.py --stored`: a case is found
when a finding lands in its `bad` code and flagged wrongly when one lands in
its `good` code. The selection, the scorer and the name of the rule it counts
(`java-taint-stored-xss`) were committed (c9056cc) before the rule was written
and before any tool ran on these files. Semgrep 1.183.0 with
`p/default` and `p/java`.

## First run (held-out)

| Category (cases) | larpcop: found / good flagged / score | Semgrep (juliet-stored-semgrep-default): found / good flagged / score | Semgrep (juliet-stored-semgrep-java): found / good flagged / score |
|---|---|---|---|
| xss (148) | 75% / 0% / **+75%** | 0% / 0% / **+0%** | 0% / 0% / **+0%** |
| **average** | **+75.0%** | **+0.0%** | **+0.0%** |

Every CWE80 and CWE83 case is found, and no `good` code is flagged. The 37
misses are the CWE81 cases, which write the value with `response.sendError`:
larpcop does not treat `sendError` as an HTML sink, on purpose, as in the
request-data cases (`juliet-java.md`).

`java-taint-stored-xss` takes rows read through JDBC (`executeQuery`,
`getResultSet`), Spring's `JdbcTemplate.queryFor*` and JPA query results
(`getResultList`, `getSingleResult`) as sources, with the sinks, escapers and
HTML contexts of `java-taint-xss`. A value held in a local declared `int`,
`long`, `boolean`, `UUID`… carries no markup (`int n = rs.getInt(1)`); that
holds for every rule in Java, C# and Kotlin, which enforce declared types when
the program runs, not for TypeScript annotations.

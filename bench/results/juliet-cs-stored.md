# NIST Juliet C# 1.3: stored XSS

The XSS cases of Juliet C# (CWE80, CWE81, CWE83) whose data comes from a database row (`_Web_Database_`), 148 cases scored with `bench/scripts/juliet.py --stored` as the Java set (`juliet-java-stored.md`). The selection and the rule counted (`cs-taint-stored-xss`) were committed before the rule was written and before any tool ran on these files. The numbers are those of the first run; no rule was changed in response to them.

| Category (cases) | larpcop: found / good flagged / score |
|---|---|
| xss (148) | 100% / 0% / **+100%** |
| **average** | **+100.0%** |

`cs-taint-stored-xss` takes rows read through ADO.NET (`ExecuteReader`,
`ExecuteScalar`), Dapper (`Query<T>`, `QueryFirst<T>`…) and EF Core raw SQL
(`FromSqlRaw`, `SqlQuery<T>`) as sources, with the sinks and encoders of
`cs-taint-xss`. Unlike the Java servlet cases, Juliet C#'s CWE81 cases write
the value into the response body, so they are found too.

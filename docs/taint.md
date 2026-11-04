# Taint analysis

This page describes how larpcop's taint rules follow data across functions and files, the `taint:` rule format, what the 99 `recommended` taint rules cover, type-aware sinks, and the known limits of the analysis.

[Back to the README](../README.md)

Taint analysis is layer 2 of the four security layers described in [security](security.md).

## Tracking across functions and files

larpcop follows data from `sources` to the argument of `sinks` through assignments, in code line order.

- Data that passes through `sanitizers` is clean.
- Assigning a clean value to a variable ends its taint.
- Destructuring is followed.
- Each function has a summary: which parameters reach a sink, which parameters are returned, and whether the function returns source data.
- Because of the summaries, data is followed through function calls in the same file, through `import`/`require`/tsconfig aliases, through Python `from … import`, and through packages in the same Go module.
- Callbacks and closures see the tainted variables they capture.
- A method is known as `Class.method`, also when the class is imported. For `obj.method(…)` where the type of `obj` is unknown, larpcop uses the only method that has that name.
- A field that a method assigns tainted data to (`this.term = req.query.q`, `self.term = …`) is tainted in every other method of that class.

## Rule format

Patterns are written in ast-grep syntax:

```yaml
taint:
  - id: taint-sql
    languages: [TypeScript, Tsx, JavaScript]
    message: Request data reaches a SQL query.
    sources: ["req.query", "req.body", "req.params"]
    sinks: ["$DB.query($SQL)", "$DB.query($SQL, $$$REST)"]
    sink_arg: SQL                 # only this argument must be clean
    sanitizers: ["Number($X)", "$S.parse($X)"]
    guards: ["$U.startsWith($P)", "$L.includes($U)"]   # true when the value is safe
    rejects: ['$P.includes("$S")']                    # true when the value is NOT safe ("..")
    unless: ['new\s+Yaml\s*\(\s*new\s+SafeConstructor']  # the function containing the sink built it safely: no finding
    safe_prefix: '^/[^/\\]'                          # "/products/" + id: a fixed prefix is safe
    param_decorators: [Body, Query]                   # NestJS: the @Body() dto is request data
    handler_decorators: '^\w+\.(get|post|route)\('     # Python: every parameter of a route function
    resolver_args: true                               # GraphQL: (parent, args) => …
    response_returns:                                 # the value a handler returns is the response body
      headers: ['@(Get|Post)Mapping\b', '@(ResponseBody|RestController)\b']   # all of them match the header of the function/class
      not: 'produces\s*=\s*[^)]*json'
      types: '^String$'                               # declared return type, if any
```

### Key summary

| Key | Meaning | Details |
| --- | --- | --- |
| `id` | Rule id. | [Rule format](#rule-format) |
| `languages` | Languages the rule applies to. | [Rule format](#rule-format) |
| `message` | Message of the finding. | [Rule format](#rule-format) |
| `sources` | Patterns where data counts as tainted. | [Tracking](#tracking-across-functions-and-files) |
| `sinks` | Patterns whose argument must be clean. | [Tracking](#tracking-across-functions-and-files) |
| `sink_arg` | The metavariable naming the only sink argument that must be clean. | [Rule format](#rule-format) |
| `sanitizers` | Patterns that make a value clean. | [Tracking](#tracking-across-functions-and-files) |
| `guards` | True in an `if` condition when the value is safe. | [Guards and rejects](#guards-and-rejects) |
| `rejects` | True in an `if` condition when the value is not safe. | [Guards and rejects](#guards-and-rejects) |
| `unless` | Regexes on the function that contains the sink: on a match, the function built the sink safely and nothing is reported. | [Rule format](#rule-format) |
| `safe_prefix` | Regex on the fixed start of a concatenated argument. | [Safe prefix](#safe-prefix) |
| `param_decorators` | Parameters with one of these decorators or annotations are request data (NestJS `@Body()`, `@Query()`). | [Other sources of request data](#other-sources-of-request-data) |
| `handler_decorators` | Regex on the decorators or annotations of a function: when it matches, every parameter of the function is request data (for example a Python route function). | [Other sources of request data](#other-sources-of-request-data) |
| `resolver_args` | GraphQL resolver arguments are request data. | [Other sources of request data](#other-sources-of-request-data) |
| `response_returns` | The value a handler returns is a sink. | [Response returns](#response-returns) |
| `html_fragments` | Values concatenated into HTML markup assigned to a variable are sinks (enabled for PHP). | [HTML fragments](#html-fragments) |
| `exclude` | Glob of files in which the rule reports nothing. | [Excluded files](#excluded-files) |
| `sanitizer_names` | Regex on called function names whose result is always clean. | [Source and sanitizer names](#source-and-sanitizer-names) |
| `source_names` | Names that are sources at every place they are read. | [Source and sanitizer names](#source-and-sanitizer-names) |
| `quote_escapers` | Functions that only escape quotes. | [Escaping and context](#escaping-and-context) |
| `sink_types` | Required type of a sink metavariable. | [Type-aware sinks](#type-aware-sinks) |
| `strict_sink_types` | Like `sink_types`, but the sink counts only when the receiver type is certain (a declaration, or `new URL(…)` right at the sink). | [Sink matching](#sink-matching) |

Top-level key `language_servers` sets the language server commands (see [Type-aware sinks](#type-aware-sinks)).

## Example

```ts
const name = req.query.name as string;
const sql = "SELECT * FROM users WHERE name = '" + name + "'";
res.json(await db.query(sql));          // taint-sql
```

The rule `taint-sql` reports the last line.

## Guards and rejects

`guards` and `rejects` are checks on the condition of an `if`.

- `guards` is true when the value is safe (`isLocalUrl(u)`, `allowed.includes(h)`).
- `rejects` is true when the value is not safe (`name.includes("..")`).

Conditions are read through `!`, `&&`, `||`, `not in` and comparisons with `false`/`-1`/`null` (`s.indexOf("..") === -1`, `strpos($p, "..") !== false`). The variable is clean in the branch that runs when the check says the value is safe, and after the `if` when the other branch exits (`return`, `throw`, `die()`, `abort()`, `panic()`…). `if (!isLocalUrl(u)) { redirect(u) }` is still reported.

When a call matches both lists (`allowed.includes(x)` matches `$A.includes($B)`), the more specific pattern decides: the one with more characters that are not metavariables.

### Equality with a literal

A comparison for equality with a string literal is a built-in guard in every language and needs no declaration. When `x == "jpg"` is true, `x` is that string, also through a function that only changes case (`strtolower($ext) == 'jpg' || strtolower($ext) == 'png'`, `kind.lower() == 'csv'`). `substr($x, 0, 3) == 'abc'` and `x != ''` do not count.

### Safe prefix

`safe_prefix` is a regex on the fixed part at the start of a concatenated argument. `res.redirect("/p/" + id)` cannot lead outside the site. It also decides whether a guard `x.startsWith("…")` can be trusted.

With `safe_prefix`, a variable that starts with a safe value (`url = reverse(…)`, `url = "/search"`) stays clean when more is appended (`url += "?q=" + q`). The same holds for `reverse(…) + "?q=" + q` at the sink.

### Project functions as guards

A function of the project itself is also a guard when it returns `null`/`false`/`None`/`nil` unless its parameter has passed a guard (`static String cmdFilter(String s) { if (!P.matcher(s).matches()) return null; return s; }`, `def is_safe(p): return '..' not in p`). `if (pathFilter(p) == null) return;` cleans `p` exactly as a `guards:` pattern does. A function that returns `null` for another reason (`if (p.isEmpty()) return null;`) does not count.

### Replacing an unsafe value

A branch that replaces the unsafe value with a clean one (`if not nxt or urlsplit(nxt).netloc != '': nxt = url_for('index')`) also cleans the variable after the `if`. The condition proves that the path that does not enter the branch is safe. `if not nxt: nxt = url_for('index')` does not clean it.

## Special sink keys

### HTML fragments

`html_fragments` (enabled for PHP) treats a value that is concatenated into a string containing an HTML tag, and then assigned to a variable, as a sink at the point of concatenation:

```php
$html .= '<pre>Hello ' . $_GET['name'] . '</pre>'
```

PHP pages often build markup into a variable that a shared template prints later, through an `include` whose path is only known at runtime. Markup has only one use: to be displayed.

### Response returns

`response_returns` treats the value a handler returns as a sink: a Spring `@ResponseBody`/`@RestController` method that returns a `String`, or a Flask view that returns an HTML string.

### Excluded files

`exclude` is a glob of files in which the rule reports nothing. The `recommended` set skips test files: `res.end('poking ' + req.params.user)` in an Express test is not a vulnerability. Functions in those files are still used when another file calls them.

## Recommended taint rules

The `recommended` set has 99 taint rules. They are listed here by language.

### JavaScript and TypeScript

Rules for:

- SQL
- shell
- open redirect
- code injection (`eval`, `vm`, `mathjs.eval`)
- reflected XSS (`res.send` of an HTML string, `innerHTML`)
- path traversal
- SSRF
- NoSQL injection (MongoDB/Mongoose; Sequelize filters are not covered)
- regex injection
- log injection

### Python

Rules for:

- SQL.
- OS commands: `os.system`, `shell=True`, and argument lists that run through a shell such as `['sh', '-c', cmd]`, including lists built with `append` in `if`/`else` branches. With `sh -c` only the element right after `-c` is the command. With `cmd /c` every element after it is.
- Path traversal. This includes `p = base / name` followed by `p.exists()`/`p.read_text()` when `p` is certainly a `pathlib.Path`. The `exists()` of a Django queryset does not count.
- SSRF.
- SSTI (`render_template_string`).
- XSS (`Markup`, `mark_safe`, `make_response`/`HttpResponse` of a string).
- Open redirect (`url_for`/`reverse` are safe).
- Code injection.
- Deserialization (`pickle`, `yaml.load`).
- Log injection. Sources come from Flask, Django, FastAPI/Starlette, aiohttp and Tornado. `request.path` in a handler whose route has no variable is the route itself, unless the project mounts a blueprint under a `url_prefix` that has a variable.

### Go

Rules for Go (net/http, gin, echo, chi, gorilla/mux):

- SQL
- shell
- path traversal
- SSRF
- open redirect
- XSS (`template.HTML`, writing straight to `ResponseWriter`)

### Java

Rules for Java (Servlet, Spring with `@RequestParam`/`@PathVariable`/`@RequestBody`…). Classes imported from another package are followed through the `src/main/java` source root of every module. The rules are:

- SQL (JDBC, JdbcTemplate, JPA).
- OS commands (including `loadLibrary`/`System.load`).
- Stored XSS (`java-taint-stored-xss`): a row read through JDBC `executeQuery`, `JdbcTemplate.queryFor*`, JPA `getResultList`, or a `find*`/`get*`/`stream*` read method of a field declared with a Spring Data `*Repository`/`*Dao` type, that goes into the response without escaping.
- Path traversal.
- XSS.
- LDAP.
- XPath.
- Open redirect.
- Trust boundary.
- SSRF (`openConnection`, `RestTemplate`, `Jsoup.connect`).
- Code injection (ScriptEngine, SpEL, OGNL, MVEL, `Class.forName`).
- Deserialization (`ObjectInputStream`, `XMLDecoder`, XStream, Jackson `readValue`). `readValue` counts when that mapper has default typing enabled in the file: `activateDefaultTyping` at the place the mapper is created, in the factory function it calls, or called on that same name.
- SSTI (Velocity, FreeMarker, Thymeleaf/Pebble/Jinjava with a template from the request).
- XSS when a `@ResponseBody` handler returns a string.
- `return "redirect:" + url`.
- MyBatis `setOrderByClause`.

### gRPC methods

A gRPC method receives the client's message as a parameter, so that parameter is tainted data. How a gRPC method is recognised depends on the language:

| Language | Recognised by |
| --- | --- |
| Java/Kotlin | A class that extends `*ImplBase`/`*CoroutineImplBase`, or a method with a `StreamObserver` parameter. |
| C# | A `ServerCallContext` parameter. |
| Python | A `*Servicer` class. |
| Go | `in *pb.XxxRequest` in a method that has a receiver and takes `ctx context.Context`. |
| Node | `call.request`. |

Framework parameters (observer, context, `*http.Request`) are not tainted.

### Kotlin

12 corresponding rules (`kt-taint-*`):

- They use the same Servlet and Spring sources as Java.
- Getters are read as properties (`request.queryString`, `response.writer`).
- They add Ktor (`call.parameters[…]`, `call.receiveText()`, `call.respondRedirect`, `call.respondFile`) and Exposed `exec`.
- `toInt()` and similar calls are sanitizers.
- They follow top-level functions in the same package, an `import` to a `.kt` or `.java` file, `x?.let { … it … }`, `forEach { }` and `x !in allowed`.
- In addition there are `kt-no-weak-hash` and `kt-no-weak-cipher`, which trace the algorithm to its real value as the Java version does.

### PHP

Rules for SQL, OS commands, `eval`, path traversal/file inclusion, XSS, SSRF, header/redirect, `unserialize`, LDAP and XPath.

- Sources are `$_GET`/`$_POST`… and Laravel `$request->input()`.
- A function in a file that is `require`d has a summary.
- A file that mixes HTML with `<?php … ?>`/`<?=` is read as PHP code, and line numbers stay the same.
- A field that the constructor or another method assigns request data to is followed into the getters of the class.
- Casts, `settype`, `filter_var` for numbers or IPs, arithmetic and `sprintf("%d", …)` produce numbers.
- `preg_match` with an allow-list anchored as `^…$` is a guard, also when the pattern is in a local variable and the result is compared with `== 1`.
- `->query()` is an XPath sink only on `DOMXPath`.
- `foreach ($rows as $k => $v)` assigns each element.
- A row read from the database into the page is stored XSS: `php-taint-stored-xss`.

### C#

Rules for C# (ASP.NET Core):

- SQL (ADO.NET, Dapper, EF Core `FromSqlRaw`).
- OS commands.
- Path traversal.
- XSS, including stored XSS from rows read through ADO.NET, Dapper or EF Core (`cs-taint-stored-xss`).
- SSRF.
- Open redirect.
- LDAP.
- XPath.
- Deserialization.

Sources are `Request.Query`/`Form`/`Cookies`… and the parameters of actions marked `[HttpGet]`/`[FromQuery]`….

### Ruby

Rules for Ruby (Rails, Sinatra):

- SQL (ActiveRecord `where`/`order`/`find_by_sql`, `connection.execute`).
- OS commands (`system`, backtick, `Open3`).
- `eval`/`constantize`/`send`.
- Path traversal (`File.read`, `send_file`, `render file:`).
- XSS (`html_safe`, `raw`, `render html:`).
- Open redirect.
- SSRF.
- `Marshal.load`/`YAML.load`.

Sources are `params`, `cookies` and `request.*`. The constant `User` is loaded from `app/*/user.rb`, like Rails autoload.

How Ruby code is read:

- Calls without parentheses (`system cmd`, `redirect_to url`, and a bare `current_user`), implicit return values (the last line of a method), Rails `scope :name, ->(x) { … }` and `unless`/`… if x` conditions are all read.
- `where(id: x)` (a hash) is a bind parameter, not SQL.
- A record found with request data (`User.find_by(token: …)`) is data of the database, not of the request.

### C and C++

Rules `c-taint-shell` and `c-taint-format`:

- OS commands: `system`, `popen`, and the `exec*`/`_spawn*` family when the argument vector runs through `sh -c`/`cmd /c`.
- Format string: `printf(data)`, `fprintf`, `snprintf`, `syslog`…

How the analysis works:

- Sources are `getenv` and the functions that write external data into an argument (`fgets(buf, …)`, `recv(s, buf, …)`, `scanf`).
- Data flows through the functions that copy into their first argument (`strcpy`, `strncat`, `sprintf`, `memcpy`…).
- Macros that only rename (`#define SYSTEM system`, `#define ARG data`) are substituted before parsing, and line numbers stay the same.
- A function that is called (or taken as a function pointer) but not defined in the file is looked up in the C/C++ files in the same directory.
- Pointers to local variables are followed (`char **p = &data`: writing through `*p` writes to `data`). So are function pointers (`void (*fp)(char *) = sink; fp(x)`) and global variables (`static`/`extern`) that the called function reads.

Environment variables that login sets for the user's own session (`HOME`, `USER`, `SHELL`, `PWD`, `TMPDIR`, `PATH`…) are not sources, because anyone who can change them already runs with that user's privileges. `LANG`/`LC_*`/`TERM` (SSH forwards them), CGI variables (`QUERY_STRING`, `HTTP_*`) and variables specific to the application are still sources.

## Notes for all languages

### Source and sanitizer names

- `sanitizer_names` is a regex on the names of called functions whose result is always clean. Rails route helpers `*_path`/`*_url` only build URLs of the app itself.
- A source written as a bare name (`params`) is no longer a source in a function that has a parameter with the same name (`def error_messages_for(*params)`).
- `source_names` declares names that are sources at every place they are read. `$_GET` cannot be written as an ast-grep pattern, because `$_…` is a metavariable.

### Cleaning inside branches

A clean assignment inside a branch (`if`, loop, `try`) only cleans the variable up to the end of that branch. After `if (p == null) p = "";` the variable `p` is still tainted.

### Other sources of request data

Request data that does not come through `req.query` also counts:

- Parameters with a NestJS decorator (`@Body()`, `@Query()`), unless they pass through `ParseIntPipe`….
- Parameters of a route function declared with a decorator (FastAPI, Flask), except those typed `int`/`UUID`… that the framework has already checked, and `Depends(...)`.
- Arguments of a GraphQL resolver (`(parent, args) => …`, `def resolve_x(root, info, id)`).

### Sink names

Sinks are declared by object name (`cp.exec`, `res.send`, `session.get`), because `$X.exec` also matches `RegExp.prototype.exec` and `$X.get` matches `dict.get`.

### Layer 1 and layer 2

Layer 1 (see [security](security.md)) catches ``db.query(`…${id}`)`` at the call site. Layer 2 catches what layer 1 does not see, when the SQL string is built in a variable or in another function.

In Java, C# and Kotlin, a variable declared with a numeric, boolean or UUID type (`int n = rs.getInt(1)`, `long id`) carries no string, so it is not considered tainted. TypeScript annotations (`id: number`) do not count, because the value can still be a string at runtime.

## Type-aware sinks

Types declared in the code are read first: `Statement st`, `ExpressRunner r`, `var x = new T()`, `db: Pool`, and a class that is called statically as in `URLUtil.url(x)`. So in Java, C# and TypeScript, `sink_types` usually does not need a server:

- `$S.execute($SQL)` counts only when `S` is declared as `Statement`/`Connection`/`JdbcTemplate`…. It does not count `executor.execute(task)`.
- A variable of unknown type keeps its finding.

For everything else, larpcop asks the project's own language server (typescript-language-server, pyright, gopls, rust-analyzer) instead of implementing its own type checker. `sink_types` requires the metavariable of the sink to have a type that matches the regex:

```yaml
    sinks: ["$DB.query($SQL)"]
    sink_arg: SQL
    sink_types: { DB: "\\bPool\\b" }   # pool.query(sql) is caught; searchIndex.query(text) is not
```

larpcop only asks the server about candidates that the syntax layer has already found, once per position, so the cost is paid only when there are candidates. Trial runs took 1.9 s with tsserver, 0.5 s with pyright, 0.7 s with gopls and 6 s with rust-analyzer, which has to load the workspace. larpcop waits for rust-analyzer to report that it is done through `experimental/serverStatus`.

If the server is missing, cannot start or does not answer, the finding is kept. In other words, the check fails closed.

- The server command can be changed with `language_servers: { typescript: [...] }`.
- `LARPCOP_DEBUG_TYPES=1` prints the answers of the server.
- Tests run with all four real servers, also in CI.

A language server answers with the right types only when the project has all its dependencies installed.

## Limitations

### Second-order SQL

Rules `{php,py,go,java,cs}-taint-stored-sql`. The source is a place that reads a row (`mysqli_fetch_assoc`, `fetchone`, `rows.Scan`, `ResultSet.getString`, `SqlDataReader.GetString`). The sink is a query.

In Java and C#, `executeQuery`/`ExecuteReader` both read and are the sink. So the source there is the function that gets the value of the row, not the query call. In Java, a value that goes through a `ResultSet` whose type is not declared in the file cannot be followed.

### Script blocks in pages

`<script>` in pages (`.html`, `.php`, `.jsp`, `.erb`, `.twig`, `.vue`, `.svelte`…) is read as a JavaScript file, so the JS rules and DOM taint apply to it. Handlers written in attributes (`onclick="…"`) are not read this way. `<script src>` is still a normal `.js` file.

### Taint is approximate

#### Sink matching

A sink whose method name matches a common method (`URL.getContent()` versus the `getContent()` of a page or entity) counts only when the type of the receiver is certain (`strict_sink_types`: a declaration, or `new URL(…)` right at the sink).

#### Fields and objects

- Fields of the object itself (`this.x`, `self.x`, `$this->x`, and Java/C# fields written without `this.`) are followed between the methods of a class.
- A static field of another class that the called function reads (`String data = CaseA.data;`) is treated as an implicit parameter. The call is reported when the caller holds that field tainted (`data = request.getParameter(…)` in `CaseA`, or `CaseA.data = …`). It is not reported when the caller has just assigned a constant.
- A field of another object, read in another method, is not followed.
- A call through a name declared as an interface or a superclass (`Store s; s.save(x)`, a Spring-injected field) goes to every known implementation of that type. A sink or a return value of any implementation counts. A check function counts only when every implementation checks.
- A call on an object of unknown type is followed only when every class that has a method with that name does the same thing.
- Data written to a stream is followed (`out.writeObject(x)`, C# `formatter.Serialize(ms, x)`, also a stream wrapped inside `new ObjectOutputStream(bytes)`). So data that is serialized and read back in another class still carries taint.
- Java and C# treat files in the same directory, whose class name is mentioned, as the same package. Java also reads classes written with their full name and no import, and classes that `implements` an imported interface (a Spring-injected implementation in another package).
- A setter (`p.setNote(x)`) of an object that the scope itself created (`new PayRequest()`) makes the object carry the value.
- A function that stores an argument into an object it receives (`fill(o, x)` calls `o.setNote(x)` or `l.add(x)`) makes the object of the caller carry the value after the call. A getter (`o.getNote()`) of that object returns tainted data.
- A field assigned from tainted data (`o.name = x`) taints only that field (`o.kind` stays clean). Passing the whole object carries the taint along.

#### Imports and library calls

- Imports are followed 4 levels deep. In the first 2 levels every file is summarised. In the last 2 levels only a file is summarised when it, or a file it imports, matches a source or sink of the rule. For other files, a call into them is treated as passing the taint straight through, so skipping them loses no finding.
- A chain longer than 5 files is not followed (collections are: `push`, `set`, `append`, `Object.assign`…).
- The return value of a function without a summary (a library) is considered tainted if an argument is tainted.

#### Callbacks and collections

- A mapped collection carries exactly the value that the callback returns. This covers `xs.map(…)` (JS, Java streams, Ruby, Kotlin), `Select` (C#), `map(f, xs)` (Python), `array_map` (PHP) and Python list comprehensions.
- The callback can be an expression (`x -> esc(x)`).
- The callback can have several statements. Local variables are followed in order, an assignment in a branch only taints and does not clean, every `return` counts, and the last statement of a Kotlin/Ruby block is also a value.
- The callback can be a function reference (`Encode::forHtml`, `::esc`, `html.escape`, `'htmlspecialchars'`). It is clean if it is a sanitizer of the rule, follows its summary if it is a function of the project, and is tainted if it is any other library function.
- A callback that runs on a tainted collection (`list.forEach(p -> …)`, in Java too) receives each element. What the callback writes into variables of the outer scope (`out.append(p.getContent())`) is kept after it.
- A function that runs a function it receives (`render(rows, format)` calls `format(r)`, Java `function.apply(x)`) gets one extra summary for each such parameter, which treats those calls as sanitizing. When the caller passes a function that always returns clean data (`post -> StringEscapeUtils.escapeHtml4(post)`, `escapeHtml` by reference), that summary is used. Passing `x -> x` does not use it.

#### Guards in loops, switches and lambdas

`guards` read the conditions of `if`, the ternary operator (`isLocal(u) ? u : "/"`) and loops.

- In a loop, the condition is true inside the body and false after it if the body does not `break` out. `while (p.includes("..")) p = p.replace("..", "")` cleans `p`. The same holds for `do … while` and Ruby `until`/`… while c`.
- A branch of `switch`/`when`/`match` on a variable with fixed labels (a literal, constants such as `MODE`/`Mode.FAST`, Kotlin `in ALLOWED`) cleans that variable inside the branch. The `default` branch, or a branch that falls through from a label that is not fixed, does not.
- A self-written check function counts when it returns `null`/`false` unless its parameter has passed a known guard.
- A check that is passed to a function which runs the sink only when the check is true also counts:
  - a lambda (`readFile(() -> ALLOWED.contains(f), f)` with `if (condition.get())`);
  - a lambda assigned to a variable, then `validator.get()` passed to a boolean parameter (`if (isValid)`);
  - a method reference applied to the value itself (`redirect(url, WHITELIST::contains)` with `if (validator.apply(url))`).
  A lambda with several `return`s other than `false` does not count.
- Checking a normalised path that is built from values (`target = Paths.get(BASE + f).normalize(); target.startsWith(base)`) proves the values that built it (`f`), in an `if` or in a lambda.
- `startsWith` with a fixed string counts only when that string is a safe prefix according to `safe_prefix`: `startsWith("/")` does, `startsWith("http")` does not. A rule without `safe_prefix`, such as path traversal, counts it only on a resolved path: `canonical.startsWith("/srv/")` after `getCanonicalPath()`/`normalize()`/`realpath`, and not `name.startsWith("id=")`.

#### Maps and lists

- A map with fixed keys (`m['a']`, `m.put("a", x)`) is followed per element.
- A list created in a function and changed only by `add`/`append`/`remove(i)`/`get(i)` in the same branch is followed per position.
- A list that is changed in another branch, passed on, or iterated is treated as one value.
- The exception is an argument list that runs through a shell. It is read in every way it can be built through the `if`/`else` branches.

#### Constants and branches

- Hash and cipher algorithms are traced to their real value (a constant, `getProperty` in a `.properties` file, `@Value` in `application*.yml`). A value that is only known at runtime (an environment variable, a parameter) is not.
- A conditional branch that can be computed in advance from literals and local variables assigned once (`if 7 * 42 - num > 200`, `x if c else y`, `match`/`switch` on `"ABC"[1]`) counts only the branch that runs. A condition that depends on a field, a parameter or a function counts both branches.

#### Database as a source

The database is a source for stored XSS in:

- Java (`java-taint-stored-xss`): JDBC, `JdbcTemplate`, JPA query.
- C# (`cs-taint-stored-xss`): ADO.NET, Dapper, EF Core raw SQL.
- PHP (`php-taint-stored-xss`): `mysqli_fetch_*`, `mysql_fetch_*`, `pg_fetch_*`, PDO `fetch`/`fetchAll`, SQLite3 `fetchArray`, `$wpdb->get_results`….

Spring Data repositories and DAOs also count (`postRepository.findByLevel(l)` on a field declared `*Repository`/`*Dao`). A name that is not declared with a type in the file does not count.

The database is not yet a source in Python, JS/TS, Go, Ruby or Kotlin.

#### Escaping and context

- HTML escape functions (`escapeHtml4`, `htmlEscape`, `html.escape`, `htmlspecialchars`…) do not count as sanitizing when the value is:
  - in an attribute without quotes (`<img src=%s>`);
  - in the position of a tag name or an attribute name (`<div <?= h($x) ?>>`);
  - in an `on…=` handler or a `style` attribute;
  - inside `<script>` or `<style>`;
  - at the start of an `href`/`action` value (`javascript:`).
- The context is read from concatenated strings, from format strings (through local constants), from the template around the value, and, for PHP files that mix HTML, from the HTML part of the page before `echo`/`<?=`.
- An escaped value assigned to a local variable (also when copied on to another variable) is judged where that variable is used.
- Dedicated template engines (`.html`, `.jsp`, Twig, Blade) are not handled yet.
- Functions that only escape quotes (`quote_escapers`: `mysqli_real_escape_string`, `addslashes`, ESAPI `encodeForSQL`) clean a value only when it sits inside a pair of quotes. `"… WHERE id=" . mysqli_real_escape_string($c, $id)` is still reported.
- For PHP code (`eval`) only single quotes count, because `"…"` interpolates `{${…}}`.
- XPath 1.0 has no escape with `\`, so `addslashes` does not clean XPath.

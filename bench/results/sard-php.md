# NIST SARD PHP Vulnerability Test Suite (2015-10-27)

The PHP Vulnerability Test Suite (SARD #103, sha256 `3407473f…`): 42,212
single-file cases, each labelled bad or good as a whole by its
`manifest.sarif`. `sard_php.py --select` keeps the 20,856 cases whose data
comes from the HTTP request (8 of the suite's 16 inputs: `$_GET`, `$_POST`,
`$_GET` in an array or through an object, a `$_POST` string given to
`unserialize`) in 8 categories; CWE 862 (authorization) is left out. A case is
found when a finding of its category lands in its file, and flagged wrongly
when that happens in a good case; score = found rate − wrongly flagged rate,
per category. larpcop is counted through its `php-taint-*` rules. The
selection, the scorer and the rules it counts were committed (d94970f,
2d73792) before any tool ran on these files. Semgrep 1.183.0 with
`p/default`.

## First run (held-out)

| Category (bad/good) | larpcop: found / good flagged / score | Semgrep (p/default): found / good flagged / score |
|---|---|---|
| code (168/648) | 62% / 53% / **+9%** | 0% / 0% / **+0%** |
| include (336/1296) | 62% / 53% / **+9%** | 0% / 0% / **+0%** |
| ldap (1056/864) | 51% / 62% / **-11%** | 0% / 0% / **+0%** |
| redirect (1296/1104) | 31% / 26% / **+5%** | 0% / 0% / **+0%** |
| shell (312/936) | 62% / 56% / **+6%** | 32% / 33% / **-1%** |
| sql (456/4320) | 56% / 46% / **+10%** | 34% / 31% / **+2%** |
| xpath (632/2392) | 61% / 48% / **+12%** | 0% / 0% / **+0%** |
| xss (2176/2864) | 28% / 27% / **+1%** | 0% / 0% / **+0%** |
| **average** | **+5.3%** | **+0.1%** |

Most cases print or use the request data from a file that mixes HTML and
PHP (`<html>…<?php … ?>…`). ast-grep parses PHP with the PHP-only grammar,
which read that HTML as code: findings after it were lost, and nothing told
an `htmlspecialchars` in a `<script>` block from one in a paragraph. The
other misses and wrong flags came from:

- objects: request data stored in a field by the constructor and read back
  by a getter (`$temp = new Input(); $tainted = $temp->getInput();`), or
  into an entry of a field (`$this->input[1] = $_GET[…]`);
- sanitizers the rules did not know or read wrongly: PHP casts and
  `settype`, `filter_var` with the numeric, IP and `SPECIAL_CHARS` filters,
  `preg_match` with an anchored allow-list held in a local
  (`$re = "/^[0-9]*$/"; if (preg_match($re, $t) == 1)`), `preg_replace`
  stripping everything but word characters, arithmetic (`$t + 0`), a
  ternary or an `if`/`else` that assigns a literal in every branch;
- `sprintf("… %d", $t)`: a value written through a numeric placeholder;
- escapers used where they do not protect: SQL escaping outside quotes
  (`WHERE id=` . `mysqli_real_escape_string(…)`), SQL escaping counted as
  LDAP or XPath escaping;
- `preg_replace` counted as code execution whatever argument was tainted,
  and `http_redirect` not a redirect sink.

## After fixing the engine and rules (not held-out)

| Category (bad/good) | larpcop: found / good flagged / score |
|---|---|
| code (168/648) | 86% / 12% / **+73%** |
| include (336/1296) | 81% / 21% / **+60%** |
| ldap (1056/864) | 82% / 44% / **+37%** |
| redirect (1296/1104) | 79% / 0% / **+79%** |
| shell (312/936) | 82% / 32% / **+50%** |
| sql (456/4320) | 89% / 4% / **+85%** |
| xpath (632/2392) | 54% / 21% / **+33%** |
| xss (2176/2864) | 48% / 14% / **+34%** |
| **average** | **+56.4%** |

larpcop took 16.9 s on the first run and 23.6 s on the last (a loaded
machine); Semgrep 98.1 s.

What changed:

- PHP files mixing HTML and code: the HTML becomes a `/*@…*/` comment of the
  same length before parsing (`?>` and the opening tag give the room; `<?=`
  is an `echo`), so lines stay where they are and the page before an
  `echo` stays readable. An HTML escaper does not clean a value echoed in a
  `<script>` or `<style>` block, a tag or attribute name, an unquoted
  attribute, an event handler, a `style` attribute or at the start of a URL
  attribute, followed through locals the escaped value is copied to.
- A rule's `quote_escapers` (regex over the sanitizer call) clean only a
  value placed inside quotes (`quote_chars`; single quotes only for PHP
  code, where `"…"` interpolates). XPath 1.0 has no backslash escape:
  `addslashes` is not an XPath sanitizer, an entity-escaped quote is, inside
  quotes.
- Fields a constructor or another method stores request data in start
  tainted in the class's other methods (summaries), entries included.
- `values:` (regex over every value a metavariable can hold, as far as the
  file tells): an allow-list `preg_match` guards only when its pattern is
  anchored and its class has no punctuation; `preg_replace` cleans only
  when it strips everything else; `preg_replace` executes its replacement
  only with an `/e` modifier. PHP strings keep unknown escapes (`'/\W/'`),
  locals are read through `$name`, and `== 1` keeps a guard's sense.
- Arithmetic makes a number; `sprintf`/`printf`/`String.format` arguments
  written through `%d`, `%u`, `%x`, `%f`… are numbers (not Go's `Sprintf`,
  whose `%d` of a string prints the string).
- An `if` with an `else` whose every branch assigns a name leaves the name
  clean when no branch assigned it source data; `case`/`match`/`switch`/
  `when` expressions hold a branch's result, not their subject.
- PHP variables have the type they are created with (`new DOMXPath(…)`) or
  declared as a parameter; `->query()` is an XPath sink only on a
  `DOMXPath`. A database query's result is not its text.

DVWA keeps +80.0%: the SQLite `->query()` taken for XPath and a
`preg_replace` taken for code execution are gone; new are the query lines of
the medium SQL injection level (`mysqli_real_escape_string` on a number
placed outside quotes) and three `{$user}` printed after a login, escaped for
SQL only. The other benches and the 12 real applications give the same
findings as before.

## What is left

Most of the remaining misses and wrong flags are cases whose label the code
contradicts, or where the label assumes an escaper protects a sink it was not
made for:

- 768 bad cases test and copy `$sanitized`, which they never assign
  (`if (filter_var($sanitized, FILTER_VALIDATE_EMAIL)) $tainted = $sanitized;
  else $tainted = "";`): nothing from the request reaches the sink.
- 272 bad cases print only literals (`$tainted == 'safe1' ? 'safe1' :
  'safe2'`, an `in_array` allow-list), labelled flawed because of where they
  print them.
- 552 bad XSS cases: digits (`FILTER_SANITIZE_NUMBER_*`) or URL-encoded text
  (`urlencode`, `rawurlencode`, `http_build_query`) in a script block, a style
  block, a comment, a tag or attribute name, an unquoted attribute or a CSS
  value, and HTML-escaped text in a comment: none of these can end the
  context or start markup. The `span_Style_Property_Value` cases echo the
  constant `checked_data`, not the request data.
- 192 bad XPath cases use `FILTER_SANITIZE_(FULL_)SPECIAL_CHARS` inside quotes,
  which PHP documents as `htmlspecialchars` with `ENT_QUOTES`; the suite
  labels `htmlspecialchars(…, ENT_QUOTES)` in the same places safe.
- 144 bad LDAP and redirect cases strip everything but word characters
  (`preg_replace('/\W/si', '', …)`); 96 more send letters or digits only to
  `Location:`, which cannot leave the site; 56 write the value through
  `%d`/`%u` (one is named `sprintf_%s` and uses `%d`).
- 1,328 good cases use an escaper made for another sink: `addslashes`,
  magic quotes or `mysql_real_escape_string` for XPath (no backslash escape
  in XPath 1.0), a shell command (a backslash is literal inside single
  quotes) or a file path, `htmlspecialchars` for LDAP (`*()\` untouched),
  SQL (a trailing backslash escapes the closing quote) or code.
- 336 good cases put an HTML-escaped value in a JavaScript string: in an
  event handler the browser decodes `&#039;` back to a quote before running
  the code; in a `<script>` block HTML escaping leaves `\`, which escapes
  the string's closing quote, so a second value on the line runs as code.
- 48 good cases sanitize `$tained` (sic); the raw `$tainted` reaches
  `system()`.
- 48 good XSS cases put `addslashes`, magic quotes or
  `mysql_real_escape_string` output in an HTML attribute, which a backslash
  does not protect; 16 more use the e-mail filter or a replacement there.

Not modelled, so still flagged: a replacement that removes one quote
character (`preg_replace('/\'/', '', …)`, 264 good cases), and LDAP escaping
written by hand with `str_replace` over arrays (96).

# PHP applications: XVWA and WackoPicko

Two deliberately vulnerable PHP applications, neither seen before this run:

- XVWA, `s4n7h0/xvwa` fb30fa5: 19 modules, one per issue its README lists;
- WackoPicko, `adamdoupe/WackoPicko` cabc1b3: the 14 vulnerabilities its
  README lists (a 15th, the admin/admin password, lives in the database dump,
  not in code).

The truth files (`xvwa-truth.json`, `wackopicko-truth.json`) map each listed
issue to the line of code that has it. They were committed (d46b77e) together
with `php-taint-stored-xss` and PHP `foreach` (9083607), before any tool ran
on either application. Scoring is `score.py`: a listed line counts as found
when a security finding of the tool is within three lines of it in the same
file. Commands: `bench/run.sh`.

## First run (held-out)

larpcop 9083607 (`/tmp/larpcop-php5`), Semgrep 1.183.0 `p/default`.

| | larpcop | Semgrep OSS |
|---|---|---|
| XVWA: lines found / 19 | **12** (11 of the named kind) | 5 |
| WackoPicko: lines found / 14 | **9** | 1 |
| XVWA time | 0.94 s | |
| WackoPicko time | 1.32 s | |

The twelfth XVWA line is the template injection (`$twig->render($name)` with
`Twig_Loader_String`), credited for `php-taint-xss` on the `echo` of the
rendered output one line below: an XSS, not the injection. The SSRF line is
found by `php-taint-path` (and by Semgrep's `tainted-filename`), since
`file_get_contents($_POST['img_url'])` is reported as a path, not as a request.

Found by neither tool:

- XVWA: formula injection (rows exported to CSV as stored), DOM XSS
  (`document.write` of `location` in an inline script), the session id kept
  at login, unsalted MD5 password hashes, an IDOR, a delete without the
  admin check, CSRF (password changed by a GET).
- WackoPicko: the second-order SQL injection (a first name read back from the
  database and put into a query), the admin session id taken from an
  auto-increment column, forceful browsing to a picture not bought, any
  user's page reachable without login, a coupon applied any number of times.

Wrong reports outside the listed lines (the other findings off them are real:
`test.php` echoing `$_GET`, `login.php` redirecting to `$_POST['next']`,
`redirect.php`, the second shell and SQL sinks of the same modules):

- `base64_encode` and password-hash output printed as HTML (3, XVWA crypto);
- rows of `$conn->query($sql)` taken for the query text and reported as
  reflected XSS too (10), and XML node values of `$xpath->query()` (2);
- `php-taint-sql` on `$xpath->query($query)` (1);
- `php-no-eval` reported twice on each `eval(...)` statement;
- `http_redirect(".." . X . "?picid=" . $_POST['picid'])`: the request only
  sets a query parameter of a fixed path (4);
- `add_guestbook(…, False)` and `create_user(…, False)`: the `False` flag
  picks the escaping branch of the callee (3);
- `date("l jS \of F Y", $date)` printed (1).

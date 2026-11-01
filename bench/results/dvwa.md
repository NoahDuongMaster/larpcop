| Category | larpcop: TPR / FPR / score | Semgrep OSS: TPR / FPR / score |
|---|---|---|
| path | 3/6 found, 0/2 fixed flagged / **+50%** | 0/6 found, 1/2 fixed flagged / **-50%** |
| redirect | 3/3 found, 0/1 fixed flagged / **+100%** | 0/3 found, 0/1 fixed flagged / **+0%** |
| shell | 3/3 found, 0/1 fixed flagged / **+100%** | 3/3 found, 1/1 fixed flagged / **+0%** |
| sql | 6/6 found, 0/2 fixed flagged / **+100%** | 4/6 found, 0/2 fixed flagged / **+67%** |
| xss | 3/6 found, 0/2 fixed flagged / **+50%** | 0/6 found, 0/2 fixed flagged / **+0%** |
| **average** | **+80.0%** | **+3.3%** |

First run +40.0%. Fixed since: DVWA builds each level's page into `$html`
(`$html .= '<pre>Hello ' . $_GET['name'] . '</pre>'`), printed later by a shared
template through an include whose path is only known at run time; PHP's
`html_fragments` makes a value placed into markup a sink where it is placed
(reflected XSS 0/3 → 3/3). The fixed upload level checks the extension
(`strtolower($ext) == 'jpg' || … == 'png'`) after building the file name from
it: comparing with a literal is a guard, and it pins values built only from
what it checks (`$name = bin2hex(random_bytes(16)) . '.' . $ext`), so the
fixed level is no longer flagged.

Still missed: the file-inclusion levels only assign `$file` at the top level
of a file that `fi/index.php` requires through a path chosen at run time
(`source/{$vulnerabilityFile}`), then includes; variables a required file
sets are not followed into the file requiring it; this flow is reported
neither in the per-level files the scorer credits nor in the shared ones. The
stored-XSS levels write the guestbook row, which a shared `dvwaGuestbook()`
prints from `mysqli_fetch_row`: `php-taint-stored-xss` (added after this
bench was seen, so not a held-out result) reports it there
(`dvwa/includes/dvwaPage.inc.php:625`), not in the per-level files the scorer
credits.

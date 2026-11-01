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

Still missed, because of how the scorer credits a level: the file-inclusion
levels only assign `$file`, which `fi/index.php` includes; the stored-XSS levels
write the guestbook row, which a shared `dvwaGuestbook()` prints. larpcop
reports those flows where the include and the print happen, not in the
per-level files.

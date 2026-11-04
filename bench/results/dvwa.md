# DVWA (PHP)

[digininja/DVWA](https://github.com/digininja/DVWA) `a1978a2`: PHP.

Answer key: the project's own layout. In each of 8 modules (SQL injection, blind SQL injection, command injection, file inclusion, upload, reflected XSS, stored XSS, open redirect), `source/low.php`, `medium.php` and `high.php` are vulnerable by design and `impossible.php` is the fixed version. A level is counted when a finding of the module's category falls in its file. Per category, `found` counts the vulnerable levels reported, `fixed flagged` counts the `impossible` levels reported, and score = found rate − fixed-flagged rate (`bench/scripts/dvwa.py`).

| Category | larpcop: TPR / FPR / score |
|---|---|
| path | 3/6 found, 0/2 fixed flagged / **+50%** |
| redirect | 3/3 found, 0/1 fixed flagged / **+100%** |
| shell | 3/3 found, 0/1 fixed flagged / **+100%** |
| sql | 6/6 found, 0/2 fixed flagged / **+100%** |
| xss | 3/6 found, 0/2 fixed flagged / **+50%** |
| **average** | **+80.0%** |

First run (before rules were added for this suite): +40.0%. Current: +80.0%.

What changed in between: DVWA builds each level's page into `$html` (`$html .= '<pre>Hello ' . $_GET['name'] . '</pre>'`) and a shared template prints it through an include whose path is only known at run time. PHP's `html_fragments` therefore makes a value placed into markup a sink at the point where it is placed (reflected XSS 0/3 → 3/3). The fixed upload level checks the extension (`strtolower($ext) == 'jpg' || … == 'png'`) after building the file name from it. Comparing with a literal is a guard, and it covers values built only from what it checks (`$name = bin2hex(random_bytes(16)) . '.' . $ext`), so the fixed level is not flagged.

Missed: the file-inclusion levels only assign `$file` at the top level of a file that `fi/index.php` requires through a path chosen at run time (`source/{$vulnerabilityFile}`) and then includes. Variables set by a required file are not followed into the file that requires it, so this flow is reported neither in the per-level files the scorer credits nor in the shared ones. The stored-XSS levels write the guestbook row, which a shared `dvwaGuestbook()` prints from `mysqli_fetch_row`. `php-taint-stored-xss` (added after the suite had been scored, so not a held-out result) reports it there (`dvwa/includes/dvwaPage.inc.php:625`), not in the per-level files the scorer credits.

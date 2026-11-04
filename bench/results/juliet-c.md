# NIST Juliet C/C++ 1.3: OS command injection and format string

The `.c` cases of Juliet C/C++ 1.3 for CWE78 (OS command injection, 3,800 cases) and CWE134 (uncontrolled format string, 2,280 cases), scored with `bench/scripts/juliet.py --c`: a case is found when a finding lands in its `bad` code and flagged wrongly when one lands in its `good` code. Every case has both. The data comes from the console (`fgets`), the environment (`getenv`), a file (`fgets` on `fopen`), or a socket (`recv` after `connect` or `accept`); the sinks are `system`, `popen`, the `exec*`/`_spawn*` families running `sh -c` or `cmd.exe /c`, and the `printf` family. The selection, the scorer, the names of the rules it counts (`c-taint-shell`, `c-taint-format`) and the rules themselves were committed before any tool ran on these files.

## First run

| Category (cases) | larpcop: found / good flagged / score |
|---|---|
| format (2280) | 87% / 0% / **+87%** |
| shell (3800) | 83% / 0% / **+83%** |
| **average** | **+84.7%** |

No `good` code is flagged. Every source and every sink is covered; the 960 misses are whole flow variants:

- 32: two pointers to one local (`char **p1 = &data, **p2 = &data;`), written through one and read through the other;
- 44, 65: a function pointer (`void (*fp)(char *) = badSink; fp(data);`), in the same file and in another one;
- 45, 68: a global (`static char *badData;`, `extern char *badData;`) set by the caller and read by the callee, in the same file and in another one;
- 53, 54 (CWE78 only): calls through 4 and 5 files ending in an `exec*` or `_spawn*` call. Past two files deep, a file is followed only when it mentions one of the rule's sources or sinks, and that check saw pattern sinks only, not argument vectors (`execl("/bin/sh", "sh", "-c", data)`) or out-parameter sources (`fgets(buf, …)`).

## Current

The engine was adjusted after the first run using these misses, so the numbers below are not held-out.

| Category (cases) | larpcop: found / good flagged / score |
|---|---|
| format (2280) | 100% / 0% / **+100%** |
| shell (3800) | 100% / 0% / **+100%** |
| **average** | **+100.0%** |

Pointers to a local and the local are one place for the walk; a call through a local holding a function (`fp = sink`) uses that function's summary; C file-scope variables a callee reads are inputs of the callee, like the static fields of Java and C#; the depth check counts argument vectors and out-parameter sources. The C/C++ files of the same directory are searched for functions called or taken as pointers, since C has no imports. These changes leave the findings on the 12 real applications and on the other suites unchanged.

## Real C code

jq (70c9dc5, 46 files), tmux (a73616d, 206 files) and curl (31c911e, 807 files) give no C finding. The variables the login sets for the user's own session (`HOME`, `USER`, `LOGNAME`, `SHELL`, `PWD`, `OLDPWD`, `TMPDIR`, `PATH`) are not sources: whoever can change them already runs as that user. With them counted as sources, tmux would produce one finding, `execl(_PATH_BSHELL, "sh", "-c", cmd)` of `pipe-pane`, where `cmd` is expanded from formats that include the current directory, which comes from `getenv("PWD")`/`getenv("HOME")` three files away. `LANG`, `LC_*` and `TERM` (forwarded by SSH), CGI variables (`QUERY_STRING`, `HTTP_*`) and the application's own variables are sources. Juliet C keeps +100.0% under this rule (its variable is `ADD`).

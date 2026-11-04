# Repositories not written for a benchmark

Figures on this page were measured with larpcop 0.3.0 and have not been re-measured since.

The other suites measure recall on code that is wrong on purpose. These two repositories are production code that ships to millions of sites, so every finding is either a real problem upstream or a false positive of larpcop. The measurement script is `bench/scripts/scale.sh`.

| | django/django `a05e16a` | rails/rails `d0f264a` |
|---|---|---|
| Files read | 2,939 `.py` | 3,481 `.rb` |
| Whole repository | **131 s** warm, 162 s cold (8 cores) | **18 s** |
| Parsing alone (`larpcop metrics`) | 3.9 s | – |
| Findings | 632 | 266 |

Run with `standards/recommended` and `dependency-vulnerability` disabled (no network in this measurement). The machine was otherwise idle for the final pair of runs. `--changed` and `--staged`, which an agent hook and a pre-commit run use, stay under a second on both.

A full check uses every core: 500–670% of 800% on the 8-core test machine. `--jobs` (or `LARPCOP_JOBS`) caps it; the same Django run takes 277 s on 2 threads. Loading the rules costs 0.41 s per invocation whatever the repository, so the incremental modes are the ones to use in a hook.

## What it reports

Django, by rule: `complexity` 161, `function-length` 149, `max-lines` 85, `py-no-sql-interpolation` 75, `gha-unpinned-action` 66, `no-unescaped-template-output` 17, `py-taint-redirect` 15, `py-taint-stored-sql` 13, `secrets` 12 (test keys), then single digits.

Rails, by rule: `max-lines` 83, `function-length` 37, `secrets` 26 (test fixtures), `rb-no-weak-hash` 23, `no-unescaped-template-output` 18, `gha-unpinned-action` 16, `no-console` 14, `rb-no-sql-interpolation` 10.

## Checking the findings

The findings were opened by hand. Each one was either a real habit upstream or a rule that needed to be more precise:

- `py-taint-stored-sql` flagged `DatabaseCache._base_delete_many`, where the query text is `"… IN (%s)" % (table, …, ", ".join(["%s"] * len(keys)))` with the keys **bound**. `len(keys)` carried taint into the SQL string. A count (`len`, `count`, `strlen`, `.size()`) is treated as a number, so nothing written by a user can travel through it (`numeric.rs::counted`). The other twelve Django reports remain: they build the query around a value read back from the database.
- On djangoproject.com, `py-django-csrf-exempt` flagged `@csrf_exempt` on `fundraising/views.py:receive_webhook`, which verifies a Stripe signature. A view named `*webhook*`/`*hook*`/`*stripe*`… is treated as exempt on purpose.
- `py-django-debug-true` flagged `djangoproject/settings/dev.py`. Settings files named `dev`/`local`/`development`/`test` are not treated as what runs in production.
- `py-no-sql-interpolation` (75 in Django) is Django's own idiom: `"DESCRIBE %s" % quote_name(table)` inserts an identifier quoted by Django. The rule stays: it is a convention ("no SQL by interpolation"), a reviewer decides, and the finding's note says what to do instead.
- `rb-no-weak-hash` in Rails is MD5/SHA-1 where the algorithm is dictated: RFC 4122 UUIDs (`uuid_from_hash(OpenSSL::Digest::MD5, …)`), S3 ETags, cache variation digests. The rule stays; it is the noisiest rule on Ruby.
- `secrets` in both: test fixtures with fake tokens (`"7VwW7k6…"`) and `django/test/…`. The rule stays: a real key committed in a test is still a leak.
- `no-unescaped-template-output`: `|safe` in Django's admin templates and `.html_safe` in Rails' *test fixtures*; developer-written text, not request data. The rule stays.

## Framework rules on applications that use the framework

| Repository | Rule | What it found |
|---|---|---|
| node-express-realworld-example-app | `no-cors-any-origin` | `cors()` with no options, so every origin is allowed |
| spring-petclinic | `spring-actuator-exposed` | `management.endpoints.web.exposure.include=*` |
| halo (Vue + Vite) | `no-cors-any-origin` | a dev-server plugin setting `Access-Control-Allow-Origin: *` for the bridge script |
| djangoproject.com | – | nothing after the two fixes above |

Three of the four applications produced a real finding. One of them is a Vite dev plugin, where the wildcard never reaches production.

## Cost

Python costs about eight times what Ruby does per file here (2,939 files in 131 s against 3,481 in 18 s). Parsing is a small part of it; the rest is the taint walk, which is recomputed per rule.

### Where a file's time goes

Timers inside `check_file`, summed over `rails/activerecord` (1,363 files, one thread, 39 s):

| Step | Time |
|---|---|
| **taint rules** | **34 s** |
| everything else (parse, ast rules, metrics, secrets, text, page scripts) | 5 s |
| of the taint time: `prepare` (pattern scan, sanitizer filtering, summaries) | **2 s** |

The walk is the cost: every rule walks the same file and re-evaluates the same expressions for its own taint set. The timers put `prepare` at 5% of a file's time. A sampling profiler attributes 27% of the run to it, because with a full LTO build the samples land in inlined code and the nearest symbol is not the function running.

A rule's walk cannot be skipped when the rule matched no sink in the file. A finding is always at a sink, but the sink does not always appear in the rule's sink hits: skipping the walk when no sink matched in the file and none in any summary it can call would lose 160 `c-taint-format` findings on Juliet C, where the sink is a buffer written through an argument (`sprintf(buf, …)`). The redundancy between rules is load-bearing: which mechanisms can report is per rule (`writes`, `responds`, configured sinks), and the walk is where all of them meet.

The walk's own prune asks "does this subtree's text contain a tainted name" and answers by scanning the text. A 64-bit Bloom filter of the words under each node (built in one pass over the tree) would answer it in one AND, but the prune is a *substring* test and word-level bits do not cover it: `valid` contains `id`, and `$obj->name` is not the word `name`. The filter fails 39 rule fixtures. Only a Bloom filter over every substring would be exact, and building that costs more than the scan it replaces.

### Effect of the performance work

What the walk does with a file, before and after:

| | Before | After |
|---|---|---|
| Parses of one file | 3 (ast rules, metrics, taint) | 1, shared by all three |
| Walks of the tree for ast rules | 1 per rule (83) | 1, bucketed by node kind |
| Source/sanitizer lookup per node | scan of every span in the file | binary search |

Measured on `rails/activerecord` (1,363 files) single-threaded, median of three runs each: **41.3 s → 37.1 s (-10.2%)**, every finding the same on the 19 benches. Wall-clock on 8 cores varies by about ±20% on the test machine, which is why the comparison uses one thread. The table above accounts for -4.4%, the allocator (below) for another -5.5%, reading each node's text once per pattern group for the last -0.3%, and cross-crate inlining for another -5% (37.4 s → 35.5 s). On eight threads the release profile changes nothing (125.2 s against 125.4 s): that run is waiting on memory, not on instructions.

End to end, against the build before the performance work:

| | Before | After |
|---|---|---|
| `django/django`, 8 threads, wall | 132.9 s | **125.1 s** (-5.9%) |
| `django/django`, 8 threads, CPU | 912 s | **840 s** (-7.9%) |
| `rails/activerecord`, 1 thread | 41.3 s | **35.5 s** (-14.0%) |

CPU is the number to trust on eight threads: wall time on the test machine moves by ±10% between runs that do identical work.

#### Allocator

With the system allocator, four threads took the same wall time as eight on `django/django` (160.0 s against 160.1 s) while using 611 s of CPU instead of 935 s: eight threads spent a third of their time inside the allocator's per-thread magazine locks, not in the rules. mimalloc (`[global_allocator]`, three lines) removes that:

| | System malloc | mimalloc |
|---|---|---|
| `django/django`, 8 threads | 160.1 s / 935 s CPU | **146.0 s / 874 s CPU** |
| `django/django`, 4 threads | 160.0 s / 611 s CPU | 152.6 s / 588 s CPU |
| `rails/activerecord`, 1 thread | 39.5 s | **36.7 s** |

Every rule allocates: a parse per file, a node per token, a `String` per name. That is why the allocator matters, and why `--jobs 4` buys almost nothing with mimalloc: the lock is gone and what is left is memory bandwidth.

#### Measured and not adopted

| Change | Result |
|---|---|
| Per-file cache of declared types, call names and constructed objects | Slower: the cache key cost more than the lookups it saved |
| Skip a rule whose literal "needles" appear nowhere in the file | Fast, but loses 6 `java-taint-xss` findings in java-sec-code and 4 `php-taint-xss` in DVWA: a finding that comes through a callee in another file has no needle in this one |
| Re-summarize only functions that name a callee whose summary changed | Slower: scanning each function's text for every changed name cost more than the round it saved |
| Largest file first, to keep threads from waiting on one big file | No effect beyond the noise |
| `Rc` snapshots of the summaries, rebuilt only when a round changed them | 38.9 s against 36.7 s: comparing each inserted summary replaced one map comparison per round with one per function |
| One `Env` per function instead of one per sanitizer, and a sorted span set for "is this sink call a source" | 37.9 s against 37.4 s: inside the noise, and `prepare` costs what the pattern scan costs |
| Skipping parameters a function body never names | 36.1 s against 35.9 s: neutral |
| Profile-guided build (needs `llvm-profdata` and a training corpus) | -2.4% on `rails/activerecord` (34.9 s → 34.1 s, one thread, median of two) and nothing on eight threads; small enough that it is not the default build |
| `-Ctarget-cpu=native` | 35.3 s against 34.8 s: neutral to worse |
| Caching the OSV `querybatch` answer for a few hours | Not done: advisory details must be refetched when OSV reports an edit, because a package that becomes malware today must block today. An offline run can take eight seconds to fail closed |

The remaining cost is structural: the taint walk and its summaries are computed per rule, and a function with five parameters is walked five times (once per parameter, per round). Sharing that work would mean tracking, per parameter, which names are tainted.

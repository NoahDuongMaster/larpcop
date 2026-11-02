# Repositories nobody wrote for a benchmark

The benches measure recall on code that is wrong on purpose. These two are
real: `django/django` and `rails/rails`, production code that ships to
millions of sites, where every finding is either a real problem upstream or a
false positive of ours.

| | django/django `a05e16a` | rails/rails `d0f264a` |
|---|---|---|
| Files read | 2,939 `.py` | 3,481 `.rb` |
| Whole repository | **131 s** warm, 162 s cold (8 cores) | **18 s** |
| Parsing alone (`larpcop metrics`) | 3.9 s | – |
| Findings | 632 | 266 |

Run with `standards/recommended` and `dependency-vulnerability` disabled
(no network in this measurement). The machine was otherwise idle for the
final pair of runs. `--changed` and `--staged`, what an agent hook and a
pre-commit run, stay under a second on both.

A full check uses every core: 500–670% of 800% on this machine, which is
why a laptop feels stuck for the two minutes it runs. `--jobs` (or
`LARPCOP_JOBS`) caps it — the same Django run takes 277 s on 2 threads —
and loading the rules costs 0.41 s per invocation whatever the repository,
so the incremental modes are what a hook should use.
(no network in this measurement). The machine was otherwise idle for the
final pair of runs. `--changed` and `--staged`, what an agent hook and a
pre-commit run, stay under a second on both.

## What it reports

Django, by rule: `complexity` 161, `function-length` 149, `max-lines` 85,
`py-no-sql-interpolation` 75, `gha-unpinned-action` 66,
`no-unescaped-template-output` 17, `py-taint-redirect` 15,
`py-taint-stored-sql` 13, `secrets` 12 (test keys), then single digits.

Rails, by rule: `max-lines` 83, `function-length` 37, `secrets` 26 (test
fixtures), `rb-no-weak-hash` 23, `no-unescaped-template-output` 18,
`gha-unpinned-action` 16, `no-console` 14, `rb-no-sql-interpolation` 10.

## Checking the findings

Every one opened was either a real habit upstream or a rule we could sharpen:

- `py-taint-stored-sql` first flagged `DatabaseCache._base_delete_many`, where
  the query text is `"… IN (%s)" % (table, …, ", ".join(["%s"] * len(keys)))`
  with the keys **bound**. `len(keys)` was carrying taint into the SQL string.
  Fixed: a count (`len`, `count`, `strlen`, `.size()`) is a number, so nothing
  written by a user can travel through it (`numeric.rs::counted`). The other
  twelve Django hits stayed: those build the query around a value read back
  from the database.
- `py-django-csrf-exempt` flagged `@csrf_exempt` on
  `fundraising/views.py:receive_webhook`, which verifies a Stripe signature.
  Fixed: a view named `*webhook*`/`*hook*`/`*stripe*`… is exempt on purpose.
- `py-django-debug-true` flagged `djangoproject/settings/dev.py`. Fixed:
  settings files named `dev`/`local`/`development`/`test` are not what runs in
  production.
- `py-no-sql-interpolation` (75 in Django) is Django's own idiom:
  `"DESCRIBE %s" % quote_name(table)` inserts an identifier quoted by Django.
  Kept: the rule is a convention ("no SQL by interpolation"), and a reviewer
  decides; the note says what to do instead.
- `rb-no-weak-hash` in Rails is MD5/SHA-1 where the algorithm is dictated:
  RFC 4122 UUIDs (`uuid_from_hash(OpenSSL::Digest::MD5, …)`), S3 ETags, cache
  variation digests. Kept, but it is the noisiest rule on Ruby.
- `secrets` in both: test fixtures with fake tokens (`"7VwW7k6…"`) and
  `django/test/…`. Kept: a real key committed in a test is still a leak.
- `no-unescaped-template-output`: `|safe` in Django's admin templates and
  `.html_safe` in Rails' *test fixtures*; developer-written text, not request
  data. Kept, same reason.

## The four framework rules, on applications that use the framework

| Repository | Rule | What it found |
|---|---|---|
| node-express-realworld-example-app | `no-cors-any-origin` | `cors()` with no options — every origin allowed |
| spring-petclinic | `spring-actuator-exposed` | `management.endpoints.web.exposure.include=*` |
| halo (Vue + Vite) | `no-cors-any-origin` | a dev-server plugin setting `Access-Control-Allow-Origin: *` for the bridge script |
| djangoproject.com | – | nothing after the two fixes above |

Three real findings out of four applications, and one on a Vite dev plugin
where the wildcard never reaches production.

## What this says about cost

Python costs about eight times what Ruby does per file here (2,939 files in
131 s against 3,481 in 18 s), and parsing is a small part of it: the rest is
the taint walk, which is recomputed per rule.

A whole-repository check uses every core — 500–670% of 800% on this machine —
which is why a laptop feels stuck for the two minutes it runs. `--jobs` (or
`LARPCOP_JOBS`) caps that: the same Django run takes 277 s on 2 threads.

What the walk does with a file, before and after:

| | Before | After |
|---|---|---|
| Parses of one file | 3 (ast rules, metrics, taint) | 1, shared by all three |
| Walks of the tree for ast rules | 1 per rule (83) | 1, bucketed by node kind |
| Source/sanitizer lookup per node | scan of every span in the file | binary search |

Measured on `rails/activerecord` (1,363 files) single-threaded, median of
three runs each: **41.3 s → 37.1 s (-10.2%)**, every finding the same on the 19
benches. Wall-clock on 8 cores is dominated by machine noise (±20%), which is
why this was measured on one thread: the table above is -4.4%, the allocator
below another -5.5%, and reading each node's text once per pattern group the
last -0.3%.

### The allocator was the second bottleneck

Four threads took the same wall time as eight on `django/django` (160.0 s
against 160.1 s) while using 611 s of CPU instead of 935 s: eight threads were
spending a third of their time inside the system allocator's per-thread
magazine locks, not in the rules. Swapping it for mimalloc (`[global_allocator]`,
three lines):

| | System malloc | mimalloc |
|---|---|---|
| `django/django`, 8 threads | 160.1 s / 935 s CPU | **146.0 s / 874 s CPU** |
| `django/django`, 4 threads | 160.0 s / 611 s CPU | 152.6 s / 588 s CPU |
| `rails/activerecord`, 1 thread | 39.5 s | **36.7 s** |

Every rule allocates: a parse per file, a node per token, a `String` per name.
That is why the allocator showed up at all - and why `--jobs 4` now buys
almost nothing: the lock is gone, and what is left is memory bandwidth.

Four further optimizations were written, measured and **rejected**:

| Attempt | Result |
|---|---|
| Per-file cache of declared types, call names and constructed objects | slower: the cache key cost more than the lookups it saved |
| Skip a rule whose literal "needles" appear nowhere in the file | fast, but lost 6 `java-taint-xss` findings in java-sec-code and 4 `php-taint-xss` in DVWA: a finding that comes through a callee in another file has no needle in this one |
| Re-summarize only functions that name a callee whose summary changed | slower: scanning each function's text for every changed name cost more than the round it saved |
| Largest file first, to keep threads from waiting on one big file | no effect in the noise; reverted |
| `Rc` snapshots of the summaries, rebuilt only when a round changed them | 38.9 s against 36.7 s: comparing each inserted summary replaced one map comparison per round with one per function |
| One `Env` per function instead of one per sanitizer, and a sorted span set for "is this sink call a source" | 37.9 s against 37.4 s: inside the noise, and `prepare` costs what the pattern scan costs, not what these two did |

What is left is the structural one: the taint walk and its summaries are
computed per rule, and a function with five parameters is walked five times
(once per parameter, per round). Sharing that means tracking, per parameter,
which names are tainted — a rewrite of the walker's core type, not a patch.

### Where a file's time actually goes

Timer inside `check_file`, summed over `rails/activerecord` (1,363 files, one
thread, 39 s):

| Step | Time |
|---|---|
| **taint rules** | **34 s** |
| everything else (parse, ast rules, metrics, secrets, text, page scripts) | 5 s |
| of the taint time: `prepare` (pattern scan, sanitizer filtering, summaries) | **2 s** |

Two things this corrected:

- The sampling profiler said `prepare` was 27% of the run. It was wrong: with
  a full LTO build the samples land in inlined code and the nearest symbol is
  not the function running. The timers say `prepare` is 5% of the file.
- The first version of those timers printed `0 s` for everything, because they
  summed `elapsed().as_millis()` per call and every call is shorter than a
  millisecond. Microseconds show the real split.

So the walk is not one of several costs to trim - it *is* the cost. Every rule
walks the same file and re-evaluates the same expressions for its own taint
set.

Skipping that walk when it cannot report looks safe and is not: a finding is
always at a sink, so a rule with no sink matched in the file and no sink in any
summary it can call should have nothing to say. It cost **160 `c-taint-format`
findings** on Juliet C, where the sink is a buffer written through an argument
(`sprintf(buf, …)`) and never appears in the rule's sink hits. The redundancy
between rules is load-bearing: which mechanisms can report is per rule
(`writes`, `responds`, configured sinks), and the walk is where all of them
meet.

Cheapening the walk's own prune fails the same way. The walk asks "does this
subtree's text contain a tainted name" and answers by scanning the text; a
64-bit Bloom of the words under each node (built in one pass over the tree)
answers it in one AND. It cost 39 failing rule fixtures: the prune is a
*substring* test, and word-level bits do not cover it - `valid` contains `id`,
`$obj->name` is not the word `name`. Only a Bloom over every substring would
be exact, and building that costs more than the scan it replaces.

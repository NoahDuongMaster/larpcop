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
131 s against 3,481 in 18 s), and parsing is 3.9 s of it: the rest is the
taint summaries, which are recomputed per rule.

A whole-repository check uses every core — 500–670% of 800% on this machine —
which is why a laptop feels stuck for the two minutes it runs. `--jobs` (or
`LARPCOP_JOBS`) caps that: the same Django run takes 277 s on 2 threads.

Three further optimizations were written, measured and **rejected**; the
machine varies by ±20% between runs, so a change had to win by more than that
*and* keep every finding on the 19 benches:

| Attempt | Result |
|---|---|
| Per-file cache of declared types, call names and constructed objects | 148–162 s, slower: the cache key (document, range, kind) cost more than the lookups |
| Skip a rule whose literal "needles" appear nowhere in the file | 115 s, but lost 6 `java-taint-xss` findings in java-sec-code and 4 `php-taint-xss` in DVWA: a finding that comes through a callee in another file has no needle in this one |
| Re-summarize only functions that name a callee whose summary changed | 157 s, slower: scanning each function's text for every changed name cost more than the round it saved |

Kept: the type lookup no longer walks declarations that cannot contain the
name (142 s → 131 s), rule files are read and parsed in parallel, and
`--jobs`.

What is left is the structural one: the walk and the summaries are computed
per rule, and sharing them across rules means tracking, per rule, which names
are sanitized (they differ per rule), which is a rewrite of the walker, not a
patch.

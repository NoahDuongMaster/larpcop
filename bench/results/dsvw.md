# DSVW — first run (held-out)

`stamparm/DSVW` 9ca3c9a, 98 lines of Python in one file, 14 sink lines (truth
in `bench/dsvw-truth.json`, committed as `d198ad0` **before** any rule ran on
it, from the app's own CASES table).

Result: **1 of 14** — `exec(program)` at line 49 (`py-taint-shell`). Nothing
else fired.

## Why, and why it was not fixed here

The whole app reads its input through one dict built at the top of `do_GET`:

```python
params = dict((match.group("parameter"), urllib.parse.unquote(...re.findall(...)))
              for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)([^&]+)", query))
```

Every sink then uses `params["id"]`, `params["domain"]`, and so on. The source
is `self.path` — the `BaseHTTPRequestHandler` idiom — and it is not one of the
Python sources the rules know (`request.args`, `sys.argv`, `input()`, …). One
gap, 13 misses: this is a **rule** gap, not a walker gap.

A source for `self.path`/`self.headers` in `BaseHTTPRequestHandler` would close
it, but the truth for this file has now been seen, so a score after adding that
source is no longer held-out. It is recorded here as a measurement, not as
something to fix against this set: the fix belongs on a file whose truth is
still unknown.

What this set is good for: `dsvw.py` is small, its 14 lines are known, and the
one finding it does produce runs through the dict comprehension. Any change to
the walker that loses the `exec` line shows up here in under a second.

    larpcop check --format json   # in a clone of DSVW, extends the recommended set

# Multi-Rule Context & Sink Dispatcher Design

## 1. Executive Summary & Architecture Overview

In `larpcop`, taint analysis currently executes as an $O(R \times N)$ sequential loop over active rules (`file.rs::taint_check_root`). For a file with $N$ AST nodes and $R$ rules:
- **Ruby (Rails/ActiveRecord)**: 8 taint rules walk the AST 8 times.
- **Java**: ~30 taint rules walk the AST 30 times.
- **TypeScript**: ~40 taint rules walk the AST 40 times.

Profiling reveals that rule preparation and summary extraction take **~2s**, while the redundant top-level AST walks (`ctx.run` in `check.rs`) consume **~32s out of 39s total** (>80% of runtime). Unified multi-taint lattice analysis solves this by collapsing $R$ walks into a **single unified AST walk** ($O(N)$ with bitvector state operations).

```
                    [ Source File: lang, AST root ]
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
1. Three-Stage Filter                               2. Shared Skeleton
   • handles(lang)                                     • FileIndex skeleton cache
   • !exclude.is_match()                               • Zero AST re-walks
   • prepare() fast-path prune
         │
         ▼
3. Per-Rule Prepare (~2s)
   • Compute individual summaries & Hit lists
   • Retain cached imported summaries (zero regression risk)
         │
         ▼
4. Multi-Rule Aggregation
   • MultiHits: indexed sink & guard bitmasks per node
   • MultiSummaries: union returns_source & returns masks
   • MultiRuleContext: bitvector lattice environment
         │
         ▼
5. Single Unified AST Walk (`ctx.run`, ~3-5s)
   • Evaluates tainted expressions over RuleMask (u128)
   • Dispatches Reached::Sink to matching rules
   • Fixed-point field tracking: HashMap<Class, HashMap<Var, RuleMask>>
         │
         ▼
6. Violation Collection & Deduplication
```

---

## 2. Three-Stage Active Rule Filtering

Before walking or summarizing, each file filters candidate rules through three cascading gates:

### Stage 1: Language Support (`t.handles(lang)`)
- Checked via `self.patterns(lang).is_some() && !self.companions.contains(&lang)`.
- Rapidly eliminates all rules targeting other languages (e.g. discards 40 TS rules when scanning Ruby).

### Stage 2: Path Exclusion Regex (`!t.exclude.is_match(&file.rel)`)
- Prunes rules excluded on test paths, fixtures, or user configuration.

### Stage 3: File-Level Source & Reachability Fast-Path Prune (`prepare.rs`)
At top-level check depth (`depth == 0`), `prepare` immediately returns `None` without running summaries if the file cannot introduce taint under the rule:
```rust
if depth == 0
    && base.sources.is_empty()
    && !self.source_texts.iter().any(|s| property(s) == Some(true))
    && !known.values().any(|s| s.returns_source)
    && !self.decorated_input(&file.content)
    && !self.writes.reads_input(&file.content)
{
    return None;
}
```
**Outcome**: Only rules that genuinely have sources, entry-point parameters, or source-returning callees in the current file advance to the unified walk.

---

## 3. Aggregating Hits into MultiHits

In single-rule execution, `Hits<'a, D>` stores a `Vec<Hit<'a, D>>` where `Hit = (usize, Node<'a, D>, Vec<(usize, Node<'a, D>)>)`. Skeletons are already shared via `FileIndex::skeletons: Rc<RefCell<HashMap<Key, Rc<Skeleton>>>>`.

`MultiHits<'a, D>` merges hits from all passing rules into a unified spatial index:

```rust
pub type RuleMask = u128;
pub type RuleId = u8;

#[derive(Clone, Debug)]
pub struct SinkRegistration<'a, D: Doc> {
    pub rule_id: RuleId,
    pub typed: Vec<(usize, Node<'a, D>)>,
}

#[derive(Clone, Debug)]
pub struct MultiHit<'a, D: Doc> {
    pub at: usize,
    pub node: Node<'a, D>,
    pub sink_mask: RuleMask,
    pub sinks: SmallVec<[SinkRegistration<'a, D>; 2]>,
}

pub struct MultiHits<'a, D: Doc> {
    pub list: Vec<MultiHit<'a, D>>,
    by_scope: HashMap<(usize, usize), Vec<usize>>,
    skeletons: Skeletons<'a, D>,
    events: RefCell<HashMap<MultiEventsKey, MultiEvents<'a, D>>>,
}
```

### Merging Logic:
1. Collect passing rule hits: Sort by `(at, node.range().start, node.range().end)`.
2. Group by exact node span: If multiple rules define a sink on the same node (e.g. SQL injection + Command injection), set `sink_mask |= 1 << rule_id` and accumulate their typed metavariables.
3. Skeletons (`Skeleton<'a, D>`) remain unchanged. `Shape::If` guard events are resolved with rule-specific bitmasks: `Event::Clean(names, rule_mask)`, `Event::Enter(names, rule_mask)`.

---

## 4. Feasibility: Per-Rule Summaries vs. Unified AST Walk

### The Performance Dilemma
Should interprocedural function summaries (`summary.rs`) also be converted to multi-rule lattices, or remain per-rule?

| Phase | Single-Rule Time | Multi-Rule Strategy | Rationale |
| :--- | :--- | :--- | :--- |
| **Imported File Summaries** | ~1.2s | Per-rule (cached) | Highly cached in `Mutex<HashMap<(PathBuf, usize), Slot>>`. Unifying would invalidate cross-file cache boundaries. |
| **Local File `summarize()`** | ~0.8s | Per-rule in `prepare` | Only iterates named function definitions (`index.functions()`) up to 3 rounds. Negligible cost. |
| **Top-Level `ctx.run()`** | **~32.0s** | **Unified Multi-Taint Walk** | Dominates runtime (82%). Traverses full AST body, statements, nested closures, and fixed-point field passes. |

### Feasibility Verdict: Keep Summaries Per-Rule, Unify Walk
Building function summaries per-rule during `prepare` is **optimal and lowest-risk**:
1. `prepare.rs` and `summary.rs` require zero structural rewrites, maintaining 100% precision on edge cases (flags, lambdas, higher-order functions).
2. Before the top-level walk, per-rule `Summaries` are merged into `MultiSummaries` in $O(F)$ time (where $F$ is count of defined functions):
   - `returns_source`: `RuleMask` (bit $k$ set if `summaries[k].returns_source`).
   - `returns`: `HashMap<usize, RuleMask>` (bit $k$ set if rule $k$ returns param $i$).
   - `sinks`: `HashMap<usize, SmallVec<[(RuleId, String); 2]>>` (callee sinks).
   - `validates`: `HashMap<usize, RuleMask>`.

---

## 5. Violation Dispatch Tracing

During the unified walk (`MultiCtx::run`), dynamic events are dispatched directly to rule violations without re-traversal:

### 5.1 Reached::Sink Dispatch
When the walker reaches a sink argument node `arg`:
```rust
Event::Sink(arg, sink_mask, registrations) => {
    let arg_mask = self.tainted(arg, &env);
    let reached_mask = arg_mask & sink_mask;
    if reached_mask != 0 {
        for reg in registrations {
            let k = reg.rule_id as usize;
            let bit = 1u128 << k;
            if (reached_mask & bit) != 0 {
                let rule = &self.rules[k];
                if rule.typed.holds(lang, file, &reg.typed) {
                    out.push(rule.violation(file, arg, None));
                }
            }
        }
    }
}
```

### 5.2 Interprocedural Call Sinks (`Reached::Call`)
When a call node invokes a summarized callee with sinks on parameter $p$:
```rust
if let Some(sinks) = multi_summary.sinks.get(&p) {
    let arg_mask = self.tainted(arg, &env);
    for (rule_id, into) in sinks {
        if (arg_mask & (1 << *rule_id)) != 0 {
            out.push(self.rules[*rule_id as usize].violation(file, arg, Some(into.clone())));
        }
    }
}
```

### 5.3 Class Field Fixed-Point (`Reached::Field`)
In class methods, storing tainted data to a field emits `Reached::Field(node, mask)`:
```rust
// fields: HashMap<ClassKey, HashMap<String, RuleMask>>
let mut stored: HashMap<(usize, usize), HashMap<String, RuleMask>> = HashMap::new();
for (node, mask) in field_writes {
    if let Some(c) = class_of(&node) {
        let name = entries::entry(&node).unwrap_or_else(|| node.text().to_string());
        *stored.entry(c).or_default().entry(name).or_default() |= mask;
    }
}
```
Fixed-point loop converges in at most 2 iterations when `stored[c][f] & known[c][f] == stored[c][f]`.

### 5.4 Responds Dispatch (`Reached::Responds`)
When nested callbacks or blocks return a value with `mask = self.tainted(val, &env)`:
For each bit $k$ in `mask`, if `rules[k].responds.as_ref().is_some_and(|r| r.holds(&f, &val))`, rule $k$ generates a violation.

---
## 6. Implementation & Module Structure (<300 Lines/File)

To strictly comply with larpcop's architecture and the `< 300` lines/file limit, multi-taint functionality is partitioned into 4 focused modules under `src/rules/taint/`:

1. **`src/rules/taint/multi_mask.rs` (~120 LOC)**:
   - `RuleMask = u128`, `RuleId = u8`, bitwise operators, conversion utilities.
   - `TaintEnv`: Sparse variable-to-mask mapping, scoped branch joins, entry precision.
2. **`src/rules/taint/multi_hits.rs` (~210 LOC)**:
   - `MultiHits`, `MultiHit`, `SinkRegistration`.
   - Aggregation from per-rule `prepare` results, deduplication of overlapping sink patterns.
   - Event builder mapping `Skeleton` + multi-rule guards into `MultiEvents`.
3. **`src/rules/taint/multi_summary.rs` (~180 LOC)**:
   - `MultiSummary`, `MultiSummaries`.
   - Zero-allocation merge of individual rule `Summaries` into bitmask representations.
4. **`src/rules/taint/multi_check.rs` (~260 LOC)**:
   - `check_indexed_multi`: Runs the 3-stage filter, invokes per-rule `prepare`, constructs `MultiHits` and `MultiSummaries`, executes unified `MultiCtx::run`, and drives the 2-iteration class field fixed point.
   - Dispatches violations and dedups findings by `(rule_id, line, column)`.

### Integration Point in `src/rules/file.rs`
```rust
fn taint_check_root<D: Doc>(&self, file: &SourceFile, lang: SupportLang, root: &Node<D>) -> Vec<Violation> {
    if !self.taint.iter().any(|t| t.handles(lang)) {
        return Vec::new();
    }
    let index = taint::FileIndex::new(root.clone());
    taint::check_indexed_multi(&self.taint, file, lang, &index)
}
```

---

## 7. Verification & Benchmark Rollout

1. **Golden Parity**: Every test in `cargo test --bin larpcop rules::taint::tests` must produce identical violation counts, lines, columns, and messages.
2. **Benchmark Verification**: Measure runtime on Rails/ActiveRecord (8 rules), Java (30 rules), and TS (40 rules):
   - Target: Reduce `ctx.run` from **32s to ~4-5s** (6x-8x speedup on multi-rule files).
   - Overall taint analysis time drops from **39s to ~7-9s** with zero false positive/negative drift.

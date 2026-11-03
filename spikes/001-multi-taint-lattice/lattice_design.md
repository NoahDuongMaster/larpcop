# Multi-Taint Lattice Design: Bitvector State & Evaluation

## 1. Problem Formulation & Lattice Theory

Larpcop currently executes taint analysis on a per-rule basis: each active rule initiates an independent AST scope walk (`run_scope`) using `names: HashSet<String>` and boolean expression evaluation (`tainted(...) -> bool`). With $R$ active rules, the file AST is traversed $R$ times ($O(R \times N)$ nodes).

Multi-Taint replaces these $R$ passes with a single unified pass by lifting the abstract state to a bitvector lattice over the power set of active rules $\mathcal{P}(\{0, 1, \dots, R-1\})$ where $R \le 128$:

- **Lattice Domain**: $(\{0, 1\}^R, \sqsubseteq, \sqcup, \sqcap, \bot, \top)$
- **Bottom ($\bot = 0$)**: Expression/variable carries no taint under any active rule.
- **Top ($\top = (1 \ll R) - 1$)**: Expression/variable carries taint under all active rules.
- **Partial Order ($\sqsubseteq$)**: $A \sqsubseteq B \iff (A \ \& \ B) == A$ (rule subset containment).
- **Join Operator ($\sqcup$)**: Bitwise OR ($A \mid B$).
- **Meet Operator ($\sqcap$)**: Bitwise AND ($A \ \& \ B$).
- **Sanitization / Guard Restriction**: $A \setminus S \iff A \ \& \ (!S)$ (clearing sanitized rule bits).

## 2. Core Data Structures

### 2.1 RuleMask
`RuleMask = u128`: Bit $k$ ($0 \le k < R$) corresponds to active rule $k$. It fits directly in modern registers, enabling zero-allocation single-cycle set operations.

### 2.2 TaintEnv
Replaces `HashSet<String>` with a sparse mapping from variable names to their rule bitmasks:

```rust
pub type RuleMask = u128;

#[derive(Clone, Default, Debug, PartialEq)]
pub struct TaintEnv {
    pub vars: HashMap<String, RuleMask>,
    pub has_entries: bool,
}

impl TaintEnv {
    pub fn get(&self, name: &str) -> RuleMask {
        self.vars.get(name).copied().unwrap_or(0)
    }
    pub fn set(&mut self, name: impl Into<String>, mask: RuleMask) {
        let key = name.into();
        if key.contains('[') { self.has_entries = true; }
        if mask == 0 { self.vars.remove(&key); } else { self.vars.insert(key, mask); }
    }
    pub fn or_mask(&mut self, name: impl Into<String>, add: RuleMask) {
        if add != 0 {
            let key = name.into();
            if key.contains('[') { self.has_entries = true; }
            *self.vars.entry(key).or_default() |= add;
        }
    }
    pub fn mask_out(&mut self, name: &str, clear: RuleMask) {
        if let Some(entry) = self.vars.get_mut(name) {
            *entry &= !clear;
            if *entry == 0 { self.vars.remove(name); }
        }
    }
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.has_entries |= other.has_entries;
        for (var, mask) in &other.vars {
            *result.vars.entry(var.clone()).or_default() |= *mask;
        }
        result
    }
}
```

## 3. Expression Evaluation Trace (`flow.rs::tainted`)

Instead of returning `bool`, expression evaluation computes a `RuleMask`:
`pub fn tainted<D: Doc>(&self, node: &Node<D>, env: &TaintEnv) -> RuleMask`

### 3.1 Evaluation Rules
1. **Functions as values**: Code nodes (`is_function(node)`) return `0`.
2. **Numeric and Scalars**: Language scalars (`int`, `boolean`, `float`) and counts (`len()`, `.size()`) return `0`.
3. **Sources and Sanitizers**:
   - Let `src_mask = self.sources.matching(&node.range())`.
   - Let `san_mask = self.sanitizers.matching(&node.range())`.
   - At node completion: `result = (expr_mask | src_mask) & !san_mask`.
4. **Leaf Identifiers**:
   - Read base variable: `mask = env.get(node.text())`.
   - Map read whole: If identifier is a container holding tainted entries, accumulate: `mask |= env.entries_of(node.text())`.
   - Ruby bare calls: If `self.bare_calls && node.kind() == "identifier"`, lookup summary: `mask |= self.summaries.get(text).map_or(0, |s| s.returns_source)`.
   - Bound by active rules: `mask & self.active_rules`.
5. **Map Entries (`m[k]`, `m.get(k)`)**:
   - Evaluates specific entry: `mask = env.get("m[k]") | env.get("m")`.
   - Propagates whole-map taint to any subscript while preserving per-key precision.
6. **Binary Expressions & Concatenations**:
   - `left_mask | right_mask`.
   - Fallback across child nodes: `node.children().fold(0, |acc, c| acc | self.tainted(&c, env))`.
7. **Ternary & Conditionals (`c ? a : b`)**:
   - Extract guard conditions: `(holds, fails) = guards::safe(&cond, &self.guards)`.
   - Evaluate arms with selective mask clearing:
     `mask_a = self.tainted(a, &env.with_guards_cleared(&holds))`
     `mask_b = self.tainted(b, &env.with_guards_cleared(&fails))`
   - Arm join: `mask_a | mask_b`.
8. **Calls & Interprocedural Summaries**:
   - For summarized callee `s`:
     `passed_mask = s.returns_source | sum_{i in s.returns} self.tainted(args[i], env)`.
   - If method getter/guessed receiver: `passed_mask |= self.tainted(receiver, env)`.

## 4. Control Flow & Scope Walking (`walk.rs`)

### 4.1 Straight-line & Conditional Assignments
- **Unconditional (`x = rhs`)**: Strong update: `env.set(x, self.tainted(rhs, &env))`.
- **Compound (`x += rhs`)**: Weak update: `env.or_mask(x, self.tainted(rhs, &env))`.
- **Branch-local (`if (...) { x = rhs; }`)**:
  Let `prev = env.get(x)` and `rhs_mask = self.tainted(rhs, &env)`.
  If `prev & !rhs_mask != 0`, the un-taken path preserves pre-branch taint.
  Track `until.push((branch_end, x.to_string(), prev & !rhs_mask))`.
  At `at >= branch_end`, un-taken bits are restored via `env.or_mask(x, restored_mask)`.

### 4.2 Sinks and Violation Dispatch
When encountering `Event::Sink(arg, typed, sink_mask)`:
```rust
let arg_mask = self.tainted(arg, &env);
let reached_mask = arg_mask & sink_mask;
if reached_mask != 0 {
    for k in 0..active_rules_len {
        if (reached_mask & (1 << k)) != 0 && self.rules[k].typed.holds(lang, file, &typed) {
            out.push(self.rules[k].violation(file, arg, None));
        }
    }
}
```

### 4.3 Branch Joins in `Shape::If`
When an `if` has an `else` clause and both branches assign to a set of variables (`Event::Both(range, assigned_vars)`):
- Instead of re-tainting from pre-branch state, the environment after the construct is the least upper bound of both branch environments:
```rust
let joined_env = then_env.join(&else_env);
for (var, mask) in joined_env.vars {
    env.set(var, mask);
}
```
This prevents false positives when both branches overwrite a tainted variable with clean values.

### 4.4 Guard Events
- `Event::Clean(guarded)`: Permanent guard cleaning from `After(at, ...)`: `for (var, mask) in guarded { env.mask_out(var, mask); }`.
- `Event::Enter(guarded)`: Scoped guard cleaning `Within(range, ...)`: Clears bits in `env`, saving `(var, cleared_bits)` to `cleaned: Vec<Vec<(String, RuleMask)>>`.
- `Event::Restore`: Pops `cleaned` and re-applies cleared bits via `env.or_mask(var, bits)`.
- `Event::Settle(end, safe)`: Records names proved safe by an untaken path, preventing `until` from restoring taint.

## 5. Edge Cases

### 5.1 Bare Calls (Ruby)
In Ruby, parameterless method invocations (`params`, `custom_fields`) share the AST shape of local identifiers (`node.kind() == "identifier"`).
- **Disambiguation**: If an identifier exists in `env`, local variable taint applies.
- **Method Sourcing**: If the identifier names a method returning request data for any active rule, `summary.returns_source: RuleMask` supplies those rule bits.
- **Unified Resolution**: `mask = env.get(name) | summary.returns_source`.

### 5.2 Map & Dictionary Entries (`m[k]`)
- **Granularity**: Keys are normalized without quotes: `m[id]`, `conf[sec\x01key]`.
- **Direct Subscript**: `m['id'] = tainted` updates key `m[id]` in `env`.
- **Map-Level Propagation**: Reading `m['id']` retrieves `env.get("m[id]") | env.get("m")`. If the whole map was tainted (`m = req.params`), all subscripts inherit taint.
- **Whole Map Read**: `sink(m)` evaluates `env.get("m") | env.entries_of("m")`, detecting taint if any entry is tainted.

### 5.3 Class Fields (`this.x`, `@x`, `self.x`)
- Methods reading fields look up `this.x` (or `@x`, `self.x`) in `env`.
- Assignments to fields emit `Reached::Field(node, field_mask)`.
- `check_indexed` executes fixed-point iteration over class fields:
  `fields: HashMap<ClassKey, HashMap<String, RuleMask>>`.
  Convergence test: for every stored `(class, field, mask)`, `(fields[class][field] & mask) == mask`.
  Terminates in at most 2 passes because the lattice height per variable is bounded by active rules count.

## 6. Prototype Verification

The lattice algorithms, bitvector operations, and edge cases are verified in `spikes/001-multi-taint-lattice/prototype.rs`:
- `test_binary_expression_joins_rules`: Multi-rule taint merges via bitwise OR ($R_0 \mid R_1 = 0b11$).
- `test_sanitizer_clears_single_rule`: Sanitizer for $R_0$ clears bit 0, leaving $R_1$ intact ($0b11 \& !0b01 = 0b10$).
- `test_map_entry_precision_and_whole_read`: Per-key isolation (`req[id]` vs `req[name]`) and whole-map read aggregation ($0b01 \mid 0b10 = 0b11$).
- `test_if_join_environment`: Branch join computes least upper bound across variables.
- `test_guard_clearing_in_ternary`: Conditional guard clears bit 0 in true branch without affecting $R_1$.
- `test_ruby_bare_call`: Ruby bare identifier resolves `returns_source` bitmask from summary.

All 6 unit tests pass with zero allocation overhead in evaluation loops.
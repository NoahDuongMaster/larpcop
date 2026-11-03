//! One scope of the flow walk: its events in source order change which names
//! are tainted; sinks, calls and returns are judged with the state at that point.

use super::containers::filled;
use super::events::{Event, Hits};
use super::flow::{Ctx, Reached, Seen};
use super::summary::args;
use super::{NAMES, VARIABLES, destructure};
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

impl Ctx {
    pub(super) fn run_scope<'a, D: Doc>(
        &self,
        scope: &Node<'a, D>,
        mut names: HashSet<String>,
        hits: &Hits<'a, D>,
        on: &mut impl FnMut(Seen<'a, D>),
    ) -> HashSet<String> {
        let events = hits.events(scope, &self.guards);
        let mut cleaned: Vec<Vec<String>> = Vec::new();
        // Names a branch cleaned, tainted again where the branch ends.
        let mut until: Vec<(usize, String)> = Vec::new();
        // Names whose value starts safely (`url = reverse(…)`): appending to
        // them (`url += "?q=" + q`) cannot change where they lead.
        let mut prefixed: HashSet<String> = HashSet::new();
        // (end of an `if`, names its untaken path proved safe).
        let mut settled: Vec<(usize, HashSet<String>)> = Vec::new();
        // Objects this scope builds (`req = new PayRequest()`): what their
        // setters are given, they hold.
        let mut built: HashSet<String> = HashSet::new();
        // What each tainted local was built from, for checks made after.
        let mut origins = super::origins::Origins::default();
        // C `p = &data`: `p` and `data` are one place.
        let pointers = super::pointers::groups(&events);
        // `if` nodes whose every branch assigns these names, and the names
        // an assignment inside tainted (joins.rs).
        let mut joined: Vec<(std::ops::Range<usize>, HashSet<String>, HashSet<String>)> =
            Vec::new();
        for (at, e) in events.iter() {
            super::pointers::spread(&pointers, &mut names);
            until.retain(|(end, name)| {
                let over = *end <= *at;
                let both = |(r, set, dirty): &(
                    std::ops::Range<usize>,
                    HashSet<String>,
                    HashSet<String>,
                )| {
                    r.start < *end && *end <= r.end && set.contains(name) && !dirty.contains(name)
                };
                let kept = settled.iter().any(|(e, s)| e == end && s.contains(name))
                    || joined.iter().any(both);
                if over && !kept {
                    names.insert(name.clone());
                }
                !over
            });
            match e {
                Event::Clean(guarded) => {
                    let guarded = origins.widen(guarded, &names);
                    names.retain(|n| !guarded.contains(n))
                }
                Event::Enter(guarded) => {
                    let guarded = origins.widen(guarded, &names);
                    let was: Vec<String> = guarded
                        .iter()
                        .filter(|g| names.remove(*g))
                        .cloned()
                        .collect();
                    cleaned.push(was);
                }
                Event::Restore => names.extend(cleaned.pop().unwrap_or_default()),
                // The other path proved these safe: a clean value assigned in
                // the branch stays (`if (!ok(x)) x = fallback;`).
                Event::Settle(end, safe) => settled.push((*end, safe.clone())),
                Event::Both(range, set) => {
                    joined.push((range.clone(), set.clone(), HashSet::new()))
                }
                Event::Assign(left, right, branch, true) => {
                    let ltext = left.text();
                    if self.tainted(right, &names) {
                        mark(&mut joined, *at, &ltext);
                        names.insert(ltext.to_string());
                        on(Seen::Reached(Reached::Field(left.clone())));
                    } else if names.remove(ltext.as_ref())
                        && let Some(end) = branch
                    {
                        until.push((*end, ltext.to_string()));
                    }
                }
                Event::Assign(left, right, branch, false) => {
                    let name = left.text().to_string();
                    let appended =
                        branch.is_some_and(|end| end == left.parent().map_or(0, |p| p.range().end));
                    if appended && prefixed.contains(&name) && !names.contains(&name) {
                        continue;
                    }
                    let safe_start = self.starts_safe(right);
                    if !appended {
                        if safe_start {
                            prefixed.insert(name);
                        } else {
                            prefixed.remove(&name);
                        }
                    }
                    // PHP `$t += 0`: a number, whatever `$t` held.
                    let numeric = self.numbers
                        && left.parent().is_some_and(|p| {
                            p.kind() == "augmented_assignment_expression"
                                && super::numeric::arithmetic(&p)
                        });
                    let appended = appended && !numeric;
                    let branch = if numeric { &None } else { branch };
                    let tainted = !numeric && !safe_start && self.tainted(right, &names);
                    // Built from tainted names only, or from a source itself.
                    let from = (tainted && !self.tainted(right, &HashSet::new())).then(|| {
                        right
                            .dfs()
                            .filter(|c| NAMES.contains(&c.kind().as_ref()))
                            .filter_map(|c| names.get(c.text().as_ref()).cloned())
                            .collect()
                    });
                    if right.kind() == "object_creation_expression" && left.kind() == "identifier" {
                        built.insert(left.text().to_string());
                    }
                    // `m['k'] = v`: that entry only.
                    if let Some(entry) = super::entries::entry(left) {
                        if tainted {
                            // `$this->input[1] = …`: an entry of an own field.
                            if super::fields::is_field(&left.child(0).unwrap_or(left.clone())) {
                                on(Seen::Reached(Reached::Field(left.clone())));
                            }
                            names.insert(entry);
                        } else if names.remove(&entry)
                            && let Some(end) = branch
                        {
                            until.push((*end, entry));
                        }
                        continue;
                    }
                    for v in left
                        .dfs()
                        .filter(|n| VARIABLES.contains(&n.kind().as_ref()))
                    {
                        let vtext = v.text();
                        if tainted {
                            let adds = appended || branch.is_some();
                            origins.record(
                                &vtext,
                                from.clone(),
                                adds && names.contains(vtext.as_ref()),
                            );
                            mark(&mut joined, *at, &vtext);
                            names.insert(vtext.to_string());
                        } else if NAMES.contains(&left.kind().as_ref())
                            && names.remove(vtext.as_ref())
                            && let Some(end) = branch
                        {
                            until.push((*end, vtext.to_string()));
                        }
                    }
                    if !tainted && right.kind() == "identifier" {
                        let object = right.text();
                        names.extend(destructure::from_object(left, &object, &self.source_texts));
                    }
                }
                Event::Sink(arg, typed) if self.tainted(arg, &names) => {
                    on(Seen::Reached(Reached::Sink(arg.clone(), typed.clone())))
                }
                Event::Nested(f) => {
                    on(Seen::Nested(f.clone(), names.clone()));
                    // `rows.forEach(r -> out.append(r))`: what it writes here.
                    let written = self.captured_writes(scope, f, &names, hits);
                    names.extend(written);
                }
                Event::Call(call) => {
                    // `fgets(buf, …)`, `strcat(dst, src)`: the written argument.
                    let written = self.writes.written(call, |a| self.tainted(a, &names));
                    names.extend(written);
                    // `list.push(x)`, `map.set(k, x)`, `Object.assign(o, x)`: the
                    // container now holds what was put in.
                    // `m.put("k", v)`: that entry only.
                    if let Some(value) = super::entries::stored(call)
                        && let Some(entry) = super::entries::entry(call)
                    {
                        if self.tainted(&value, &names) {
                            names.insert(entry);
                        } else {
                            names.remove(&entry);
                        }
                    } else if let Some(container) = filled(call)
                        .filter(|_| !(self.writes_clean && super::containers::writes(call)))
                        .or_else(|| super::containers::set_on(call, &built))
                        && args(call).iter().any(|a| self.tainted(a, &names))
                    {
                        names.extend(super::containers::wrapped(call, &container));
                        names.insert(container.clone());
                        on(Seen::Reached(Reached::Filled(container)));
                    } else if let Some(object) = super::containers::setter_object(call)
                        && args(call).iter().any(|a| self.tainted(a, &names))
                    {
                        // A setter of an object given to this scope: its
                        // caller's object holds the value (not this scope's
                        // view of it: a framework object stays as it is).
                        on(Seen::Reached(Reached::Filled(object)));
                    }
                    let Some(s) = self.summary(call) else {
                        continue;
                    };
                    let args = args(call);
                    // `fill(order, x)`: `order` now holds `x`.
                    for (i, j) in &s.fills {
                        if let (Some(from), Some(to)) = (args.get(*i), args.get(*j))
                            && NAMES.contains(&to.kind().as_ref())
                            && self.tainted(from, &names)
                        {
                            names.insert(to.text().to_string());
                        }
                    }
                    for (i, into) in &s.sinks {
                        // `http_redirect("?picid=" . $id)` calling `header(…)`:
                        // the argument starts safely, whatever the callee does.
                        let safe = |a: &Node<D>| self.starts_safe(a);
                        if let Some(a) =
                            args.get(*i).filter(|a| self.tainted(a, &names) && !safe(a))
                        {
                            // `readFile(() -> ALLOWED.contains(f), f)`: the callee
                            // reaches its sink only when this check holds.
                            let checked = s.conditions.get(i).is_some_and(|(g, applied)| {
                                args.get(*g).is_some_and(|check| {
                                    let applied = applied.and_then(|k| args.get(k));
                                    let safe = super::lambdas::validated(
                                        check,
                                        applied,
                                        call,
                                        &self.guards,
                                    );
                                    super::lambdas::covers(a, &names, &safe)
                                })
                            });
                            if !checked {
                                on(Seen::Reached(Reached::Call(a.clone(), into.clone())));
                            }
                        }
                    }
                    // A static field the callee reads, tainted here.
                    for (key, into) in &s.statics {
                        if super::statics::held(call, key, &names) {
                            on(Seen::Reached(Reached::Call(call.clone(), into.clone())));
                        }
                    }
                }
                Event::Return(r) if self.tainted(r, &names) => {
                    on(Seen::Reached(Reached::Return(r.clone())))
                }
                _ => {}
            }
        }
        names
    }

    /// Under `safe_prefix`: does the value start with a matching literal, or
    /// with what a sanitizer returns (a URL the app builds, `reverse(…)`)?
    fn starts_safe<D: Doc>(&self, value: &Node<D>) -> bool {
        let Some(safe) = &self.safe_prefix else {
            return false;
        };
        let first = super::prefix::leftmost(value);
        let r = first.range();
        self.sanitizers.covers(&r) || super::prefix::safe_start(safe, value)
    }
}

/// An assignment at `at` tainted `name`: inside an `if` whose branches all
/// assign it, the name is no longer clean whatever the branches end with.
fn mark(
    joined: &mut [(std::ops::Range<usize>, HashSet<String>, HashSet<String>)],
    at: usize,
    name: &str,
) {
    for (r, set, dirty) in joined.iter_mut() {
        if r.contains(&at) && set.contains(name) {
            dirty.insert(name.to_string());
        }
    }
}

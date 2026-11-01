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
    ) {
        let events = hits.events(scope, &self.guards);
        let mut cleaned: Vec<Vec<String>> = Vec::new();
        // Names a branch cleaned, tainted again where the branch ends.
        let mut until: Vec<(usize, String)> = Vec::new();
        // Names whose value starts safely (`url = reverse(…)`): appending to
        // them (`url += "?q=" + q`) cannot change where they lead.
        let mut prefixed: HashSet<String> = HashSet::new();
        // (end of an `if`, names its untaken path proved safe).
        let mut settled: Vec<(usize, HashSet<String>)> = Vec::new();
        for (at, e) in events.iter() {
            until.retain(|(end, name)| {
                let over = *end <= *at;
                let kept = settled.iter().any(|(e, s)| e == end && s.contains(name));
                if over && !kept {
                    names.insert(name.clone());
                }
                !over
            });
            match e {
                Event::Clean(guarded) => names.retain(|n| !guarded.contains(n)),
                Event::Enter(guarded) => {
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
                Event::Assign(left, right, branch, true) => {
                    if self.tainted(right, &names) {
                        names.insert(left.text().to_string());
                        on(Seen::Reached(Reached::Field(left.clone())));
                    } else if names.remove(left.text().as_ref())
                        && let Some(end) = branch
                    {
                        until.push((*end, left.text().to_string()));
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
                    let tainted = !safe_start && self.tainted(right, &names);
                    // `m['k'] = v`: that entry only.
                    if let Some(entry) = super::entries::entry(left) {
                        if tainted {
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
                        if tainted {
                            names.insert(v.text().to_string());
                        } else if NAMES.contains(&left.kind().as_ref())
                            && names.remove(v.text().as_ref())
                            && let Some(end) = branch
                        {
                            until.push((*end, v.text().to_string()));
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
                Event::Nested(f) => on(Seen::Nested(f.clone(), names.clone())),
                Event::Call(call) => {
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
                        && args(call).iter().any(|a| self.tainted(a, &names))
                    {
                        names.insert(container);
                    }
                    let Some(s) = self.summary(call) else {
                        continue;
                    };
                    let args = args(call);
                    for (i, into) in &s.sinks {
                        if let Some(a) = args.get(*i).filter(|a| self.tainted(a, &names)) {
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
                }
                Event::Return(r) if self.tainted(r, &names) => {
                    on(Seen::Reached(Reached::Return(r.clone())))
                }
                _ => {}
            }
        }
    }

    /// Under `safe_prefix`: does the value start with a matching literal, or
    /// with what a sanitizer returns (a URL the app builds, `reverse(…)`)?
    fn starts_safe<D: Doc>(&self, value: &Node<D>) -> bool {
        let Some(safe) = &self.safe_prefix else {
            return false;
        };
        let first = super::prefix::leftmost(value);
        let r = first.range();
        self.sanitizers
            .iter()
            .any(|s| s.start <= r.start && r.end <= s.end)
            || super::prefix::leading(value).is_some_and(|start| safe.is_match(&start))
    }
}

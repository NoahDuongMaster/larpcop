//! Multi-Taint Lattice Prototype: bitvector state, environment, and evaluation.
use std::collections::HashMap;

pub type RuleMask = u128;

#[derive(Clone, Default, Debug, PartialEq)]
pub struct TaintEnv {
    pub vars: HashMap<String, RuleMask>,
    pub has_entries: bool,
}

impl TaintEnv {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get(&self, name: &str) -> RuleMask {
        self.vars.get(name).copied().unwrap_or(0)
    }
    pub fn set(&mut self, name: impl Into<String>, mask: RuleMask) {
        let key = name.into();
        if key.contains('[') {
            self.has_entries = true;
        }
        if mask == 0 {
            self.vars.remove(&key);
        } else {
            self.vars.insert(key, mask);
        }
    }
    pub fn or_mask(&mut self, name: impl Into<String>, add_mask: RuleMask) {
        if add_mask != 0 {
            let key = name.into();
            if key.contains('[') {
                self.has_entries = true;
            }
            *self.vars.entry(key).or_default() |= add_mask;
        }
    }
    pub fn mask_out(&mut self, name: &str, clear_mask: RuleMask) {
        if let Some(entry) = self.vars.get_mut(name) {
            *entry &= !clear_mask;
            if *entry == 0 {
                self.vars.remove(name);
            }
        }
    }
    pub fn entries_of(&self, base: &str) -> RuleMask {
        if !self.has_entries {
            return 0;
        }
        let prefix = format!("{base}[");
        self.vars
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .fold(0, |acc, (_, v)| acc | *v)
    }
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.has_entries |= other.has_entries;
        for (var, mask) in &other.vars {
            *result.vars.entry(var.clone()).or_default() |= *mask;
        }
        result
    }
    pub fn with_guards_cleared(&self, guards: &HashMap<String, RuleMask>) -> Self {
        let mut next = self.clone();
        for (var, clear_mask) in guards {
            next.mask_out(var, *clear_mask);
        }
        next
    }
}

#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub returns_source: RuleMask,
    pub returns_args: Vec<usize>,
}

pub struct EvalContext<'a> {
    pub active_rules: RuleMask,
    pub sources: &'a HashMap<String, RuleMask>,
    pub sanitizers: &'a HashMap<String, RuleMask>,
    pub summaries: &'a HashMap<String, Summary>,
    pub bare_calls: bool,
}

pub enum Expr {
    Ident(String),
    Scalar(String),
    MapAccess {
        base: String,
        key: String,
    },
    Binary(Box<Expr>, Box<Expr>),
    Ternary {
        holds_guards: HashMap<String, RuleMask>,
        fails_guards: HashMap<String, RuleMask>,
        then_arm: Box<Expr>,
        else_arm: Box<Expr>,
    },
    Call {
        callee: String,
        args: Vec<Expr>,
    },
}

impl<'a> EvalContext<'a> {
    pub fn eval(&self, expr: &Expr, env: &TaintEnv) -> RuleMask {
        match expr {
            Expr::Scalar(_) => 0,
            Expr::Ident(name) => {
                let src = self.sources.get(name).copied().unwrap_or(0);
                let san = self.sanitizers.get(name).copied().unwrap_or(0);
                let mut mask = env.get(name);
                if env.has_entries {
                    mask |= env.entries_of(name);
                }
                if self.bare_calls {
                    if let Some(s) = self.summaries.get(name) {
                        mask |= s.returns_source;
                    }
                }
                ((mask | src) & !san) & self.active_rules
            }
            Expr::MapAccess { base, key } => {
                let entry_name = format!("{base}[{key}]");
                let src = self.sources.get(&entry_name).copied().unwrap_or(0);
                let san = self.sanitizers.get(&entry_name).copied().unwrap_or(0);
                let mask = env.get(&entry_name) | env.get(base);
                ((mask | src) & !san) & self.active_rules
            }
            Expr::Binary(left, right) => {
                (self.eval(left, env) | self.eval(right, env)) & self.active_rules
            }
            Expr::Ternary {
                holds_guards,
                fails_guards,
                then_arm,
                else_arm,
            } => {
                let env_then = env.with_guards_cleared(holds_guards);
                let env_else = env.with_guards_cleared(fails_guards);
                let tm = self.eval(then_arm, &env_then);
                let em = self.eval(else_arm, &env_else);
                (tm | em) & self.active_rules
            }
            Expr::Call { callee, args } => {
                let src = self.sources.get(callee).copied().unwrap_or(0);
                let san = self.sanitizers.get(callee).copied().unwrap_or(0);
                let mut passed = 0;
                if let Some(s) = self.summaries.get(callee) {
                    passed |= s.returns_source;
                    for &idx in &s.returns_args {
                        if let Some(arg) = args.get(idx) {
                            passed |= self.eval(arg, env);
                        }
                    }
                } else {
                    for arg in args {
                        passed |= self.eval(arg, env);
                    }
                }
                ((passed | src) & !san) & self.active_rules
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_ctx<'a>(
        active_rules: RuleMask,
        sanitizers: &'a HashMap<String, RuleMask>,
        summaries: &'a HashMap<String, Summary>,
        bare_calls: bool,
    ) -> EvalContext<'a> {
        static EMPTY_MAP: std::sync::LazyLock<HashMap<String, RuleMask>> =
            std::sync::LazyLock::new(HashMap::new);
        EvalContext {
            active_rules,
            sources: &EMPTY_MAP,
            sanitizers,
            summaries,
            bare_calls,
        }
    }

    #[test]
    fn test_binary_expression_joins_rules() {
        let mut env = TaintEnv::new();
        env.set("a", 1 << 0); // Rule 0 (SQLi)
        env.set("b", 1 << 1); // Rule 1 (XSS)
        let empty_sum = HashMap::new();
        let empty_san = HashMap::new();
        let ctx = mock_ctx(0b11, &empty_san, &empty_sum, false);
        let expr = Expr::Binary(
            Box::new(Expr::Ident("a".into())),
            Box::new(Expr::Ident("b".into())),
        );
        assert_eq!(ctx.eval(&expr, &env), 0b11);
    }

    #[test]
    fn test_sanitizer_clears_single_rule() {
        let mut env = TaintEnv::new();
        env.set("input", 0b11);
        let mut sanitizers = HashMap::new();
        sanitizers.insert("escape_sql".into(), 1 << 0);
        let empty_sum = HashMap::new();
        let ctx = mock_ctx(0b11, &sanitizers, &empty_sum, false);
        let call = Expr::Call {
            callee: "escape_sql".into(),
            args: vec![Expr::Ident("input".into())],
        };
        assert_eq!(ctx.eval(&call, &env), 0b10);
    }

    #[test]
    fn test_map_entry_precision_and_whole_read() {
        let mut env = TaintEnv::new();
        env.set("req[id]", 1 << 0);
        env.set("req[name]", 1 << 1);
        let empty_san = HashMap::new();
        let empty_sum = HashMap::new();
        let ctx = mock_ctx(0b11, &empty_san, &empty_sum, false);
        let read_id = Expr::MapAccess {
            base: "req".into(),
            key: "id".into(),
        };
        assert_eq!(ctx.eval(&read_id, &env), 1 << 0);
        let read_whole = Expr::Ident("req".into());
        assert_eq!(ctx.eval(&read_whole, &env), 0b11);
    }

    #[test]
    fn test_if_join_environment() {
        let mut then_env = TaintEnv::new();
        then_env.set("x", 1 << 0);
        let mut else_env = TaintEnv::new();
        else_env.set("x", 1 << 1);
        let joined = then_env.join(&else_env);
        assert_eq!(joined.get("x"), 0b11);
    }

    #[test]
    fn test_guard_clearing_in_ternary() {
        let mut env = TaintEnv::new();
        env.set("url", 0b11);
        let mut holds = HashMap::new();
        holds.insert("url".into(), 1 << 0);
        let empty_san = HashMap::new();
        let empty_sum = HashMap::new();
        let ctx = mock_ctx(0b11, &empty_san, &empty_sum, false);
        let ternary = Expr::Ternary {
            holds_guards: holds,
            fails_guards: HashMap::new(),
            then_arm: Box::new(Expr::Ident("url".into())),
            else_arm: Box::new(Expr::Scalar("safe".into())),
        };
        assert_eq!(ctx.eval(&ternary, &env), 0b10);
    }

    #[test]
    fn test_ruby_bare_call() {
        let env = TaintEnv::new();
        let mut summaries = HashMap::new();
        summaries.insert(
            "custom_params".into(),
            Summary {
                returns_source: 1 << 2,
                returns_args: Vec::new(),
            },
        );
        let empty_san = HashMap::new();
        let ctx = mock_ctx(1 << 2, &empty_san, &summaries, true);
        let bare = Expr::Ident("custom_params".into());
        assert_eq!(ctx.eval(&bare, &env), 1 << 2);
    }
}

//! Routes without variables (`@app.route('/a/b')`): in their handlers the
//! request path is the route itself. Werkzeug dispatches a request only when
//! its decoded path equals the rule (`//a/b` and `/a/b/` are redirected, a
//! `;` makes it a 404), so a source listed in `fixed_route_sources`
//! (`request.path`) is a constant there, not request data. Off in a project
//! that mounts a blueprint under a prefix with variables
//! (`url_prefix='/<lang>'`), in any of its files.

use super::handlers::decorators_of;
use crate::files::{self, Scope};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

pub(crate) struct FixedRoutes {
    /// Sources whose value is the route (`request.path`), without whitespace.
    pub sources: Vec<String>,
    /// Whether some blueprint of the project has a prefix with variables.
    pub prefixed: OnceLock<bool>,
}

impl FixedRoutes {
    /// Is `source` the path of a route without variables?
    pub(super) fn is_constant<D: Doc>(
        &self,
        source: &Node<D>,
        handlers: &Regex,
        root: &Path,
    ) -> bool {
        let text: String = source.text().split_whitespace().collect();
        if !self.sources.contains(&text) {
            return false;
        }
        let Some(f) = source.ancestors().find(|a| is_function(a)) else {
            return false;
        };
        let routes: Vec<String> = decorators_of(&f)
            .into_iter()
            .filter(|d| handlers.is_match(d))
            .collect();
        !routes.is_empty()
            && routes.iter().all(|d| fixed(d))
            && !*self.prefixed.get_or_init(|| prefixed(root))
    }
}

/// `app.route('/a/b', methods=[…])`: the first argument a plain string
/// without `<converter:name>` parts.
fn fixed(decorator: &str) -> bool {
    let Some(open) = decorator.find('(') else {
        return false;
    };
    let rest = decorator[open + 1..].trim_start();
    let Some(quote) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') else {
        return false;
    };
    rest[1..]
        .find(quote)
        .is_some_and(|end| !rest[1..1 + end].contains(['<', '{', '\\']))
}

/// Does a Python file of the project mount routes under a variable prefix?
fn prefixed(root: &Path) -> bool {
    let re = Regex::new(r#"url_prefix\s*=\s*[rRuUfF]?['"][^'"]*[<{]"#).expect("valid regex");
    files::list(root, &Scope::All)
        .unwrap_or_default()
        .iter()
        .filter(|p| p.ends_with(".py"))
        .any(|p| std::fs::read_to_string(root.join(p)).is_ok_and(|s| re.is_match(&s)))
}

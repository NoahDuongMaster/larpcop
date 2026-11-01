//! RPC service methods: gRPC hands a method the client's message as a
//! parameter, with no request object in sight.
//! - A method taking a `StreamObserver<…>` (gRPC Java) or a
//!   `ServerCallContext` (gRPC C#) is one.
//! - `handler_classes`: every method of a class whose header matches
//!   (`class GreeterService : GreeterGrpcKt.GreeterCoroutineImplBase()`,
//!   `class Greeter(helloworld_pb2_grpc.GreeterServicer)`).
//! - `input_types`: a parameter whose declared type matches, in a method
//!   that also takes the call's `context.Context` (Go
//!   `func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest)`;
//!   a helper given an internally built `*core.InternalRequest` is not one).
//!
//! The framework's own parameters (the observer, the call context,
//! `context.Context`, `*http.Request`) are not request data.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use regex::Regex;
use std::collections::HashSet;

/// Parameter types that make a method an RPC handler.
const MARKERS: [&str; 2] = ["StreamObserver", "ServerCallContext"];
/// Parameters that belong to the framework, by type or (untyped) name.
const FRAMEWORK_TYPES: [&str; 5] = [
    "StreamObserver",
    "ServerCallContext",
    "context.Context",
    "CancellationToken",
    "http.Request",
];
const FRAMEWORK_NAMES: [&str; 4] = ["self", "cls", "context", "ctx"];

pub(super) fn params<D: Doc>(
    f: &Node<D>,
    classes: Option<&Regex>,
    types: Option<&Regex>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(list) = f.part("parameters") else {
        return out;
    };
    let params: Vec<(String, Option<String>)> = list
        .children()
        .filter(|c| c.is_named() && !matches!(c.kind().as_ref(), "comment" | "parameter_modifiers"))
        .filter_map(|p| Some((super::handlers::name_of(&p)?, super::handlers::type_of(&p))))
        .collect();
    let framework = |(name, ty): &(String, Option<String>)| match ty {
        Some(t) => FRAMEWORK_TYPES.iter().any(|f| t.contains(f)),
        None => FRAMEWORK_NAMES.contains(&name.as_str()),
    };
    let marked = params.iter().any(|(_, ty)| {
        ty.as_ref()
            .is_some_and(|t| MARKERS.iter().any(|m| t.contains(m)))
    });
    let in_class = classes.is_some_and(|re| header(f).is_some_and(|h| re.is_match(&h)));
    let rpc_shaped = f.kind() == "method_declaration"
        && params.iter().any(|(_, ty)| {
            ty.as_deref()
                .is_some_and(|t| t.ends_with("context.Context"))
        });
    for p in &params {
        if framework(p) {
            continue;
        }
        let typed =
            rpc_shaped && types.is_some_and(|re| p.1.as_ref().is_some_and(|t| re.is_match(t)));
        if marked || in_class || typed {
            out.insert(p.0.clone());
        }
    }
    out
}

/// Could a file define an RPC handler? Cheap text check before the walk.
pub(super) fn may_serve(content: &str, classes: Option<&Regex>, typed: bool) -> bool {
    MARKERS.iter().any(|m| content.contains(m))
        || classes.is_some_and(|re| re.is_match(content))
        || (typed && content.contains("Request"))
}

/// The header of the class `f` is a method of: `class A extends B ` up to
/// its body.
fn header<D: Doc>(f: &Node<D>) -> Option<String> {
    let class = f
        .ancestors()
        .take_while(|a| !crate::rules::complexity::is_function(a))
        .find(|a| {
            matches!(
                a.kind().as_ref(),
                "class_declaration" | "class_definition" | "object_declaration"
            )
        })?;
    let body = class.part("body")?;
    let start = class.range().start;
    let text = class.text();
    Some(text[..body.range().start.checked_sub(start)?].to_string())
}

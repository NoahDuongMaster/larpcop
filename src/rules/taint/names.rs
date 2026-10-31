//! Node kinds that are names, across grammars.

/// Kinds of a name as it is read: most grammars, PHP `$x`, Ruby `@x`, Kotlin.
pub(super) const NAMES: [&str; 5] = [
    "identifier",
    "shorthand_property_identifier",
    "variable_name",
    "instance_variable",
    "simple_identifier",
];

/// Kinds that bind a name on the left of an assignment: `NAMES` and
/// destructuring.
pub(super) const VARIABLES: [&str; 6] = [
    "identifier",
    "shorthand_property_identifier",
    "variable_name",
    "instance_variable",
    "simple_identifier",
    "shorthand_property_identifier_pattern",
];

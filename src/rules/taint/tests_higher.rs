//! A function that runs a function it is given: a cleaning argument makes
//! what it returns clean (higher.rs).

use super::tests_calls::{found, rule};

#[test]
fn helpers_running_a_cleaning_function_return_clean_data() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.js"),
        "\
const express = require('express');
const app = express();
function render(rows, format) {
  return rows.map(r => '<li>' + format(r) + '</li>').join('');
}
function wrap(value, format) {
  return '<b>' + format.call(null, value) + '</b>';
}
app.get('/a', (req, res) => res.send(render(req.query.items, x => x)));
app.get('/b', (req, res) => res.send(render(req.query.items, x => escapeHtml(x))));
app.get('/c', (req, res) => res.send(wrap(req.query.q, escapeHtml)));
app.get('/d', (req, res) => res.send(wrap(req.query.q, String)));
",
    )
    .unwrap();
    let r = rule(
        "JavaScript",
        dir.path(),
        &["req.query.$F"],
        &["res.send($X)"],
        &["escapeHtml($X)"],
    );
    let lines: Vec<usize> = found(&r, dir.path(), "a.js")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(lines, [9, 12]);
}

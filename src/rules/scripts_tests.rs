//! The JavaScript view of a page's scripts (scripts.rs).

use super::scripts::view;

#[test]
fn scripts_keep_their_lines_and_the_rest_is_blank() {
    let page = "<p>a</p>\n<script>\nvar x = 1;\n</script>\n<p>b</p>\n";
    let (js, ts) = view("index.html", page).unwrap();
    assert!(!ts);
    assert_eq!(js.len(), page.len());
    assert_eq!(js.lines().nth(2), Some("var x = 1;"));
    assert!(js.lines().next().unwrap().trim().is_empty());
    assert!(js.lines().nth(4).unwrap().trim().is_empty());
}

#[test]
fn server_tags_become_values_or_blanks() {
    let page = "<script>\nvar n = <?= $n ?>;\n<?php if ($a) { ?>go();<?php } ?>\nvar s = '{{ name }}';\nvar e = <%= id %>;\n</script>";
    let (js, _) = view("page.php", page).unwrap();
    let lines: Vec<&str> = js.lines().map(str::trim_end).collect();
    assert_eq!(lines[1], "var n = 0        ;");
    assert_eq!(lines[2].trim(), "go();");
    assert_eq!(lines[3], "var s = '0         ';");
    assert_eq!(lines[4], "var e = 0        ;");
}

#[test]
fn other_scripts_are_left_out() {
    // A template script, one in a comment, one in PHP code, a non-page file.
    let page = "<script type=\"text/template\"><b>{{x}}</b></script>\n<!-- <script>a()</script> -->\n<?php echo '<script>b()</script>'; ?>\n";
    assert_eq!(view("page.php", page), None);
    assert_eq!(view("app.js", "<script>c()</script>"), None);
    let (_, ts) = view(
        "App.vue",
        "<script setup lang=\"ts\">\nlet a: number = 1;\n</script>",
    )
    .unwrap();
    assert!(ts);
}

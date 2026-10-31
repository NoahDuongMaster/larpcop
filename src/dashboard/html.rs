//! The dashboard as one HTML file: no scripts, no external assets, so it can
//! be attached to a CI run, served by GitHub Pages or opened from disk.

use super::Dashboard;
use std::fmt::Write;

const STYLE: &str = "
:root{--fg:#1d2025;--muted:#6a7280;--line:#e3e6ea;--card:#f6f7f9;--err:#c62828;--warn:#b26a00;--ok:#2e7d32;--bar:#5b6cff}
@media(prefers-color-scheme:dark){:root{--fg:#e6e8eb;--muted:#9aa3ad;--line:#2c3138;--card:#181b20;--bar:#7d8bff}body{background:#0f1115}}
body{font:14px/1.5 system-ui,sans-serif;color:var(--fg);max-width:1100px;margin:32px auto;padding:0 20px}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:32px 0 10px}.muted{color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:18px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.tile b{display:block;font-size:24px}.err{color:var(--err)}.warn{color:var(--warn)}.ok{color:var(--ok)}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted)}td.n{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:8px;background:var(--bar);border-radius:4px;min-width:2px}code{font-size:12px}
svg{width:100%;height:140px;background:var(--card);border:1px solid var(--line);border-radius:8px}
";

pub fn page(d: &Dashboard) -> String {
    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width'>\
    <title>larpcop · {repo}</title><style>{STYLE}</style><h1>larpcop · {repo}</h1>\
    <div class=muted>Generated {gen} · {files} files checked</div><div class=tiles>",
        repo = esc(&d.repo),
        gen = esc(&d.generated),
        files = d.files
    );
    let enforced = d.org.as_ref().map(|rows| {
        let on = rows.iter().filter(|r| r.enforced()).count();
        format!("{on}/{}", rows.len())
    });
    let tiles = [
        (
            "errors",
            d.errors.to_string(),
            if d.errors > 0 { "err" } else { "ok" },
        ),
        (
            "warnings",
            d.warnings.to_string(),
            if d.warnings > 0 { "warn" } else { "ok" },
        ),
        ("baselined (debt)", d.baselined.to_string(), ""),
        ("functions", d.metrics.functions.to_string(), ""),
        (
            "mean complexity",
            format!("{:.2}", d.metrics.mean_complexity),
            "",
        ),
    ];
    for (label, value, class) in tiles {
        let _ = write!(
            h,
            "<div class=tile><b class='{class}'>{value}</b>{label}</div>"
        );
    }
    if let Some(e) = enforced {
        let _ = write!(h, "<div class=tile><b>{e}</b>repos with the CI gate</div>");
    }
    h.push_str("</div>");
    rules(&mut h, d);
    debt(&mut h, d);
    hotspots(&mut h, d);
    org(&mut h, d);
    h.push_str("</html>\n");
    h
}

fn rules(h: &mut String, d: &Dashboard) {
    let max = d
        .rules
        .iter()
        .map(|r| r.open + r.baselined)
        .max()
        .unwrap_or(0)
        .max(1);
    h.push_str("<h2>Rules</h2><table><tr><th>Rule</th><th>Level</th><th>Open</th><th>Baselined</th><th style='width:30%'></th></tr>");
    for r in &d.rules {
        let width = 100 * (r.open + r.baselined) / max;
        let _ = write!(
            h,
            "<tr><td><code>{}</code><div class=muted>{}</div></td><td>{}</td><td class=n>{}</td><td class=n>{}</td>\
<td><div class=bar style='width:{width}%'></div></td></tr>",
            esc(&r.id),
            esc(&r.message),
            r.level.as_str(),
            r.open,
            r.baselined
        );
    }
    h.push_str("</table>");
}

fn debt(h: &mut String, d: &Dashboard) {
    h.push_str("<h2>Baseline debt over time</h2>");
    if d.debt.len() < 2 {
        h.push_str("<p class=muted>Not enough history: the baseline changed in fewer than two commits.</p>");
        return;
    }
    let max = d.debt.iter().map(|p| p.entries).max().unwrap_or(1).max(1) as f64;
    let step = 1000.0 / (d.debt.len() - 1) as f64;
    let points: Vec<String> = d
        .debt
        .iter()
        .enumerate()
        .map(|(i, p)| {
            format!(
                "{:.1},{:.1}",
                i as f64 * step,
                130.0 - 120.0 * p.entries as f64 / max
            )
        })
        .collect();
    let (first, last) = (&d.debt[0], &d.debt[d.debt.len() - 1]);
    let _ = write!(
        h,
        "<svg viewBox='0 0 1000 140' preserveAspectRatio=none><polyline fill=none stroke='var(--bar)' stroke-width=3 \
points='{}'/></svg><div class=muted>{} ({}): {} → {} ({}): {}</div>",
        points.join(" "),
        esc(&first.date),
        esc(&first.commit),
        first.entries,
        esc(&last.date),
        esc(&last.commit),
        last.entries
    );
}

fn hotspots(h: &mut String, d: &Dashboard) {
    h.push_str("<h2>Most complex functions</h2><table><tr><th>Function</th><th>File</th><th>Complexity</th><th>Lines</th></tr>");
    for f in &d.metrics.most_complex {
        let _ = write!(
            h,
            "<tr><td><code>{}</code></td><td>{}:{}</td><td class=n>{}</td><td class=n>{}</td></tr>",
            esc(&f.name),
            esc(&f.file),
            f.line,
            f.complexity,
            f.lines
        );
    }
    h.push_str("</table>");
}

fn org(h: &mut String, d: &Dashboard) {
    let Some(rows) = &d.org else { return };
    h.push_str("<h2>Repositories</h2><table><tr><th>Repository</th><th>Config</th><th>CI gate</th><th>Last run</th><th>Standards</th></tr>");
    for r in rows {
        let mark = |b: bool| {
            if b {
                "<span class=ok>✓</span>"
            } else {
                "<span class=err>✗</span>"
            }
        };
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            esc(&r.repo),
            mark(r.config),
            mark(r.enforced()),
            esc(r.last_run.as_deref().unwrap_or("–")),
            esc(&r.standards.join(", "))
        );
    }
    h.push_str("</table>");
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#39;")
        .replace('"', "&quot;")
}

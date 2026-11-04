#!/usr/bin/env python3
"""Writes bench/truth/java-sec-code-truth.json: every endpoint of JoyChou93/java-sec-code
(4711f4e) in a category larpcop could check, labelled from the
project itself: `vuln`/`sec` in the route, else the comment above it
("Vuln Code", "Safe code", a PoC URL). Written before any tool ran on it.

    python3 bench/truth/java_sec_code_truth.py <java-sec-code checkout> bench/truth/java-sec-code-truth.json"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from java_endpoints import endpoints  # noqa: E402

# (file, route) -> (category, vulnerable)
LABELS = {
    ("SQLI.java", "/jdbc/vuln"): ("sql", True), ("SQLI.java", "/jdbc/sec"): ("sql", False),
    ("SQLI.java", "/jdbc/ps/vuln"): ("sql", True), ("SQLI.java", "/mybatis/vuln01"): ("sql", True),
    ("SQLI.java", "/mybatis/vuln02"): ("sql", True), ("SQLI.java", "/mybatis/orderby/vuln03"): ("sql", True),
    ("SQLI.java", "/mybatis/sec01"): ("sql", False), ("SQLI.java", "/mybatis/sec02"): ("sql", False),
    ("SQLI.java", "/mybatis/sec03"): ("sql", False), ("SQLI.java", "/mybatis/orderby/sec04"): ("sql", False),
    # PoC `filepath=/tmp;cat /etc/passwd`, `Host: …;cat /etc/passwd`.
    ("CommandInject.java", "/codeinject"): ("shell", True), ("CommandInject.java", "/codeinject/host"): ("shell", True),
    ("CommandInject.java", "/codeinject/sec"): ("shell", False),
    ("Rce.java", "/runtime/exec"): ("shell", True), ("Rce.java", "/ProcessBuilder"): ("shell", True),
    ("PathTraversal.java", "/path_traversal/vul"): ("path", True),
    ("PathTraversal.java", "/path_traversal/sec"): ("path", False),
    ("SSRF.java", "/urlConnection/vuln"): ("ssrf", True), ("SSRF.java", "/urlConnection/sec"): ("ssrf", False),
    ("SSRF.java", "/HttpURLConnection/sec"): ("ssrf", False), ("SSRF.java", "/HttpURLConnection/vuln"): ("ssrf", True),
    ("SSRF.java", "/request/sec"): ("ssrf", False),
    # PoC `url=file:///etc/passwd`.
    ("SSRF.java", "/openStream"): ("ssrf", True),
    ("SSRF.java", "/ImageIO/sec"): ("ssrf", False), ("SSRF.java", "/okhttp/sec"): ("ssrf", False),
    ("SSRF.java", "/httpclient/sec"): ("ssrf", False), ("SSRF.java", "/commonsHttpClient/sec"): ("ssrf", False),
    ("SSRF.java", "/Jsoup/sec"): ("ssrf", False), ("SSRF.java", "/IOUtils/sec"): ("ssrf", False),
    ("SSRF.java", "/HttpSyncClients/vuln"): ("ssrf", True), ("SSRF.java", "/restTemplate/vuln1"): ("ssrf", True),
    ("SSRF.java", "/restTemplate/vuln2"): ("ssrf", True), ("SSRF.java", "/hutool/vuln"): ("ssrf", True),
    ("SSRF.java", "/dnsrebind/vuln"): ("ssrf", True),
    # PoC `url=http://www.baidu.com`; forward is "Safe code" (paths of this app only).
    ("URLRedirect.java", "/redirect"): ("redirect", True), ("URLRedirect.java", "/setHeader"): ("redirect", True),
    ("URLRedirect.java", "/sendRedirect"): ("redirect", True), ("URLRedirect.java", "/forward"): ("redirect", False),
    ("URLRedirect.java", "/sendRedirect/sec"): ("redirect", False),
    # "Vuln Code" / "Vul Code" / "safe Code".
    ("XSS.java", "/reflect"): ("xss", True), ("XSS.java", "/stored/show"): ("xss", True),
    ("XSS.java", "/safe"): ("xss", False),
    ("Deserialize.java", "/rememberMe/vuln"): ("deserialization", True),
    ("Deserialize.java", "/rememberMe/security"): ("deserialization", False),
    # enableDefaultTyping + a JNDI payload above it; README lists Fastjson and XStream as vulns.
    ("Deserialize.java", "/jackson"): ("deserialization", True),
    ("Fastjson.java", "/deserialize"): ("deserialization", True),
    ("XStreamRce.java", "/xstream"): ("deserialization", True),
    ("Rce.java", "/vuln/yarm"): ("deserialization", True), ("Rce.java", "/sec/yarm"): ("deserialization", False),
    ("SpEL.java", "/spel/vuln1"): ("code", True), ("SpEL.java", "spel/vuln2"): ("code", True),
    ("SpEL.java", "spel/sec"): ("code", False),
    # PoC loads remote JS / runs `"open -a Calculator".execute()`.
    ("Rce.java", "/jscmd"): ("code", True), ("Rce.java", "groovy"): ("code", True),
    ("QLExpress.java", "/vuln1"): ("code", True), ("QLExpress.java", "/sec"): ("code", False),
    ("SSTI.java", "/velocity"): ("ssti", True),
}
XXE = "XXE.java"


def main(root, out):
    controllers = pathlib.Path(root) / "src/main/java/org/joychou/controller"
    rows = []
    for f in sorted(controllers.rglob("*.java")):
        for at, start, end, name, route in endpoints(f):
            label = LABELS.get((f.name, route))
            if f.name == XXE:
                label = ("xxe", "vuln" in route.lower())
            if f.parent.name == "othervulns" and route == "/readxlsx":
                label = ("xxe", True)
            if label:
                rel = str(f.relative_to(root))
                rows.append({"file": rel, "start": at, "end": end, "method": name, "route": route,
                             "category": label[0], "vulnerable": label[1]})
    missing = set(LABELS) - {(pathlib.Path(r["file"]).name, r["route"]) for r in rows}
    assert not missing, missing
    pathlib.Path(out).write_text(json.dumps(rows, indent=1) + "\n")
    sys.stdout.write(f"{len(rows)} endpoints; {sum(r['vulnerable'] for r in rows)} vulnerable\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

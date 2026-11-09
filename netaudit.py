#!/usr/bin/env python3
"""netaudit: offline security audit for Cisco IOS and MikroTik RouterOS configs.

No device access needed: point it at saved config files (e.g. from netconfig-backup)
and get a score, findings with fixes, and an HTML / Markdown / JSON report.
Zero dependencies. The exit code makes it usable as a CI gate.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

SEVERITY_WEIGHT = {"high": 10, "medium": 5, "low": 2}


# ---------------------------------------------------------------------------
class Config:
    def __init__(self, name: str, text: str):
        self.name = name
        self.text = text.replace("\r\n", "\n")
        self.vendor = detect_vendor(self.text)
        self.lines = [line.rstrip() for line in self.text.split("\n")]
        if self.vendor == "mikrotik":
            self.lines = terse(self.text)

    def find(self, pattern: str) -> list[str]:
        rx = re.compile(pattern, re.IGNORECASE)
        return [line.strip() for line in self.lines if rx.search(line)]

    def has(self, pattern: str) -> bool:
        return bool(self.find(pattern))

    def blocks(self, header: str) -> list[tuple[str, list[str]]]:
        """Cisco-style sections: a header line followed by indented children."""
        rx = re.compile(header, re.IGNORECASE)
        out, current = [], None
        for line in self.lines:
            if line and not line.startswith((" ", "\t")):
                current = (line.strip(), []) if rx.match(line) else None
                if current:
                    out.append(current)
            elif current is not None and line.strip():
                current[1].append(line.strip())
        return out


def terse(text: str) -> list[str]:
    """Turn a normal RouterOS `/export` into `/export terse` style lines.

    /ip service            ->  /ip service set telnet disabled=yes
    set telnet disabled=yes
    (also joins lines continued with a trailing backslash)
    """
    joined = re.sub(r"\\\n\s*", "", text)
    out, section = [], ""
    for line in joined.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            out.append(line)
        elif line.startswith("/"):
            # "/ip service" alone opens a section; "/ip service set ..." is already terse
            is_command = re.search(r"\s(set|add|remove|enable|disable)(\s|$)", line)
            section = "" if is_command else line
            out.append(line)
        elif section:
            out.append(f"{section} {line}")
        else:
            out.append(line)
    return out


def detect_vendor(text: str) -> str:
    if re.search(r"^/(ip|interface|system|tool|ppp|routing) ", text, re.M) or "by RouterOS" in text:
        return "mikrotik"
    if re.search(r"^(hostname|interface|line vty|version \d)", text, re.M):
        return "cisco"
    return "unknown"


@dataclass
class Rule:
    id: str
    vendor: str
    severity: str
    title: str
    fix: str
    check: Callable[[Config], tuple[bool, str]]


@dataclass
class Finding:
    rule: Rule
    passed: bool
    evidence: str


def must_have(pattern: str, missing: str = "not configured"):
    return lambda c: (c.has(pattern), "" if c.has(pattern) else missing)


def must_not_have(pattern: str):
    def check(c):
        hits = c.find(pattern)
        return (not hits, "; ".join(hits[:3]))
    return check


# ---- Cisco IOS rules -------------------------------------------------------
def _vty(c: Config, test: Callable[[list[str]], bool], label: str):
    bad = [h for h, body in c.blocks(r"^line vty") if not test(body)]
    return (not bad, f"{label}: {', '.join(bad)}" if bad else "")


def cisco_ssh_only(c):
    return _vty(c, lambda b: any(re.fullmatch(r"transport input ssh", x) for x in b), "telnet allowed on")


def cisco_vty_acl(c):
    return _vty(c, lambda b: any(x.startswith("access-class ") for x in b), "no access-class on")


def cisco_exec_timeout(c):
    bad = [h for h, b in c.blocks(r"^line (vty|con)") if "exec-timeout 0 0" in b or "no exec-timeout" in b]
    return (not bad, f"exec-timeout disabled on: {', '.join(bad)}" if bad else "")


def cisco_snmp_acl(c):
    # snmp-server community <name> [view <v>] RO|RW <acl>  -> an ACL must follow RO/RW
    def has_acl(line):
        tokens = line.split()[3:]
        return any(t.upper() in ("RO", "RW") and i + 1 < len(tokens) for i, t in enumerate(tokens))
    bad = [x for x in c.find(r"^snmp-server community ") if not has_acl(x)]
    return (not bad, "; ".join(bad[:3]))


RULES: list[Rule] = [
    Rule("IOS-001", "cisco", "high", "Telnet allowed on VTY lines", "line vty 0 15 → transport input ssh", cisco_ssh_only),
    Rule("IOS-002", "cisco", "high", "'enable password' used instead of 'enable secret'",
         "no enable password / enable algorithm-type scrypt secret <pw>", must_not_have(r"^enable password")),
    Rule("IOS-003", "cisco", "high", "Local user with reversible 'password'",
         "username <u> algorithm-type scrypt secret <pw>", must_not_have(r"^username \S+ .*\bpassword\b")),
    Rule("IOS-004", "cisco", "high", "Default SNMP community (public/private)",
         "no snmp-server community public; use SNMPv3", must_not_have(r"^snmp-server community (public|private)\b")),
    Rule("IOS-005", "cisco", "medium", "SNMP community without an ACL",
         "snmp-server community <c> RO <acl>", cisco_snmp_acl),
    Rule("IOS-006", "cisco", "medium", "No ACL restricting VTY access",
         "line vty 0 15 → access-class MGMT in", cisco_vty_acl),
    Rule("IOS-007", "cisco", "medium", "HTTP server enabled", "no ip http server",
         must_not_have(r"^ip http server")),
    Rule("IOS-008", "cisco", "medium", "SSH version 2 not enforced", "ip ssh version 2",
         must_have(r"^ip ssh version 2")),
    Rule("IOS-009", "cisco", "medium", "Passwords stored in clear text", "service password-encryption",
         must_have(r"^service password-encryption")),
    Rule("IOS-010", "cisco", "medium", "No remote syslog server", "logging host <ip>",
         must_have(r"^logging (host )?\d+\.\d+\.\d+\.\d+")),
    Rule("IOS-011", "cisco", "low", "Session timeout disabled", "exec-timeout 10 0", cisco_exec_timeout),
    Rule("IOS-012", "cisco", "low", "No NTP server (logs will have wrong time)", "ntp server <ip>",
         must_have(r"^ntp server ")),
    Rule("IOS-013", "cisco", "low", "No login banner", "banner login ^ Authorized access only ^",
         must_have(r"^banner (login|motd)")),
    Rule("IOS-014", "cisco", "low", "AAA not enabled", "aaa new-model", must_have(r"^aaa new-model")),
    Rule("IOS-015", "cisco", "low", "CDP enabled globally", "no cdp run (or disable per edge interface)",
         must_have(r"^no cdp run", "cdp is on by default")),
]


# ---- MikroTik RouterOS rules (works on `/export` and `/export terse`) ------
def mt_service_disabled(name: str):
    return must_have(rf"^/ip service set (\[ find name=)?{name}\b.*disabled=yes",
                     f"{name} service is enabled (default)")


def mt_has_input_drop(c: Config) -> bool:
    return any("chain=input" in x and "action=drop" in x for x in c.find(r"action=drop"))


def mt_input_firewall(c):
    return (mt_has_input_drop(c), "" if mt_has_input_drop(c) else "no drop rule in chain=input")


def mt_open_dns(c):
    open_dns = c.has(r"^/ip dns set .*allow-remote-requests=yes")
    bad = open_dns and not mt_has_input_drop(c)
    return (not bad, "allow-remote-requests=yes with no input firewall" if bad else "")


RULES += [
    Rule("MT-001", "mikrotik", "high", "No firewall drop rule on the input chain",
         "/ip firewall filter add chain=input in-interface-list=WAN action=drop", mt_input_firewall),
    Rule("MT-002", "mikrotik", "high", "Telnet service enabled", "/ip service set telnet disabled=yes",
         mt_service_disabled("telnet")),
    Rule("MT-003", "mikrotik", "high", "FTP service enabled", "/ip service set ftp disabled=yes",
         mt_service_disabled("ftp")),
    Rule("MT-004", "mikrotik", "high", "Open DNS resolver (amplification risk)",
         "drop udp/tcp 53 from WAN on chain=input", mt_open_dns),
    Rule("MT-005", "mikrotik", "medium", "WebFig over plain HTTP enabled", "/ip service set www disabled=yes",
         mt_service_disabled("www")),
    Rule("MT-006", "mikrotik", "medium", "API service enabled", "/ip service set api disabled=yes",
         mt_service_disabled("api")),
    Rule("MT-007", "mikrotik", "medium", "Winbox reachable from any address",
         "/ip service set winbox address=192.168.88.0/24",
         must_have(r"^/ip service set .*\bwinbox\b.*address=\S+", "winbox has no address restriction")),
    Rule("MT-008", "mikrotik", "medium", "MAC server / MAC-Winbox open on all interfaces",
         "/tool mac-server set allowed-interface-list=LAN",
         must_have(r"^/tool mac-server (set|mac-winbox set) .*(allowed-interface-list=(none|LAN)|disabled=yes)")),
    Rule("MT-009", "mikrotik", "medium", "Bandwidth-test server enabled", "/tool bandwidth-server set enabled=no",
         must_have(r"^/tool bandwidth-server set .*enabled=no", "enabled by default")),
    Rule("MT-010", "mikrotik", "medium", "SOCKS or web proxy enabled", "/ip socks set enabled=no",
         must_not_have(r"^/ip (socks|proxy) set .*enabled=yes")),
    Rule("MT-011", "mikrotik", "low", "UPnP enabled", "/ip upnp set enabled=no",
         must_not_have(r"^/ip upnp set .*enabled=yes")),
    Rule("MT-012", "mikrotik", "low", "Neighbor discovery on all interfaces",
         "/ip neighbor discovery-settings set discover-interface-list=LAN",
         must_have(r"^/ip neighbor discovery-settings set .*discover-interface-list=")),
    Rule("MT-013", "mikrotik", "low", "SSH strong crypto off", "/ip ssh set strong-crypto=yes",
         must_have(r"^/ip ssh set .*strong-crypto=yes")),
    Rule("MT-014", "mikrotik", "low", "No NTP client", "/system ntp client set enabled=yes",
         must_have(r"^/system ntp client set .*enabled=yes")),
    Rule("MT-015", "mikrotik", "low", "No remote logging", "/system logging action add target=remote remote=<ip>",
         must_have(r"^/system logging action .*target=remote")),
]


# ---------------------------------------------------------------------------
def audit(cfg: Config, ignore: set[str] = frozenset()) -> list[Finding]:
    out = []
    for rule in RULES:
        if rule.vendor == cfg.vendor and rule.id not in ignore:
            passed, evidence = rule.check(cfg)
            out.append(Finding(rule, passed, evidence))
    return out


def score(findings: list[Finding]) -> int:
    total = sum(SEVERITY_WEIGHT[f.rule.severity] for f in findings)
    lost = sum(SEVERITY_WEIGHT[f.rule.severity] for f in findings if not f.passed)
    return round(100 * (1 - lost / total)) if total else 100


def grade(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


# ---- Reports ---------------------------------------------------------------
COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "ok": "\033[32m", "end": "\033[0m"}


def report_text(results, color: bool) -> str:
    c = COLORS if color else {k: "" for k in COLORS}
    out = []
    for cfg, findings in results:
        s = score(findings)
        out.append(f"\n{cfg.name}  [{cfg.vendor}]  score {s}/100 ({grade(s)})")
        for f in sorted(findings, key=lambda f: (f.passed, list(SEVERITY_WEIGHT).index(f.rule.severity))):
            if f.passed:
                continue
            sev = f.rule.severity.upper()
            out.append(f"  {c[f.rule.severity]}{sev:<6}{c['end']} {f.rule.id}  {f.rule.title}")
            if f.evidence:
                out.append(f"         ↳ {f.evidence}")
            out.append(f"         fix: {f.rule.fix}")
        passed = sum(f.passed for f in findings)
        out.append(f"  {c['ok']}✔ {passed}/{len(findings)} checks passed{c['end']}")
    return "\n".join(out)


def report_json(results) -> str:
    return json.dumps([{
        "file": cfg.name, "vendor": cfg.vendor, "score": score(fs), "grade": grade(score(fs)),
        "findings": [{"id": f.rule.id, "severity": f.rule.severity, "title": f.rule.title,
                      "passed": f.passed, "evidence": f.evidence, "fix": f.rule.fix} for f in fs],
    } for cfg, fs in results], indent=2)


def report_markdown(results) -> str:
    out = ["# 🛡️ Network config audit", "", "| File | Vendor | Score | High | Medium | Low |", "|---|---|---|---|---|---|"]
    for cfg, fs in results:
        n = {sev: sum(1 for f in fs if not f.passed and f.rule.severity == sev) for sev in SEVERITY_WEIGHT}
        out.append(f"| `{cfg.name}` | {cfg.vendor} | **{score(fs)}** ({grade(score(fs))}) | {n['high']} | {n['medium']} | {n['low']} |")
    for cfg, fs in results:
        failed = [f for f in fs if not f.passed]
        if failed:
            out += ["", f"## {cfg.name}", "", "| Severity | Rule | Issue | Fix |", "|---|---|---|---|"]
            out += [f"| {f.rule.severity} | {f.rule.id} | {f.rule.title} | `{f.rule.fix}` |" for f in failed]
    return "\n".join(out) + "\n"


def report_html(results) -> str:
    e = html.escape
    cards = []
    for cfg, fs in results:
        s = score(fs)
        rows = "".join(
            f"<tr class='{'pass' if f.passed else f.rule.severity}'><td>{'✔' if f.passed else '✘'}</td>"
            f"<td><span class=sev>{e(f.rule.severity)}</span></td><td>{e(f.rule.id)}</td><td>{e(f.rule.title)}"
            f"{'<br><small>' + e(f.evidence) + '</small>' if f.evidence and not f.passed else ''}</td>"
            f"<td><code>{'' if f.passed else e(f.rule.fix)}</code></td></tr>"
            for f in sorted(fs, key=lambda f: (f.passed, list(SEVERITY_WEIGHT).index(f.rule.severity))))
        cards.append(f"<section><div class=head><h2>{e(cfg.name)}</h2><span class=muted>{e(cfg.vendor)}</span>"
                     f"<div class='score g{grade(s)}'>{s}<small>{grade(s)}</small></div></div>"
                     f"<div class=scroll><table><tr><th></th><th>Severity</th><th>Rule</th><th>Finding</th><th>Fix</th></tr>"
                     f"{rows}</table></div></section>")
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Network config audit</title><style>
:root{{--bg:#f6f7fb;--card:#fff;--text:#1c2230;--muted:#6b7385;--line:#e4e7ee}}
@media (prefers-color-scheme:dark){{:root{{--bg:#10141d;--card:#181e2a;--text:#e7e9ee;--muted:#8d95a8;--line:#273042}}}}
body{{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--text)}}main{{max-width:1100px;margin:auto;padding:24px 16px}}
section{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}}
.head{{display:flex;align-items:center;gap:12px}}.head h2{{margin:0;font-size:17px}}.muted{{color:var(--muted)}}
.score{{margin-left:auto;font-size:26px;font-weight:700}}.score small{{font-size:13px;margin-left:4px}}
.gA,.gB{{color:#16a34a}}.gC{{color:#ca8a04}}.gD,.gF{{color:#dc2626}}.scroll{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;margin-top:10px}}td,th{{padding:7px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{color:var(--muted);font-weight:500}}small{{color:var(--muted)}}code{{font-size:12px}}
.sev{{font-size:11px;text-transform:uppercase;padding:2px 6px;border-radius:4px;background:var(--line)}}
tr.high .sev{{background:#dc2626;color:#fff}}tr.medium .sev{{background:#d97706;color:#fff}}tr.low .sev{{background:#0891b2;color:#fff}}
tr.pass{{opacity:.55}}</style></head><body><main><h1>🛡️ Network config audit</h1>{''.join(cards)}</main></body></html>"""


# ---------------------------------------------------------------------------
def collect(paths: list[str]) -> list[Path]:
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.suffix.lower() in (".cfg", ".conf", ".txt", ".rsc"))
        elif p.exists():
            files.append(p)
        else:
            print(f"not found: {p}", file=sys.stderr)
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline security audit for Cisco IOS & MikroTik configs")
    ap.add_argument("paths", nargs="+", help="config files or folders")
    ap.add_argument("-f", "--format", choices=["text", "json", "markdown", "html"], default="text")
    ap.add_argument("-o", "--output", help="write report to file")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                    help="exit 1 if a finding of this severity or worse exists (default: high)")
    ap.add_argument("--ignore", default="", help="comma separated rule ids to skip")
    ap.add_argument("--list-rules", action="store_true")
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    if args.list_rules:
        for r in RULES:
            print(f"{r.id:<8} {r.vendor:<9} {r.severity:<7} {r.title}")
        return 0

    ignore = {x.strip().upper() for x in args.ignore.split(",") if x.strip()}
    results = []
    for path in collect(args.paths):
        cfg = Config(path.name, path.read_text(encoding="utf-8", errors="replace"))
        if cfg.vendor == "unknown":
            print(f"skipping {path}: vendor not recognised", file=sys.stderr)
            continue
        results.append((cfg, audit(cfg, ignore)))
    if not results:
        print("nothing to audit", file=sys.stderr)
        return 2

    render = {"text": lambda r: report_text(r, color=sys.stdout.isatty() and not args.output),
              "json": report_json, "markdown": report_markdown, "html": report_html}[args.format]
    report = render(results)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"report written to {args.output}")
    else:
        print(report)

    if args.fail_on == "never":
        return 0
    limit = list(SEVERITY_WEIGHT).index(args.fail_on)
    worst = [f for _, fs in results for f in fs if not f.passed and list(SEVERITY_WEIGHT).index(f.rule.severity) <= limit]
    return 1 if worst else 0


if __name__ == "__main__":
    sys.exit(main())

"""Rendering of scan results to console, JSON and a self-contained HTML report."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import __version__
from .console import color, echo, rule
from .modules import Finding, Severity

# --- Safety / ethics framing (must appear in every report) -------------------

SAFETY_POINTS = [
    (
        "A finding is a LEAD, not proof.",
        "iScout flags artifacts that warrant further investigation. On its own it "
        "can neither confirm nor rule out an infection.",
    ),
    (
        "No findings does NOT mean the device is clean.",
        "Public indicators are incomplete and retrospective. A quiet result is "
        "reassuring but not a guarantee.",
    ),
    (
        "Safety first if you suspect stalkerware.",
        "If someone with physical/account access may be monitoring you, removing "
        "the spyware can alert them and escalate danger — and deleting it destroys "
        "evidence. Plan on a SEPARATE safe device with a trained advocate before acting.",
    ),
    (
        "Consent required.",
        "Only scan a device you own or are expressly authorised to examine.",
    ),
    (
        "Get expert help for serious concern.",
        "Escalate to professionals rather than relying on an automated triage tool alone.",
    ),
]

RESOURCES = [
    ("Coalition Against Stalkerware", "https://stopstalkerware.org"),
    ("Access Now Digital Security Helpline", "https://www.accessnow.org/help/"),
    ("Amnesty International Security Lab", "https://securitylab.amnesty.org"),
    ("NNEDV Safety Net (techsafety.org)", "https://www.techsafety.org"),
]


@dataclass
class ScanResult:
    target_path: str
    target_kind: str
    scanned_at: str  # ISO-8601, supplied by the caller
    device_info: Dict[str, object] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    module_errors: Dict[str, List[str]] = field(default_factory=dict)
    feeds: Dict[str, dict] = field(default_factory=dict)
    indicator_count: int = 0
    modules_run: List[str] = field(default_factory=list)

    def by_severity(self, sev: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def counts(self) -> Dict[str, int]:
        return {s.value: len(self.by_severity(s)) for s in Severity}

    def to_dict(self) -> dict:
        return {
            "tool": "iScout",
            "version": __version__,
            "scanned_at": self.scanned_at,
            "target": {"path": self.target_path, "kind": self.target_kind},
            "device_info": {str(k): _jsonable(v) for k, v in self.device_info.items()},
            "summary": self.counts(),
            "indicator_feeds": self.feeds,
            "indicator_count": self.indicator_count,
            "modules_run": self.modules_run,
            "module_errors": self.module_errors,
            "findings": [f.to_dict() for f in self.findings],
            "disclaimer": "A finding is a lead, not proof. Absence of findings does not "
            "prove the device is clean. See safety guidance in the report.",
        }


def _jsonable(v):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)


# --- console -----------------------------------------------------------------

_SEV_STYLE = {
    Severity.DETECTED: ("red", "🔴"),
    Severity.WARNING: ("yellow", "🟡"),
    Severity.INFO: ("grey", "·"),
}


def render_console(result: ScanResult, verbose: bool = False) -> None:
    echo()
    echo(color("  iScout — iPhone spyware / stalkerware screening", "bold", "cyan"))
    echo(color(f"  target: {result.target_path}  ({result.target_kind})", "grey"))
    echo(color(f"  scanned: {result.scanned_at}   indicators: {result.indicator_count}", "grey"))
    rule()

    counts = result.counts()
    echo(
        "  "
        + color(f"DETECTED {counts['DETECTED']}", "red", "bold")
        + "   "
        + color(f"WARNING {counts['WARNING']}", "yellow", "bold")
        + "   "
        + color(f"INFO {counts['INFO']}", "grey")
    )
    rule()

    for sev in (Severity.DETECTED, Severity.WARNING):
        items = result.by_severity(sev)
        if not items:
            continue
        style, glyph = _SEV_STYLE[sev]
        echo(color(f"  {sev.value}", style, "bold"))
        for f in items:
            echo(f"  {glyph} " + color(f.title, style))
            if f.malware_family:
                echo(color(f"      family: {f.malware_family}   confidence: {f.confidence or 'n/a'}", "grey"))
            if f.matched_value:
                echo(color(f"      match:  {f.matched_value}", "grey"))
            if f.artifact:
                loc = f.artifact + (f"  @ {f.timestamp}" if f.timestamp else "")
                echo(color(f"      source: {loc}", "grey"))
            if f.source:
                echo(color(f"      via:    {f.source}", "grey"))
            if f.description:
                echo(color(f"      {f.description}", "dim"))
        echo()

    if verbose:
        info = result.by_severity(Severity.INFO)
        if info:
            echo(color("  INFO", "grey", "bold"))
            for f in info:
                echo(color(f"  · {f.title}", "grey"))
            echo()

    if any(result.module_errors.values()):
        echo(color("  Module notes:", "grey", "bold"))
        for mod, errs in result.module_errors.items():
            for e in errs:
                echo(color(f"    {mod}: {e}", "grey"))
        echo()

    rule()
    echo(color("  READ THIS — how to interpret the result", "bold", "yellow"))
    for head, body in SAFETY_POINTS:
        echo("  " + color("• " + head, "yellow"))
        echo(color(f"    {body}", "dim"))
    echo()
    echo(color("  Help & safety planning:", "bold"))
    for name, url in RESOURCES:
        echo(color(f"    {name}: {url}", "grey"))
    echo()


# --- JSON --------------------------------------------------------------------

def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)


# --- HTML --------------------------------------------------------------------

def write_html(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_html(result))


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def _finding_card(f: Finding) -> str:
    cls = f.severity.value.lower()
    rows = []
    if f.malware_family:
        rows.append(f"<span class='chip'>{_e(f.malware_family)}</span>")
    if f.confidence:
        rows.append(f"<span class='chip conf-{_e(f.confidence)}'>confidence: {_e(f.confidence)}</span>")
    meta = []
    if f.matched_value:
        meta.append(f"<div class='kv'><b>Match</b><code>{_e(f.matched_value)}</code></div>")
    if f.artifact:
        loc = _e(f.artifact) + (f" &nbsp;<span class='ts'>@ {_e(f.timestamp)}</span>" if f.timestamp else "")
        meta.append(f"<div class='kv'><b>Source</b>{loc}</div>")
    if f.source:
        meta.append(f"<div class='kv'><b>Via</b>{_e(f.source)}</div>")
    return (
        f"<div class='card {cls}'>"
        f"<div class='card-h'><span class='sev sev-{cls}'>{f.severity.value}</span>"
        f"<span class='mod'>{_e(f.module)}</span> {''.join(rows)}</div>"
        f"<div class='title'>{_e(f.title)}</div>"
        f"<div class='desc'>{_e(f.description)}</div>"
        f"{''.join(meta)}"
        f"</div>"
    )


def _html(result: ScanResult) -> str:
    counts = result.counts()
    safety = "".join(f"<li><b>{_e(h)}</b> {_e(b)}</li>" for h, b in SAFETY_POINTS)
    resources = "".join(f"<li><a href='{_e(u)}'>{_e(n)}</a></li>" for n, u in RESOURCES)

    dev = "".join(
        f"<div class='kv'><b>{_e(k)}</b>{_e(v)}</div>" for k, v in result.device_info.items()
    ) or "<div class='kv'>No device metadata available.</div>"

    sections = []
    for sev in (Severity.DETECTED, Severity.WARNING, Severity.INFO):
        items = result.by_severity(sev)
        if not items:
            continue
        cards = "".join(_finding_card(f) for f in items)
        sections.append(
            f"<h2 class='sev-{sev.value.lower()}'>{sev.value} "
            f"<span class='count'>{len(items)}</span></h2>{cards}"
        )

    feeds = "".join(
        f"<li><b>{_e(name)}</b> — {_e(meta.get('count', 0))} indicators"
        + (f" · {_e(meta.get('source'))}" if meta.get("source") else "")
        + "</li>"
        for name, meta in result.feeds.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>iScout Report — {_e(result.target_kind)} scan</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d0a07;color:#e8dcc8;font-family:-apple-system,Segoe UI,Roboto,Georgia,serif;line-height:1.5;padding:0 0 60px}}
.wrap{{max-width:920px;margin:0 auto;padding:0 16px}}
header{{padding:28px 16px 18px;border-bottom:1px solid #c4a26522}}
.logo{{font-size:22px;font-weight:800;letter-spacing:2px;background:linear-gradient(135deg,#c4a265,#d4b86a,#a08040);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}}
.sub{{font-size:12px;color:#c4a26580;margin-top:4px}}
.banner{{margin:18px 0;padding:16px 18px;border-radius:12px;background:#3a1f1f;border:1px solid #c47070aa}}
.banner h3{{color:#f0b8b8;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px}}
.banner ul{{list-style:none;display:grid;gap:8px}}
.banner li{{font-size:13px;color:#f2dede}}
.summary{{display:flex;gap:12px;margin:18px 0;flex-wrap:wrap}}
.stat{{flex:1;min-width:120px;padding:16px;border-radius:12px;background:#15110c;border:1px solid #c4a26522;text-align:center}}
.stat .n{{font-size:30px;font-weight:800}}
.stat .l{{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#c4a26580}}
.stat.detected .n{{color:#e06666}} .stat.warning .n{{color:#d4b86a}} .stat.info .n{{color:#8aa0b0}}
h2{{margin:26px 0 12px;font-size:15px;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #c4a26522;padding-bottom:6px}}
h2 .count{{font-size:12px;color:#c4a26580}}
.sev-detected{{color:#e06666}} .sev-warning{{color:#d4b86a}} .sev-info{{color:#8aa0b0}}
.card{{margin:10px 0;padding:14px 16px;border-radius:10px;background:#15110c;border:1px solid #c4a26522;border-left:4px solid #444}}
.card.detected{{border-left-color:#e06666}} .card.warning{{border-left-color:#d4b86a}} .card.info{{border-left-color:#3a4a55}}
.card-h{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}}
.sev{{font-size:10px;font-weight:800;letter-spacing:1px;padding:2px 8px;border-radius:6px}}
.sev-detected{{background:#e0666622;color:#e06666}} .sev-warning{{background:#d4b86a22;color:#d4b86a}} .sev-info{{background:#3a4a5522;color:#8aa0b0}}
.mod{{font-size:11px;color:#c4a26580;font-family:monospace}}
.chip{{font-size:11px;padding:2px 8px;border-radius:10px;background:#c4a26518;color:#d4b86a}}
.conf-high{{background:#e0666622;color:#e06666}} .conf-low{{background:#3a4a5522;color:#8aa0b0}}
.title{{font-weight:700;font-size:15px;margin-bottom:4px}}
.desc{{font-size:13px;color:#c9b59a;margin-bottom:8px}}
.kv{{font-size:12px;color:#a99a80;margin:2px 0}} .kv b{{display:inline-block;min-width:64px;color:#c4a26580}}
.kv code{{color:#e8dcc8;font-family:monospace;background:#0d0a07;padding:1px 6px;border-radius:4px;word-break:break-all}}
.ts{{color:#8aa0b0}}
.device{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:6px;padding:14px 16px;background:#15110c;border:1px solid #c4a26522;border-radius:10px}}
footer{{margin-top:32px;padding-top:16px;border-top:1px solid #c4a26522;font-size:12px;color:#c4a26580}}
footer a{{color:#d4b86a}} footer ul{{list-style:none;margin:8px 0;display:grid;gap:4px}}
</style></head>
<body>
<header><div class="wrap"><div class="logo">iScout · iPhone Screening</div>
<div class="sub">Target: {_e(result.target_path)} ({_e(result.target_kind)}) · scanned {_e(result.scanned_at)} · {_e(result.indicator_count)} indicators loaded</div>
</div></header>
<div class="wrap">
<div class="banner"><h3>How to read this report</h3><ul>{safety}</ul></div>
<div class="summary">
  <div class="stat detected"><div class="n">{counts['DETECTED']}</div><div class="l">Detected</div></div>
  <div class="stat warning"><div class="n">{counts['WARNING']}</div><div class="l">Warning</div></div>
  <div class="stat info"><div class="n">{counts['INFO']}</div><div class="l">Info</div></div>
</div>
<h2>Device</h2><div class="device">{dev}</div>
{''.join(sections)}
<footer>
<b>Indicator feeds loaded</b><ul>{feeds or '<li>none</li>'}</ul>
<b>Help &amp; safety planning</b><ul>{resources}</ul>
<p>iScout {_e(__version__)} — modelled on the methodology of Amnesty International's MVT
and Kaspersky's iShutdown / triangle_check. A finding is a lead, not proof; absence of
findings does not prove a device is clean.</p>
</footer>
</div></body></html>"""

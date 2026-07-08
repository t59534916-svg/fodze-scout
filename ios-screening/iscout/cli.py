"""iScout command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .backup import ArtifactError, BackupTarget, EncryptedBackupError, open_target
from .console import color, echo, set_enabled
from .engine import run_scan
from .indicators import Indicators
from .modules import ALL_MODULES, MODULES_BY_NAME
from .prep import decrypt_backup, diagnose, discover_backups
from .report import render_console, write_html, write_json

_EPILOG = """\
examples:
  iscout scan  ~/Backup/00008030-001A...        # scan an iOS backup directory
  iscout scan  ./fsdump --type fs               # scan a filesystem dump / sysdiagnose
  iscout scan  ./backup --iocs pegasus.stix2    # add an external STIX2 feed
  iscout scan  ./backup --html out/report.html --json out/report.json
  iscout list-modules
  iscout list-iocs

iScout screens a CONSENSUAL iOS backup for spyware/stalkerware indicators.
A finding is a lead, not proof. Absence of findings does not prove a clean device.
Create an ENCRYPTED backup (Finder/iTunes) for full coverage, decrypt it with
`mvt-ios decrypt-backup`, then point iScout at the decrypted folder.
"""


def _load_indicators(args) -> Indicators:
    ind = Indicators()
    if not args.no_builtin:
        ind.load_builtin()
    for path in args.iocs or []:
        try:
            ind.load_path(path)
        except (OSError, ValueError) as exc:
            echo(color(f"warning: could not load indicators from {path}: {exc}", "yellow"))
    for env in ("ISCOUT_STIX2", "MVT_STIX2"):
        val = os.environ.get(env)
        if val:
            for p in val.split(os.pathsep):
                if p and os.path.exists(p):
                    try:
                        ind.load_path(p)
                    except (OSError, ValueError):
                        pass
    return ind


def cmd_scan(args) -> int:
    if args.no_color:
        set_enabled(False)

    try:
        target = open_target(args.target, kind=args.type)
    except ArtifactError as exc:
        echo(color(f"error: {exc}", "red"))
        return 2

    # Encrypted backups: either decrypt them (--decrypt) or stop with guidance.
    if isinstance(target, BackupTarget) and target.is_encrypted():
        if args.decrypt:
            work = args.work or (os.path.abspath(args.target.rstrip("/\\")) + "-decrypted")
            password = os.environ.get(args.password_env) if args.password_env else None
            echo(color(f"  decrypting backup into {work} …", "cyan"))
            ok, msg = decrypt_backup(args.target, work, password=password)
            echo(color(f"  {msg}", "grey" if ok else "red"))
            if not ok:
                return 3
            target = open_target(work, kind="backup")
        else:
            echo(color("error: this backup is ENCRYPTED and cannot be read directly.", "red", "bold"))
            echo(
                "Decrypt and scan in one step (recommended):\n"
                "    pip install mvt\n"
                f"    iscout scan {args.target} --decrypt --work ./decrypted\n"
                "  (mvt prompts for the backup password; iScout never handles the secret.)\n"
                "Or decrypt manually, then scan the decrypted copy:\n"
                f"    mvt-ios decrypt-backup -d ./decrypted {args.target}\n"
                "    iscout scan ./decrypted\n"
                "An encrypted backup is REQUIRED for full coverage — it contains SMS,\n"
                "Safari history and more that unencrypted backups omit."
            )
            return 3

    ind = _load_indicators(args)
    if not ind.all:
        echo(color("warning: no indicators loaded — only heuristics will run.", "yellow"))

    modules = ALL_MODULES
    if args.modules:
        chosen = []
        for name in args.modules:
            if name not in MODULES_BY_NAME:
                echo(color(f"error: unknown module '{name}'. Try `iscout list-modules`.", "red"))
                return 2
            chosen.append(MODULES_BY_NAME[name])
        modules = chosen

    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    options = {"redact": args.redact}

    try:
        result = run_scan(target, ind, scanned_at, modules=modules, options=options)
    except EncryptedBackupError as exc:
        echo(color(f"error: {exc}", "red"))
        return 3

    if not args.quiet:
        render_console(result, verbose=args.verbose)

    if args.json:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
            write_json(result, args.json)
            echo(color(f"  JSON report written to {args.json}", "grey"))
        except OSError as exc:
            echo(color(f"  warning: could not write JSON report: {exc}", "yellow"))
    if args.html:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(args.html)), exist_ok=True)
            write_html(result, args.html)
            echo(color(f"  HTML report written to {args.html}", "grey"))
        except OSError as exc:
            echo(color(f"  warning: could not write HTML report: {exc}", "yellow"))

    counts = result.counts()
    if args.fail_on_detected and counts["DETECTED"]:
        return 1
    return 0


def cmd_list_backups(args) -> int:
    if getattr(args, "no_color", False):
        set_enabled(False)
    roots = None
    if args.root:
        roots = args.root
    backups = discover_backups(roots)
    if not backups:
        echo(color("No iPhone backups found in the standard locations.", "yellow"))
        echo(color("  macOS:   ~/Library/Application Support/MobileSync/Backup/", "grey"))
        echo(color("  Windows: %APPDATA%\\Apple*\\MobileSync\\Backup  or  %USERPROFILE%\\Apple\\MobileSync\\Backup", "grey"))
        echo(color("  Pass --root DIR to search a custom location.", "grey"))
        return 0
    echo(color(f"Found {len(backups)} backup(s):", "bold"))
    for b in backups:
        lock = color("🔒 encrypted", "yellow") if b["encrypted"] else color("🔓 unencrypted", "grey")
        name = b.get("device_name") or b.get("product_type") or "unknown device"
        echo(f"\n  {color(str(name), 'cyan', 'bold')}   {lock}")
        echo(color(f"    iOS {b.get('product_version') or '?'} · {b.get('product_type') or '?'} · last backup {b.get('last_backup') or '?'}", "grey"))
        echo(color(f"    {b['path']}", "grey"))
        if b["encrypted"]:
            echo(color(f"    → iscout scan {b['path']} --decrypt --work ./decrypted", "grey"))
        else:
            echo(color(f"    → iscout scan {b['path']} -v", "grey"))
    return 0


def cmd_doctor(args) -> int:
    if getattr(args, "no_color", False):
        set_enabled(False)
    d = diagnose(args.target, kind=args.type)
    echo(color(f"iScout preflight — {args.target}", "bold", "cyan"))
    if d["error"]:
        echo(color(f"  ✗ {d['error']}", "red"))
    else:
        echo(color(f"  input type: {d['kind']}", "grey"))
        if d["device"]:
            dev = d["device"]
            echo(color(f"  device: {dev.get('Product Type','?')} · iOS {dev.get('Product Version','?')}", "grey"))
        if d["encrypted"]:
            echo(color("  🔒 encrypted backup", "yellow"))
        if d["artifacts"]:
            echo(color("  artifacts:", "grey"))
            for key, present in d["artifacts"].items():
                mark = color("✓", "green") if present else color("·", "grey")
                echo(f"      {mark} {key}")
        if d["profiles"] is not None:
            echo(color(f"      configuration profiles: {d['profiles']}", "grey"))
    verdict = color("READY to scan", "green", "bold") if d["ready"] else color("NOT ready", "yellow", "bold")
    echo(f"\n  {verdict}")
    for step in d["next_steps"]:
        echo(color(f"  {step}", "grey"))
    return 0 if d["ready"] else 3


def cmd_list_modules(args) -> int:
    echo(color("Available detection modules:", "bold"))
    for m in ALL_MODULES:
        echo(f"  {color(m.name.ljust(24), 'cyan')} {m.description}  {color('[' + ','.join(m.supports) + ']', 'grey')}")
    return 0


def cmd_list_iocs(args) -> int:
    ind = Indicators()
    ind.load_builtin()
    echo(color(f"Loaded {len(ind.all)} built-in indicators from {len(ind.feeds)} feed(s):", "bold"))
    for name, meta in ind.feeds.items():
        echo(f"  {color(name.ljust(18), 'cyan')} {meta.get('count', 0):>4} indicators   {color(meta.get('source', ''), 'grey')}")
    echo()
    echo(color("By type:", "bold"))
    for t, n in sorted(ind.summary().items()):
        echo(f"  {t.ljust(16)} {n}")
    echo()
    echo(color(
        "This is a small, source-attributed STARTER set. For real investigations, "
        "load the full public feeds, e.g. Amnesty's pegasus.stix2 / cytrox.stix2 via "
        "`--iocs` or the ISCOUT_STIX2 env var. See data/indicators/README.md.", "grey"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iscout",
        description="iScout — forensic screening of iPhone/iPad backups for spyware & stalkerware.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"iScout {__version__}")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan", help="scan a backup or filesystem dump", epilog=_EPILOG,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("target", help="path to an iOS backup directory or filesystem dump")
    sp.add_argument("--type", choices=["auto", "backup", "fs", "sysdiagnose"], default="auto",
                    help="input type (default: auto-detect)")
    sp.add_argument("--iocs", action="append", metavar="PATH",
                    help="additional indicator feed file/dir (JSON or STIX2); repeatable")
    sp.add_argument("--no-builtin", action="store_true", help="do not load the built-in indicators")
    sp.add_argument("--modules", nargs="+", metavar="NAME", help="only run these modules")
    sp.add_argument("--json", metavar="FILE", help="write a JSON report")
    sp.add_argument("--html", metavar="FILE", help="write an HTML report")
    sp.add_argument("--decrypt", action="store_true",
                    help="if the backup is encrypted, decrypt it first with mvt-ios (prompts for password)")
    sp.add_argument("--work", metavar="DIR", help="destination for the decrypted copy (with --decrypt)")
    sp.add_argument("--password-env", metavar="VAR",
                    help="read the backup password from this env var instead of prompting (with --decrypt)")
    sp.add_argument("--redact", action="store_true", help="mask serial/IMEI/phone number in output")
    sp.add_argument("-v", "--verbose", action="store_true", help="also show INFO findings on the console")
    sp.add_argument("-q", "--quiet", action="store_true", help="suppress the console report (still writes files)")
    sp.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    sp.add_argument("--fail-on-detected", action="store_true",
                    help="exit non-zero if any DETECTED finding is present")
    sp.set_defaults(func=cmd_scan)

    lb = sub.add_parser("list-backups", help="find iPhone backups in the standard OS locations")
    lb.add_argument("--root", metavar="DIR", action="append",
                    help="also search this backup root (repeatable)")
    lb.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    lb.set_defaults(func=cmd_list_backups)

    dc = sub.add_parser("doctor", help="check whether a target is ready to scan and what to do next")
    dc.add_argument("target", help="path to a backup or filesystem dump")
    dc.add_argument("--type", choices=["auto", "backup", "fs", "sysdiagnose"], default="auto")
    dc.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    dc.set_defaults(func=cmd_doctor)

    sub.add_parser("list-modules", help="list detection modules").set_defaults(func=cmd_list_modules)
    sub.add_parser("list-iocs", help="list built-in indicators").set_defaults(func=cmd_list_iocs)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

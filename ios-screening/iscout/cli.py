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

    # Guard against encrypted backups up front — with actionable guidance.
    if isinstance(target, BackupTarget) and target.is_encrypted():
        echo(color("error: this backup is ENCRYPTED and cannot be read directly.", "red", "bold"))
        echo(
            "Decrypt it first, then scan the decrypted copy. For example:\n"
            "    pip install mvt\n"
            "    mvt-ios decrypt-backup -p '<backup password>' -d ./decrypted "
            f"{args.target}\n"
            "    iscout scan ./decrypted\n"
            "(An encrypted backup is REQUIRED for full coverage — it contains SMS,\n"
            "Safari history and more that unencrypted backups omit.)"
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
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        write_json(result, args.json)
        echo(color(f"  JSON report written to {args.json}", "grey"))
    if args.html:
        os.makedirs(os.path.dirname(os.path.abspath(args.html)), exist_ok=True)
        write_html(result, args.html)
        echo(color(f"  HTML report written to {args.html}", "grey"))

    counts = result.counts()
    if args.fail_on_detected and counts["DETECTED"]:
        return 1
    return 0


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
    sp.add_argument("--redact", action="store_true", help="mask serial/IMEI/phone number in output")
    sp.add_argument("-v", "--verbose", action="store_true", help="also show INFO findings on the console")
    sp.add_argument("-q", "--quiet", action="store_true", help="suppress the console report (still writes files)")
    sp.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    sp.add_argument("--fail-on-detected", action="store_true",
                    help="exit non-zero if any DETECTED finding is present")
    sp.set_defaults(func=cmd_scan)

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

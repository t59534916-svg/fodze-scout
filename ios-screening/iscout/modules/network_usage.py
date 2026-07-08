"""Network-usage analysis (DataUsage.sqlite and, for FS dumps, netusage.sqlite).

Two detections, both grounded in Amnesty's Pegasus methodology:

1. **Indicator match** — a process/bundle name recorded as using the network
   matches a known spyware ``process:name`` / ``app:id`` indicator.
2. **Orphaned-usage heuristic** — Pegasus deleted its process names from the
   ``ZPROCESS`` table but left the corresponding ``ZLIVEUSAGE`` rows behind. A
   usage row that references a process primary key which no longer exists is an
   anomaly worth investigating.
"""

from __future__ import annotations

import sqlite3
from typing import Dict, List, Optional, Set

from ..backup import open_sqlite_ro
from ..utils import convert_mactime
from .base import Finding, Module, Severity


def _columns(conn: sqlite3.Connection, table: str) -> Set[str]:
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table});")}
    except sqlite3.DatabaseError:
        return set()


class NetworkUsageModule(Module):
    name = "network_usage"
    description = "DataUsage/netusage process & bundle network activity"
    supports = ("backup", "fs")

    def run(self) -> List[Finding]:
        for key, label in (("datausage", "DataUsage.sqlite"), ("netusage", "netusage.sqlite")):
            path = self.target.locate(key)
            if path:
                self._analyse(path, label)
        return self.findings

    def _analyse(self, path: str, label: str) -> None:
        try:
            conn = open_sqlite_ro(path)
        except sqlite3.DatabaseError as exc:
            self.errors.append(f"{label}: {exc}")
            return
        try:
            proc_cols = _columns(conn, "ZPROCESS")
            live_cols = _columns(conn, "ZLIVEUSAGE")
            if not proc_cols:
                return

            # Valid process primary keys, for orphan detection.
            valid_pks: Set[int] = {
                r[0] for r in conn.execute("SELECT Z_PK FROM ZPROCESS;") if r[0] is not None
            }

            # Inventory processes and match indicators. Build the column list
            # from the actual schema — timestamp columns vary across iOS versions.
            first_col = "ZFIRSTTIMESTAMP" if "ZFIRSTTIMESTAMP" in proc_cols else "NULL AS ZFIRSTTIMESTAMP"
            last_col = "ZTIMESTAMP" if "ZTIMESTAMP" in proc_cols else "NULL AS ZTIMESTAMP"
            proc_sql = f"SELECT Z_PK, ZPROCNAME, ZBUNDLENAME, {first_col}, {last_col} FROM ZPROCESS;"

            hits = 0
            for row in conn.execute(proc_sql):
                pk, procname, bundle, first_ts, last_ts = (
                    row["Z_PK"],
                    row["ZPROCNAME"],
                    row["ZBUNDLENAME"],
                    row["ZFIRSTTIMESTAMP"],
                    row["ZTIMESTAMP"],
                )
                ts = convert_mactime(first_ts) or convert_mactime(last_ts)
                ind = self.indicators.match_process(procname) or self.indicators.match_app_id(bundle)
                if ind:
                    hits += 1
                    self.add_ioc_finding(
                        ind,
                        title=f"Network-active process matches indicator: {procname or bundle}",
                        artifact=label,
                        timestamp=ts,
                        evidence={
                            "process_name": procname,
                            "bundle_name": bundle,
                            "first_seen": convert_mactime(first_ts),
                            "last_seen": convert_mactime(last_ts),
                        },
                    )

            # Orphaned ZLIVEUSAGE rows (usage attributed to a deleted process).
            if "ZHASPROCESS" in live_cols:
                orphans = []
                for row in conn.execute(
                    "SELECT Z_PK, ZHASPROCESS, ZTIMESTAMP FROM ZLIVEUSAGE;"
                ):
                    hp = row["ZHASPROCESS"]
                    if hp and hp not in valid_pks:
                        orphans.append(
                            {
                                "liveusage_pk": row["Z_PK"],
                                "missing_process_pk": hp,
                                "timestamp": convert_mactime(row["ZTIMESTAMP"]),
                            }
                        )
                if orphans:
                    self.add(
                        severity=Severity.WARNING,
                        title=f"{len(orphans)} network-usage record(s) reference a deleted process",
                        description=(
                            "Usage rows in ZLIVEUSAGE point to process entries that no longer "
                            "exist in ZPROCESS. Pegasus is known to delete its process names while "
                            "leaving usage rows behind — investigate this inconsistency. (It can "
                            "also occur benignly after DB maintenance.)"
                        ),
                        source="iScout heuristic: orphaned network usage (Amnesty Pegasus methodology)",
                        artifact=label,
                        evidence={"orphan_count": len(orphans), "orphans": orphans[:25]},
                    )

            self.add(
                severity=Severity.INFO,
                title=f"{len(valid_pks)} process(es) recorded network usage ({label})",
                description="Baseline network-usage inventory." + (" No indicator matches." if not hits else ""),
                artifact=label,
                evidence={"process_count": len(valid_pks)},
            )
        finally:
            conn.close()

"""Safari browsing-history analysis.

Matches visited URLs against ``domain``/``url``/``ip`` indicators and surfaces
redirect chains (``redirect_source``/``redirect_destination``) that end at a
known malicious host — the fingerprint of a network-injection / one-click
exploit-delivery redirect.
"""

from __future__ import annotations

import sqlite3
from typing import List

from ..backup import open_sqlite_ro
from ..utils import convert_mactime
from .base import Finding, Module, Severity


class SafariHistoryModule(Module):
    name = "safari_history"
    description = "Safari history vs malicious domains / redirect chains"
    supports = ("backup", "fs")

    def run(self) -> List[Finding]:
        path = self.target.locate("safari")
        if not path:
            return self.findings
        try:
            conn = open_sqlite_ro(path)
        except sqlite3.DatabaseError as exc:
            self.errors.append(f"History.db: {exc}")
            return self.findings
        try:
            try:
                rows = conn.execute(
                    "SELECT history_items.url AS url, history_visits.visit_time AS visit_time, "
                    "history_visits.redirect_source AS redirect_source, "
                    "history_visits.redirect_destination AS redirect_destination "
                    "FROM history_items "
                    "JOIN history_visits ON history_visits.history_item = history_items.id "
                    "ORDER BY history_visits.visit_time;"
                ).fetchall()
            except sqlite3.OperationalError:
                rows = conn.execute("SELECT url, NULL AS visit_time, NULL AS redirect_source, "
                                    "NULL AS redirect_destination FROM history_items;").fetchall()

            count = 0
            for r in rows:
                count += 1
                url = r["url"]
                ind = self.indicators.match_url(url)
                if ind:
                    redirect = bool(r["redirect_source"] or r["redirect_destination"])
                    self.add_ioc_finding(
                        ind,
                        title=f"Safari visited a flagged host: {url[:120]}",
                        description=(ind.description or "")
                        + (" Reached via a redirect chain (possible exploit delivery)." if redirect else ""),
                        artifact="Safari History.db",
                        timestamp=convert_mactime(r["visit_time"]),
                        evidence={
                            "url": url,
                            "redirect": redirect,
                            "redirect_source_id": r["redirect_source"],
                            "redirect_destination_id": r["redirect_destination"],
                        },
                    )

            self.add(
                severity=Severity.INFO,
                title=f"{count} Safari history visit(s) scanned",
                artifact="Safari History.db",
                evidence={"visit_count": count},
            )
        finally:
            conn.close()
        return self.findings

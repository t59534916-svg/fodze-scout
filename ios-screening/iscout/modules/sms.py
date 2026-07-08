"""SMS / iMessage link analysis.

Extracts URLs from message bodies and matches them against
``domain``/``url``/``ip`` indicators. Malicious one-click/zero-click spyware is
frequently delivered as a link in an SMS or iMessage.
"""

from __future__ import annotations

import sqlite3
from typing import List

from ..backup import open_sqlite_ro
from ..utils import convert_mactime, extract_urls
from .base import Finding, Module, Severity


class SMSModule(Module):
    name = "sms"
    description = "SMS/iMessage links vs malicious domains"
    supports = ("backup", "fs")

    def run(self) -> List[Finding]:
        path = self.target.locate("sms")
        if not path:
            return self.findings
        try:
            conn = open_sqlite_ro(path)
        except sqlite3.DatabaseError as exc:
            self.errors.append(f"sms.db: {exc}")
            return self.findings
        try:
            try:
                rows = conn.execute(
                    "SELECT message.text AS text, message.date AS date, "
                    "message.is_from_me AS is_from_me, handle.id AS contact "
                    "FROM message LEFT JOIN handle ON handle.rowid = message.handle_id;"
                ).fetchall()
            except sqlite3.OperationalError:
                rows = conn.execute("SELECT text, date, is_from_me, NULL AS contact FROM message;").fetchall()

            scanned = 0
            links = 0
            for r in rows:
                scanned += 1
                for url in extract_urls(r["text"]):
                    links += 1
                    ind = self.indicators.match_url(url)
                    if ind:
                        self.add_ioc_finding(
                            ind,
                            title=f"Message contains a flagged link: {url[:120]}",
                            artifact="sms.db",
                            timestamp=convert_mactime(r["date"]),
                            evidence={
                                "url": url,
                                "from_me": bool(r["is_from_me"]),
                                "contact": r["contact"],
                            },
                        )
            self.add(
                severity=Severity.INFO,
                title=f"{scanned} message(s) scanned, {links} link(s) inspected",
                artifact="sms.db",
                evidence={"messages": scanned, "links": links},
            )
        finally:
            conn.close()
        return self.findings

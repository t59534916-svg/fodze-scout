"""TCC (privacy permissions) analysis.

Surfaces which apps hold camera / microphone / screen-recording access and flags
grants that were applied by MDM policy or granted to a raw executable path —
both are unusual for a normal consumer device and consistent with covert
monitoring.
"""

from __future__ import annotations

import sqlite3
from typing import List

from ..backup import open_sqlite_ro
from ..utils import convert_unixtime
from .base import Finding, Module, Severity

_SENSITIVE = {
    "kTCCServiceCamera": "camera",
    "kTCCServiceMicrophone": "microphone",
    "kTCCServiceScreenCapture": "screen recording",
    "kTCCServiceListenEvent": "keystroke/input monitoring",
    "kTCCServiceLocation": "location",
    "kTCCServiceMediaLibrary": "media library",
}

_AUTH_REASON = {
    1: "error",
    2: "user_consent",
    3: "user_set",
    4: "system_set",
    5: "service_policy",
    6: "mdm_policy",
    7: "override_policy",
    8: "missing_usage_string",
    9: "prompt_timeout",
    10: "preflight_unknown",
    11: "entitled",
    12: "app_type_policy",
}


class TCCModule(Module):
    name = "tcc"
    description = "Privacy permissions (camera/mic) and MDM-granted access"
    supports = ("backup", "fs")

    def run(self) -> List[Finding]:
        path = self.target.locate("tcc")
        if not path:
            return self.findings
        try:
            conn = open_sqlite_ro(path)
        except sqlite3.DatabaseError as exc:
            self.errors.append(f"TCC.db: {exc}")
            return self.findings
        try:
            rows, has_reason = self._read(conn)
            sensitive_grants = 0
            for row in rows:
                service = row.get("service")
                client = row.get("client")
                client_type = row.get("client_type")
                auth_value = row.get("auth_value")
                auth_reason = row.get("auth_reason")
                last_modified = row.get("last_modified")

                allowed = auth_value in (1, 2, 3) if not has_reason else auth_value in (2, 3)
                if service not in _SENSITIVE or not allowed:
                    continue
                sensitive_grants += 1
                ts = convert_unixtime(last_modified)
                reason = _AUTH_REASON.get(auth_reason, str(auth_reason)) if auth_reason is not None else None

                # Direct IOC match on the grantee.
                ind = self.indicators.match_app_id(client) or self.indicators.match_path(client)
                if ind:
                    self.add_ioc_finding(
                        ind,
                        title=f"Spyware indicator holds {_SENSITIVE[service]} access: {client}",
                        artifact="TCC.db",
                        timestamp=ts,
                        evidence={"service": service, "client": client, "auth_reason": reason},
                    )
                    continue

                if auth_reason == 6:  # mdm_policy
                    self.add(
                        severity=Severity.WARNING,
                        title=f"{_SENSITIVE[service].title()} access granted by MDM policy: {client}",
                        description=(
                            "A management profile (not you) granted this sensitive permission. "
                            "If you did not enrol this device in MDM, treat it as covert monitoring."
                        ),
                        matched_value=client,
                        source="iScout heuristic: MDM-granted sensitive TCC permission",
                        artifact="TCC.db",
                        timestamp=ts,
                        evidence={"service": service, "client": client, "auth_reason": reason},
                    )
                elif client_type and client_type != 0:
                    self.add(
                        severity=Severity.WARNING,
                        title=f"{_SENSITIVE[service].title()} access granted to a raw executable: {client}",
                        description=(
                            "Sensitive access is held by a filesystem path rather than an App Store "
                            "app — unusual on a non-jailbroken device."
                        ),
                        matched_value=client,
                        source="iScout heuristic: non-bundle TCC grantee",
                        artifact="TCC.db",
                        timestamp=ts,
                        evidence={"service": service, "client": client, "auth_reason": reason},
                    )

            self.add(
                severity=Severity.INFO,
                title=f"{sensitive_grants} app(s) hold camera/microphone/location access",
                description="Review each grantee under Settings > Privacy & Security.",
                artifact="TCC.db",
                evidence={"sensitive_grants": sensitive_grants},
            )
        finally:
            conn.close()
        return self.findings

    def _read(self, conn: sqlite3.Connection):
        """Return (list-of-dict rows, has_auth_reason). Handles TCC v1/v2/v3."""
        queries = [
            ("SELECT service, client, client_type, auth_value, auth_reason, last_modified FROM access;", True),
            ("SELECT service, client, client_type, allowed AS auth_value, NULL AS auth_reason, last_modified FROM access;", False),
            ("SELECT service, client, client_type, allowed AS auth_value, NULL AS auth_reason, NULL AS last_modified FROM access;", False),
        ]
        for sql, has_reason in queries:
            try:
                rows = [dict(r) for r in conn.execute(sql).fetchall()]
                return rows, has_reason
            except sqlite3.OperationalError:
                continue
        return [], False

"""shutdown.log 'sticky process' heuristic (Kaspersky iShutdown).

``shutdown.log`` (only present in a full filesystem dump / sysdiagnose) records,
at each reboot, any client process still running when the graceful shutdown
begins. A process that repeatedly resists shutdown — Kaspersky treats **more than
four** delay entries for the same client path as anomalous (clean phones show
~2-3) — is a known Pegasus/Predator/Reign indicator, especially when its path is
under a known infection directory such as ``/private/var/db/…`` or
``/private/var/tmp/``.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import List

from ..utils import convert_unixtime
from .base import Finding, Module, Severity

_STICKY_THRESHOLD = 4
_INFECTION_DIRS = (
    "/private/var/db/com.apple.xpc.roleaccountd.staging",
    "/private/var/tmp/",
    "/private/var/db/",
)

_CLIENT_RE = re.compile(r"remaining client pid:\s*(\d+)\s*\(([^)]+)\)")
_SIGTERM_RE = re.compile(r"SIGTERM:?\s*\[?(\d{9,})\]?")


class ShutdownLogModule(Module):
    name = "shutdownlog"
    description = "shutdown.log sticky-process reboot-delay heuristic"
    supports = ("fs",)

    def run(self) -> List[Finding]:
        path = self.target.locate("shutdownlog")
        if not path:
            return self.findings
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            self.errors.append(f"shutdown.log: {exc}")
            return self.findings

        counts: Counter = Counter()
        last_ts = None
        for line in text.splitlines():
            ts_match = _SIGTERM_RE.search(line)
            if ts_match:
                last_ts = convert_unixtime(int(ts_match.group(1)))
            m = _CLIENT_RE.search(line)
            if m:
                counts[m.group(2).strip()] += 1

        for client_path, n in counts.most_common():
            infection = any(d in client_path for d in _INFECTION_DIRS)
            if n > _STICKY_THRESHOLD or infection:
                sev = Severity.DETECTED if infection else Severity.WARNING
                self.add(
                    severity=sev,
                    title=f"Process resisted shutdown {n}× : {client_path}",
                    description=(
                        f"This client appeared in {n} reboot-delay entries"
                        + (" and runs from a known malware execution directory." if infection else ".")
                        + " Repeated shutdown resistance is a documented spyware indicator "
                        "(Kaspersky iShutdown)."
                    ),
                    matched_value=client_path,
                    source="iScout heuristic: shutdown.log sticky process (Kaspersky iShutdown)",
                    artifact="shutdown.log",
                    timestamp=last_ts,
                    evidence={"client_path": client_path, "delay_count": n, "infection_dir": infection},
                )

        self.add(
            severity=Severity.INFO,
            title=f"shutdown.log parsed ({len(counts)} distinct sticky client(s))",
            artifact="shutdown.log",
            evidence={"clients": dict(counts.most_common(20))},
        )
        return self.findings

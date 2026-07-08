"""Filesystem path / name / hash IOC scanning and jailbreak detection.

Runs over every file the target exposes (Manifest.db entries for a backup, the
whole tree for a filesystem dump) and matches paths, basenames and — when hash
indicators are loaded — file hashes. Also flags jailbreak artifacts (Cydia,
Sileo, MobileSubstrate, rootless ``/var/jb`` …), which are a *prerequisite* for
most on-device iOS stalkerware and thus a risk indicator in their own right.
"""

from __future__ import annotations

import hashlib
import os
from typing import List

from ..indicators import CATEGORY_JAILBREAK
from .base import Finding, Module, Severity

_MAX_HASH_BYTES = 64 * 1024 * 1024  # don't hash files larger than 64 MiB


class FileScanModule(Module):
    name = "filescan"
    description = "Path/name/hash IOC matching + jailbreak artifacts"
    supports = ("backup", "fs")

    def run(self) -> List[Finding]:
        want_hashes = bool(self.indicators.hashes)
        scanned = 0
        jailbreak_hits: List[str] = []
        seen_paths = set()

        for device_path, local_path in self.target.walk_files():
            scanned += 1
            ind = self.indicators.match_path(device_path)
            if ind and device_path not in seen_paths:
                seen_paths.add(device_path)
                if ind.category == CATEGORY_JAILBREAK:
                    jailbreak_hits.append(device_path)
                else:
                    self.add_ioc_finding(
                        ind,
                        title=f"File path matches indicator: {device_path}",
                        artifact=device_path,
                        evidence={"path": device_path},
                    )

            if want_hashes and os.path.isfile(local_path):
                digest = self._hash(local_path)
                if digest:
                    hit = self.indicators.match_hash(digest)
                    if hit:
                        self.add_ioc_finding(
                            hit,
                            title=f"File hash matches indicator: {device_path}",
                            artifact=device_path,
                            evidence={"path": device_path, "sha256": digest},
                        )

        if jailbreak_hits:
            self.add(
                severity=Severity.WARNING,
                title=f"Jailbreak artifacts present ({len(jailbreak_hits)})",
                description=(
                    "The device appears to be jailbroken. Jailbreaking is a prerequisite for "
                    "most on-device iOS stalkerware and disables key iOS protections. If you did "
                    "not jailbreak this device yourself, treat it as a serious red flag."
                ),
                matched_value=", ".join(sorted(jailbreak_hits)[:10]),
                source="iScout jailbreak indicators",
                artifact=jailbreak_hits[0],
                evidence={"paths": sorted(jailbreak_hits)[:50]},
            )

        self.add(
            severity=Severity.INFO,
            title=f"{scanned} file(s) scanned for path/hash indicators",
            evidence={"files_scanned": scanned, "hash_matching": want_hashes},
        )
        return self.findings

    @staticmethod
    def _hash(path: str) -> str:
        try:
            if os.path.getsize(path) > _MAX_HASH_BYTES:
                return ""
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ""

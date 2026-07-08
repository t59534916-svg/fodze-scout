"""Indicator (IOC) loading and matching.

Supports two feed formats:

1. iScout curated JSON (``iscout/data/indicators/*.json``) — a small, fully
   source-attributed starter set. Each indicator carries a ``confidence`` and a
   ``source`` so findings can be justified.

2. STIX2 bundles (``*.stix2`` / ``*.json`` with ``"type": "bundle"``) — the same
   format Amnesty International's MVT distributes (``pegasus.stix2``,
   ``cytrox.stix2`` for Predator, ``stalkerware.stix2`` …). Load external feeds
   with ``--iocs FILE`` or by pointing ``ISCOUT_STIX2`` / ``MVT_STIX2`` at them.

The starter set is deliberately small and conservative. It is NOT a substitute
for the full, regularly-updated public feeds — always pull those in for a real
investigation (see ``data/indicators/README.md``).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .utils import defang, parent_domains, url_host

# Indicator categories drive how strongly a match is reported. A jailbreak is a
# risk indicator, not proof of spyware, so it never escalates to DETECTED.
CATEGORY_MERCENARY = "mercenary"
CATEGORY_STALKERWARE = "stalkerware"
CATEGORY_JAILBREAK = "jailbreak"
CATEGORY_GENERIC = "generic"


@dataclass
class Indicator:
    type: str
    value: str
    confidence: str = "medium"  # high | medium | low
    malware_family: str = ""
    category: str = CATEGORY_GENERIC
    source: str = ""
    feed: str = ""
    description: str = ""


# Map STIX2 pattern object-paths to our internal indicator types.
_STIX_TYPE_MAP = {
    "domain-name:value": "domain",
    "url:value": "url",
    "process:name": "process_name",
    "app:id": "app_id",
    "configuration-profile:id": "profile_id",
    "email-addr:value": "email",
    "file:name": "file_name",
    "file:path": "file_path",
    "ipv4-addr:value": "ip",
    "ipv6-addr:value": "ip",
    "file:hashes.md5": "hash",
    "file:hashes.sha-1": "hash",
    "file:hashes.sha-256": "hash",
    "file:hashes.sha1": "hash",
    "file:hashes.sha256": "hash",
}

_STIX_PATTERN_RE = re.compile(r"([\w\-]+:[\w.'\-]+)\s*=\s*'([^']+)'")


class Indicators:
    """A loaded, indexed set of indicators with fast per-type lookups."""

    def __init__(self) -> None:
        self.all: List[Indicator] = []
        self.feeds: Dict[str, dict] = {}  # feed name -> metadata (source, count)
        self.domains: Dict[str, Indicator] = {}
        self.processes: Dict[str, Indicator] = {}
        self.app_ids: Dict[str, Indicator] = {}
        self.app_names: Dict[str, Indicator] = {}
        self.profile_ids: Dict[str, Indicator] = {}
        self.emails: Dict[str, Indicator] = {}
        self.file_names: Dict[str, Indicator] = {}
        self.file_paths: List[Indicator] = []  # substring match
        self.urls: List[Indicator] = []  # substring match
        self.ips: Dict[str, Indicator] = {}
        self.hashes: Dict[str, Indicator] = {}

    # -- loading ---------------------------------------------------------------
    def add(self, ind: Indicator) -> None:
        self.all.append(ind)
        t = ind.type
        v = ind.value.strip()
        if not v:
            return
        if t == "domain":
            self.domains[defang(v).lower()] = ind
        elif t == "process_name":
            self.processes[v.lower()] = ind
        elif t == "app_id":
            self.app_ids[v.lower()] = ind
        elif t == "app_name":
            self.app_names[v.lower()] = ind
        elif t == "profile_id":
            self.profile_ids[v.lower()] = ind
        elif t == "email":
            self.emails[v.lower()] = ind
        elif t == "file_name":
            self.file_names[v.lower()] = ind
        elif t == "file_path":
            self.file_paths.append(ind)
        elif t == "url":
            self.urls.append(ind)
        elif t == "ip":
            self.ips[v] = ind
        elif t == "hash":
            self.hashes[v.lower()] = ind

    def load_curated_file(self, path: str) -> int:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("type") == "bundle":
            return self.load_stix2_obj(data, os.path.basename(path))
        feed = data.get("feed") or os.path.splitext(os.path.basename(path))[0]
        category = data.get("category", CATEGORY_GENERIC)
        feed_source = data.get("source", "")
        count = 0
        for raw in data.get("indicators", []):
            ind = Indicator(
                type=raw["type"],
                value=raw["value"],
                confidence=raw.get("confidence", "medium"),
                malware_family=raw.get("malware_family", ""),
                category=raw.get("category", category),
                source=raw.get("source", feed_source),
                feed=feed,
                description=raw.get("description", ""),
            )
            self.add(ind)
            count += 1
        self.feeds[feed] = {
            "source": feed_source,
            "reference": data.get("reference", ""),
            "category": category,
            "count": count,
            "path": path,
        }
        return count

    def load_stix2_obj(self, bundle: dict, feed: str) -> int:
        # STIX2 patterns carry no confidence field. Derive the category from the
        # feed name and default the confidence per indicator type: precise types
        # (domain/process/hash/…) are trusted as high; the SUBSTRING-matched
        # loose types (url, file_path) default to medium so a broad external
        # value cannot escalate straight to DETECTED.
        category = CATEGORY_STALKERWARE if "stalker" in feed.lower() else CATEGORY_MERCENARY
        count = 0
        for obj in bundle.get("objects", []):
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            labels = obj.get("labels") or []
            family = obj.get("name") or (",".join(labels) if labels else "")
            for lhs, val in _STIX_PATTERN_RE.findall(pattern):
                key = lhs.replace("'", "").lower()
                itype = _STIX_TYPE_MAP.get(key)
                if not itype:
                    continue
                confidence = "medium" if itype in ("url", "file_path") else "high"
                self.add(
                    Indicator(
                        type=itype,
                        value=val,
                        confidence=confidence,
                        malware_family=family,
                        category=category,
                        source=f"STIX2:{feed}",
                        feed=feed,
                        description=obj.get("description", ""),
                    )
                )
                count += 1
        self.feeds[feed] = {"source": f"STIX2 {feed}", "count": count, "category": category}
        return count

    def load_builtin(self, data_dir: Optional[str] = None) -> int:
        data_dir = data_dir or os.path.join(os.path.dirname(__file__), "data", "indicators")
        total = 0
        if not os.path.isdir(data_dir):
            return 0
        for name in sorted(os.listdir(data_dir)):
            if not name.endswith(".json"):
                continue
            if name.startswith("_") or name == "profiles_highrisk.json":
                continue  # rule files, loaded separately
            try:
                total += self.load_curated_file(os.path.join(data_dir, name))
            except (json.JSONDecodeError, KeyError, OSError):
                continue
        return total

    def load_path(self, path: str) -> int:
        """Load an external feed file or a directory of feed files."""
        if os.path.isdir(path):
            total = 0
            for name in sorted(os.listdir(path)):
                if name.endswith((".json", ".stix2")):
                    try:
                        total += self.load_curated_file(os.path.join(path, name))
                    except (json.JSONDecodeError, KeyError, OSError):
                        continue
            return total
        return self.load_curated_file(path)

    # -- matching --------------------------------------------------------------
    def match_domain(self, host: Optional[str]) -> Optional[Indicator]:
        if not host:
            return None
        for cand in parent_domains(host):
            hit = self.domains.get(cand)
            if hit:
                return hit
        return None

    def match_url(self, url: Optional[str]) -> Optional[Indicator]:
        if not url:
            return None
        host = url_host(url)
        hit = self.match_domain(host)
        if hit:
            return hit
        # url-type indicators: anchor on the host (suffix) and, when the
        # indicator carries a path, require it to be a path prefix — never a raw
        # unanchored substring (which over-matches query params / nested URLs).
        for ind in self.urls:
            if _url_indicator_matches(ind.value, url, host):
                return ind
        # Bare-IP hosts
        if host and host in self.ips:
            return self.ips[host]
        return None

    def match_process(self, name: Optional[str]) -> Optional[Indicator]:
        if not name:
            return None
        return self.processes.get(name.strip().lower())

    def match_app_id(self, bundle_id: Optional[str]) -> Optional[Indicator]:
        if not bundle_id:
            return None
        return self.app_ids.get(bundle_id.strip().lower())

    def match_app_name(self, name: Optional[str]) -> Optional[Indicator]:
        if not name:
            return None
        return self.app_names.get(name.strip().lower())

    def match_profile_id(self, pid: Optional[str]) -> Optional[Indicator]:
        if not pid:
            return None
        return self.profile_ids.get(pid.strip().lower())

    def match_path(self, path: Optional[str]) -> Optional[Indicator]:
        if not path:
            return None
        low = path.lower().replace("\\", "/")
        base = low.rsplit("/", 1)[-1]
        hit = self.file_names.get(base)
        if hit:
            return hit
        for ind in self.file_paths:
            if _path_contains(low, ind.value.lower().replace("\\", "/")):
                return ind
        return None

    def match_hash(self, digest: Optional[str]) -> Optional[Indicator]:
        if not digest:
            return None
        return self.hashes.get(digest.strip().lower())

    def summary(self) -> Dict[str, int]:
        from collections import Counter

        c = Counter(i.type for i in self.all)
        return dict(c)


def _path_contains(path: str, value: str) -> bool:
    """Segment-boundary containment: '/var/jb' matches '/private/var/jb' but not
    '/private/var/jbGameCache'. Avoids substring over-matching of short paths."""
    p = "/" + path.strip("/") + "/"
    v = "/" + value.strip("/") + "/"
    return v in p


def _url_indicator_matches(indicator_value: str, url: str, url_host_value: Optional[str]) -> bool:
    """A url-type indicator matches only when its host suffix-matches the target
    host AND (if it carries a path) that path is a prefix of the target's path."""
    ind_host = url_host(indicator_value)
    if not ind_host or not url_host_value:
        return False
    if not (url_host_value == ind_host or url_host_value.endswith("." + ind_host)):
        return False
    ind_path = _url_path(indicator_value)
    if not ind_path or ind_path == "/":
        return True
    return _url_path(url).startswith(ind_path)


def _url_path(url: str) -> str:
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url.strip())
    s = s.split("@")[-1]  # strip userinfo
    slash = s.find("/")
    if slash == -1:
        return "/"
    return s[slash:].split("?", 1)[0].split("#", 1)[0].lower()

"""Access layer over an iOS backup or a full filesystem dump / sysdiagnose.

The :class:`Target` interface hides *where* an artifact lives so detection
modules stay input-agnostic:

* :class:`BackupTarget` resolves artifacts through ``Manifest.db`` (the
  ``Files`` table maps ``domain``/``relativePath`` to a 40-char ``fileID`` whose
  content is stored on disk at ``<root>/<fileID[:2]>/<fileID>``).
* :class:`FilesystemTarget` resolves artifacts by their absolute on-device path
  inside an extracted filesystem tree or sysdiagnose.

All facts below (schema, hard-coded fileIDs, domains, paths) are grounded in the
MVT source and were SHA1-reverified during design.
"""

from __future__ import annotations

import os
import plistlib
import re
import sqlite3
from typing import Dict, Iterator, List, Optional, Tuple

# Config profiles live under this backup domain; each profile file's basename
# starts with "profile-".
CONF_PROFILES_DOMAIN = "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles"
CONF_PROFILE_EVENTS_RELPATH = "Library/ConfigurationProfiles/MCProfileEvents.plist"

# (domain, relativePath) for backup artifacts. Safari's domain moved between iOS
# versions, so it is resolved by relativePath alone.
_BACKUP_ARTIFACTS = {
    "datausage": ("WirelessDomain", "Library/Databases/DataUsage.sqlite"),
    "sms": ("HomeDomain", "Library/SMS/sms.db"),
    "tcc": ("HomeDomain", "Library/TCC/TCC.db"),
    "safari": (None, "Library/Safari/History.db"),
}

# Absolute on-device paths for the same artifacts in a filesystem dump.
_FS_ARTIFACTS = {
    "datausage": ["private/var/wireless/Library/Databases/DataUsage.sqlite"],
    "netusage": [
        "private/var/networkd/netusage.sqlite",
        "private/var/networkd/db/netusage.sqlite",
    ],
    "sms": ["private/var/mobile/Library/SMS/sms.db"],
    "tcc": ["private/var/mobile/Library/TCC/TCC.db"],
    "safari": ["private/var/mobile/Library/Safari/History.db"],
    "shutdownlog": ["private/var/db/diagnostics/shutdown.log"],
}


def open_sqlite_ro(path: str) -> sqlite3.Connection:
    """Open a SQLite file strictly read-only (never mutate evidence)."""
    # Escape '%' FIRST — SQLite URI filenames percent-decode '%XX', so a path
    # with a literal percent sequence would otherwise resolve to the wrong file.
    escaped = os.path.abspath(path).replace("%", "%25").replace("?", "%3f").replace("#", "%23")
    conn = sqlite3.connect(f"file:{escaped}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# A backup fileID is the 40-char lowercase-hex SHA1 of "domain-relativePath".
# Anything else in Manifest.db's fileID column is untrusted and could be a path
# traversal payload ("../../etc/..."), so we validate before touching the disk.
_FILEID_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class ArtifactError(Exception):
    pass


class EncryptedBackupError(Exception):
    """Raised when a backup is encrypted and therefore cannot be parsed."""


class Target:
    """Abstract source of iOS artifacts."""

    kind = "target"

    def is_encrypted(self) -> bool:
        return False

    def device_info(self) -> Dict[str, object]:
        return {}

    def installed_apps(self) -> Tuple[List[str], Dict[str, dict]]:
        return [], {}

    def locate(self, key: str) -> Optional[str]:
        """Return a local filesystem path to artifact *key*, or ``None``."""
        raise NotImplementedError

    def profiles(self) -> List[Tuple[str, dict]]:
        return []

    def profile_events(self) -> dict:
        return {}

    def walk_files(self) -> Iterator[Tuple[str, str]]:
        """Yield ``(relative_or_device_path, local_path)`` for every stored file."""
        return iter(())


class BackupTarget(Target):
    kind = "backup"

    def __init__(self, root: str) -> None:
        self.root = root
        self.manifest_db = os.path.join(root, "Manifest.db")
        self._manifest_plist: Optional[dict] = None
        self._info: Optional[dict] = None
        self._file_index: Optional[List[Tuple[str, str, str]]] = None

    # -- validation ------------------------------------------------------------
    @staticmethod
    def looks_like_backup(root: str) -> bool:
        return os.path.isfile(os.path.join(root, "Manifest.db")) or os.path.isfile(
            os.path.join(root, "Manifest.plist")
        )

    def manifest_plist(self) -> dict:
        if self._manifest_plist is None:
            path = os.path.join(self.root, "Manifest.plist")
            self._manifest_plist = {}
            if os.path.isfile(path):
                try:
                    with open(path, "rb") as fh:
                        loaded = plistlib.load(fh)
                    if isinstance(loaded, dict):
                        self._manifest_plist = loaded
                except Exception:  # noqa: BLE001 - a corrupt plist must not crash the scan
                    pass
        return self._manifest_plist

    def is_encrypted(self) -> bool:
        # Prefer the declared flag; fall back to probing Manifest.db.
        if self.manifest_plist().get("IsEncrypted"):
            return True
        if not os.path.isfile(self.manifest_db):
            return False
        try:
            conn = open_sqlite_ro(self.manifest_db)
            conn.execute("SELECT fileID FROM Files LIMIT 1;").fetchone()
            conn.close()
            return False
        except sqlite3.DatabaseError:
            return True

    # -- Manifest.db lookups ---------------------------------------------------
    def _index(self) -> List[Tuple[str, str, str]]:
        if self._file_index is None:
            rows: List[Tuple[str, str, str]] = []
            try:
                conn = open_sqlite_ro(self.manifest_db)
                for r in conn.execute("SELECT fileID, domain, relativePath FROM Files;"):
                    fid = r["fileID"]
                    # Reject anything that is not a well-formed SHA1 fileID: a
                    # malicious Manifest.db could otherwise point us at files
                    # outside the backup (arbitrary local-file read).
                    if not (isinstance(fid, str) and _FILEID_RE.match(fid)):
                        continue
                    rows.append((fid, r["domain"], r["relativePath"]))
                conn.close()
            except sqlite3.DatabaseError as exc:
                raise EncryptedBackupError(
                    "Manifest.db could not be read (backup is encrypted or corrupt)."
                ) from exc
            self._file_index = rows
        return self._file_index

    def _disk_path(self, file_id: str) -> str:
        return os.path.join(self.root, file_id[:2], file_id)

    def find_by_relpath(
        self, relative_path: str, domain: Optional[str] = None
    ) -> Optional[str]:
        for file_id, dom, rel in self._index():
            if rel == relative_path and (domain is None or dom == domain):
                p = self._disk_path(file_id)
                if os.path.isfile(p):
                    return p
        return None

    def locate(self, key: str) -> Optional[str]:
        spec = _BACKUP_ARTIFACTS.get(key)
        if not spec:
            return None
        domain, relpath = spec
        return self.find_by_relpath(relpath, domain)

    # -- Info.plist ------------------------------------------------------------
    def _info_plist(self) -> dict:
        if self._info is None:
            path = os.path.join(self.root, "Info.plist")
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    self._info = plistlib.load(fh)
            else:
                self._info = {}
        return self._info

    def device_info(self) -> Dict[str, object]:
        info = self._info_plist()
        keys = [
            "Device Name",
            "Product Name",
            "Product Type",
            "Product Version",
            "Build Version",
            "Serial Number",
            "IMEI",
            "ICCID",
            "Phone Number",
            "Last Backup Date",
            "Unique Identifier",
            "Target Identifier",
            "iTunes Version",
            "GUID",
        ]
        out: Dict[str, object] = {k: info.get(k) for k in keys if info.get(k) is not None}
        out["Encrypted"] = self.is_encrypted()
        return out

    def installed_apps(self) -> Tuple[List[str], Dict[str, dict]]:
        info = self._info_plist()
        installed = list(info.get("Installed Applications", []) or [])
        apps: Dict[str, dict] = {}
        raw_apps = info.get("Applications", {}) or {}
        for bundle_id, meta in raw_apps.items():
            entry: Dict[str, object] = {}
            itunes = meta.get("iTunesMetadata") if isinstance(meta, dict) else None
            if isinstance(itunes, (bytes, bytearray)):
                try:
                    md = plistlib.loads(bytes(itunes))
                    entry["name"] = md.get("itemName") or md.get("bundleDisplayName")
                    entry["version"] = md.get("bundleShortVersionString")
                    entry["seller"] = md.get("artistName")
                    dinfo = md.get("com.apple.iTunesStore.downloadInfo", {}) or {}
                    entry["purchaseDate"] = dinfo.get("purchaseDate")
                    entry["softwareVersionBundleId"] = md.get("softwareVersionBundleId")
                except Exception:  # noqa: BLE001 - metadata is best-effort
                    pass
            apps[bundle_id] = entry
        # Ensure every installed bundle id is represented.
        for b in installed:
            apps.setdefault(b, {})
        return installed, apps

    # -- configuration profiles ------------------------------------------------
    def profiles(self) -> List[Tuple[str, dict]]:
        out: List[Tuple[str, dict]] = []
        for file_id, dom, rel in self._index():
            if dom != CONF_PROFILES_DOMAIN:
                continue
            if not os.path.basename(rel).startswith("profile-"):
                continue
            p = self._disk_path(file_id)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "rb") as fh:
                    out.append((rel, plistlib.load(fh)))
            except Exception:  # noqa: BLE001
                continue
        return out

    def profile_events(self) -> dict:
        p = self.find_by_relpath(CONF_PROFILE_EVENTS_RELPATH)
        if not p:
            return {}
        try:
            with open(p, "rb") as fh:
                data = plistlib.load(fh)
            return data.get("ProfileEvents", data) if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    def walk_files(self) -> Iterator[Tuple[str, str]]:
        for file_id, dom, rel in self._index():
            yield (f"{dom}/{rel}" if dom else rel, self._disk_path(file_id))


class FilesystemTarget(Target):
    """A full filesystem dump (jailbroken device image) or sysdiagnose tree."""

    kind = "fs"

    def __init__(self, root: str) -> None:
        self.root = root
        self._real_root = os.path.realpath(root)

    @staticmethod
    def looks_like_fs(root: str) -> bool:
        return os.path.isdir(os.path.join(root, "private")) or os.path.isdir(
            os.path.join(root, "private", "var")
        )

    def _within_root(self, path: str) -> bool:
        """True if *path* resolves to a location inside the dump (blocks symlink escapes)."""
        try:
            real = os.path.realpath(path)
        except OSError:
            return False
        return real == self._real_root or real.startswith(self._real_root + os.sep)

    def _safe_file(self, path: str) -> bool:
        return os.path.isfile(path) and self._within_root(path)

    def locate(self, key: str) -> Optional[str]:
        for rel in _FS_ARTIFACTS.get(key, []):
            p = os.path.join(self.root, rel)
            if self._safe_file(p):
                return p
        # Safari may live inside per-app containers.
        if key == "safari":
            base = os.path.join(self.root, "private/var/mobile/Containers/Data/Application")
            if os.path.isdir(base):
                for app in os.listdir(base):
                    cand = os.path.join(base, app, "Library/Safari/History.db")
                    if self._safe_file(cand):
                        return cand
        return None

    def walk_files(self) -> Iterator[Tuple[str, str]]:
        for dirpath, _dirs, files in os.walk(self.root):  # followlinks=False by default
            for name in files:
                local = os.path.join(dirpath, name)
                # Skip file symlinks that point outside the extracted tree.
                if os.path.islink(local) and not self._within_root(local):
                    continue
                rel = "/" + os.path.relpath(local, self.root).replace("\\", "/")
                yield (rel, local)


def open_target(path: str, kind: str = "auto") -> Target:
    """Construct the right :class:`Target` for *path*."""
    if not os.path.isdir(path):
        raise ArtifactError(f"Not a directory: {path}")
    if kind == "backup":
        return BackupTarget(path)
    if kind in ("fs", "filesystem", "sysdiagnose"):
        return FilesystemTarget(path)
    # auto-detect
    if BackupTarget.looks_like_backup(path):
        return BackupTarget(path)
    if FilesystemTarget.looks_like_fs(path):
        return FilesystemTarget(path)
    raise ArtifactError(
        f"Could not recognise {path!r} as an iOS backup (needs Manifest.db) "
        f"or a filesystem dump (needs a 'private/' tree). "
        f"Use --type to force a mode."
    )

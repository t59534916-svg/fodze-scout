"""Real-device preparation helpers: locate backups, diagnose a target, decrypt.

These make iScout usable against a *real* iPhone backup without hunting for the
cryptic UDID folder or guessing whether a backup is encrypted:

* :func:`discover_backups` finds backups in the standard macOS/Windows locations.
* :func:`diagnose` reports whether a path is scan-ready and what to do next.
* :func:`decrypt_backup` drives ``mvt-ios decrypt-backup`` when available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from .backup import BackupTarget, FilesystemTarget, Target, open_target


def default_backup_roots() -> List[str]:
    """Standard per-OS locations that hold iTunes/Finder backups."""
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    userprofile = os.environ.get("USERPROFILE", home)
    candidates = [
        # macOS (Finder / iTunes)
        os.path.join(home, "Library", "Application Support", "MobileSync", "Backup"),
        # Windows — Microsoft Store "Apple Devices" app
        os.path.join(userprofile, "Apple", "MobileSync", "Backup"),
        # Windows — classic iTunes
        os.path.join(appdata, "Apple Computer", "MobileSync", "Backup") if appdata else "",
        os.path.join(appdata, "Apple", "MobileSync", "Backup") if appdata else "",
    ]
    seen: List[str] = []
    for c in candidates:
        if c and os.path.isdir(c) and c not in seen:
            seen.append(c)
    return seen


def summarize_backup(path: str) -> Dict[str, object]:
    """Read the (plaintext) device metadata for a single backup folder.

    Info.plist and Manifest.plist are NOT encrypted even in an encrypted backup,
    so device name / iOS version / date and the encrypted flag are always readable.
    """
    t = BackupTarget(path)
    info: Dict[str, object] = {"path": path}
    try:
        meta = t.device_info()
    except Exception:  # noqa: BLE001
        meta = {}
    info.update(
        {
            "udid": os.path.basename(path),
            "device_name": meta.get("Device Name"),
            "product_type": meta.get("Product Type"),
            "product_version": meta.get("Product Version"),
            "last_backup": str(meta.get("Last Backup Date")) if meta.get("Last Backup Date") else None,
            "encrypted": bool(meta.get("Encrypted")),
            "serial": meta.get("Serial Number"),
        }
    )
    return info


def discover_backups(roots: Optional[List[str]] = None) -> List[Dict[str, object]]:
    """Enumerate backups under *roots* (default: the standard OS locations)."""
    roots = roots if roots is not None else default_backup_roots()
    out: List[Dict[str, object]] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            sub = os.path.join(root, name)
            if os.path.isdir(sub) and BackupTarget.looks_like_backup(sub):
                out.append(summarize_backup(sub))
    return out


# --- diagnosis ----------------------------------------------------------------

_ARTIFACTS = [
    ("datausage", "DataUsage (network activity)"),
    ("sms", "SMS / iMessage"),
    ("safari", "Safari history"),
    ("tcc", "Privacy permissions (TCC)"),
]


def diagnose(path: str, kind: str = "auto") -> Dict[str, object]:
    """Return a structured readiness report for *path*."""
    result: Dict[str, object] = {
        "path": path,
        "kind": None,
        "encrypted": False,
        "device": {},
        "artifacts": {},
        "profiles": None,
        "ready": False,
        "next_steps": [],
        "error": None,
    }
    if not os.path.isdir(path):
        result["error"] = f"Not a directory: {path}"
        result["next_steps"] = ["Point iScout at a backup folder or a filesystem dump."]
        return result

    try:
        target: Target = open_target(path, kind=kind)
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        result["next_steps"] = [
            "If this really is a backup, ensure Manifest.db is present, or pass --type.",
        ]
        return result

    result["kind"] = target.kind

    if isinstance(target, BackupTarget):
        result["device"] = {k: str(v) for k, v in target.device_info().items()}
        if target.is_encrypted():
            result["encrypted"] = True
            result["ready"] = False
            result["next_steps"] = [
                "This backup is ENCRYPTED — decrypt it first, then scan the decrypted copy:",
                f"    iscout scan {path} --decrypt --work ./decrypted",
                "  (needs MVT: `pip install mvt`; mvt will prompt for the backup password),",
                "  or manually: `mvt-ios decrypt-backup -d ./decrypted <backup>` then `iscout scan ./decrypted`.",
                "An encrypted backup is REQUIRED for full coverage (SMS, Safari, call history).",
            ]
            return result

    # Not encrypted (or a filesystem dump): report which artifacts are present.
    for key, _label in _ARTIFACTS:
        try:
            result["artifacts"][key] = target.locate(key) is not None
        except Exception:  # noqa: BLE001
            result["artifacts"][key] = False
    if isinstance(target, BackupTarget):
        try:
            result["profiles"] = len(target.profiles())
        except Exception:  # noqa: BLE001
            result["profiles"] = None
    else:
        result["artifacts"]["shutdownlog"] = target.locate("shutdownlog") is not None
        result["artifacts"]["netusage"] = target.locate("netusage") is not None

    present = sum(1 for v in result["artifacts"].values() if v)
    result["ready"] = present > 0
    if result["ready"]:
        result["next_steps"] = [f"Ready to scan:  iscout scan {path} -v"]
    else:
        result["next_steps"] = [
            "No known artifacts were found. If this is an UNENCRYPTED backup it will be "
            "missing SMS/Safari history — create an ENCRYPTED backup for meaningful screening.",
        ]
    return result


# --- decryption (optional, via MVT) -------------------------------------------

def find_decryptor() -> Optional[str]:
    """Return the path to `mvt-ios` if it is installed, else None."""
    return shutil.which("mvt-ios")


def decrypt_backup(
    src: str, dest: str, password: Optional[str] = None
) -> Tuple[bool, str]:
    """Decrypt an encrypted backup into *dest* using `mvt-ios decrypt-backup`.

    When *password* is None, mvt is run attached to the terminal so it prompts
    for the password itself — iScout never handles the secret. Returns
    ``(ok, message)``.
    """
    mvt = find_decryptor()
    if not mvt:
        return (
            False,
            "MVT is not installed. Run `pip install mvt`, then retry — or decrypt "
            "manually with `mvt-ios decrypt-backup -d <dest> <backup>`.",
        )
    os.makedirs(dest, exist_ok=True)
    cmd = [mvt, "decrypt-backup", "-d", dest]
    if password:
        cmd += ["-p", password]
    cmd.append(src)
    try:
        # Inherit stdio so mvt can prompt for the password interactively.
        proc = subprocess.run(cmd)
    except OSError as exc:
        return False, f"Failed to run mvt-ios: {exc}"
    if proc.returncode != 0:
        return False, f"mvt-ios decrypt-backup exited with code {proc.returncode}."
    if not BackupTarget.looks_like_backup(dest):
        return False, f"Decryption did not produce a readable backup in {dest}."
    return True, f"Decrypted backup written to {dest}."

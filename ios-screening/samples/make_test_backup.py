#!/usr/bin/env python3
"""Generate a synthetic (unencrypted) iOS backup for testing / demoing iScout.

This builds a *structurally faithful* backup: a real ``Manifest.db`` whose
``Files`` table maps domains/relativePaths to ``fileID = sha1(domain-relpath)``,
with each artifact stored on disk at ``<root>/<fileID[:2]>/<fileID>``. With
``--infected`` it seeds benign-looking artifacts with a handful of well-known
public indicators so every detection path can be exercised.

Nothing here is real spyware — the DBs contain only public IOC *strings*
(process names / domains) used purely to verify matching logic.

    python samples/make_test_backup.py ./demo-backup --infected
    iscout scan ./demo-backup -v
"""

from __future__ import annotations

import argparse
import hashlib
import os
import plistlib
import sqlite3
from datetime import datetime, timezone

MAC_OFFSET = 978307200


def _mac_now() -> float:
    # A fixed, deterministic Mac-absolute timestamp (2023-06-01T00:00:00Z).
    return datetime(2023, 6, 1, tzinfo=timezone.utc).timestamp() - MAC_OFFSET


def _unix(y=2023, mo=6, d=1) -> int:
    return int(datetime(y, mo, d, tzinfo=timezone.utc).timestamp())


def file_id(domain: str, relpath: str) -> str:
    return hashlib.sha1(f"{domain}-{relpath}".encode()).hexdigest()


def _place(root: str, domain: str, relpath: str, content: bytes) -> str:
    fid = file_id(domain, relpath)
    sub = os.path.join(root, fid[:2])
    os.makedirs(sub, exist_ok=True)
    with open(os.path.join(sub, fid), "wb") as fh:
        fh.write(content)
    return fid


def _sqlite_bytes(build) -> bytes:
    """Run *build(conn)* against a temp DB and return its raw bytes."""
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        conn = sqlite3.connect(path)
        build(conn)
        conn.commit()
        conn.close()
        with open(path, "rb") as fh:
            return fh.read()
    finally:
        os.remove(path)


def _datausage(infected: bool) -> bytes:
    def build(conn):
        conn.execute("CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, ZFIRSTTIMESTAMP REAL, ZTIMESTAMP REAL, ZPROCNAME TEXT, ZBUNDLENAME TEXT);")
        conn.execute("CREATE TABLE ZLIVEUSAGE (Z_PK INTEGER PRIMARY KEY, ZHASPROCESS INTEGER, ZTIMESTAMP REAL, ZWIFIIN REAL, ZWIFIOUT REAL, ZWWANIN REAL, ZWWANOUT REAL);")
        ts = _mac_now()
        conn.execute("INSERT INTO ZPROCESS VALUES (1,?,?,?,?)", (ts, ts, "com.apple.mobilesafari", "com.apple.mobilesafari"))
        conn.execute("INSERT INTO ZPROCESS VALUES (2,?,?,?,?)", (ts, ts, "mediaserverd", "com.apple.mediaserverd"))
        conn.execute("INSERT INTO ZLIVEUSAGE VALUES (1,1,?,100,200,50,60)", (ts,))
        conn.execute("INSERT INTO ZLIVEUSAGE VALUES (2,2,?,10,20,5,6)", (ts,))
        if infected:
            # Pegasus process name recorded with network usage.
            conn.execute("INSERT INTO ZPROCESS VALUES (3,?,?,?,?)", (ts, ts, "bh", None))
            conn.execute("INSERT INTO ZLIVEUSAGE VALUES (3,3,?,0,0,900,900)", (ts,))
            # Orphaned usage row -> references a process pk that does not exist.
            conn.execute("INSERT INTO ZLIVEUSAGE VALUES (4,999,?,0,0,1234,4321)", (ts,))

    return _sqlite_bytes(build)


def _safari(infected: bool) -> bytes:
    def build(conn):
        conn.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT);")
        conn.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, redirect_source INTEGER, redirect_destination INTEGER);")
        ts = _mac_now()
        conn.execute("INSERT INTO history_items VALUES (1, 'https://www.apple.com/')")
        conn.execute("INSERT INTO history_visits VALUES (1,1,?,NULL,NULL)", (ts,))
        if infected:
            conn.execute("INSERT INTO history_items VALUES (2, 'https://free247downloads.com/xyz')")
            conn.execute("INSERT INTO history_visits VALUES (2,2,?,1,NULL)", (ts,))

    return _sqlite_bytes(build)


def _sms(infected: bool) -> bytes:
    def build(conn):
        conn.execute("CREATE TABLE handle (rowid INTEGER PRIMARY KEY, id TEXT);")
        conn.execute("CREATE TABLE message (rowid INTEGER PRIMARY KEY, text TEXT, date REAL, is_from_me INTEGER, handle_id INTEGER);")
        ts = _mac_now()
        conn.execute("INSERT INTO handle VALUES (1, '+15551234567')")
        conn.execute("INSERT INTO message VALUES (1, 'hey see you tomorrow', ?, 0, 1)", (ts,))
        if infected:
            conn.execute("INSERT INTO handle VALUES (2, '+15559999999')")
            conn.execute("INSERT INTO message VALUES (2, 'install this: http://flexispy.com/login', ?, 0, 2)", (ts,))

    return _sqlite_bytes(build)


def _tcc(infected: bool) -> bytes:
    def build(conn):
        conn.execute("CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER);")
        lm = _unix()
        conn.execute("INSERT INTO access VALUES ('kTCCServiceCamera','com.burbn.instagram',0,2,2,?)", (lm,))
        if infected:
            conn.execute("INSERT INTO access VALUES ('kTCCServiceMicrophone','com.unknown.monitor',0,2,6,?)", (lm,))
            conn.execute("INSERT INTO access VALUES ('kTCCServiceCamera','/private/var/tmp/agent',1,2,3,?)", (lm,))

    return _sqlite_bytes(build)


def _profile(infected: bool) -> bytes:
    payload = {
        "PayloadDisplayName": "Corp Config" if not infected else "Mobile Configuration",
        "PayloadIdentifier": "com.example.profile",
        "PayloadOrganization": "Example Corp" if not infected else "",
        "PayloadUUID": "11111111-2222-3333-4444-555555555555",
        "PayloadType": "Configuration",
        "InstallDate": datetime(2023, 6, 1, tzinfo=timezone.utc),
        "PayloadContent": [{"PayloadType": "com.apple.wifi.managed", "PayloadDisplayName": "Wi-Fi"}],
    }
    if infected:
        payload["PayloadContent"] = [
            {"PayloadType": "com.apple.mdm", "PayloadDisplayName": "MDM", "ServerURL": "https://mdm.unknown.example"},
            {"PayloadType": "com.apple.security.root", "PayloadDisplayName": "Root CA"},
        ]
    return plistlib.dumps(payload)


def _info_plist(infected: bool) -> bytes:
    installed = ["com.apple.mobilesafari", "com.burbn.instagram"]
    apps = {
        "com.apple.mobilesafari": {"iTunesMetadata": plistlib.dumps({"itemName": "Safari"}, fmt=plistlib.FMT_BINARY)},
        "com.burbn.instagram": {"iTunesMetadata": plistlib.dumps({"itemName": "Instagram"}, fmt=plistlib.FMT_BINARY)},
    }
    if infected:
        installed.append("com.example.syscore")
        apps["com.example.syscore"] = {
            "iTunesMetadata": plistlib.dumps(
                {"itemName": "System Core", "com.apple.iTunesStore.downloadInfo": {"purchaseDate": "2023-05-20T10:00:00Z"}},
                fmt=plistlib.FMT_BINARY,
            )
        }
    info = {
        "Device Name": "Test iPhone",
        "Product Name": "iPhone",
        "Product Type": "iPhone13,2",
        "Product Version": "16.5",
        "Build Version": "20F66",
        "Serial Number": "F2LXK1TESTED",
        "IMEI": "351234560000000",
        "Phone Number": "+1 555 123 4567",
        "Last Backup Date": datetime(2023, 6, 1, tzinfo=timezone.utc),
        "Unique Identifier": "00008030001A2B3C4D5E6F70",
        "Installed Applications": installed,
        "Applications": apps,
    }
    return plistlib.dumps(info)


def build_backup(root: str, infected: bool = True) -> str:
    os.makedirs(root, exist_ok=True)
    conf_domain = "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles"

    files = [
        ("WirelessDomain", "Library/Databases/DataUsage.sqlite", _datausage(infected)),
        ("HomeDomain", "Library/SMS/sms.db", _sms(infected)),
        ("HomeDomain", "Library/TCC/TCC.db", _tcc(infected)),
        ("HomeDomain", "Library/Safari/History.db", _safari(infected)),
        (conf_domain, "Library/ConfigurationProfiles/profile-example.stub", _profile(infected)),
    ]

    # Build Manifest.db
    manifest_path = os.path.join(root, "Manifest.db")
    if os.path.exists(manifest_path):
        os.remove(manifest_path)
    conn = sqlite3.connect(manifest_path)
    conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);")
    for domain, relpath, content in files:
        fid = _place(root, domain, relpath, content)
        conn.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (fid, domain, relpath, 1, b""))
    conn.commit()
    conn.close()

    with open(os.path.join(root, "Manifest.plist"), "wb") as fh:
        plistlib.dump({"IsEncrypted": False, "Version": "10.0", "Date": datetime(2023, 6, 1, tzinfo=timezone.utc)}, fh)
    with open(os.path.join(root, "Info.plist"), "wb") as fh:
        fh.write(_info_plist(infected))
    with open(os.path.join(root, "Status.plist"), "wb") as fh:
        plistlib.dump({"IsFullBackup": True, "SnapshotState": "finished"}, fh)
    return root


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a synthetic iOS backup for iScout testing.")
    ap.add_argument("output", help="output directory for the backup")
    ap.add_argument("--infected", action="store_true", help="seed public spyware indicators to exercise detections")
    ap.add_argument("--clean", action="store_true", help="build a benign backup (default if --infected absent)")
    args = ap.parse_args()
    infected = args.infected and not args.clean
    root = build_backup(args.output, infected=infected)
    print(f"Built {'INFECTED (demo)' if infected else 'clean'} backup at: {root}")
    print(f"Now run:  iscout scan {root} -v")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

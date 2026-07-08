"""Robustness against realistic iOS schema / layout variation."""

import hashlib
import os
import plistlib
import sqlite3
import tempfile

from iscout.backup import open_target
from iscout.engine import run_scan
from iscout.indicators import Indicators
from iscout.modules import Severity


def _fid(domain, rel):
    return hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()


def _place(root, domain, rel, content):
    fid = _fid(domain, rel)
    d = os.path.join(root, fid[:2])
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, fid), "wb") as fh:
        fh.write(content)
    return fid


def _sqlite_bytes(build):
    fd, p = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        c = sqlite3.connect(p)
        build(c)
        c.commit()
        c.close()
        with open(p, "rb") as fh:
            return fh.read()
    finally:
        os.remove(p)


def _build_variant(root):
    # DataUsage whose ZPROCESS lacks ZFIRSTTIMESTAMP/ZTIMESTAMP (older schema).
    def du(c):
        c.execute("CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, ZPROCNAME TEXT, ZBUNDLENAME TEXT)")
        c.execute("CREATE TABLE ZLIVEUSAGE (Z_PK INTEGER PRIMARY KEY, ZHASPROCESS INTEGER, ZTIMESTAMP REAL)")
        c.execute("INSERT INTO ZPROCESS VALUES (1, 'bh', NULL)")
        c.execute("INSERT INTO ZLIVEUSAGE VALUES (1, 1, 0)")

    # Safari under the PRE-iOS-13 domain (AppDomain-com.apple.mobilesafari).
    def sf(c):
        c.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT)")
        c.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, redirect_source INTEGER, redirect_destination INTEGER)")
        c.execute("INSERT INTO history_items VALUES (1, 'https://urlpush.net/x')")
        c.execute("INSERT INTO history_visits VALUES (1, 1, 0, NULL, NULL)")

    files = [
        ("WirelessDomain", "Library/Databases/DataUsage.sqlite", _sqlite_bytes(du)),
        ("AppDomain-com.apple.mobilesafari", "Library/Safari/History.db", _sqlite_bytes(sf)),
    ]
    os.makedirs(root, exist_ok=True)
    conn = sqlite3.connect(os.path.join(root, "Manifest.db"))
    conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    for dom, rel, content in files:
        fid = _place(root, dom, rel, content)
        conn.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (fid, dom, rel, 1, b""))
    conn.commit()
    conn.close()
    with open(os.path.join(root, "Manifest.plist"), "wb") as fh:
        plistlib.dump({"IsEncrypted": False}, fh)
    with open(os.path.join(root, "Info.plist"), "wb") as fh:
        plistlib.dump({"Product Version": "12.4", "Product Type": "iPhone9,3"}, fh)
    return root


def _scan(root):
    ind = Indicators()
    ind.load_builtin()
    return run_scan(open_target(root), ind, "2024-01-01T00:00:00Z")


def test_datausage_missing_timestamp_columns(tmp_path):
    res = _scan(_build_variant(str(tmp_path / "b")))
    assert any(
        f.matched_value == "bh" and f.severity == Severity.DETECTED for f in res.findings
    ), [f.title for f in res.findings]


def test_pre_ios13_safari_domain_resolves(tmp_path):
    res = _scan(_build_variant(str(tmp_path / "b2")))
    assert any(
        (f.matched_value == "urlpush.net") for f in res.findings
    ), [f.title for f in res.findings]

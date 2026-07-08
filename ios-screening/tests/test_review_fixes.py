"""Regression tests for issues found in the adversarial code review."""

import hashlib
import json
import os
import plistlib
import sqlite3
from datetime import datetime, timezone

import pytest

from iscout.backup import BackupTarget, FilesystemTarget, open_sqlite_ro
from iscout.indicators import Indicator, Indicators
from iscout.modules import Severity
from iscout.modules.base import severity_for_indicator
from iscout.modules.filescan import FileScanModule
from iscout.report import ScanResult, write_json
from iscout.modules.base import Finding
from iscout.utils import extract_urls_from_blob
from make_test_backup import build_backup


# --- Fix: multi-hash (md5/sha1/sha256) matching --------------------------------

def test_filescan_matches_md5_and_sha1(tmp_path):
    root = tmp_path / "fs"
    d = root / "private" / "var" / "tmp"
    d.mkdir(parents=True)
    payload = b"malicious-sample-bytes"
    (d / "agent").write_bytes(payload)
    md5 = hashlib.md5(payload).hexdigest()
    sha1 = hashlib.sha1(payload).hexdigest()

    for algo, digest in (("md5", md5), ("sha1", sha1)):
        ind = Indicators()
        ind.add(Indicator(type="hash", value=digest, confidence="high", category="mercenary", malware_family="Test"))
        mod = FileScanModule(FilesystemTarget(str(root)), ind, {})
        mod.run()
        assert any(f.severity == Severity.DETECTED for f in mod.findings), f"{algo} not matched"


# --- Fix: attributedBody URL extraction ---------------------------------------

def test_extract_urls_from_blob():
    blob = b"\x01\x02streamtyped stuff http://flexispy.com/login more bytes\x00"
    urls = extract_urls_from_blob(blob)
    assert any("flexispy.com" in u for u in urls)
    assert extract_urls_from_blob(None) == []


def test_sms_reads_attributedbody(tmp_path):
    root = tmp_path / "fs"
    d = root / "private" / "var" / "mobile" / "Library" / "SMS"
    d.mkdir(parents=True)
    conn = sqlite3.connect(str(d / "sms.db"))
    conn.execute("CREATE TABLE handle (rowid INTEGER PRIMARY KEY, id TEXT)")
    conn.execute(
        "CREATE TABLE message (rowid INTEGER PRIMARY KEY, text TEXT, attributedBody BLOB, "
        "date REAL, is_from_me INTEGER, handle_id INTEGER)"
    )
    conn.execute(
        "INSERT INTO message VALUES (1, NULL, ?, 0, 0, NULL)",
        (b"streamtyped body http://free247downloads.com/x end",),
    )
    conn.commit()
    conn.close()

    from iscout.modules.sms import SMSModule

    ind = Indicators()
    ind.load_builtin()
    mod = SMSModule(FilesystemTarget(str(root)), ind, {})
    mod.run()
    assert any(f.severity == Severity.DETECTED for f in mod.findings)


# --- Fix: malformed Manifest.plist must not crash -----------------------------

def test_malformed_manifest_plist_does_not_crash(tmp_path):
    root = build_backup(str(tmp_path / "b"), infected=False)
    (tmp_path / "b" / "Manifest.plist").write_bytes(b"not a real plist \x00\xff")
    t = BackupTarget(root)
    assert t.manifest_plist() == {}
    # is_encrypted must not raise; falls back to probing Manifest.db (readable -> False)
    assert t.is_encrypted() is False


# --- Fix: fileID path-traversal is rejected -----------------------------------

def test_malicious_fileid_is_skipped(tmp_path):
    root = build_backup(str(tmp_path / "b"), infected=False)
    conn = sqlite3.connect(os.path.join(root, "Manifest.db"))
    conn.execute(
        "INSERT INTO Files VALUES (?,?,?,?,?)",
        ("../../../../../../etc/passwd", "HomeDomain", "Library/Evil", 1, b""),
    )
    conn.commit()
    conn.close()
    t = BackupTarget(root)
    paths = [dev for dev, _local in t.walk_files()]
    assert not any("etc/passwd" in p for p in paths)
    # legit entries survive
    assert t.locate("datausage") is not None


# --- Fix: daemon-colliding Pegasus names are WARNING, not DETECTED ------------

def test_daemon_collision_names_are_warning():
    ind = Indicators()
    ind.load_builtin()
    for name in ("pcsd", "gatekeeperd", "ckkeyrollfd", "fmld"):
        hit = ind.match_process(name)
        assert hit is not None
        assert severity_for_indicator(hit) == Severity.WARNING, name
    # Clearly-malicious fabricated names stay DETECTED
    assert severity_for_indicator(ind.match_process("bh")) == Severity.DETECTED
    assert severity_for_indicator(ind.match_process("roleaboutd")) == Severity.DETECTED


# --- Fix: STIX2 confidence per type -------------------------------------------

def test_stix2_loose_types_default_medium(tmp_path):
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "name": "X", "pattern": "[domain-name:value = 'd.example']"},
            {"type": "indicator", "name": "Y", "pattern": "[url:value = 'http://u.example/p']"},
        ],
    }
    p = tmp_path / "f.stix2"
    p.write_text(json.dumps(bundle))
    ind = Indicators()
    ind.load_path(str(p))
    assert ind.match_domain("d.example").confidence == "high"      # precise type
    # url-type -> medium -> WARNING
    url_ind = [i for i in ind.all if i.type == "url"][0]
    assert url_ind.confidence == "medium"
    assert severity_for_indicator(url_ind) == Severity.WARNING


# --- Fix: anchored URL matching ----------------------------------------------

def test_match_url_is_anchored():
    ind = Indicators()
    ind.add(Indicator(type="url", value="http://evil.example/path", confidence="medium", category="mercenary"))
    assert ind.match_url("http://evil.example/path/deep") is not None
    assert ind.match_url("http://evil.example/other") is None          # path prefix required
    assert ind.match_url("http://safe.example/?x=http://evil.example/path") is None  # host must match


# --- Fix: path segment-boundary matching --------------------------------------

def test_match_path_segment_boundary():
    ind = Indicators()
    ind.add(Indicator(type="file_path", value="/var/jb", confidence="high", category="jailbreak"))
    assert ind.match_path("/private/var/jb/tweak.dylib") is not None
    assert ind.match_path("/private/var/jbGameCache/x") is None


# --- Fix: JSON report is safe with datetime/bytes evidence + carries safety ----

def test_json_report_serialises_and_frames(tmp_path):
    res = ScanResult(target_path="x", target_kind="backup", scanned_at="2024-01-01T00:00:00Z")
    res.findings.append(
        Finding(
            module="configuration_profiles",
            severity=Severity.WARNING,
            title="t",
            evidence={"installed": datetime(2023, 6, 1, tzinfo=timezone.utc), "blob": b"\x00\x01"},
        )
    )
    out = tmp_path / "r.json"
    write_json(res, str(out))  # must not raise
    data = json.loads(out.read_text())
    assert "safety" in data and any("stalkerware" in s["headline"].lower() for s in data["safety"])
    assert "resources" in data and data["resources"]
    ev = data["findings"][0]["evidence"]
    assert "2023-06-01" in ev["installed"]
    assert ev["blob"].startswith("base64:")


# --- Fix: '%' in path opens correctly -----------------------------------------

def test_open_sqlite_ro_percent_in_path(tmp_path):
    d = tmp_path / "back%41up"
    d.mkdir()
    dbp = d / "x.sqlite"
    conn = sqlite3.connect(str(dbp))
    conn.execute("CREATE TABLE t (a)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()
    ro = open_sqlite_ro(str(dbp))
    assert ro.execute("SELECT a FROM t").fetchone()[0] == 1
    ro.close()


# --- Fix: symlink escaping the dump is skipped --------------------------------

@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_symlink_escape_skipped(tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("SECRET")
    root = tmp_path / "fs"
    d = root / "private" / "var" / "mobile" / "Library" / "SMS"
    d.mkdir(parents=True)
    link = d / "sms.db"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlink here")
    t = FilesystemTarget(str(root))
    assert t.locate("sms") is None  # escaping symlink not followed
    paths = [dev for dev, _l in t.walk_files()]
    assert not any("sms.db" in p for p in paths)

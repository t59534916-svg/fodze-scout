import json
import os
import plistlib

import pytest

from iscout.backup import BackupTarget, EncryptedBackupError, open_target
from iscout.engine import run_scan
from iscout.indicators import Indicators
from iscout.modules import Severity
from iscout.report import write_html, write_json
from make_test_backup import build_backup


@pytest.fixture
def indicators():
    ind = Indicators()
    ind.load_builtin()
    return ind


def _scan(root, indicators):
    target = open_target(root)
    return run_scan(target, indicators, scanned_at="2024-01-01T00:00:00Z")


def test_infected_backup_detects_expected(tmp_path, indicators):
    root = build_backup(str(tmp_path / "inf"), infected=True)
    res = _scan(root, indicators)
    titles = " | ".join(f.title for f in res.findings)
    counts = res.counts()
    assert counts["DETECTED"] >= 3, titles
    assert counts["WARNING"] >= 3, titles
    # Specific detections
    fams = {f.malware_family for f in res.by_severity(Severity.DETECTED)}
    assert "NSO Pegasus" in fams
    assert any("flexispy" in (f.matched_value or "") for f in res.findings)
    # Orphaned-usage heuristic fired
    assert any("deleted process" in f.title for f in res.findings)


def test_clean_backup_has_no_alerts(tmp_path, indicators):
    root = build_backup(str(tmp_path / "clean"), infected=False)
    res = _scan(root, indicators)
    counts = res.counts()
    assert counts["DETECTED"] == 0, [f.title for f in res.by_severity(Severity.DETECTED)]
    assert counts["WARNING"] == 0, [f.title for f in res.by_severity(Severity.WARNING)]
    assert counts["INFO"] > 0


def test_backup_parsing(tmp_path):
    root = build_backup(str(tmp_path / "b"), infected=True)
    t = BackupTarget(root)
    assert not t.is_encrypted()
    info = t.device_info()
    assert info["Product Type"] == "iPhone13,2"
    installed, apps = t.installed_apps()
    assert "com.example.syscore" in installed
    assert apps["com.example.syscore"].get("name") == "System Core"
    # artifact resolution via Manifest.db
    assert t.locate("datausage") is not None
    assert t.locate("sms") is not None
    assert t.locate("safari") is not None
    profiles = t.profiles()
    assert len(profiles) == 1


def test_encrypted_backup_flagged(tmp_path):
    root = tmp_path / "enc"
    root.mkdir()
    plistlib.dump({"IsEncrypted": True}, open(root / "Manifest.plist", "wb"))
    (root / "Manifest.db").write_bytes(b"garbage")
    t = BackupTarget(str(root))
    assert t.is_encrypted() is True
    with pytest.raises(EncryptedBackupError):
        run_scan(t, Indicators(), scanned_at="2024-01-01T00:00:00Z")


def test_reports_written(tmp_path, indicators):
    root = build_backup(str(tmp_path / "r"), infected=True)
    res = _scan(root, indicators)
    j = tmp_path / "r.json"
    h = tmp_path / "r.html"
    write_json(res, str(j))
    write_html(res, str(h))
    data = json.loads(j.read_text())
    assert data["tool"] == "iScout"
    assert data["summary"]["DETECTED"] >= 3
    assert "disclaimer" in data
    html = h.read_text()
    assert "How to read this report" in html
    assert "DETECTED" in html


def test_auto_detect_and_type_override(tmp_path):
    root = build_backup(str(tmp_path / "a"), infected=False)
    assert open_target(root).kind == "backup"
    assert open_target(root, kind="backup").kind == "backup"

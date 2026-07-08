"""Tests for the real-device preparation layer (discover / diagnose / decrypt)."""

import os
import plistlib
import stat

import pytest

from iscout import prep
from make_test_backup import build_backup


def _encrypted_stub(path):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "Manifest.plist"), "wb") as fh:
        plistlib.dump({"IsEncrypted": True}, fh)
    with open(os.path.join(path, "Manifest.db"), "wb") as fh:
        fh.write(b"garbage-not-sqlite")
    return path


def test_discover_backups(tmp_path):
    root = tmp_path / "Backup"
    root.mkdir()
    build_backup(str(root / "00008030-CLEAN"), infected=False)
    _encrypted_stub(str(root / "00008030-ENC"))
    (root / "not-a-backup").mkdir()

    found = prep.discover_backups([str(root)])
    by_udid = {b["udid"]: b for b in found}
    assert "00008030-CLEAN" in by_udid
    assert "00008030-ENC" in by_udid
    assert "not-a-backup" not in by_udid
    assert by_udid["00008030-CLEAN"]["encrypted"] is False
    assert by_udid["00008030-CLEAN"]["product_version"] == "16.5"
    assert by_udid["00008030-ENC"]["encrypted"] is True


def test_diagnose_unencrypted_ready(tmp_path):
    root = build_backup(str(tmp_path / "b"), infected=True)
    d = prep.diagnose(root)
    assert d["kind"] == "backup"
    assert d["encrypted"] is False
    assert d["ready"] is True
    assert d["artifacts"]["datausage"] and d["artifacts"]["sms"] and d["artifacts"]["safari"]
    assert d["profiles"] == 1


def test_diagnose_encrypted_not_ready(tmp_path):
    root = _encrypted_stub(str(tmp_path / "enc"))
    d = prep.diagnose(root)
    assert d["encrypted"] is True
    assert d["ready"] is False
    assert any("decrypt" in s.lower() for s in d["next_steps"])


def test_diagnose_bad_path(tmp_path):
    d = prep.diagnose(str(tmp_path / "does-not-exist"))
    assert d["error"]
    assert d["ready"] is False


def test_decrypt_backup_without_mvt(tmp_path, monkeypatch):
    monkeypatch.setattr(prep, "find_decryptor", lambda: None)
    ok, msg = prep.decrypt_backup(str(tmp_path / "src"), str(tmp_path / "dst"))
    assert ok is False
    assert "mvt" in msg.lower()


@pytest.mark.skipif(os.name != "posix", reason="stub executable needs POSIX")
def test_decrypt_backup_with_stub(tmp_path, monkeypatch):
    # A stand-in mvt-ios that emits a minimal valid backup into -d <dest>.
    stub = tmp_path / "mvt-ios"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, os, sqlite3, plistlib\n"
        "a = sys.argv[1:]\n"
        "dest = a[a.index('-d')+1]\n"
        "os.makedirs(dest, exist_ok=True)\n"
        "c = sqlite3.connect(os.path.join(dest,'Manifest.db'))\n"
        "c.execute('CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)')\n"
        "c.commit(); c.close()\n"
        "plistlib.dump({'IsEncrypted': False}, open(os.path.join(dest,'Manifest.plist'),'wb'))\n"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setattr(prep, "find_decryptor", lambda: str(stub))

    ok, msg = prep.decrypt_backup(str(tmp_path / "src"), str(tmp_path / "out"), password="x")
    assert ok is True, msg
    from iscout.backup import BackupTarget

    assert BackupTarget.looks_like_backup(str(tmp_path / "out"))

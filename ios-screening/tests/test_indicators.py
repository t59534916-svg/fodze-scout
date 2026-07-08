import json

from iscout.indicators import CATEGORY_JAILBREAK, Indicators


def test_builtin_loads_and_indexes():
    ind = Indicators()
    n = ind.load_builtin()
    assert n > 40
    # Known high-confidence values from the curated feeds.
    assert ind.match_process("bh") is not None
    assert ind.match_process("BH") is not None  # case-insensitive
    assert ind.match_domain("free247downloads.com") is not None
    assert ind.match_domain("sub.free247downloads.com") is not None  # suffix match
    assert ind.match_domain("notevil.example") is None


def test_jailbreak_category_and_paths():
    ind = Indicators()
    ind.load_builtin()
    hit = ind.match_path("/private/var/mobile/Applications/Cydia.app/Cydia")
    assert hit is not None
    assert hit.category == CATEGORY_JAILBREAK


def test_app_name_lead():
    ind = Indicators()
    ind.load_builtin()
    hit = ind.match_app_name("System Core")
    assert hit is not None
    assert hit.confidence == "low"


def test_no_bundle_id_indicators_shipped():
    # Research: no verified public iOS bundle IDs exist -> app_id index empty.
    ind = Indicators()
    ind.load_builtin()
    assert ind.app_ids == {}


def test_stix2_pattern_parsing(tmp_path):
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "name": "X", "pattern": "[domain-name:value = 'a.example']"},
            {"type": "indicator", "name": "Y", "pattern": "[process:name = 'weirdd']"},
            {"type": "indicator", "name": "Z", "pattern": "[file:hashes.'SHA-256' = 'deadbeef']"},
        ],
    }
    p = tmp_path / "f.stix2"
    p.write_text(json.dumps(bundle))
    ind = Indicators()
    ind.load_path(str(p))
    assert ind.match_domain("a.example") is not None
    assert ind.match_process("weirdd") is not None
    assert ind.match_hash("DEADBEEF") is not None


def test_confidence_to_severity_policy():
    from iscout.indicators import Indicator
    from iscout.modules.base import Severity, severity_for_indicator

    high_merc = Indicator(type="domain", value="x", confidence="high", category="mercenary")
    low_merc = Indicator(type="domain", value="y", confidence="low", category="mercenary")
    jb = Indicator(type="file_path", value="/Applications/Cydia.app", confidence="high", category="jailbreak")
    assert severity_for_indicator(high_merc) == Severity.DETECTED
    assert severity_for_indicator(low_merc) == Severity.WARNING
    assert severity_for_indicator(jb) == Severity.WARNING  # jailbreak never DETECTED

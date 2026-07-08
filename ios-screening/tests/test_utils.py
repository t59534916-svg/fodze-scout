from datetime import datetime, timezone

from iscout.utils import (
    MAC_EPOCH_OFFSET,
    convert_mactime,
    convert_unixtime,
    defang,
    extract_urls,
    parent_domains,
    redact_serial,
    url_host,
)


def test_mac_vs_unix_epoch_offset():
    # 2023-06-01T00:00:00Z as a Unix timestamp
    unix = int(datetime(2023, 6, 1, tzinfo=timezone.utc).timestamp())
    mac = unix - MAC_EPOCH_OFFSET
    assert convert_mactime(mac) == "2023-06-01T00:00:00Z"
    assert convert_unixtime(unix) == "2023-06-01T00:00:00Z"
    # Same numeric value interpreted in the two epochs must differ by 31 years.
    assert convert_mactime(unix) != convert_unixtime(unix)


def test_convert_handles_none_and_zero():
    assert convert_mactime(None) is None
    assert convert_mactime(0) is None
    assert convert_unixtime("") is None


def test_nanosecond_normalisation():
    unix_ns = int(datetime(2023, 6, 1, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    assert convert_unixtime(unix_ns) == "2023-06-01T00:00:00Z"


def test_extract_urls_and_host():
    urls = extract_urls("go to http://Evil.example/a?b=1 and https://ok.test now")
    assert "http://Evil.example/a?b=1" in urls
    assert url_host("http://Evil.example/a?b=1") == "evil.example"
    assert url_host("user:pw@host.tld:8443/p") == "host.tld"


def test_defang():
    assert defang("evil[.]com") == "evil.com"
    assert defang("hxxps://bad[.]net") == "https://bad.net"


def test_parent_domains_includes_self_and_parents():
    doms = set(parent_domains("a.b.example.com"))
    assert "a.b.example.com" in doms
    assert "example.com" in doms
    assert "com" not in doms  # never strips down to the TLD alone


def test_redact_serial():
    assert redact_serial("F2LXK1TESTED") == "********STED"
    assert redact_serial("ab") == "**"

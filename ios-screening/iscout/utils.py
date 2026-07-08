"""Small, dependency-free helpers: timestamp conversion, URL/host parsing, defang."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, List, Optional

# Seconds between the Unix epoch (1970-01-01) and the Cocoa/Mac "absolute time"
# epoch (2001-01-01). DataUsage, netusage, Safari History and sms.db store Mac
# absolute time; add this offset to get a Unix timestamp. TCC.db and shutdown.log
# already store Unix time — do NOT add it there. Getting this wrong shifts every
# date by ~31 years.
MAC_EPOCH_OFFSET = 978307200


def convert_mactime(value: Optional[float]) -> Optional[str]:
    """Cocoa/Mac absolute time (seconds since 2001-01-01) -> ISO-8601 UTC string."""
    return _to_iso(value, offset=MAC_EPOCH_OFFSET)


def convert_unixtime(value: Optional[float]) -> Optional[str]:
    """Unix time (seconds since 1970-01-01) -> ISO-8601 UTC string."""
    return _to_iso(value, offset=0)


def _to_iso(value: Optional[float], offset: int) -> Optional[str]:
    if value in (None, 0, ""):
        return None
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    # Core Data occasionally stores nanoseconds; normalise obvious ns values.
    if abs(ts) > 1e12:
        ts = ts / 1e9
    try:
        dt = datetime.fromtimestamp(ts + offset, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# A deliberately permissive URL matcher for message/history bodies.
_URL_RE = re.compile(r"""(?xi)\b((?:https?://|www\.)[^\s<>"'\)\]}]+)""")


def extract_urls(text: Optional[str]) -> List[str]:
    """Return the list of URL-like substrings found in *text*."""
    if not text:
        return []
    out = []
    for m in _URL_RE.finditer(text):
        url = m.group(1).rstrip(".,;:!?")
        out.append(url)
    return out


def extract_urls_from_blob(blob) -> List[str]:
    """Extract URL-like substrings from a raw binary blob (e.g. ``attributedBody``).

    Modern iOS often stores the message body only in the ``attributedBody``
    NSKeyedArchiver/typedstream blob with ``text`` NULL. Fully decoding that
    format is heavy; URLs appear as plaintext runs inside it, so a lenient
    decode + the normal URL regex recovers them reliably.
    """
    if not blob:
        return []
    if isinstance(blob, (bytes, bytearray)):
        text = bytes(blob).decode("utf-8", "ignore")
    else:
        text = str(blob)
    return extract_urls(text)


def url_host(url: str) -> Optional[str]:
    """Extract the lower-cased host (no port) from a URL or bare host string."""
    if not url:
        return None
    s = url.strip()
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", s)  # strip scheme
    s = s.split("/", 1)[0]  # strip path
    s = s.split("?", 1)[0]
    s = s.split("@")[-1]  # strip userinfo
    s = s.split(":", 1)[0]  # strip port
    s = s.strip(".")
    return s.lower() or None


def defang(value: str) -> str:
    """Turn a defanged indicator (``evil[.]com``, ``hxxp``) back into a real value."""
    if not value:
        return value
    return (
        value.replace("[.]", ".")
        .replace("[dot]", ".")
        .replace("(.)", ".")
        .replace("hxxps", "https")
        .replace("hxxp", "http")
        .replace("[:]", ":")
        .strip()
    )


def parent_domains(host: str) -> Iterable[str]:
    """Yield *host* and each of its parent domains (for suffix matching)."""
    host = (host or "").strip(".").lower()
    if not host:
        return
    parts = host.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])
    yield host  # ensure the full host is included even for 2-label hosts


def redact_serial(value: Optional[str], keep: int = 4) -> Optional[str]:
    """Mask all but the last *keep* characters of an identifier."""
    if not value:
        return value
    s = str(value)
    if len(s) <= keep:
        return "*" * len(s)
    return "*" * (len(s) - keep) + s[-keep:]

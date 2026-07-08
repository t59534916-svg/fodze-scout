# iScout indicator feeds

This directory ships a **small, deliberately conservative, fully source-attributed
starter set** of indicators of compromise (IOCs). It is **not** a substitute for
the full, regularly-updated public feeds. For any real investigation, load those
in as well (see *External feeds* below).

## Files

| File | Category | What it contains | Primary source |
|------|----------|------------------|----------------|
| `pegasus.json` | mercenary | NSO Pegasus process names, infra domains, staging dir | Amnesty International Security Lab (2021) |
| `triangulation.json` | mercenary | Operation Triangulation C2 domains, `BackupAgent` signal | Kaspersky GReAT (2023) |
| `paragon.json` | mercenary | Paragon Graphite server IP | Citizen Lab (2025) |
| `stalkerware.json` | stalkerware | Consumer-spyware exfil domains + weak app-name leads | Echap stalkerware-indicators; TechCrunch; Certo |
| `jailbreak.json` | jailbreak | Jailbreak filesystem artifacts (FS dumps only) | TheAppleWiki; MVT |
| `profiles_highrisk.json` | profile_rules | High-risk configuration-profile payload types | Apple; MVT |

Every indicator carries a `confidence` (`high`/`medium`/`low`) and a `source`.
A **high**-confidence mercenary/stalkerware match is reported as **DETECTED**;
everything weaker (and all jailbreak matches) is a **WARNING**.

## Confidence & caveats

- **No verified public iOS bundle IDs** exist for consumer stalkerware, so the
  `app:id` indicator type is supported but intentionally empty here.
- Most stalkerware domains are **shared/Android-centric exfil infrastructure**;
  short or obscure hosts are marked `low` and may be stale or sinkholed.
- Pegasus **rotates process names** — absence of these names does not rule out
  infection.
- A match is a **lead, not proof**. Absence of matches does not prove a clean
  device.

## External feeds (recommended)

iScout reads the same STIX2 format Amnesty International's MVT distributes.
Pull the full public feeds and load them:

```bash
# Option A: use MVT to download the official indicator bundles
pip install mvt
mvt-ios download-iocs          # fetches pegasus.stix2, cytrox.stix2 (Predator), etc.

# then point iScout at them
iscout scan ./backup --iocs ~/.local/share/mvt/indicators/
# or
export ISCOUT_STIX2="/path/to/pegasus.stix2:/path/to/cytrox.stix2"
iscout scan ./backup
```

Supported STIX2 pattern types: `domain-name:value`, `url:value`, `process:name`,
`app:id`, `configuration-profile:id`, `email-addr:value`, `file:name`,
`file:path`, `ipv4-addr:value`, `file:hashes.{md5,sha-1,sha-256}`.

## Adding your own indicators

Create a JSON file in the iScout curated format:

```json
{
  "feed": "my-feed",
  "category": "mercenary",
  "source": "where these came from",
  "indicators": [
    {"type": "domain", "value": "evil.example", "confidence": "high",
     "malware_family": "Example", "description": "why it's flagged"}
  ]
}
```

and load it with `--iocs my-feed.json`, or drop it in this directory to make it
built-in.

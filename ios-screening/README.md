# iScout — iPhone Spyware / Stalkerware Screening

A forensic **screening tool for Apple iPhones/iPads** that surfaces indicators of
malware, mercenary spyware (Pegasus, Predator, Graphite, Operation Triangulation),
consumer **stalkerware**, and covert monitoring (rogue MDM/configuration profiles,
jailbreak-installed agents).

It is modelled on the methodology of Amnesty International's
[Mobile Verification Toolkit (MVT)](https://github.com/mvt-project/mvt) and
Kaspersky's [iShutdown](https://securelist.com/shutdownlog-lightweight-ios-malware-detection-method/111337/) /
[triangle_check](https://github.com/KasperskyLab/triangle_check) research, and reads
the same **STIX2 indicator feeds** that MVT distributes.

> **Why not an app that runs on the phone?** iOS sandboxes every app, so no App
> Store app can scan other apps for spyware. The effective, professional approach
> is **offline forensic analysis** of a backup or filesystem dump — which is what
> iScout does.

---

## ⚠️ Read this first — how to interpret results

- **A finding is a *lead*, not proof.** iScout flags artifacts that *warrant
  further investigation*. On its own it can neither confirm nor rule out an
  infection.
- **No findings does *not* mean the device is clean.** Public indicators are
  incomplete and retrospective.
- **Safety first if you suspect stalkerware.** If someone with physical or
  account access may be monitoring you, *removing* the spyware can **alert them
  and escalate danger**, and deleting it **destroys evidence**. Plan on a
  **separate, safe device** with a trained advocate before acting.
- **Consent required.** Only scan a device you own or are expressly authorised to
  examine.

**Help & safety planning:**
[Coalition Against Stalkerware](https://stopstalkerware.org) ·
[Access Now Digital Security Helpline](https://www.accessnow.org/help/) ·
[Amnesty Security Lab](https://securitylab.amnesty.org) ·
[NNEDV Safety Net](https://www.techsafety.org)

---

## Install

No third-party dependencies are required — the engine uses only the Python
standard library (Python ≥ 3.9).

```bash
cd ios-screening
pip install -e .          # provides the `iscout` command
# or run without installing:
python -m iscout --help
```

## Quick start

### 1. Make a backup of the iPhone

On a computer, create an **encrypted** local backup (Finder on macOS, or Apple
Devices / iTunes on Windows). *Encrypted* is important — it includes SMS, Safari
history and call data that unencrypted backups omit.

### 2. Decrypt it

iScout reads a **decrypted** backup. Decrypt with MVT:

```bash
pip install mvt
mvt-ios decrypt-backup -p '<backup password>' -d ./decrypted "<path to backup>"
```

(If you point iScout at an encrypted backup it stops and tells you this.)

### 3. Load the full public indicators (recommended)

```bash
mvt-ios download-iocs          # fetches pegasus.stix2, cytrox.stix2 (Predator), …
export ISCOUT_STIX2="$HOME/.local/share/mvt/indicators"   # or pass --iocs
```

### 4. Scan

```bash
iscout scan ./decrypted -v
iscout scan ./decrypted --html report.html --json report.json
iscout scan ./fsdump --type fs          # jailbroken full-filesystem dump / sysdiagnose
```

## What it checks

| Module | Looks at | Detects |
|--------|----------|---------|
| `device_info` | `Info.plist` | Model / iOS version / backup metadata (context) |
| `applications` | Installed apps | Known spyware bundle IDs; stalkerware display-name leads |
| `configuration_profiles` | Config profiles | Rogue **MDM**, root-CA (HTTPS MITM), VPN, web-filter payloads |
| `network_usage` | `DataUsage.sqlite` / `netusage.sqlite` | Spyware process/bundle names; **orphaned-usage** Pegasus heuristic |
| `safari_history` | `History.db` | Visits/redirect chains to malicious domains |
| `sms` | `sms.db` | Malicious links in SMS/iMessage |
| `tcc` | `TCC.db` | Camera/mic access granted by MDM policy or to a raw executable |
| `filescan` | All files | Path/name/hash IOC matches; **jailbreak** artifacts |
| `shutdownlog` | `shutdown.log` *(FS/sysdiagnose)* | "Sticky process" reboot-delay heuristic (Kaspersky iShutdown) |

Severities: **DETECTED** (a specific high-confidence IOC matched) ·
**WARNING** (a heuristic or weaker/combined signal) · **INFO** (inventory/context).

## Indicators

A small, **fully source-attributed starter set** ships in
[`iscout/data/indicators/`](iscout/data/indicators/) (Pegasus, Operation
Triangulation, Paragon, consumer stalkerware, jailbreak artifacts, high-risk
profile payload types). Every indicator carries a `confidence` and a `source`.

It is **not** a substitute for the full public feeds — load those with `--iocs`
or `ISCOUT_STIX2`/`MVT_STIX2`. See
[`iscout/data/indicators/README.md`](iscout/data/indicators/README.md).

```bash
iscout list-iocs        # what's loaded, by feed and type
iscout list-modules     # available detection modules
```

## Try it without a real device

```bash
python samples/make_test_backup.py ./demo-backup --infected
iscout scan ./demo-backup -v
```

`make_test_backup.py` builds a structurally faithful synthetic backup and (with
`--infected`) seeds public IOC *strings* so every detection path can be
exercised. Nothing there is real malware.

## Develop / test

```bash
pip install pytest
PYTHONPATH=. python -m pytest -q
```

## Scope & limits

- Consumer stalkerware on iPhone usually works via **stolen iCloud credentials
  with no app on the device**, or on a **jailbroken** device. For the
  credentials case, also check on the phone itself: *Settings → [your name] →
  Devices* (unknown sessions), whether iCloud Backup was enabled without your
  knowledge, and *Settings → General → VPN & Device Management* (unknown
  profiles). iScout complements — it does not replace — those checks.
- No verified public **iOS bundle IDs** exist for consumer stalkerware, so that
  indicator type is supported but intentionally empty.
- iScout does not (yet) decrypt backups itself — decrypt with MVT first.
- This is a **triage funnel into human review**, not a standalone oracle.

## License

MIT. Defensive security / victim-protection use only.

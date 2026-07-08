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

## Scan a real iPhone — step by step

### 1. Make an encrypted backup

Connect the iPhone to a computer and create an **encrypted** local backup:

- **macOS:** Finder → select the iPhone → *Back up all the data…* → tick
  **Encrypt local backup**, set a password.
- **Windows:** the *Apple Devices* app (or iTunes) → **Encrypt local backup**.

*Encrypted* matters — it includes SMS, Safari history and call data that
unencrypted backups omit. Remember the password.

### 2. Find the backup

```bash
iscout list-backups
```

This lists every backup in the standard locations with device name, iOS version,
date and whether it's encrypted — no need to hunt for the cryptic UDID folder.
(Point at a custom location with `--root DIR`.)

### 3. Check it's ready

```bash
iscout doctor "<path from step 2>"
```

Tells you the input type, whether it's encrypted, which artifacts are present,
and the exact next command.

### 4. (Recommended) load the full public indicators

```bash
pip install mvt
mvt-ios download-iocs          # fetches pegasus.stix2, cytrox.stix2 (Predator), …
export ISCOUT_STIX2="$HOME/.local/share/mvt/indicators"   # or pass --iocs
```

### 5. Scan

```bash
# Encrypted backup — decrypt (mvt prompts for the password) and scan in one step:
iscout scan "<backup path>" --decrypt --work ./decrypted --html report.html

# Already-decrypted backup, or an unencrypted one:
iscout scan ./decrypted -v --html report.html --json report.json

# Jailbroken full-filesystem dump / sysdiagnose:
iscout scan ./fsdump --type fs
```

With `--decrypt`, iScout runs `mvt-ios decrypt-backup` for you and never handles
the password itself (mvt prompts). Prefer that over passing the password on the
command line. To automate, put the password in an env var and use
`--password-env VAR`.

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
iscout list-backups     # find iPhone backups on this computer
iscout doctor <path>    # is a target ready to scan, and what to do next
iscout list-iocs        # what indicators are loaded, by feed and type
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
- iScout does not implement backup **crypto** itself — `--decrypt` drives the
  well-tested `mvt-ios decrypt-backup` (install with `pip install mvt`).
- This is a **triage funnel into human review**, not a standalone oracle.

## License

MIT. Defensive security / victim-protection use only.

"""Configuration-profile / MDM inspection.

A configuration profile can legitimately be installed by an employer or a
carrier. But an *unrecognised* profile carrying a high-risk payload — MDM
enrolment, a root CA certificate, an always-on VPN, or a web-content filter — is
a classic covert-surveillance vector (remote admin + HTTPS interception). The
presence of such a payload alone is NOT malicious; iScout flags the combination
for human review.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from .base import Finding, Module, Severity


def _fmt_date(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


# PayloadType -> (short risk explanation). Loaded/augmented from
# data/indicators/profiles_highrisk.json when present.
_DEFAULT_HIGH_RISK = {
    "com.apple.mdm": "Mobile Device Management — persistent remote administration of the device.",
    "com.apple.security.root": "Installs a root CA certificate — enables HTTPS interception (MITM).",
    "com.apple.security.pem": "Installs a certificate — can enable HTTPS interception.",
    "com.apple.security.pkcs1": "Installs a certificate — can enable HTTPS interception.",
    "com.apple.security.pkcs12": "Installs a certificate + private key — can enable HTTPS interception.",
    "com.apple.vpn.managed": "Managed VPN — can route/inspect all network traffic.",
    "com.apple.vpn.managed.applayer": "Per-app managed VPN — can route/inspect app traffic.",
    "com.apple.webcontent-filter": "Web content filter — can monitor/redirect browsing.",
    "com.apple.notificationsettings": "Overrides notification settings (flagged by MVT).",
}


def _load_rules() -> Dict[str, str]:
    rules = dict(_DEFAULT_HIGH_RISK)
    path = os.path.join(os.path.dirname(__file__), "..", "data", "indicators", "profiles_highrisk.json")
    try:
        with open(os.path.abspath(path), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry in data.get("payload_types", []):
            rules[entry["type"]] = entry.get("risk", rules.get(entry["type"], ""))
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return rules


def _payload_types(profile: dict) -> List[str]:
    types = []
    top = profile.get("PayloadType")
    if top:
        types.append(top)
    for item in profile.get("PayloadContent", []) or []:
        if isinstance(item, dict) and item.get("PayloadType"):
            types.append(item["PayloadType"])
    return types


class ConfigurationProfilesModule(Module):
    name = "configuration_profiles"
    description = "Installed configuration profiles / MDM enrolment"
    supports = ("backup",)

    def run(self) -> List[Finding]:
        rules = _load_rules()
        profiles = self.target.profiles()
        if not profiles:
            self.add(
                severity=Severity.INFO,
                title="No configuration profiles installed",
                description="A device with no third-party profiles is the expected clean state.",
            )
            return self.findings

        for relpath, profile in profiles:
            display = profile.get("PayloadDisplayName") or "(unnamed profile)"
            org = profile.get("PayloadOrganization") or ""
            uuid = profile.get("PayloadUUID") or ""
            install_date = profile.get("InstallDate")
            ptypes = _payload_types(profile)

            # Direct IOC match on the profile identifier.
            pid = profile.get("PayloadIdentifier") or profile.get("PayloadUUID")
            ioc = self.indicators.match_profile_id(pid)
            if ioc:
                self.add_ioc_finding(
                    ioc,
                    title=f"Configuration profile matches indicator: {display}",
                    artifact=relpath,
                    timestamp=_fmt_date(install_date),
                    evidence={"uuid": uuid, "organization": org, "payload_types": ptypes},
                )

            risky = [t for t in ptypes if t in rules]
            if risky:
                risk_desc = "; ".join(rules[t] for t in dict.fromkeys(risky))
                self.add(
                    severity=Severity.WARNING,
                    title=f'High-risk configuration profile: "{display}"',
                    description=(
                        f"Contains payload(s): {', '.join(dict.fromkeys(risky))}. {risk_desc} "
                        f"Organisation: {org or 'UNKNOWN'}. If you did not install this profile "
                        "(or do not recognise the organisation), treat it as suspicious and remove it "
                        "via Settings > General > VPN & Device Management."
                    ),
                    matched_value=", ".join(dict.fromkeys(risky)),
                    source="iScout rule: high-risk profile payload",
                    artifact=relpath,
                    timestamp=_fmt_date(install_date),
                    evidence={
                        "display_name": display,
                        "organization": org,
                        "uuid": uuid,
                        "payload_types": ptypes,
                    },
                )
            else:
                self.add(
                    severity=Severity.INFO,
                    title=f'Configuration profile installed: "{display}"',
                    description=f"Organisation: {org or 'unknown'}. Confirm you recognise this profile.",
                    artifact=relpath,
                    evidence={"payload_types": ptypes, "uuid": uuid},
                )

        # Profile install/removal events add timeline context.
        events = self.target.profile_events()
        if events:
            self.add(
                severity=Severity.INFO,
                title=f"{len(events)} configuration-profile event(s) recorded",
                description="Install/remove history for configuration profiles.",
                evidence={"profile_uuids": list(events.keys())[:50]},
            )
        return self.findings

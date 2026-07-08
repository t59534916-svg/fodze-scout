"""Installed-application inventory and matching.

Matches installed bundle IDs against ``app:id`` indicators and installed app
*display names* against known stalkerware home-screen labels (e.g. FlexiSpy's
"Phone Monitor" / "System Core" — low-confidence leads, never proof).
"""

from __future__ import annotations

from typing import List

from .base import Finding, Module, Severity


class ApplicationsModule(Module):
    name = "applications"
    description = "Installed apps vs known spyware bundle IDs / display names"
    supports = ("backup",)

    def run(self) -> List[Finding]:
        installed, apps = self.target.installed_apps()
        if not installed and not apps:
            return self.findings

        for bundle_id in sorted(set(installed) | set(apps.keys())):
            meta = apps.get(bundle_id, {})
            display = str(meta.get("name") or "")

            hit = self.indicators.match_app_id(bundle_id)
            if hit:
                self.add_ioc_finding(
                    hit,
                    title=f"Installed app matches spyware indicator: {bundle_id}",
                    artifact="Info.plist (Installed Applications)",
                    timestamp=str(meta.get("purchaseDate") or "") or None,
                    evidence={"bundle_id": bundle_id, "display_name": display, "meta": _clean(meta)},
                )
                continue

            name_hit = self.indicators.match_app_name(display)
            if name_hit:
                self.add(
                    severity=Severity.WARNING,
                    title=f'App display name matches a stalkerware label: "{display}"',
                    description=(
                        f"{name_hit.description or ''} This is a LOW-confidence lead — "
                        "the label can also belong to a legitimate app. Verify the app's "
                        "developer and purpose."
                    ).strip(),
                    matched_value=display,
                    malware_family=name_hit.malware_family or None,
                    confidence="low",
                    source=name_hit.source,
                    artifact="Info.plist (Applications)",
                    evidence={"bundle_id": bundle_id, "display_name": display},
                )

        self.add(
            severity=Severity.INFO,
            title=f"{len(set(installed) | set(apps.keys()))} applications inventoried",
            description="Review any app you do not recognise or did not install yourself.",
            evidence={"installed_count": len(set(installed) | set(apps.keys()))},
        )
        return self.findings


def _clean(meta: dict) -> dict:
    return {k: (str(v) if v is not None else None) for k, v in meta.items()}

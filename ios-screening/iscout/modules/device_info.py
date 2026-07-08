"""Report device/backup metadata as context (INFO)."""

from __future__ import annotations

from typing import List

from ..utils import redact_serial
from .base import Finding, Module, Severity


class DeviceInfoModule(Module):
    name = "device_info"
    description = "Device model, iOS version and backup metadata"
    supports = ("backup",)

    def run(self) -> List[Finding]:
        info = self.target.device_info()
        if not info:
            return self.findings
        redact = self.options.get("redact", False)
        shown = dict(info)
        if redact:
            for k in ("Serial Number", "IMEI", "ICCID", "Phone Number", "Unique Identifier"):
                if k in shown:
                    shown[k] = redact_serial(str(shown[k]))
        version = info.get("Product Version")
        product = info.get("Product Type") or info.get("Product Name")
        title = f"Device: {product or 'unknown'} · iOS {version or '?'}"
        self.add(
            severity=Severity.INFO,
            title=title,
            description=(
                "Keep iOS up to date — most mercenary spyware relies on "
                "vulnerabilities patched in newer releases. Enable Lockdown Mode "
                "if you are at elevated risk."
            ),
            evidence={str(k): (str(v) if not isinstance(v, (int, float, bool)) else v) for k, v in shown.items()},
        )
        return self.findings

"""Scan orchestration: run the selected modules over a target."""

from __future__ import annotations

from typing import List, Optional, Type

from .backup import EncryptedBackupError, Target
from .indicators import Indicators
from .modules import ALL_MODULES, Module
from .report import ScanResult


def run_scan(
    target: Target,
    indicators: Indicators,
    scanned_at: str,
    modules: Optional[List[Type[Module]]] = None,
    options: Optional[dict] = None,
) -> ScanResult:
    modules = modules or ALL_MODULES
    options = options or {}

    result = ScanResult(
        target_path=getattr(target, "root", "?"),
        target_kind=target.kind,
        scanned_at=scanned_at,
        indicator_count=len(indicators.all),
        feeds=indicators.feeds,
    )
    try:
        result.device_info = target.device_info()
    except EncryptedBackupError:
        raise
    except Exception:  # noqa: BLE001
        result.device_info = {}

    for mod_cls in modules:
        mod = mod_cls(target, indicators, options)
        if not mod.supported():
            continue
        result.modules_run.append(mod.name)
        try:
            findings = mod.run()
        except EncryptedBackupError:
            raise
        except Exception as exc:  # noqa: BLE001 - never let one module abort the scan
            result.module_errors.setdefault(mod.name, []).append(f"unexpected error: {exc}")
            continue
        result.findings.extend(findings)
        if mod.errors:
            result.module_errors.setdefault(mod.name, []).extend(mod.errors)

    # Stable ordering: severity desc, then module.
    result.findings.sort(key=lambda f: (-f.severity.rank, f.module, f.title))
    return result

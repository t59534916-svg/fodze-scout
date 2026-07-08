"""Detection module base class and the Finding / Severity data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..indicators import (
    CATEGORY_JAILBREAK,
    CATEGORY_MERCENARY,
    CATEGORY_STALKERWARE,
    Indicator,
    Indicators,
)


class Severity(str, Enum):
    # A specific indicator matched. Warrants investigation — NOT proof of infection.
    DETECTED = "DETECTED"
    # A heuristic or a weaker/combined signal fired. Review recommended.
    WARNING = "WARNING"
    # Context / inventory. No action implied.
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"DETECTED": 3, "WARNING": 2, "INFO": 1}[self.value]


@dataclass
class Finding:
    module: str
    severity: Severity
    title: str
    description: str = ""
    matched_value: Optional[str] = None
    malware_family: Optional[str] = None
    confidence: Optional[str] = None
    source: Optional[str] = None
    artifact: Optional[str] = None
    timestamp: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "matched_value": self.matched_value,
            "malware_family": self.malware_family,
            "confidence": self.confidence,
            "source": self.source,
            "artifact": self.artifact,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
        }


def severity_for_indicator(ind: Indicator) -> Severity:
    """Policy: how strongly to report a match on *ind*.

    * Jailbreak indicators are a *risk*, never proof of spyware -> WARNING.
    * A high-confidence mercenary/stalkerware IOC -> DETECTED.
    * Everything weaker -> WARNING (with the confidence surfaced).
    """
    if ind.category == CATEGORY_JAILBREAK:
        return Severity.WARNING
    if ind.confidence == "high" and ind.category in (CATEGORY_MERCENARY, CATEGORY_STALKERWARE):
        return Severity.DETECTED
    return Severity.WARNING


class Module:
    """Base class for detection modules.

    Subclasses set ``name``/``description``/``supports`` and implement ``run``,
    appending :class:`Finding` objects via :meth:`add`.
    """

    name = "base"
    description = ""
    supports = ("backup", "fs")  # target kinds this module can run on

    def __init__(self, target, indicators: Indicators, options: Optional[dict] = None) -> None:
        self.target = target
        self.indicators = indicators
        self.options = options or {}
        self.findings: List[Finding] = []
        self.errors: List[str] = []

    def supported(self) -> bool:
        return getattr(self.target, "kind", None) in self.supports

    def add(self, **kwargs) -> Finding:
        f = Finding(module=self.name, **kwargs)
        self.findings.append(f)
        return f

    def add_ioc_finding(
        self,
        ind: Indicator,
        *,
        title: str,
        description: str = "",
        artifact: Optional[str] = None,
        timestamp: Optional[str] = None,
        evidence: Optional[dict] = None,
    ) -> Finding:
        return self.add(
            severity=severity_for_indicator(ind),
            title=title,
            description=description or ind.description,
            matched_value=ind.value,
            malware_family=ind.malware_family or None,
            confidence=ind.confidence,
            source=ind.source or ind.feed,
            artifact=artifact,
            timestamp=timestamp,
            evidence=evidence or {},
        )

    def run(self) -> List[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

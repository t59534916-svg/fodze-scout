"""iScout — forensic screening of iPhone/iPad backups for spyware and stalkerware.

iScout analyses a *consensual* iOS backup (or a full filesystem dump / sysdiagnose)
offline and matches its artifacts against curated, source-attributed indicators of
compromise (IOCs) and behavioural heuristics. It is modelled on the methodology of
Amnesty International's Mobile Verification Toolkit (MVT) and Kaspersky's
triangle_check / iShutdown research.

A finding is always a *lead that warrants further investigation*, never a verdict.
See ``iscout.report`` for the safety framing that every report carries.
"""

__version__ = "0.2.0"
__all__ = ["__version__"]

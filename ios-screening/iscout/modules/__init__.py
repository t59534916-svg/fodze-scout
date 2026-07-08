"""Detection-module registry."""

from __future__ import annotations

from typing import List, Type

from .applications import ApplicationsModule
from .base import Finding, Module, Severity
from .configuration_profiles import ConfigurationProfilesModule
from .device_info import DeviceInfoModule
from .filescan import FileScanModule
from .network_usage import NetworkUsageModule
from .safari_history import SafariHistoryModule
from .shutdownlog import ShutdownLogModule
from .sms import SMSModule
from .tcc import TCCModule

# Order matters only for display grouping; device_info first for context.
ALL_MODULES: List[Type[Module]] = [
    DeviceInfoModule,
    ApplicationsModule,
    ConfigurationProfilesModule,
    NetworkUsageModule,
    SafariHistoryModule,
    SMSModule,
    TCCModule,
    FileScanModule,
    ShutdownLogModule,
]

MODULES_BY_NAME = {m.name: m for m in ALL_MODULES}

__all__ = [
    "ALL_MODULES",
    "MODULES_BY_NAME",
    "Module",
    "Finding",
    "Severity",
]

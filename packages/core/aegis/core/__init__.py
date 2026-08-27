"""Aegis Core — تصدير مكونات الطبقة 0."""

from aegis.core.event_bus import EventBus, Event
from aegis.core.plugin_manager import BasePlugin, PluginManager
from aegis.core.config_manager import ConfigManager
from aegis.core.data_manager import DataManager
from aegis.core.repositories import EvidenceRepository, FindingRepository, ScanRepository
from aegis.core.capability_registry import CapabilityRegistry, EngineCapability, EngineType
from aegis.core.audit_logger import AuditLogger
from aegis.core.crypto import decrypt_text, encrypt_text, load_or_create_key
from aegis.core.exceptions import (
    AegisError,
    AuditError,
    ConfigError,
    DataManagerError,
    EventBusError,
    OrchestratorBusyError,
    OrchestratorError,
    PluginError,
    RemediationError,
    SafetyViolationError,
    ScanTargetError,
    TwinDriftError,
    TwinError,
    ValidationError,
)

__all__ = [
    "EventBus", "Event", "BasePlugin", "PluginManager",
    "ConfigManager", "DataManager", "AuditLogger",
    "EvidenceRepository", "FindingRepository", "ScanRepository",
    "CapabilityRegistry", "EngineCapability", "EngineType",
    "load_or_create_key", "encrypt_text", "decrypt_text",
    "AegisError", "EventBusError", "PluginError", "DataManagerError",
    "ConfigError", "ValidationError", "TwinError", "TwinDriftError",
    "SafetyViolationError", "RemediationError", "OrchestratorError",
    "OrchestratorBusyError", "AuditError", "ScanTargetError",
]

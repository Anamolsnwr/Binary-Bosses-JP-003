"""
Remediation subsystem for Code Sentinel AI / ASTraGuard.
"""
from core.remediation.validator import RemediationValidationPipeline
from core.remediation.handlers import (
    BaseRemediationHandler,
    SQLInjectionHandler,
    CryptographicVulnerabilityHandler,
    HardcodedSecretHandler,
    DynamicExecutionHandler,
    QualityAndMaintainabilityHandler,
    ConservativeFallbackHandler
)
from core.remediation.registry import (
    RemediationRegistry,
    default_registry,
    get_offline_heuristic_fix,
    get_offline_heuristic_enrichment
)

__all__ = [
    "RemediationValidationPipeline",
    "BaseRemediationHandler",
    "SQLInjectionHandler",
    "CryptographicVulnerabilityHandler",
    "HardcodedSecretHandler",
    "DynamicExecutionHandler",
    "QualityAndMaintainabilityHandler",
    "ConservativeFallbackHandler",
    "RemediationRegistry",
    "default_registry",
    "get_offline_heuristic_fix",
    "get_offline_heuristic_enrichment"
]

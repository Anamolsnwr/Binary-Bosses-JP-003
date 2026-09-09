"""
Base interface for remediation handlers in Code Sentinel AI / ASTraGuard.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseRemediationHandler(ABC):
    """Abstract interface for domain-specific remediation fix generators."""

    @property
    @abstractmethod
    def handler_id(self) -> str:
        """Unique identifier for the remediation handler."""
        pass

    @abstractmethod
    def can_handle(self, finding: Dict[str, Any]) -> bool:
        """Determines whether this handler can remediate the given finding."""
        pass

    @abstractmethod
    def generate_fix(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generates the standardized remediation dictionary."""
        pass

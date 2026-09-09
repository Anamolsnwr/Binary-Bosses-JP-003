"""
Base interface for static scanning rules and tool runners.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from core.models import Finding
from core.scanner.context import FileContextManager


class BaseScannerRule(ABC):
    """Abstract interface for static analysis rule runners."""
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanning rule or sub-engine."""
        pass

    @abstractmethod
    def scan(
        self,
        target_dir: str,
        target_file: Optional[str] = None,
        context_manager: Optional[FileContextManager] = None
    ) -> List[Dict[str, Any]]:
        """Executes the scan and returns a list of raw finding dicts."""
        pass

"""
Unified Audit Service for Code Sentinel AI / ASTraGuard.
Coordinates repository audits, single-file audits, and in-memory snippet analysis.
Encapsulates scanning, scoring, remediation, and credential scrubbing.
"""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.models import Finding, AuditReport
from core.scanner.engine import StaticScanEngine, clean_rule_metadata
from core.scoring import ScoreEngine, get_codebase_verbal_rating
from core.remediation.registry import get_offline_heuristic_fix
from core.providers.manager import default_provider_manager
from core.repo_cloner import detect_code_language, scan_target_files


class AuditService:
    """
    High-level application service layer.
    Decouples UI (Streamlit) from scanner internals, scoring algorithms, and AI providers.
    """
    def __init__(self, scan_engine: Optional[StaticScanEngine] = None, score_engine: Optional[ScoreEngine] = None):
        self.scan_engine = scan_engine or StaticScanEngine()
        self.score_engine = score_engine or ScoreEngine()
        self.provider_manager = default_provider_manager

    def audit_repository(self, target_dir: str, target_file: Optional[str] = None) -> Dict[str, Any]:
        """Runs complete static scan across repository or targeted file."""
        return self.scan_engine.analyze(target_dir=target_dir, target_file=target_file)

    def audit_snippet(self, code_snippet: str, file_name: Optional[str] = None, language: Optional[str] = None) -> Dict[str, Any]:
        """
        Audits an in-memory code snippet without permanent disk writes.
        Automatically infers language extension if not explicitly specified.
        """
        if not language or language == "auto":
            detected_lang, ext = detect_code_language(code_snippet)
        else:
            detected_lang = language.lower()
            ext_map = {
                "python": ".py",
                "javascript": ".js",
                "typescript": ".ts",
                "html": ".html",
                "css": ".css"
            }
            ext = ext_map.get(detected_lang, ".py")

        target_name = file_name or f"snippet{ext}"
        if not target_name.endswith(ext):
            target_name += ext

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / target_name
            tmp_path.write_text(code_snippet, encoding="utf-8", errors="ignore")
            result = self.scan_engine.analyze(target_dir=tmpdir, target_file=target_name)
            result["detected_language"] = detected_lang
            return result

    def get_remediation(
        self,
        finding: Dict[str, Any],
        provider: str = "gemini",
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> Dict[str, Any]:
        """Dispatches finding to the multi-provider LLM remediation engine or heuristic fallback."""
        return self.provider_manager.generate_remediation(
            finding=finding,
            provider=provider,
            api_key=api_key,
            model_name=model_name,
            custom_endpoint=custom_endpoint
        )


# Global default service instance
default_audit_service = AuditService()

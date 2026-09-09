"""
Central Remediation Registry and Heuristic Generator for Code Sentinel AI / ASTraGuard.
Coordinates specialized domain handlers, validation pipelines, and schema enrichment.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional
from core.remediation.handlers.base import BaseRemediationHandler
from core.remediation.handlers.sql_handler import SQLInjectionHandler
from core.remediation.handlers.crypto_handler import CryptographicVulnerabilityHandler
from core.remediation.handlers.secret_handler import HardcodedSecretHandler
from core.remediation.handlers.eval_handler import DynamicExecutionHandler
from core.remediation.handlers.quality_handler import QualityAndMaintainabilityHandler
from core.remediation.handlers.fallback_handler import ConservativeFallbackHandler
from core.remediation.validator import RemediationValidationPipeline


class RemediationRegistry:
    """
    Registry of specialized remediation handlers.
    Dispatches findings to matching domain handlers with fallback and syntax validation.
    """
    def __init__(self):
        self.handlers: List[BaseRemediationHandler] = [
            SQLInjectionHandler(),
            CryptographicVulnerabilityHandler(),
            DynamicExecutionHandler(),
            HardcodedSecretHandler(),
            QualityAndMaintainabilityHandler(),
            ConservativeFallbackHandler()
        ]

    def register_handler(self, handler: BaseRemediationHandler, priority: int = 0) -> None:
        """Allows dynamic registration of custom remediation rules."""
        self.handlers.insert(priority, handler)

    def get_handler(self, finding: Dict[str, Any]) -> BaseRemediationHandler:
        """Finds the first handler capable of remediating this finding."""
        for handler in self.handlers:
            if handler.can_handle(finding):
                return handler
        return self.handlers[-1]  # Fallback

    def generate_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generates drop-in remediation and passes it through AST syntax validation."""
        handler = self.get_handler(finding)
        fix = handler.generate_fix(finding)

        # Run validation pipeline
        is_valid, errors = RemediationValidationPipeline.validate(fix)
        fix["validation_passed"] = is_valid
        fix["validation_errors"] = errors

        return fix


# Global singleton registry
default_registry = RemediationRegistry()


def get_offline_heuristic_fix(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Provides instant, validated remediation patch for any detected finding."""
    return default_registry.generate_remediation(finding)


def get_offline_heuristic_enrichment(
    file_path: str,
    raw_code: str,
    ast_findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Deterministic fallback generator producing the exact requested JSON schema:
    {
      "summary": "...",
      "health_score": 85,
      "detailed_findings": [ ... ]
    }
    """
    detailed = []
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for item in ast_findings:
        sev = item.get("severity", "Medium")
        if sev in counts:
            counts[sev] += 1

        fix = get_offline_heuristic_fix(item)
        line_num = item.get("line_no") or item.get("line", 1)
        before_snippet = (
            item.get("before_code")
            or item.get("vulnerable_code")
            or fix.get("original_code_snippet")
            or ""
        )
        after_snippet = fix.get("refactored_code_snippet") or "# Refactored code"
        explanation = (
            item.get("explanation")
            or fix.get("explainer_60_words")
            or item.get("title")
            or "Code pattern violates quality standards."
        )

        detailed_item = {
            "rule_id": item.get("rule_id", "QUAL001"),
            "category": item.get("category", "Quality"),
            "line_no": line_num,
            "title": item.get("title", "Code Flaw"),
            "severity": sev,
            "explanation": explanation,
            "before_code": before_snippet,
            "after_code": after_snippet,
            # Backward and UI compatibility keys
            "line": line_num,
            "file": file_path,
            "vulnerable_code": before_snippet,
            "refactored_code_snippet": after_snippet,
            "explainer_60_words": explanation,
            "highlighted_context": item.get("highlighted_context", ""),
            "context_snippet": item.get("context_snippet", ""),
            "where_changed": fix.get("where_changed", f"In '{file_path}' (Line {line_num})"),
            "what_changed": fix.get("what_changed", "Applied refactoring to resolve code flaw."),
            "required_imports": fix.get("required_imports", "None"),
            "safe_enclosing_function": fix.get("safe_enclosing_function", after_snippet)
        }
        detailed.append(detailed_item)

    deductions = (20 * counts["Critical"]) + (10 * counts["High"]) + (5 * counts["Medium"]) + (2 * counts["Low"])
    health_score = max(0, 100 - deductions)

    return {
        "summary": f"Audit of '{os.path.basename(file_path)}' identified {len(detailed)} finding(s) with health score {health_score}/100.",
        "health_score": health_score,
        "detailed_findings": detailed
    }

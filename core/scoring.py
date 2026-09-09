"""
Centralized Scoring & Health Metric Engine for Code Sentinel AI / ASTraGuard.
Computes repository and file health scores with configurable severity weights,
duplicate damping, category weighting, and transparent deduction logs.
"""
from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from core.models import Finding, Severity, Category, AuditSummary


def get_codebase_verbal_rating(score: int) -> Dict[str, Any]:
    """Translates a numeric health score into intuitive verbal ratings and executive verdicts."""
    if score >= 95:
        return {
            "label": "Pristine & Production-Ready",
            "short_label": "Perfect / Pristine",
            "grade": "A+",
            "badge": "💎 Pristine",
            "color": "#10b981",
            "bg_color": "rgba(16, 185, 129, 0.12)",
            "border_color": "#10b981",
            "description": "Codebase is extraordinarily clean, robust, and exhibits zero critical security flaws. Fully ready for production deployment."
        }
    elif score >= 80:
        return {
            "label": "Solid & Stable",
            "short_label": "Fine / Solid",
            "grade": "A",
            "badge": "🟢 Solid & Reliable",
            "color": "#38bdf8",
            "bg_color": "rgba(56, 189, 248, 0.12)",
            "border_color": "#38bdf8",
            "description": "Strong architectural foundation with minor non-blocking items or code smells. Safe for production with standard reviews."
        }
    elif score >= 60:
        return {
            "label": "Fair — Moderate Risk",
            "short_label": "Moderate / Needs Review",
            "grade": "B",
            "badge": "🟡 Moderate Risk",
            "color": "#f59e0b",
            "bg_color": "rgba(245, 158, 11, 0.12)",
            "border_color": "#f59e0b",
            "description": "Noticeable security exposures or elevated cyclomatic complexity. Polish and targeted refactoring recommended before release."
        }
    elif score >= 40:
        return {
            "label": "Degraded — High Vulnerability",
            "short_label": "Poor / Fragile",
            "grade": "C",
            "badge": "🟠 High Debt & Risk",
            "color": "#f97316",
            "bg_color": "rgba(249, 115, 22, 0.12)",
            "border_color": "#f97316",
            "description": "Multiple high-severity security leaks or unmanaged resources present. Unsafe to merge without remediation."
        }
    else:
        return {
            "label": "Critical Failure — Unsafe for Production",
            "short_label": "Critical Alert / Unsafe",
            "grade": "F",
            "badge": "🔴 Critical Failure",
            "color": "#ef4444",
            "bg_color": "rgba(239, 68, 68, 0.12)",
            "border_color": "#ef4444",
            "description": "Immediate intervention required! Contains critical vulnerabilities (e.g. SQL Injection, hardcoded secrets, weak crypto) that jeopardize repository integrity."
        }


@dataclass
class ScoringWeights:
    """Configurable weights for finding severity deductions."""
    critical: float = 20.0
    high: float = 10.0
    medium: float = 5.0
    low: float = 2.0
    info: float = 0.0
    duplicate_damping: bool = False  # Keep false by default for exact backward-compat with classic tests
    damping_decay: float = 0.7


class ScoreEngine:
    """
    Centralized health scoring engine.
    Calculates repository/file health score (0-100), categorical counts,
    and a fully transparent deduction log.
    """
    def __init__(self, weights: Optional[ScoringWeights] = None):
        self.weights = weights or ScoringWeights()

    def calculate(
        self,
        findings: List[Union[Dict[str, Any], Finding]],
        scope: str = "repo",
        target_file: Optional[str] = None,
        target_dir: str = ""
    ) -> AuditSummary:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        cat_counts = {
            "Security": 0,
            "Quality": 0,
            "Maintainability": 0,
            "Performance": 0,
            "Functional": 0
        }

        deductions_total = 0.0
        deduction_details: List[Dict[str, Any]] = []

        # Rule occurrence tracking for damping if enabled
        rule_counts: Dict[str, int] = {}

        for item in findings:
            # Handle both Finding objects and dicts
            sev = item.get("severity", "Low") if isinstance(item, dict) else item.severity
            cat = item.get("category", "Quality") if isinstance(item, dict) else item.category
            rule_id = item.get("rule_id", "unknown") if isinstance(item, dict) else item.rule_id
            conf = float(item.get("confidence", 1.0) if isinstance(item, dict) else item.confidence)
            title = item.get("title", "") if isinstance(item, dict) else item.title
            file_name = item.get("file", "") if isinstance(item, dict) else item.file

            # Severity counts
            norm_sev = sev.capitalize() if sev else "Low"
            if norm_sev in counts:
                counts[norm_sev] += 1
            else:
                counts["Low"] += 1

            # Category counts
            norm_cat = cat.capitalize() if cat else "Quality"
            if norm_cat in cat_counts:
                cat_counts[norm_cat] += 1

            # Base deduction
            if norm_sev == "Critical":
                base_weight = self.weights.critical
            elif norm_sev == "High":
                base_weight = self.weights.high
            elif norm_sev == "Medium":
                base_weight = self.weights.medium
            elif norm_sev == "Low":
                base_weight = self.weights.low
            else:
                base_weight = self.weights.info

            # Apply damping if enabled
            rule_key = f"{file_name}:{rule_id}"
            occurrence = rule_counts.get(rule_key, 0) + 1
            rule_counts[rule_key] = occurrence

            if self.weights.duplicate_damping and occurrence > 1:
                damping_multiplier = math.pow(self.weights.damping_decay, occurrence - 1)
            else:
                damping_multiplier = 1.0

            item_deduction = round(base_weight * conf * damping_multiplier)
            deductions_total += item_deduction

            deduction_details.append({
                "rule_id": rule_id,
                "file": file_name,
                "severity": norm_sev,
                "title": title,
                "base_points": base_weight,
                "confidence": conf,
                "damping_multiplier": damping_multiplier,
                "points_deducted": item_deduction
            })

        total_deductions_int = int(deductions_total)
        health_score = max(0, 100 - total_deductions_int)
        verbal_rating = get_codebase_verbal_rating(health_score)

        return AuditSummary(
            health_score=health_score,
            verbal_rating=verbal_rating,
            total_issues=len(findings),
            critical=counts["Critical"],
            high=counts["High"],
            medium=counts["Medium"],
            low=counts["Low"],
            security_count=cat_counts["Security"],
            quality_count=cat_counts["Quality"] + cat_counts["Maintainability"] + cat_counts["Performance"] + cat_counts["Functional"],
            maintainability_count=cat_counts["Maintainability"] + cat_counts["Functional"],
            performance_count=cat_counts["Performance"],
            deductions=total_deductions_int,
            scope=scope,
            target_file=target_file,
            target_dir=target_dir,
            deduction_details=deduction_details
        )


# Global default instance
_default_engine = ScoreEngine()


def calculate_code_health(
    findings: List[Union[Dict[str, Any], Finding]],
    scope: str = "repo",
    target_file: Optional[str] = None,
    target_dir: str = "",
    weights: Optional[ScoringWeights] = None
) -> AuditSummary:
    """Convenience functional interface for calculating codebase health."""
    engine = ScoreEngine(weights) if weights else _default_engine
    return engine.calculate(
        findings=findings,
        scope=scope,
        target_file=target_file,
        target_dir=target_dir
    )

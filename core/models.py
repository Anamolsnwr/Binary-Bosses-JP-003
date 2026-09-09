"""
Core domain models and schema definitions for Code Sentinel AI / ASTraGuard.
Provides strongly-typed models with full backward-compatibility for dictionary-style access.
"""
from __future__ import annotations
import hashlib
import os
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @classmethod
    def from_string(cls, val: str) -> "Severity":
        normalized = val.strip().capitalize() if val else "Low"
        for member in cls:
            if member.value.lower() == val.lower():
                return member
        return cls.LOW


class Category(str, Enum):
    SECURITY = "Security"
    QUALITY = "Quality"
    MAINTAINABILITY = "Maintainability"
    PERFORMANCE = "Performance"
    FUNCTIONAL = "Functional"

    @classmethod
    def from_string(cls, val: str) -> "Category":
        normalized = val.strip().capitalize() if val else "Quality"
        for member in cls:
            if member.value.lower() == val.lower():
                return member
        return cls.QUALITY


@dataclass
class Finding:
    """
    Standard finding representation across all scanners (Bandit, Radon, AST, Web).
    Supports both attribute access (f.line) and dict-style access (f['line'])
    for backward compatibility with existing codebase and tests.
    """
    id: str
    file: str
    line: int
    rule_id: str
    category: str
    severity: str
    title: str
    explanation: str = ""
    vulnerable_code: str = ""
    before_code: str = ""
    context_snippet: str = ""
    highlighted_context: str = ""
    tool: str = ""
    absolute_path: str = ""
    confidence: float = 1.0
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    extra_data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Normalize file path separators
        self.file = self.file.replace("\\", "/")
        if not self.before_code and self.vulnerable_code:
            self.before_code = self.vulnerable_code
        elif not self.vulnerable_code and self.before_code:
            self.vulnerable_code = self.before_code

        if not self.start_line:
            self.start_line = self.line
        if not self.end_line:
            self.end_line = self.line

        # Ensure line is int
        try:
            self.line = int(self.line)
        except (ValueError, TypeError):
            self.line = 1

    @property
    def fingerprint(self) -> str:
        """
        Deterministic SHA-256 fingerprint for finding deduplication, caching,
        and stability across line shifts.
        Normalized on (basename, rule_id, normalized_code).
        """
        base_file = os.path.basename(self.file)
        clean_code = re.sub(r"\s+", " ", self.vulnerable_code.strip()) if self.vulnerable_code else ""
        raw_sig = f"{base_file}:{self.rule_id}:{clean_code or self.line}"
        return hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Converts finding to a fully synchronized dictionary."""
        d = {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "line_no": self.line,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
            "vulnerable_code": self.vulnerable_code,
            "before_code": self.before_code,
            "context_snippet": self.context_snippet,
            "highlighted_context": self.highlighted_context,
            "tool": self.tool,
            "absolute_path": self.absolute_path,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "fingerprint": self.fingerprint,
        }
        if self.extra_data:
            d.update(self.extra_data)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        line = data.get("line") or data.get("line_no") or 1
        vuln = data.get("vulnerable_code") or data.get("before_code") or ""
        extra = {k: v for k, v in data.items() if k not in {
            "id", "file", "line", "line_no", "rule_id", "category", "severity",
            "title", "explanation", "vulnerable_code", "before_code", "context_snippet",
            "highlighted_context", "tool", "absolute_path", "confidence", "cwe", "owasp",
            "start_line", "end_line", "fingerprint"
        }}
        return cls(
            id=data.get("id", ""),
            file=data.get("file", ""),
            line=int(line),
            rule_id=data.get("rule_id", ""),
            category=data.get("category", "Security"),
            severity=data.get("severity", "Medium"),
            title=data.get("title", ""),
            explanation=data.get("explanation", ""),
            vulnerable_code=vuln,
            before_code=vuln,
            context_snippet=data.get("context_snippet", ""),
            highlighted_context=data.get("highlighted_context", ""),
            tool=data.get("tool", ""),
            absolute_path=data.get("absolute_path", ""),
            confidence=float(data.get("confidence", 1.0)),
            cwe=data.get("cwe"),
            owasp=data.get("owasp"),
            start_line=data.get("start_line"),
            end_line=data.get("end_line"),
            extra_data=extra
        )

    # Dict-like emulation for backward compatibility
    def __getitem__(self, key: str) -> Any:
        if key == "line_no":
            return self.line
        if key == "fingerprint":
            return self.fingerprint
        if hasattr(self, key):
            return getattr(self, key)
        if key in self.extra_data:
            return self.extra_data[key]
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key == "line_no":
            self.line = int(value)
        elif key == "line":
            self.line = int(value)
        elif hasattr(self, key):
            setattr(self, key, value)
        else:
            self.extra_data[key] = value

    def __contains__(self, key: str) -> bool:
        if key in ("line_no", "fingerprint"):
            return True
        return hasattr(self, key) or (key in self.extra_data)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        return self.to_dict().keys()

    def values(self):
        return self.to_dict().values()

    def items(self):
        return self.to_dict().items()


@dataclass
class AuditSummary:
    """Standardized metric summary for an audit run."""
    health_score: int
    verbal_rating: Dict[str, Any]
    total_issues: int
    critical: int
    high: int
    medium: int
    low: int
    security_count: int
    quality_count: int
    maintainability_count: int
    performance_count: int
    deductions: int
    scope: str
    target_file: Optional[str]
    target_dir: str
    deduction_details: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    """Top-level audit response containing summary and list of findings."""
    summary: AuditSummary
    findings: List[Finding]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings]
        }

    # Dict-like access for analysis["summary"] and analysis["findings"]
    def __getitem__(self, key: str) -> Any:
        if key == "summary":
            return self.summary.to_dict()
        if key == "findings":
            return [f.to_dict() for f in self.findings]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


@dataclass
class RemediationResult:
    """Result of an AI or deterministic remediation generation."""
    file: str
    start_line: int
    end_line: int
    where_changed: str
    what_changed: str
    explainer_60_words: str
    root_cause_explanation: str
    suggested_fix: str
    original_code_snippet: str
    refactored_code_snippet: str
    required_imports: str
    copy_paste_instruction: str
    safe_enclosing_function: str
    security_standard: str
    ai_provider: Optional[str] = None
    cached: bool = False
    latency_ms: float = 0.0
    validation_passed: bool = True
    validation_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

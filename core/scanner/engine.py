"""
Static Scan Engine orchestrator for Code Sentinel AI / ASTraGuard.
Coordinates Bandit, Radon, AST Visitor, and Web scanner modules.
Deduplicates findings via SHA-256 fingerprints and delegates health scoring to ScoreEngine.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.models import Finding
from core.scanner.context import FileContextManager, default_context_manager
from core.scanner.rules.ast_rules import run_ast_scan
from core.scanner.rules.bandit_runner import run_bandit_scan
from core.scanner.rules.radon_runner import run_radon_complexity_scan
from core.scanner.rules.web_rules import run_web_code_scan
from core.scoring import ScoreEngine, get_codebase_verbal_rating, calculate_code_health


def clean_rule_metadata(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cleans technical linter names (bandit, radon, ast) into authoritative, plain English descriptors
    and ensures schema consistency.
    """
    rule_id = item.get("rule_id", "").lower()
    title = item.get("title", "")
    category = item.get("category", "Security")

    # Synchronize line_no and line
    if "line_no" not in item and "line" in item:
        item["line_no"] = item["line"]
    elif "line" not in item and "line_no" in item:
        item["line"] = item["line_no"]

    # Synchronize before_code and vulnerable_code
    if "before_code" not in item and "vulnerable_code" in item:
        item["before_code"] = item["vulnerable_code"]
    elif "vulnerable_code" not in item and "before_code" in item:
        item["vulnerable_code"] = item["before_code"]

    if "explanation" not in item or not item["explanation"]:
        item["explanation"] = f"{title}. Immediate refactoring recommended to uphold repository standards."

    if "b201" in rule_id or "flask_debug" in rule_id:
        item["title"] = "Flask Interactive Debug Mode Enabled in Production"
        item["rule_id"] = "SEC-DEBUG-PRODUCTION"
    elif "b104" in rule_id:
        item["title"] = "Wildcard Network Interface Binding (0.0.0.0)"
        item["rule_id"] = "SEC-INTERFACE-BIND"
    elif any(k in rule_id for k in ["b105", "b106", "b107", "hardcoded-secret"]):
        item["title"] = "Hardcoded Authentication Credential or Secret Key"
        item["rule_id"] = "SEC-HARDCODED-SECRET"
    elif "b608" in rule_id or "sql" in rule_id:
        item["title"] = "SQL Injection Vulnerability via Formatted Query Construction"
        item["rule_id"] = "SEC-SQL-INJECTION"
    elif any(k in rule_id for k in ["b324", "b303", "md5"]):
        item["title"] = "Cryptographically Broken MD5 Hashing Algorithm"
        item["rule_id"] = "SEC-WEAK-HASHING"
    elif "b307" in rule_id or "eval" in rule_id:
        item["title"] = "Arbitrary Dynamic Code Execution via eval()"
        item["rule_id"] = "SEC-DYNAMIC-EVAL"
    elif any(k in rule_id for k in ["b602", "b603", "shell"]):
        item["title"] = "Command Injection Risk via Subprocess Shell Execution"
        item["rule_id"] = "SEC-COMMAND-INJECTION"
    elif "b506" in rule_id:
        item["title"] = "Unsafe YAML Deserialization via yaml.load()"
        item["rule_id"] = "SEC-UNSAFE-DESERIALIZATION"
    elif "complexity" in rule_id or "radon" in rule_id:
        clean_name = re.sub(r"(?i)radon:complexity:\s*", "", title)
        item["title"] = clean_name if "Complexity" in clean_name else "Excessive Cyclomatic Complexity in Business Logic"
        item["rule_id"] = "MAINT-COMPLEXITY-DEBT"
    elif "unclosed-resource" in rule_id:
        item["title"] = "Unmanaged File Resource Handle (Missing Context Manager)"
        item["rule_id"] = "MAINT-UNCLOSED-HANDLE"

    # Strip technical prefixes
    clean_title = re.sub(r"(?i)\b(bandit|radon|ast_engine|ast_visitor|sast)\b:?", "", item.get("title", "")).strip(" :-_")
    if clean_title:
        item["title"] = clean_title

    # User-facing engine descriptor without exposing internal details
    if category == "Security":
        item["tool"] = "Security Vulnerability Engine"
    elif category == "Performance":
        item["tool"] = "Performance Optimization Engine"
    elif category == "Maintainability":
        item["tool"] = "Code Maintainability Engine"
    elif category == "Quality":
        item["tool"] = "Code Quality & Logic Engine"
    else:
        item["tool"] = "Quality Engine"

    # Compute SHA-256 fingerprint for finding deduplication & tracking
    try:
        temp_finding = Finding.from_dict(item)
        item["fingerprint"] = temp_finding.fingerprint
    except Exception:
        pass

    return item


class StaticScanEngine:
    """
    High-performance Static Analysis Orchestrator.
    Manages in-memory context caching, multi-engine execution, deduplication, and score calculation.
    """
    def __init__(self, context_manager: Optional[FileContextManager] = None, score_engine: Optional[ScoreEngine] = None):
        self.ctx_mgr = context_manager or default_context_manager
        self.score_engine = score_engine or ScoreEngine()

    def analyze(self, target_dir: str, target_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Runs comprehensive scan across Bandit, Radon, AST visitor, and Web code scanners.
        Deduplicates findings, ensures schema integrity, and computes codebase health.
        """
        normalized_target_file = None
        if target_file:
            if os.path.isabs(target_file):
                try:
                    normalized_target_file = os.path.relpath(target_file, target_dir).replace("\\", "/")
                except ValueError:
                    normalized_target_file = Path(target_file).name
            else:
                normalized_target_file = Path(target_file).as_posix()

        bandit_results = run_bandit_scan(target_dir, target_file=normalized_target_file, context_manager=self.ctx_mgr)
        radon_results = run_radon_complexity_scan(target_dir, target_file=normalized_target_file, context_manager=self.ctx_mgr)
        ast_results = run_ast_scan(target_dir, target_file=normalized_target_file, context_manager=self.ctx_mgr)
        web_results = run_web_code_scan(target_dir, target_file=normalized_target_file, context_manager=self.ctx_mgr)

        all_raw = bandit_results + radon_results + ast_results + web_results
        all_findings = []
        seen_keys = set()

        for item in all_raw:
            item = clean_rule_metadata(item)
            item_file = item.get("file", "").replace("\\", "/")
            if normalized_target_file and item_file != normalized_target_file and not item_file.endswith("/" + normalized_target_file):
                continue
            key = (item["file"], item["line"], item["category"])
            if key not in seen_keys:
                seen_keys.add(key)
                all_findings.append(item)

        # Clear file cache after scan to prevent unbounded memory growth
        self.ctx_mgr.clear()

        # Delegate health score computation to centralized ScoreEngine
        scope = "file" if normalized_target_file else "repo"
        summary_obj = self.score_engine.calculate(
            findings=all_findings,
            scope=scope,
            target_file=normalized_target_file,
            target_dir=target_dir
        )

        return {
            "summary": summary_obj.to_dict(),
            "findings": all_findings
        }


# Global default engine instance
_default_scan_engine = StaticScanEngine()


def analyze_repository(target_dir: str, target_file: Optional[str] = None) -> Dict[str, Any]:
    """Global convenience function maintaining 100% backward-compatibility."""
    return _default_scan_engine.analyze(target_dir, target_file)

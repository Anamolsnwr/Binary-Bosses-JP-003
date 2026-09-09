"""
Static Code Scanner Facade for Code Sentinel AI / ASTraGuard.
Coordinates AST traversal, Bandit security auditing, Radon cyclomatic complexity,
and Web script vulnerability analysis.
Preserves 100% backward-compatible API for all existing callers and tests.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from core.scanner.context import (
    FileContextManager,
    extract_code_context as _extract_code_context,
    default_context_manager
)
from core.scanner.rules.ast_rules import ASTAuditorVisitor, run_ast_scan
from core.scanner.rules.bandit_runner import run_bandit_scan
from core.scanner.rules.radon_runner import run_radon_complexity_scan
from core.scanner.rules.web_rules import run_web_code_scan
from core.scanner.engine import (
    StaticScanEngine,
    clean_rule_metadata,
    analyze_repository
)
from core.scoring import get_codebase_verbal_rating, calculate_code_health

__all__ = [
    "_extract_code_context",
    "run_bandit_scan",
    "run_radon_complexity_scan",
    "ASTAuditorVisitor",
    "run_ast_scan",
    "get_codebase_verbal_rating",
    "calculate_code_health",
    "run_web_code_scan",
    "clean_rule_metadata",
    "analyze_repository",
    "StaticScanEngine",
    "FileContextManager"
]

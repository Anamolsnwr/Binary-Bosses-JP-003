"""
Modular static scanning subsystem for Code Sentinel AI / ASTraGuard.
"""
from core.scanner.context import FileContextManager, extract_code_context, default_context_manager
from core.scanner.rules import (
    BaseScannerRule,
    ASTAuditorVisitor,
    run_ast_scan,
    ASTScannerRule,
    run_bandit_scan,
    BanditScannerRule,
    run_radon_complexity_scan,
    RadonScannerRule,
    run_web_code_scan,
    WebScannerRule
)
from core.scanner.engine import (
    StaticScanEngine,
    clean_rule_metadata,
    analyze_repository
)

__all__ = [
    "FileContextManager",
    "extract_code_context",
    "default_context_manager",
    "BaseScannerRule",
    "ASTAuditorVisitor",
    "run_ast_scan",
    "ASTScannerRule",
    "run_bandit_scan",
    "BanditScannerRule",
    "run_radon_complexity_scan",
    "RadonScannerRule",
    "run_web_code_scan",
    "WebScannerRule",
    "StaticScanEngine",
    "clean_rule_metadata",
    "analyze_repository"
]

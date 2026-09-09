"""
Web, JavaScript, TypeScript, and HTML security & syntax auditor for Code Sentinel AI / ASTraGuard.
Detects:
- Syntax / malformed function calls
- DOM XSS via innerHTML / outerHTML / document.write
- Null dereference precedence risks
- eval() dynamic code execution
- Hardcoded secret tokens in frontend client code
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.scanner.context import FileContextManager, default_context_manager
from core.scanner.rules.base import BaseScannerRule


def run_web_code_scan(
    target_dir: str,
    target_file: Optional[str] = None,
    context_manager: Optional[FileContextManager] = None
) -> List[Dict[str, Any]]:
    """
    Analyzes JavaScript, TypeScript, and HTML files for security vulnerabilities,
    functional syntax errors, and DOM bugs.
    """
    ctx_mgr = context_manager or default_context_manager
    findings: List[Dict[str, Any]] = []
    root_path = Path(target_dir)

    target_extensions = {".js", ".jsx", ".ts", ".tsx", ".html"}
    ignore_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv"}

    if target_file:
        full_path = Path(target_dir) / target_file if not os.path.isabs(target_file) else Path(target_file)
        if full_path.suffix.lower() not in target_extensions or not full_path.exists():
            return []
        files = [full_path]
    else:
        files = [
            p for p in root_path.rglob("*")
            if p.is_file()
            and p.suffix.lower() in target_extensions
            and not any(ig in p.parts for ig in ignore_dirs)
        ]

    for fp in files:
        try:
            rel_file = fp.relative_to(root_path).as_posix()
        except ValueError:
            rel_file = fp.name

        lines = ctx_mgr.get_lines(str(fp))

        for idx, line in enumerate(lines):
            ln = idx + 1

            # 1. Syntax / Malformed function call (e.g. initSmoothScrol};)
            if re.search(r"^\s*([a-zA-Z0-9_$]+)\s*\};", line):
                ctx = ctx_mgr.extract_code_context(str(fp), ln, rule_label="Syntax Error: Malformed Function Call")
                findings.append({
                    "id": f"WEB-{len(findings) + 401}",
                    "file": rel_file,
                    "absolute_path": str(fp),
                    "line": ln,
                    "line_no": ln,
                    "rule_id": "FUNC-SYNTAX-ERROR",
                    "category": "Functional",
                    "severity": "Critical",
                    "title": "Syntax Error: Incomplete Function Call in Event Callback",
                    "vulnerable_code": ctx["target_line"],
                    "before_code": ctx["target_line"],
                    "context_snippet": ctx["snippet"],
                    "highlighted_context": ctx["highlighted_context"],
                    "tool": "web_auditor"
                })

            # 2. DOM XSS via innerHTML / outerHTML / document.write
            elif re.search(r"\.(innerHTML|outerHTML)\s*=", line) or re.search(r"\bdocument\.write\s*\(", line):
                ctx = ctx_mgr.extract_code_context(str(fp), ln, rule_label="Security: Unsanitized DOM Injection")
                findings.append({
                    "id": f"WEB-{len(findings) + 401}",
                    "file": rel_file,
                    "absolute_path": str(fp),
                    "line": ln,
                    "line_no": ln,
                    "rule_id": "SEC-DOM-XSS",
                    "category": "Security",
                    "severity": "High",
                    "title": "DOM-Based Cross-Site Scripting (XSS) via innerHTML",
                    "vulnerable_code": ctx["target_line"],
                    "before_code": ctx["target_line"],
                    "context_snippet": ctx["snippet"],
                    "highlighted_context": ctx["highlighted_context"],
                    "tool": "web_auditor"
                })

            # 3. Null reference / Operator precedence bug
            elif re.search(r"([a-zA-Z0-9_$]+)\s*&&\s*\1\.[a-zA-Z0-9_$]+\s*===.*\|\|\s*\1\.[a-zA-Z0-9_$]+", line):
                ctx = ctx_mgr.extract_code_context(str(fp), ln, rule_label="Functional: Null Reference Precedence Risk")
                findings.append({
                    "id": f"WEB-{len(findings) + 401}",
                    "file": rel_file,
                    "absolute_path": str(fp),
                    "line": ln,
                    "line_no": ln,
                    "rule_id": "FUNC-NULL-DEREF",
                    "category": "Functional",
                    "severity": "Medium",
                    "title": "Potential Null Reference Exception in Logical Condition",
                    "vulnerable_code": ctx["target_line"],
                    "before_code": ctx["target_line"],
                    "context_snippet": ctx["snippet"],
                    "highlighted_context": ctx["highlighted_context"],
                    "tool": "web_auditor"
                })

            # 4. Dangerous eval() execution
            elif re.search(r"\beval\s*\(", line):
                ctx = ctx_mgr.extract_code_context(str(fp), ln, rule_label="Security: Dynamic Code Execution")
                findings.append({
                    "id": f"WEB-{len(findings) + 401}",
                    "file": rel_file,
                    "absolute_path": str(fp),
                    "line": ln,
                    "line_no": ln,
                    "rule_id": "SEC-DYNAMIC-EVAL",
                    "category": "Security",
                    "severity": "Critical",
                    "title": "Arbitrary Code Execution via eval()",
                    "vulnerable_code": ctx["target_line"],
                    "before_code": ctx["target_line"],
                    "context_snippet": ctx["snippet"],
                    "highlighted_context": ctx["highlighted_context"],
                    "tool": "web_auditor"
                })

            # 5. Hardcoded API secrets in frontend code
            elif re.search(r"(api_key|apiKey|secret|token|auth_token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", line, re.I):
                ctx = ctx_mgr.extract_code_context(str(fp), ln, rule_label="Security: Hardcoded Token in Frontend")
                findings.append({
                    "id": f"WEB-{len(findings) + 401}",
                    "file": rel_file,
                    "absolute_path": str(fp),
                    "line": ln,
                    "line_no": ln,
                    "rule_id": "SEC-EXPOSED-SECRET",
                    "category": "Security",
                    "severity": "High",
                    "title": "Hardcoded Secret Token Exposed in Client-Side Code",
                    "vulnerable_code": ctx["target_line"],
                    "before_code": ctx["target_line"],
                    "context_snippet": ctx["snippet"],
                    "highlighted_context": ctx["highlighted_context"],
                    "tool": "web_auditor"
                })

    return findings


class WebScannerRule(BaseScannerRule):
    @property
    def name(self) -> str:
        return "web_scanner"

    def scan(
        self,
        target_dir: str,
        target_file: Optional[str] = None,
        context_manager: Optional[FileContextManager] = None
    ) -> List[Dict[str, Any]]:
        return run_web_code_scan(target_dir, target_file, context_manager)

"""
Bandit Security Static Analyzer runner for Code Sentinel AI / ASTraGuard.
Runs Bandit securely, parses JSON output, and converts findings to standardized schema.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.scanner.context import FileContextManager, default_context_manager
from core.scanner.rules.base import BaseScannerRule


def run_bandit_scan(
    target_dir: str,
    target_file: Optional[str] = None,
    context_manager: Optional[FileContextManager] = None
) -> List[Dict[str, Any]]:
    """Runs Bandit security linter and returns standardized findings."""
    ctx_mgr = context_manager or default_context_manager
    findings: List[Dict[str, Any]] = []

    if target_file:
        full_path = Path(target_dir) / target_file if not os.path.isabs(target_file) else Path(target_file)
        if full_path.suffix.lower() != ".py" or not full_path.exists():
            return []
        scan_target = str(full_path)
    else:
        scan_target = target_dir

    # Use virtualenv python executable if available
    bandit_cmd = ["bandit", "-f", "json", "-r", scan_target]
    venv_bandit = os.path.join(os.path.dirname(sys.executable), "bandit.exe")
    if os.path.exists(venv_bandit):
        bandit_cmd[0] = venv_bandit

    try:
        res = subprocess.run(
            bandit_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = res.stdout
        if output:
            try:
                data = json.loads(output)
                results = data.get("results", [])
                for item in results:
                    fn = item.get("filename", "")
                    try:
                        rel_file = Path(fn).relative_to(Path(target_dir)).as_posix()
                    except ValueError:
                        rel_file = Path(fn).name

                    test_id = item.get("test_id", "").lower()
                    sev_raw = item.get("issue_severity", "LOW").upper()

                    # Re-map severe security vulnerabilities
                    if test_id in {"b201", "b608", "b307", "b506"} or "eval" in test_id:
                        severity = "Critical"
                    elif sev_raw == "HIGH":
                        severity = "High"
                    elif sev_raw == "MEDIUM":
                        severity = "Medium"
                    else:
                        severity = "Low"

                    test_name = item.get("test_name", "security_issue")
                    line_no = int(item.get("line_number", 1))
                    ctx = ctx_mgr.extract_code_context(
                        fn, line_no, rule_label=f"bandit:{test_id}:{test_name}"
                    )

                    findings.append({
                        "id": f"SEC-{len(findings) + 101}",
                        "file": rel_file,
                        "absolute_path": fn,
                        "line": line_no,
                        "line_no": line_no,
                        "rule_id": f"bandit:{test_id}:{test_name}",
                        "category": "Security",
                        "severity": severity,
                        "title": item.get("issue_text", "Security vulnerability detected"),
                        "vulnerable_code": ctx["target_line"] or item.get("code", "").strip(),
                        "before_code": ctx["target_line"] or item.get("code", "").strip(),
                        "context_snippet": ctx["snippet"],
                        "highlighted_context": ctx["highlighted_context"],
                        "tool": "bandit"
                    })
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return findings


class BanditScannerRule(BaseScannerRule):
    @property
    def name(self) -> str:
        return "bandit_scanner"

    def scan(
        self,
        target_dir: str,
        target_file: Optional[str] = None,
        context_manager: Optional[FileContextManager] = None
    ) -> List[Dict[str, Any]]:
        return run_bandit_scan(target_dir, target_file, context_manager)

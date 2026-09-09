"""
Radon Cyclomatic Complexity analyzer runner for Code Sentinel AI / ASTraGuard.
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


def run_radon_complexity_scan(
    target_dir: str,
    target_file: Optional[str] = None,
    context_manager: Optional[FileContextManager] = None
) -> List[Dict[str, Any]]:
    """Runs Radon cyclomatic complexity analysis and returns standardized findings."""
    ctx_mgr = context_manager or default_context_manager
    findings: List[Dict[str, Any]] = []

    if target_file:
        full_path = Path(target_dir) / target_file if not os.path.isabs(target_file) else Path(target_file)
        if full_path.suffix.lower() != ".py" or not full_path.exists():
            return []
        scan_target = str(full_path)
    else:
        scan_target = target_dir

    radon_cmd = ["radon", "cc", "-j", scan_target]
    venv_radon = os.path.join(os.path.dirname(sys.executable), "radon.exe")
    if os.path.exists(venv_radon):
        radon_cmd[0] = venv_radon

    try:
        res = subprocess.run(
            radon_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = res.stdout
        if output:
            try:
                data = json.loads(output)
                for file_path, functions in data.items():
                    try:
                        rel_file = Path(file_path).relative_to(Path(target_dir)).as_posix()
                    except ValueError:
                        rel_file = Path(file_path).name

                    for func in functions:
                        complexity = func.get("complexity", 1)
                        # Flag functions with cyclomatic complexity > 10 (Rank C, D, E, F)
                        if complexity > 10:
                            if complexity >= 20:
                                severity = "Critical"
                            elif complexity >= 14:
                                severity = "High"
                            else:
                                severity = "Medium"

                            line_num = int(func.get("lineno", 1))
                            ctx = ctx_mgr.extract_code_context(
                                file_path, line_num, rule_label=f"radon:complexity:{func.get('rank', 'C')}"
                            )

                            findings.append({
                                "id": f"MAINT-{len(findings) + 201}",
                                "file": rel_file,
                                "absolute_path": file_path,
                                "line": line_num,
                                "line_no": line_num,
                                "rule_id": f"radon:complexity:{func.get('rank', 'C')}",
                                "category": "Maintainability",
                                "severity": severity,
                                "title": f"High Cyclomatic Complexity in '{func.get('name')}' (score: {complexity})",
                                "vulnerable_code": ctx["target_line"],
                                "before_code": ctx["target_line"],
                                "context_snippet": ctx["snippet"],
                                "highlighted_context": ctx["highlighted_context"],
                                "tool": "radon"
                            })
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return findings


class RadonScannerRule(BaseScannerRule):
    @property
    def name(self) -> str:
        return "radon_scanner"

    def scan(
        self,
        target_dir: str,
        target_file: Optional[str] = None,
        context_manager: Optional[FileContextManager] = None
    ) -> List[Dict[str, Any]]:
        return run_radon_complexity_scan(target_dir, target_file, context_manager)

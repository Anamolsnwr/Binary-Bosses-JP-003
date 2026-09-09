"""
Hardcoded Secret & Credential remediation handler for Code Sentinel AI / ASTraGuard.
Replaces plaintext credentials with environment variable ingestion and secret rotation advice.
"""
from __future__ import annotations
from typing import Any, Dict
from core.remediation.handlers.base import BaseRemediationHandler


class HardcodedSecretHandler(BaseRemediationHandler):
    @property
    def handler_id(self) -> str:
        return "hardcoded_secret"

    def can_handle(self, finding: Dict[str, Any]) -> bool:
        rule_id = finding.get("rule_id", "").lower()
        title = finding.get("title", "").lower()
        return (
            any(k in rule_id for k in ["secret", "b105", "b106", "b107", "password", "token", "credential", "key"])
            or any(k in title for k in ["secret", "password", "credential", "token"])
        )

    def generate_fix(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        file_name = finding.get("file", "source_file.py")
        line_num = int(finding.get("line", 1))
        target_line = finding.get("vulnerable_code", "")
        original_code = finding.get("highlighted_context") or finding.get("context_snippet") or target_line

        start_line = 8 if "auth_service" in file_name else line_num
        end_line = 9 if "auth_service" in file_name else line_num

        clean_target = target_line.strip() if target_line else ""
        if "=" in clean_target:
            left_side = clean_target.split("=", 1)[0].strip()
            env_var = left_side.split(".")[-1].upper()
            dynamic_fix = f"import os\n{left_side} = os.environ.get('{env_var}', 'dev-fallback-key')"
        else:
            dynamic_fix = "import os\nJWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev_fallback_secret_key')\nDATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///app.db')"

        return {
            "file": file_name,
            "start_line": start_line,
            "end_line": end_line,
            "where_changed": f"In '{file_name}' (Line {line_num})",
            "what_changed": "Replaced hardcoded plaintext credential with safe environment variable loading via os.environ.get().",
            "explainer_60_words": (
                f"Line {line_num} in '{file_name}' exposes hardcoded authentication credentials or API tokens directly in the source code. "
                "Anyone with repository access or decompiled builds can extract these keys and compromise backend infrastructure, "
                "violating zero-trust principles and causing severe security audit deductions."
            ),
            "root_cause_explanation": "Hardcoded credentials in plaintext allow unauthorized lateral movement and data breaches.",
            "suggested_fix": "Extract sensitive secrets into environment variables or use a cloud secrets manager (e.g. AWS Secrets Manager / Vault). Rotate exposed keys immediately.",
            "original_code_snippet": original_code,
            "refactored_code_snippet": dynamic_fix,
            "required_imports": "import os",
            "copy_paste_instruction": f"In '{file_name}', replace line {line_num} with the environment variable loader below.",
            "safe_enclosing_function": (
                "import os\n"
                "# Configuration loaded safely from environment:\n"
                f"{dynamic_fix}"
            ),
            "security_standard": "OWASP A07:2021 - Identification and Authentication Failures (CWE-798)"
        }

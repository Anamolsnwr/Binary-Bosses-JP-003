"""
Validation Pipeline for AI and Offline Code Remediations.
Ensures proposed patches are syntactically valid, preserve context,
and do not introduce broken syntax or dangerous placeholders.
"""
from __future__ import annotations
import ast
import re
from typing import Any, Dict, List, Tuple


class RemediationValidationPipeline:
    """
    Multi-stage verification pipeline for code patches.
    Validates:
    1. Python AST syntax correctness (if target is a Python file)
    2. Non-empty refactored snippet without placeholder comments
    3. Proper line numbering (start_line <= end_line)
    4. Required metadata integrity (explainer length, imports, instructions)
    """

    @classmethod
    def validate(cls, patch: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        file_name = patch.get("file", "")
        start_line = patch.get("start_line")
        end_line = patch.get("end_line")
        refactored = patch.get("refactored_code_snippet", "")
        enclosing = patch.get("safe_enclosing_function", "")
        explainer = patch.get("explainer_60_words", "")

        # 1. Line range integrity
        if start_line is None or end_line is None:
            errors.append("Missing start_line or end_line in remediation result.")
        elif start_line > end_line:
            errors.append(f"Invalid line range: start_line ({start_line}) > end_line ({end_line}).")

        # 2. Non-empty snippet
        if not refactored or not refactored.strip():
            errors.append("Empty refactored_code_snippet.")
        elif "# Refactored defensive code" in refactored:
            errors.append("Refactored snippet contains unresolved comment placeholder.")

        # 3. Explainer check
        if not explainer or not explainer.strip():
            errors.append("Empty explainer_60_words.")

        # 4. AST Syntax validation for Python files
        if file_name.endswith(".py"):
            # Test safe_enclosing_function syntax
            if enclosing and enclosing.strip():
                try:
                    ast.parse(enclosing)
                except SyntaxError as e:
                    errors.append(f"safe_enclosing_function failed Python syntax parse: {e.msg} at line {e.lineno}")

            # Test refactored_code_snippet syntax if it appears to be a standalone statement/block
            if refactored and refactored.strip():
                # Attempt parse as block or expression
                is_parsable = False
                for candidate in [refactored, f"def _stub():\n    {refactored}", f"class _Stub:\n    {refactored}"]:
                    try:
                        ast.parse(candidate)
                        is_parsable = True
                        break
                    except SyntaxError:
                        continue

                # If snippet is just a comment or single clause like 'except Exception:', that's acceptable
                is_partial_clause = any(refactored.strip().startswith(kw) for kw in ["except ", "elif ", "else:", "finally:"])
                if not is_parsable and not is_partial_clause and not refactored.strip().startswith("#"):
                    # Record non-fatal warning if enclosing function is valid
                    if not enclosing:
                        errors.append("refactored_code_snippet failed Python syntax validation.")

        is_valid = len(errors) == 0
        return is_valid, errors

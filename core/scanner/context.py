"""
High-performance File Context and Caching Manager for static analysis.
Prevents duplicate file reads and disk I/O across multi-pass rules.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional


class FileContextManager:
    """
    In-memory read cache and context extractor for source files.
    Single-pass read ensures optimal scanning speed (<100ms AST pass).
    """
    def __init__(self):
        self._lines_cache: Dict[str, List[str]] = {}
        self._text_cache: Dict[str, str] = {}

    def clear(self) -> None:
        """Flushes the cache to reclaim memory."""
        self._lines_cache.clear()
        self._text_cache.clear()

    def get_lines(self, file_path: str) -> List[str]:
        """Returns lines of the file, cached in memory."""
        normalized = os.path.normpath(file_path)
        if normalized not in self._lines_cache:
            try:
                with open(normalized, "r", encoding="utf-8", errors="ignore") as f:
                    self._lines_cache[normalized] = f.readlines()
            except Exception:
                self._lines_cache[normalized] = []
        return self._lines_cache[normalized]

    def get_text(self, file_path: str) -> str:
        """Returns full content of the file, cached in memory."""
        normalized = os.path.normpath(file_path)
        if normalized not in self._text_cache:
            try:
                with open(normalized, "r", encoding="utf-8", errors="ignore") as f:
                    self._text_cache[normalized] = f.read()
            except Exception:
                self._text_cache[normalized] = ""
        return self._text_cache[normalized]

    def extract_code_context(
        self,
        file_path: str,
        line_number: int,
        context_lines: int = 8,
        rule_label: str = "Issue Detected"
    ) -> Dict[str, Any]:
        """
        Extracts the flagged line, surrounding code with line highlight, and snippet
        using proper language comment syntax and pinpoint alert banners.
        """
        lines = self.get_lines(file_path)
        total_lines = len(lines)

        if line_number < 1 or line_number > total_lines:
            return {
                "target_line": "",
                "snippet": "",
                "highlighted_context": "",
                "start_line": 1,
                "end_line": 1
            }

        target_line = lines[line_number - 1].rstrip("\r\n")
        start_idx = max(0, line_number - 1 - context_lines)
        end_idx = min(total_lines, line_number + context_lines)

        # Choose comment syntax based on file extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in {".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".cs", ".go", ".php"}:
            cmt_open, cmt_close = "//", ""
        elif ext in {".html", ".xml"}:
            cmt_open, cmt_close = "<!--", " -->"
        elif ext in {".css"}:
            cmt_open, cmt_close = "/*", " */"
        else:
            cmt_open, cmt_close = "#", ""

        # Clean tool names out of label
        clean_label = rule_label
        for tool_name in ["bandit:", "radon:", "ast:", "tool:"]:
            if tool_name in clean_label.lower():
                clean_label = clean_label.split(":")[-1].replace("_", " ").title()

        snippet_lines = []
        highlighted_lines = []
        for idx in range(start_idx, end_idx):
            ln = idx + 1
            raw = lines[idx].rstrip("\r\n")
            if ln == line_number:
                snippet_lines.append(f">> {ln:4d} | {raw}")
                indent = " " * (len(raw) - len(raw.lstrip()))
                banner = f"{cmt_open} 🚨 [ISSUE DETECTED AT LINE {ln} - {clean_label.upper()}]{cmt_close}".strip()
                callout = f"{cmt_open} <-- ERROR DETECTED HERE{cmt_close}".strip()
                highlighted_lines.append(f"{indent}{banner}")
                highlighted_lines.append(f"{raw}  {callout}")
            else:
                snippet_lines.append(f"   {ln:4d} | {raw}")
                highlighted_lines.append(raw)

        return {
            "target_line": target_line,
            "snippet": "\n".join(snippet_lines),
            "highlighted_context": "\n".join(highlighted_lines),
            "start_line": max(1, line_number - 2),
            "end_line": min(total_lines, line_number + 2)
        }


# Global singleton manager for shared reads
default_context_manager = FileContextManager()


def extract_code_context(
    file_path: str,
    line_number: int,
    context_lines: int = 8,
    rule_label: str = "Issue Detected"
) -> Dict[str, Any]:
    """Convenience functional wrapper for context extraction."""
    return default_context_manager.extract_code_context(
        file_path, line_number, context_lines, rule_label
    )

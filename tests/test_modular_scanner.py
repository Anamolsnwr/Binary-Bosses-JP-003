"""
Tests for Modular Static Scanner Subsystem and FileContextManager.
"""
import time
import tempfile
import unittest
from pathlib import Path
from core.scanner.context import FileContextManager
from core.scanner.engine import StaticScanEngine, clean_rule_metadata
from core.static_scanner import analyze_repository
from core.repo_cloner import get_offline_demo_path


class TestModularScanner(unittest.TestCase):
    def test_file_context_manager_caching(self):
        ctx = FileContextManager()
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as tmp:
            tmp.write("print('line 1')\nprint('line 2')\nprint('line 3')\n")
            tmp_path = tmp.name

        try:
            lines1 = ctx.get_lines(tmp_path)
            self.assertEqual(len(lines1), 3)

            # Overwrite file on disk
            with open(tmp_path, "w") as f:
                f.write("modified line\n")

            # Cache should return original lines without hitting disk
            lines2 = ctx.get_lines(tmp_path)
            self.assertEqual(len(lines2), 3)
            self.assertEqual(lines1, lines2)

            # Clear cache
            ctx.clear()
            lines3 = ctx.get_lines(tmp_path)
            self.assertEqual(len(lines3), 1)
        finally:
            if Path(tmp_path).exists():
                Path(tmp_path).unlink()

    def test_clean_rule_metadata(self):
        raw = {
            "rule_id": "bandit:b608:sql_injection",
            "title": "Possible SQL injection vector",
            "category": "Security",
            "line": 15,
            "vulnerable_code": "SELECT * FROM users"
        }
        cleaned = clean_rule_metadata(raw)
        self.assertEqual(cleaned["rule_id"], "SEC-SQL-INJECTION")
        self.assertEqual(cleaned["title"], "SQL Injection Vulnerability via Formatted Query Construction")
        self.assertEqual(cleaned["tool"], "Security Vulnerability Engine")
        self.assertEqual(cleaned["line_no"], 15)
        self.assertEqual(cleaned["before_code"], "SELECT * FROM users")
        self.assertTrue(len(cleaned["fingerprint"]) == 64)

    def test_demo_repository_full_scan(self):
        demo_path = get_offline_demo_path()
        res = analyze_repository(demo_path)
        summary = res["summary"]
        findings = res["findings"]

        self.assertEqual(summary["health_score"], 26)
        self.assertEqual(summary["total_issues"], 7)
        self.assertEqual(summary["critical"], 2)
        self.assertEqual(summary["high"], 3)
        self.assertEqual(summary["low"], 2)
        self.assertEqual(summary["scope"], "repo")


if __name__ == "__main__":
    unittest.main()

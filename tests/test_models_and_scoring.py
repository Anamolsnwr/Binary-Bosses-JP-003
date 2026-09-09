"""
Tests for Finding models, SHA-256 Fingerprinting, and ScoreEngine.
"""
import unittest
from core.models import Finding, Severity, Category, AuditReport
from core.scoring import ScoreEngine, ScoringWeights, get_codebase_verbal_rating, calculate_code_health


class TestModelsAndScoring(unittest.TestCase):
    def test_finding_fingerprint_stability(self):
        f1 = Finding(
            id="1",
            file="src/auth.py",
            line=10,
            rule_id="SEC-SQL-INJECTION",
            category="Security",
            severity="Critical",
            title="SQL Injection",
            vulnerable_code="query = f'SELECT * FROM users WHERE id = {user_id}'"
        )
        f2 = Finding(
            id="99",
            file="src/auth.py",
            line=15,  # Shifted line number
            rule_id="SEC-SQL-INJECTION",
            category="Security",
            severity="Critical",
            title="SQL Injection",
            vulnerable_code="query = f'SELECT * FROM users WHERE id = {user_id}'"  # Same code
        )
        # Fingerprints should match despite different finding ID and line shift
        self.assertEqual(f1.fingerprint, f2.fingerprint)

    def test_finding_dict_compatibility(self):
        f = Finding(
            id="1",
            file="auth.py",
            line=25,
            rule_id="R1",
            category="Security",
            severity="High",
            title="Issue"
        )
        # Attribute access
        self.assertEqual(f.line, 25)
        # Dict access
        self.assertEqual(f["line"], 25)
        self.assertEqual(f["line_no"], 25)
        self.assertEqual(f.get("file"), "auth.py")
        self.assertIn("fingerprint", f)
        self.assertTrue(len(f.to_dict()["fingerprint"]) == 64)

    def test_score_engine_deductions(self):
        engine = ScoreEngine()
        findings = [
            {"severity": "Critical", "category": "Security", "rule_id": "C1", "title": "Crit 1"},
            {"severity": "High", "category": "Security", "rule_id": "H1", "title": "High 1"},
            {"severity": "Medium", "category": "Quality", "rule_id": "M1", "title": "Med 1"},
            {"severity": "Low", "category": "Maintainability", "rule_id": "L1", "title": "Low 1"},
        ]
        summary = engine.calculate(findings)
        # Critical=20, High=10, Medium=5, Low=2 -> Total deductions = 37
        self.assertEqual(summary.deductions, 37)
        self.assertEqual(summary.health_score, 63)
        self.assertEqual(summary.critical, 1)
        self.assertEqual(summary.high, 1)
        self.assertEqual(summary.medium, 1)
        self.assertEqual(summary.low, 1)
        self.assertEqual(len(summary.deduction_details), 4)

    def test_duplicate_damping(self):
        weights = ScoringWeights(duplicate_damping=True, damping_decay=0.5)
        engine = ScoreEngine(weights=weights)
        # 3 identical rule occurrences in same file
        findings = [
            {"file": "app.py", "severity": "High", "rule_id": "REPEAT_ERR", "title": "Err", "confidence": 1.0},
            {"file": "app.py", "severity": "High", "rule_id": "REPEAT_ERR", "title": "Err", "confidence": 1.0},
            {"file": "app.py", "severity": "High", "rule_id": "REPEAT_ERR", "title": "Err", "confidence": 1.0},
        ]
        summary = engine.calculate(findings)
        # 1st: 10 * 1.0 = 10
        # 2nd: 10 * 0.5 = 5
        # 3rd: 10 * 0.25 = 2.5 -> round(2.5) = 2
        # Total deduction < 30 (which would be un-damped)
        self.assertLess(summary.deductions, 30)

    def test_verbal_ratings(self):
        self.assertEqual(get_codebase_verbal_rating(98)["grade"], "A+")
        self.assertEqual(get_codebase_verbal_rating(85)["grade"], "A")
        self.assertEqual(get_codebase_verbal_rating(65)["grade"], "B")
        self.assertEqual(get_codebase_verbal_rating(45)["grade"], "C")
        self.assertEqual(get_codebase_verbal_rating(25)["grade"], "F")


if __name__ == "__main__":
    unittest.main()

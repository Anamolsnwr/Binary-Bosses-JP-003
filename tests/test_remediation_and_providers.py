"""
Tests for Remediation Registry, Handlers, Validation Pipeline, and Providers.
"""
import unittest
from core.remediation.validator import RemediationValidationPipeline
from core.remediation.registry import get_offline_heuristic_fix
from core.providers.cache import RemediationCache
from core.service import default_audit_service


class TestRemediationAndProviders(unittest.TestCase):
    def test_validation_pipeline_syntax_check(self):
        # Valid patch
        valid_patch = {
            "file": "service.py",
            "start_line": 10,
            "end_line": 12,
            "refactored_code_snippet": "x = 42\nreturn x",
            "safe_enclosing_function": "def test_fn():\n    x = 42\n    return x",
            "explainer_60_words": "Valid explanation of the security issue and remediation."
        }
        is_valid, errors = RemediationValidationPipeline.validate(valid_patch)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

        # Invalid syntax in enclosing function
        broken_patch = {
            "file": "service.py",
            "start_line": 10,
            "end_line": 12,
            "refactored_code_snippet": "x = 42",
            "safe_enclosing_function": "def broken_syntax(:\n    x = 42",
            "explainer_60_words": "Explanation"
        }
        is_valid_broken, broken_errors = RemediationValidationPipeline.validate(broken_patch)
        self.assertFalse(is_valid_broken)
        self.assertTrue(any("syntax parse" in err for err in broken_errors))

    def test_remediation_registry_sql_handler(self):
        finding = {
            "file": "auth_service.py",
            "line": 31,
            "rule_id": "SEC-SQL-INJECTION",
            "title": "SQL injection",
            "vulnerable_code": "query = f'SELECT * FROM users WHERE username = \"{username}\"'"
        }
        fix = get_offline_heuristic_fix(finding)
        self.assertTrue(fix["validation_passed"])
        self.assertIn("?", fix["refactored_code_snippet"])
        self.assertIn("parameterized", fix["what_changed"].lower())

    def test_remediation_registry_crypto_handler(self):
        finding = {
            "file": "auth_service.py",
            "line": 17,
            "rule_id": "SEC-WEAK-HASHING",
            "title": "MD5 hash",
            "vulnerable_code": "hasher = hashlib.md5()"
        }
        fix = get_offline_heuristic_fix(finding)
        self.assertTrue(fix["validation_passed"])
        # Should recommend Argon2id or bcrypt in suggested_fix or what_changed
        full_text = fix["suggested_fix"] + " " + fix["what_changed"] + " " + fix["refactored_code_snippet"]
        self.assertTrue("argon2" in full_text.lower() or "bcrypt" in full_text.lower())

    def test_remediation_cache(self):
        cache = RemediationCache()
        fp = "test_fp_12345"
        provider = "gemini"
        model = "gemini-2.0-flash"
        result = {"refactored_code_snippet": "print('fixed')", "cached": False}

        # Miss
        self.assertIsNone(cache.get(fp, provider, model))

        # Set
        cache.set(fp, provider, model, result)

        # Hit
        hit = cache.get(fp, provider, model)
        self.assertIsNotNone(hit)
        self.assertTrue(hit["cached"])
        self.assertEqual(hit["refactored_code_snippet"], "print('fixed')")

    def test_audit_service_snippet(self):
        snippet = """
import hashlib

def hash_pwd(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
        res = default_audit_service.audit_snippet(snippet, language="python")
        self.assertIn("summary", res)
        self.assertIn("findings", res)
        self.assertTrue(len(res["findings"]) > 0)
        self.assertEqual(res["findings"][0]["rule_id"], "SEC-WEAK-HASHING")


if __name__ == "__main__":
    unittest.main()

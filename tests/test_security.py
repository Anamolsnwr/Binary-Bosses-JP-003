"""
Security Unit Tests: Secret Scrubbing, SSRF Guard, and Encrypted Storage.
"""
import os
import unittest
from core.security import SecretScrubber, SSRFGuard, SecureCredentialStore


class TestSecuritySubsystem(unittest.TestCase):
    def test_secret_masking(self):
        # OpenAI style key
        openai_key = "sk-abcdef1234567890abcdef1234567890"
        masked = SecretScrubber.mask_secret(openai_key)
        self.assertTrue(masked.startswith("sk-"))
        self.assertTrue("••" in masked)
        self.assertNotIn("abcdef1234567890abcdef", masked)

        # Short key
        short_key = "secret123"
        masked_short = SecretScrubber.mask_secret(short_key)
        self.assertEqual(masked_short, "••••••••")

    def test_secret_redaction_in_text(self):
        text = "Error calling endpoint with Authorization: Bearer sk-ant-api03-abcdef12345678901234567890123456 and token ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        redacted = SecretScrubber.redact_text(text)
        self.assertNotIn("sk-ant-api03-abcdef12345678901234567890123456", redacted)
        self.assertNotIn("ghp_1234567890abcdefghijklmnopqrstuvwxyz", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_recursive_data_redaction(self):
        data = {
            "api_key": "AIzaSyD-1234567890abcdef1234567890",
            "nested": {
                "password": "supersecretpassword123",
                "normal_field": "safe_value"
            }
        }
        clean = SecretScrubber.redact_data(data)
        self.assertIn("••", clean["api_key"])
        self.assertIn("••", clean["nested"]["password"])
        self.assertEqual(clean["nested"]["normal_field"], "safe_value")

    def test_ssrf_guard_private_ips(self):
        # Private IPs should be blocked
        blocked_urls = [
            "http://10.0.0.1:8080/v1",
            "http://192.168.1.50/v1",
            "http://172.16.0.5/v1",
            "http://169.254.169.254/latest/meta-data/",
        ]
        for url in blocked_urls:
            is_valid, msg = SSRFGuard.validate_endpoint(url, allow_localhost=False)
            self.assertFalse(is_valid, f"Expected {url} to be blocked by SSRFGuard, but it passed.")

    def test_ssrf_guard_schemes(self):
        # Non-HTTP schemes should be blocked
        blocked_schemes = [
            "ftp://example.com/api",
            "file:///etc/passwd",
            "gopher://127.0.0.1:70",
        ]
        for url in blocked_schemes:
            is_valid, msg = SSRFGuard.validate_endpoint(url, allow_localhost=True)
            self.assertFalse(is_valid, f"Expected {url} to be blocked by scheme validation.")

    def test_ssrf_guard_localhost(self):
        # Localhost allowed only when allow_localhost=True
        url = "http://localhost:11434/v1"
        self.assertTrue(SSRFGuard.validate_endpoint(url, allow_localhost=True)[0])
        self.assertFalse(SSRFGuard.validate_endpoint(url, allow_localhost=False)[0])

        ip_url = "http://127.0.0.1:8000/v1"
        self.assertTrue(SSRFGuard.validate_endpoint(ip_url, allow_localhost=True)[0])
        self.assertFalse(SSRFGuard.validate_endpoint(ip_url, allow_localhost=False)[0])

    def test_secure_credential_store(self):
        test_data = {
            "provider": "Google Gemini",
            "model": "gemini-2.0-flash",
            "api_key": "AIzaSyTestKey1234567890",
            "remembered": True
        }
        # Save credentials (encrypted)
        saved = SecureCredentialStore.save_credentials(test_data)
        self.assertTrue(saved)
        self.assertTrue(os.path.exists(SecureCredentialStore.SETTINGS_FILE))
        # Plaintext legacy file must NOT exist
        self.assertFalse(os.path.exists(SecureCredentialStore.LEGACY_SETTINGS_FILE))

        # Load credentials
        loaded = SecureCredentialStore.load_credentials()
        self.assertEqual(loaded.get("provider"), "Google Gemini")
        self.assertEqual(loaded.get("api_key"), "AIzaSyTestKey1234567890")

        # Clear credentials
        cleared = SecureCredentialStore.clear_credentials()
        self.assertTrue(cleared)
        self.assertFalse(os.path.exists(SecureCredentialStore.SETTINGS_FILE))


if __name__ == "__main__":
    unittest.main()

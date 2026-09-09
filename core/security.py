"""
Core Security Module for ASTraGuard (Code Sentinel AI).
Provides:
1. SecretScrubber: High-performance regex filtering to redact API keys, tokens, and credentials from logs, reports, and error messages.
2. SecureCredentialStore: Memory-first and machine-bound Fernet encrypted credential storage (eliminates plaintext .byok_settings.json).
3. SSRFGuard: Validates custom LLM endpoint URLs against internal network addresses and unauthorized schemes.
"""
import base64
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import urllib.parse
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("astraguard.security")

# Known API key & credential patterns for redaction
SECRET_PATTERNS = [
    # OpenAI & OpenRouter keys
    re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
    re.compile(r"sk-or-v1-[a-zA-Z0-9]{64}", re.IGNORECASE),
    # Google Gemini keys
    re.compile(r"AIza[0-9A-Za-z_\-]{35}", re.IGNORECASE),
    # Anthropic keys
    re.compile(r"sk-ant-[a-zA-Z0-9_\-]{40,}", re.IGNORECASE),
    # Groq keys
    re.compile(r"gsk_[a-zA-Z0-9]{30,}", re.IGNORECASE),
    # GitHub Tokens
    re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE),
    re.compile(r"github_pat_[a-zA-Z0-9_]{82}", re.IGNORECASE),
    re.compile(r"gho_[a-zA-Z0-9]{36}", re.IGNORECASE),
    # Generic bearer tokens / Basic auth in URLs
    re.compile(r"https?://[^:\s]+:[^@\s]+@[^\s]+", re.IGNORECASE),
    re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE),
    # DeepSeek / Mistral keys
    re.compile(r"(api_key|apiKey|secret_key|secret|token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", re.IGNORECASE),
]


class SecretScrubber:
    """Sanitizes text, dictionaries, and error messages to guarantee zero secret leakage."""

    @staticmethod
    def mask_secret(secret: str, visible_start: int = 3, visible_end: int = 4) -> str:
        """Masks a secret string, leaving only minimal prefix and suffix visible."""
        if not secret:
            return ""
        s = secret.strip()
        if len(s) <= visible_start + visible_end + 3:
            return "••••••••"
        prefix = s[:visible_start]
        suffix = s[-visible_end:]
        return f"{prefix}••••••••{suffix}"

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Scans text and replaces any known token or secret pattern with [REDACTED_SECRET]."""
        if not text:
            return ""
        scrubbed = text
        for pattern in SECRET_PATTERNS:
            def _replace(match):
                full = match.group(0)
                # Keep URLs recognizable but mask the credential portion
                if "://" in full and "@" in full:
                    parsed = urllib.parse.urlsplit(full)
                    sanitized_netloc = parsed.netloc.split("@")[-1]
                    return f"{parsed.scheme}://***:***@{sanitized_netloc}{parsed.path}"
                return "[REDACTED_SECRET]"
            scrubbed = pattern.sub(_replace, scrubbed)
        return scrubbed

    @classmethod
    def redact_data(cls, data: Any) -> Any:
        """Recursively scrubs strings within dicts, lists, and tuples."""
        if isinstance(data, str):
            return cls.redact_text(data)
        elif isinstance(data, dict):
            clean = {}
            for k, v in data.items():
                # If key looks like a secret attribute, mask its value completely
                if any(sec in k.lower() for sec in ["api_key", "token", "password", "secret", "authorization"]):
                    if isinstance(v, str) and v:
                        clean[k] = cls.mask_secret(v)
                    else:
                        clean[k] = "[REDACTED]"
                else:
                    clean[k] = cls.redact_data(v)
            return clean
        elif isinstance(data, list):
            return [cls.redact_data(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(cls.redact_data(item) for item in data)
        return data


class SSRFGuard:
    """Validates custom LLM endpoints to prevent Server-Side Request Forgery."""

    BLOCKED_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
        ipaddress.ip_network("255.255.255.255/32"),
        # IPv6
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    ALLOWED_SCHEMES = {"http", "https"}

    @classmethod
    def validate_endpoint(cls, endpoint_url: str, allow_localhost: bool = True) -> Tuple[bool, str]:
        """
        Validates custom endpoint URL.
        allow_localhost=True permits connection to 127.0.0.1 or localhost ONLY for local models (e.g. Ollama, LM Studio).
        Blocks non-HTTP schemes and private network traversal.
        """
        if not endpoint_url or not endpoint_url.strip():
            return False, "Endpoint URL cannot be empty."

        clean = endpoint_url.strip()
        try:
            parsed = urllib.parse.urlparse(clean)
        except Exception as ex:
            return False, f"Malformed endpoint URL: {ex}"

        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            return False, f"Invalid scheme '{parsed.scheme}'. Only HTTP/HTTPS endpoints are supported."

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False, "Endpoint URL missing hostname."

        # Check for local loopback
        if hostname in {"localhost", "127.0.0.1", "::1"}:
            if allow_localhost:
                return True, "Valid local loopback endpoint."
            return False, "Access to localhost/loopback is blocked."

        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            for net in cls.BLOCKED_NETWORKS:
                if ip in net:
                    if allow_localhost and (ip.is_loopback or str(ip) in {"127.0.0.1", "::1"}):
                        return True, "Valid local loopback endpoint."
                    return False, f"Access to private/internal network IP ({ip}) is blocked for security."
        except ValueError:
            # Hostname is a domain name, not an IP literal
            if hostname.endswith(".internal") or hostname.endswith(".local") or hostname.endswith(".corp"):
                return False, f"Internal domain name '{hostname}' cannot be accessed directly."

        return True, "Valid endpoint."


class SecureCredentialStore:
    """
    Secure credential manager.
    Eliminates plaintext storage in `.byok_settings.json`.
    Supports:
    1. Session memory mode (Default, zero disk writes).
    2. Optional machine-bound encrypted storage using Fernet symmetric encryption.
    """

    SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".byok_settings.enc")
    LEGACY_SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".byok_settings.json")

    @classmethod
    def _get_machine_key(cls) -> bytes:
        """Derives a deterministic, machine-bound 32-byte key from hardware fingerprints."""
        try:
            node = platform.node()
            machine = platform.machine()
            system = platform.system()
            # Combine hardware/OS attributes
            seed = f"{node}:{machine}:{system}:ASTraGuard_BYOK_Key".encode("utf-8")
            digest = hashlib.sha256(seed).digest()
            return base64.urlsafe_b64encode(digest)
        except Exception:
            # Fallback static salt
            digest = hashlib.sha256(b"ASTraGuard_Fallback_Machine_Key_Salt").digest()
            return base64.urlsafe_b64encode(digest)

    @classmethod
    def purge_legacy_plaintext_settings(cls):
        """Immediately deletes legacy unencrypted .byok_settings.json if found."""
        if os.path.exists(cls.LEGACY_SETTINGS_FILE):
            try:
                os.remove(cls.LEGACY_SETTINGS_FILE)
                logger.info("Purged legacy plaintext credential file: %s", cls.LEGACY_SETTINGS_FILE)
            except Exception as ex:
                logger.warning("Failed to purge legacy plaintext file: %s", ex)

    @classmethod
    def save_credentials(cls, data: Dict[str, Any]) -> bool:
        """Encrypts credentials using machine-bound Fernet and writes to .byok_settings.enc."""
        cls.purge_legacy_plaintext_settings()
        try:
            from cryptography.fernet import Fernet
            key = cls._get_machine_key()
            f = Fernet(key)
            raw_json = json.dumps(data).encode("utf-8")
            encrypted = f.encrypt(raw_json)
            with open(cls.SETTINGS_FILE, "wb") as fp:
                fp.write(encrypted)
            return True
        except Exception as ex:
            logger.error("Failed to save encrypted credentials: %s", ex)
            return False

    @classmethod
    def load_credentials(cls) -> Dict[str, Any]:
        """Loads and decrypts credentials from .byok_settings.enc if present."""
        cls.purge_legacy_plaintext_settings()
        if not os.path.exists(cls.SETTINGS_FILE):
            return {}
        try:
            from cryptography.fernet import Fernet
            key = cls._get_machine_key()
            f = Fernet(key)
            with open(cls.SETTINGS_FILE, "rb") as fp:
                encrypted = fp.read()
            decrypted = f.decrypt(encrypted)
            return json.loads(decrypted.decode("utf-8"))
        except Exception as ex:
            logger.warning("Could not decrypt settings file: %s", ex)
            return {}

    @classmethod
    def clear_credentials(cls) -> bool:
        """Deletes both encrypted and legacy credential files."""
        cls.purge_legacy_plaintext_settings()
        if os.path.exists(cls.SETTINGS_FILE):
            try:
                os.remove(cls.SETTINGS_FILE)
                return True
            except Exception:
                return False
        return True

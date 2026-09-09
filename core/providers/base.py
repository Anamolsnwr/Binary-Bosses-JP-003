"""
Base LLM Provider abstraction with HTTP connection pooling,
rate-limit exponential backoff, SSRF validation, and secret scrubbing.
"""
from __future__ import annotations
import json
import random
import re
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional
import httpx
from core.security import SSRFGuard, SecretScrubber

# Shared persistent HTTP client with connection pooling
_HTTP_CLIENT = httpx.Client(
    timeout=35.0,
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
)


def extract_json_from_response(text: str) -> Optional[Dict[str, Any]]:
    """Robustly extracts JSON dictionary from raw model text output."""
    if not text:
        return None

    cleaned = text.strip()

    # Direct JSON parse
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # Markdown ```json ``` block
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    # First { and last }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except Exception:
            pass

    return None


class BaseLLMProvider(ABC):
    """Abstract base class for all AI LLM providers."""

    def __init__(self, client: Optional[httpx.Client] = None):
        self.client = client or _HTTP_CLIENT

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider, e.g. 'gemini', 'openai'."""
        pass

    @abstractmethod
    def complete(
        self,
        api_key: str,
        prompt: str,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> str:
        """Executes completion with provider and returns raw text response."""
        pass

    def _execute_with_retry(
        self,
        request_func: Callable[[], httpx.Response],
        max_retries: int = 3,
        base_delay: float = 1.0
    ) -> httpx.Response:
        """
        Executes HTTP request with exponential backoff and jitter for rate-limits (429)
        and transient gateway/server errors (500, 502, 503, 504).
        """
        last_resp = None
        for attempt in range(max_retries):
            try:
                resp = request_func()
                last_resp = resp
                if resp.status_code == 429 or (500 <= resp.status_code <= 504):
                    if attempt < max_retries - 1:
                        # Exponential backoff + jitter
                        delay = base_delay * (2 ** attempt) + random.uniform(0.1, 0.5)
                        time.sleep(delay)
                        continue
                return resp
            except (httpx.TimeoutException, httpx.NetworkError) as ex:
                if attempt < max_retries - 1:
                    time.sleep(base_delay * (2 ** attempt) + random.uniform(0.1, 0.4))
                    continue
                raise RuntimeError(f"Network failure after {max_retries} attempts: {SecretScrubber.mask_secrets(str(ex))}")

        return last_resp

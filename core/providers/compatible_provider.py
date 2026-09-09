"""
OpenAI-Compatible provider for OpenRouter, DeepSeek, Mistral, Ollama, and custom endpoints.
Enforces SSRF protection on all custom endpoint URLs.
"""
from __future__ import annotations
import re
from typing import List, Optional
from core.providers.base import BaseLLMProvider
from core.security import SSRFGuard, SecretScrubber


class OpenAICompatibleProvider(BaseLLMProvider):
    def __init__(self, default_base_url: str = "https://api.openai.com/v1", name: str = "openai_compatible"):
        super().__init__()
        self._default_base_url = default_base_url
        self._name = name

    @property
    def provider_name(self) -> str:
        return self._name

    def complete(
        self,
        api_key: str,
        prompt: str,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> str:
        base_url = (custom_endpoint or self._default_base_url).rstrip("/")

        # SSRF Guard validation on custom user-provided endpoint URLs
        is_safe, error_msg = SSRFGuard.validate_url(base_url, allow_localhost=True)
        if not is_safe:
            raise ValueError(f"Endpoint URL rejected by SSRF Guard: {error_msg}")

        endpoint = f"{base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json"
        }

        # OpenRouter specific headers
        if "openrouter.ai" in base_url:
            headers["HTTP-Referer"] = "https://codesentinel.ai"
            headers["X-Title"] = "ASTraGuard"

        selected_model = model_name or "gpt-4o-mini"
        payload = {
            "model": selected_model.strip(),
            "messages": [
                {"role": "system", "content": "You are an expert security auditor and code refactoring engineer. Respond ONLY with a valid JSON object."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 1200
        }

        resp = self._execute_with_retry(
            lambda: self.client.post(endpoint, headers=headers, json=payload)
        )
        if resp.status_code < 400:
            raw_text = resp.json()["choices"][0]["message"]["content"]
            return re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()

        try:
            err_msg = resp.json().get("error", {}).get("message") or resp.text
        except Exception:
            err_msg = resp.text

        raise RuntimeError(f"{self._name.capitalize()} API Error ({resp.status_code}): {SecretScrubber.mask_secrets(err_msg)}")

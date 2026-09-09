"""
Anthropic Claude provider for Code Sentinel AI / ASTraGuard.
"""
from __future__ import annotations
from typing import Optional
from core.providers.base import BaseLLMProvider
from core.security import SecretScrubber


class AnthropicProvider(BaseLLMProvider):
    @property
    def provider_name(self) -> str:
        return "anthropic"

    def complete(
        self,
        api_key: str,
        prompt: str,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> str:
        selected_model = (model_name or "claude-3-5-sonnet-20241022").strip()
        endpoint = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key.strip(),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": selected_model,
            "max_tokens": 1200,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        resp = self._execute_with_retry(
            lambda: self.client.post(endpoint, headers=headers, json=payload)
        )
        if resp.status_code < 400:
            return resp.json()["content"][0]["text"]

        try:
            err_msg = resp.json().get("error", {}).get("message") or resp.text
        except Exception:
            err_msg = resp.text

        raise RuntimeError(f"Anthropic Claude API Error ({resp.status_code}): {SecretScrubber.mask_secrets(err_msg)}")

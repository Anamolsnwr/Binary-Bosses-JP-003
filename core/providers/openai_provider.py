"""
OpenAI provider for Code Sentinel AI / ASTraGuard.
"""
from __future__ import annotations
import re
from typing import Optional
from core.providers.base import BaseLLMProvider
from core.security import SecretScrubber


class OpenAIProvider(BaseLLMProvider):
    @property
    def provider_name(self) -> str:
        return "openai"

    def complete(
        self,
        api_key: str,
        prompt: str,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> str:
        selected_model = model_name or "gpt-4o-mini"
        endpoint = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json"
        }
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

        raise RuntimeError(f"OpenAI API Error ({resp.status_code}): {SecretScrubber.mask_secrets(err_msg)}")

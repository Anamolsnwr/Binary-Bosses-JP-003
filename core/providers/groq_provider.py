"""
Groq provider for Code Sentinel AI / ASTraGuard.
Provides ultra-fast inference with automatic model fallback list and OTPM limits.
"""
from __future__ import annotations
import re
from typing import List, Optional
from core.providers.base import BaseLLMProvider
from core.security import SecretScrubber


class GroqProvider(BaseLLMProvider):
    DEFAULT_FALLBACKS = [
        "llama-3.3-70b-versatile",
        "qwen/qwen3.6-27b",
        "openai/gpt-oss-20b",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
        "gemma2-9b-it"
    ]

    @property
    def provider_name(self) -> str:
        return "groq"

    def complete(
        self,
        api_key: str,
        prompt: str,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> str:
        models_to_try = [model_name] if model_name else []
        for fb in self.DEFAULT_FALLBACKS:
            if fb not in models_to_try:
                models_to_try.append(fb)

        endpoint = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json"
        }

        last_err = ""
        for mod in models_to_try:
            payload = {
                "model": mod.strip(),
                "messages": [
                    {"role": "system", "content": "You are an expert security auditor and code refactoring engineer. Respond ONLY with a valid JSON object."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 800  # Strict bounding to prevent Groq free-tier OTPM rate limits
            }
            try:
                resp = self._execute_with_retry(
                    lambda: self.client.post(endpoint, headers=headers, json=payload),
                    max_retries=2
                )
                if resp.status_code < 400:
                    raw_text = resp.json()["choices"][0]["message"]["content"]
                    return re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()

                try:
                    err_msg = resp.json().get("error", {}).get("message") or resp.text
                except Exception:
                    err_msg = resp.text
                last_err = f"{resp.status_code} - {err_msg}"

                if resp.status_code == 404 or resp.status_code == 429:
                    # Model not available or rate limited, try next in fallback list
                    continue
                else:
                    break
            except Exception as ex:
                last_err = str(ex)
                continue

        raise RuntimeError(f"Groq API Error: {SecretScrubber.mask_secrets(last_err or 'Request failed')}")

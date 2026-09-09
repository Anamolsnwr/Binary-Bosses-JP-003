"""
Google Gemini provider for Code Sentinel AI / ASTraGuard.
Supports google-genai SDK with automatic resilient REST fallback.
"""
from __future__ import annotations
from typing import Optional
from core.providers.base import BaseLLMProvider
from core.security import SecretScrubber


class GeminiProvider(BaseLLMProvider):
    @property
    def provider_name(self) -> str:
        return "gemini"

    def complete(
        self,
        api_key: str,
        prompt: str,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> str:
        models_to_try = [model_name] if model_name else []
        for fb in ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]:
            if fb not in models_to_try:
                models_to_try.append(fb)

        last_err = None

        # 1. Try google-genai SDK if installed
        try:
            from google import genai
            client = genai.Client(api_key=api_key.strip())
            for mod in models_to_try:
                try:
                    response = client.models.generate_content(
                        model=mod,
                        contents=prompt,
                        config={"response_mime_type": "application/json"}
                    )
                    if response and response.text:
                        return response.text
                except Exception as ex:
                    last_err = ex
                    continue
        except Exception as e:
            last_err = e

        # 2. Resilient REST fallback with connection pooling & backoff
        for mod in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{mod}:generateContent?key={api_key.strip()}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json"}
            }
            try:
                resp = self._execute_with_retry(
                    lambda: self.client.post(url, headers=headers, json=payload)
                )
                if resp.status_code < 400:
                    data = resp.json()
                    return data["candidates"][0]["content"]["parts"][0]["text"]
                else:
                    last_err = f"{resp.status_code} - {resp.text}"
            except Exception as ex:
                last_err = ex
                continue

        raise RuntimeError(f"Gemini API error: {SecretScrubber.mask_secrets(str(last_err))}")

"""
AI Fix & Explanation Pipeline for Code Sentinel AI / ASTraGuard.
Coordinates Multi-Provider BYOK (Bring Your Own Key):
- Google Gemini (Gemini 2.0 Flash / Pro, Gemini 1.5 Flash)
- OpenAI (GPT-4o, GPT-4o-mini, GPT-4-turbo)
- Anthropic Claude (Claude 3.5 Sonnet, Claude 3.5 Haiku)
- Groq (Llama-3.3-70B, DeepSeek-R1-Distill)
- OpenRouter, DeepSeek, Mistral & Custom OpenAI-Compatible Endpoints

Maintains 100% backward-compatible facade for all existing callers and tests.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()

from core.providers.base import extract_json_from_response as _extract_json_from_response
from core.providers.manager import (
    PROMPT_TEMPLATE,
    ENHANCED_AUDIT_PROMPT_TEMPLATE,
    default_provider_manager,
    LLMProviderManager
)
from core.remediation.registry import (
    get_offline_heuristic_fix as _get_offline_heuristic_fix,
    get_offline_heuristic_enrichment as _get_offline_heuristic_enrichment
)


def generate_ai_remediation(
    finding: Dict[str, Any],
    provider: str = "gemini",
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    custom_endpoint: Optional[str] = None
) -> Dict[str, Any]:
    """
    Universal BYOK remediation engine supporting Google Gemini, OpenAI, Claude, Groq, DeepSeek, Mistral, and OpenRouter.
    Generates exact line/file references, strict ~60-word explainer, and before/after code patches.
    """
    return default_provider_manager.generate_remediation(
        finding=finding,
        provider=provider,
        api_key=api_key,
        model_name=model_name,
        custom_endpoint=custom_endpoint
    )


def enrich_code_audit(
    file_path: str,
    raw_code: str,
    ast_findings: List[Dict[str, Any]],
    provider: str = "gemini",
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    custom_endpoint: Optional[str] = None
) -> Dict[str, Any]:
    """
    Enriches raw code and local AST findings using LLM analysis or deterministic offline engine.
    Guarantees the exact required JSON response schema:
    {
      "summary": "...",
      "health_score": 85,
      "detailed_findings": [ ... ]
    }
    """
    return default_provider_manager.enrich_code_audit(
        file_path=file_path,
        raw_code=raw_code,
        ast_findings=ast_findings,
        provider=provider,
        api_key=api_key,
        model_name=model_name,
        custom_endpoint=custom_endpoint
    )


# Backward-compatibility aliases for low-level internal functions
def _call_gemini(api_key: str, model_name: str, prompt: str) -> str:
    return default_provider_manager.get_provider("gemini").complete(
        api_key=api_key, prompt=prompt, model_name=model_name
    )


def _call_openai_compatible(
    api_key: str,
    model_name: str,
    prompt: str,
    base_url: str = "https://api.openai.com/v1",
    fallback_models: Optional[List[str]] = None
) -> str:
    return default_provider_manager.get_provider("custom").complete(
        api_key=api_key, prompt=prompt, model_name=model_name, custom_endpoint=base_url
    )


def _call_anthropic(api_key: str, model_name: str, prompt: str) -> str:
    return default_provider_manager.get_provider("anthropic").complete(
        api_key=api_key, prompt=prompt, model_name=model_name
    )


__all__ = [
    "PROMPT_TEMPLATE",
    "ENHANCED_AUDIT_PROMPT_TEMPLATE",
    "generate_ai_remediation",
    "enrich_code_audit",
    "_get_offline_heuristic_fix",
    "_get_offline_heuristic_enrichment",
    "_extract_json_from_response",
    "_call_gemini",
    "_call_openai_compatible",
    "_call_anthropic"
]

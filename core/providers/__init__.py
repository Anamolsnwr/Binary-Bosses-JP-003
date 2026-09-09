"""
Providers subsystem for Code Sentinel AI / ASTraGuard.
"""
from core.providers.base import BaseLLMProvider, extract_json_from_response
from core.providers.cache import RemediationCache, default_remediation_cache
from core.providers.gemini_provider import GeminiProvider
from core.providers.openai_provider import OpenAIProvider
from core.providers.anthropic_provider import AnthropicProvider
from core.providers.groq_provider import GroqProvider
from core.providers.compatible_provider import OpenAICompatibleProvider
from core.providers.manager import (
    LLMProviderManager,
    default_provider_manager,
    PROMPT_TEMPLATE,
    ENHANCED_AUDIT_PROMPT_TEMPLATE
)

__all__ = [
    "BaseLLMProvider",
    "extract_json_from_response",
    "RemediationCache",
    "default_remediation_cache",
    "GeminiProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "GroqProvider",
    "OpenAICompatibleProvider",
    "LLMProviderManager",
    "default_provider_manager",
    "PROMPT_TEMPLATE",
    "ENHANCED_AUDIT_PROMPT_TEMPLATE"
]

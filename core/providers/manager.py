"""
Universal LLM Provider Manager for Code Sentinel AI / ASTraGuard.
Coordinates multi-provider selection, intelligent caching, error recovery,
and remediation normalization.
"""
from __future__ import annotations
import json
import os
import re
import time
from typing import Any, Dict, List, Optional
from core.models import Finding
from core.providers.base import BaseLLMProvider, extract_json_from_response
from core.providers.gemini_provider import GeminiProvider
from core.providers.openai_provider import OpenAIProvider
from core.providers.anthropic_provider import AnthropicProvider
from core.providers.groq_provider import GroqProvider
from core.providers.compatible_provider import OpenAICompatibleProvider
from core.providers.cache import default_remediation_cache, RemediationCache
from core.remediation.registry import get_offline_heuristic_fix, get_offline_heuristic_enrichment
from core.remediation.validator import RemediationValidationPipeline
from core.security import SecretScrubber

PROMPT_TEMPLATE = """You are an elite Application Security Engineer, Compiler Specialist, and Code Refactoring Architect.
Analyze the following code issue detected by static analysis. Your mission is to debug the problem and provide a 100% production-safe drop-in replacement that the developer can copy-paste directly into the file without causing syntax errors, indentation issues, or breaking any other functions.

Target File: {file}
Flagged Line Number: {line}
Issue Rule: {rule_id}
Category: {category}
Severity: {severity}
Description: {title}

Flagged Line:
{vulnerable_code}

Surrounding Code Context:
{context_snippet}

Respond ONLY with a valid, parseable JSON object with these exact keys:
{{
  "file": "{file}",
  "start_line": <integer, first line in {file} to replace>,
  "end_line": <integer, last line in {file} to replace>,
  "explainer_60_words": "A crisp, authoritative explanation of approximately 60 words explaining specifically why this line is wrong/critical, what attack or failure vector it enables, and why it lowered the repository health score.",
  "root_cause_explanation": "Concise 2-sentence technical root-cause analysis.",
  "suggested_fix": "Clear step-by-step guidance on how to fix this issue according to modern best practices.",
  "original_code_snippet": "The exact vulnerable code lines that should be replaced.",
  "refactored_code_snippet": "The clean, production-ready, debugged replacement code with exact indentation matching the file.",
  "required_imports": "List any new import statements needed at top of file, e.g. 'import os' or 'None (already imported)'.",
  "safe_enclosing_function": "The entire enclosing function/method rewritten securely, ready for full copy-paste without breaking any other functions.",
  "copy_paste_instruction": "Clear 1-sentence instruction, e.g. 'In {file}, replace lines X-Y with the snippet below.'",
  "where_changed": "Precise location of the change, e.g. 'In {file} (Lines X to Y)' or 'In {file} (Line X)'",
  "what_changed": "Precise, non-complex description of what was changed, e.g. 'Replaced raw string query formatting with parameterized SQL placeholders (?) to prevent SQL injection.'",
  "security_standard": "Associated standard (e.g. OWASP A03:2021-Injection, CWE-89, or ISO/IEC 25010)"
}}
"""

ENHANCED_AUDIT_PROMPT_TEMPLATE = """You are a high-speed, dual-engine Static Analysis and Code Remediation Processor. Your objective is to optimize source code for Maximum Performance, Security, and Quality with minimal API processing latency.

---

### CORE EXECUTION DIRECTIVES

1. ABSOLUTE LATENCY OPTIMIZATION:
   - Process ONLY the pre-filtered AST finding nodes provided in the context.
   - Do NOT analyze unflagged regions of the source code.
   - Output zero conversational filler, introductions, or markdown wrapped outside JSON.
   - Return STRICT JSON matching the schema below.

2. COMPREHENSIVE DUAL-CATEGORY AUDITING:
   - Category 1 (Security): Remediate vulnerabilities including Injection (SQL/Command), Unsafe Execution (eval), Hardcoded Secrets, Insecure Deserialization (pickle), and Weak Cryptography.
   - Category 2 (Quality & Efficiency): Remediate maintainability defects including Silenced Exceptions (except: pass), Non-Idiomatic Loops (range(len())), Bare Excepts, Unreachable/Dead Code, and Excessive Nesting.

3. REMEDIATION ACCURACY & REFACTORING:
   - Keep "explanation" strictly limited to 1-2 concise, impact-focused sentences.
   - "before_code": Extract ONLY the precise problematic line(s).
   - "after_code": Provide the exact, production-ready, refactored replacement snippet.

---

### INPUT DATA

[SOURCE CODE CONTEXT]
{source_code}

[DETECTED AST FINDINGS]
{ast_findings_json}

---

### MANDATORY JSON OUTPUT SCHEMA

{{
  "health_score": 85,
  "summary": "Concise 1-sentence audit summary.",
  "detailed_findings": [
    {{
      "rule_id": "RULE_ID",
      "category": "Security | Quality | Performance | Maintainability",
      "line_no": 0,
      "title": "Short Descriptive Title",
      "severity": "Critical | High | Medium | Low",
      "explanation": "Maximum 2 sentences explaining why this is problematic.",
      "before_code": "Exact flawed code line",
      "after_code": "Exact fixed replacement line"
    }}
  ]
}}
"""


class LLMProviderManager:
    """Orchestrates LLM providers with automatic caching, fallback, and validation."""

    def __init__(self, cache: Optional[RemediationCache] = None):
        self.cache = cache or default_remediation_cache
        self.providers: Dict[str, BaseLLMProvider] = {
            "gemini": GeminiProvider(),
            "openai": OpenAIProvider(),
            "anthropic": AnthropicProvider(),
            "claude": AnthropicProvider(),
            "groq": GroqProvider(),
            "deepseek": OpenAICompatibleProvider(default_base_url="https://api.deepseek.com/v1", name="deepseek"),
            "mistral": OpenAICompatibleProvider(default_base_url="https://api.mistral.ai/v1", name="mistral"),
            "openrouter": OpenAICompatibleProvider(default_base_url="https://openrouter.ai/api/v1", name="openrouter"),
            "custom": OpenAICompatibleProvider(default_base_url="http://localhost:11434/v1", name="custom"),
            "ollama": OpenAICompatibleProvider(default_base_url="http://localhost:11434/v1", name="ollama"),
            "local": OpenAICompatibleProvider(default_base_url="http://localhost:11434/v1", name="local")
        }

    def get_provider(self, name: str) -> BaseLLMProvider:
        clean = (name or "gemini").lower().strip()
        return self.providers.get(clean, self.providers["gemini"])

    def generate_remediation(
        self,
        finding: Dict[str, Any],
        provider: str = "gemini",
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generates production-grade remediation for a finding.
        Uses cached result if available; otherwise calls specified LLM provider.
        Falls back seamlessly to offline heuristic engine on error or missing key.
        """
        key = api_key or os.environ.get("LLM_API_KEY") or os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("GROQ_API_KEY")

        # Offline heuristic mode if no API key provided
        if not key or key.strip() == "" or "your_" in key.lower():
            fallback = get_offline_heuristic_fix(finding)
            fallback["ai_provider"] = "Offline Heuristic Mode (No BYOK Key Provided)"
            return fallback

        # Calculate fingerprint for cache lookup
        fp = finding.get("fingerprint")
        if not fp:
            try:
                fp = Finding.from_dict(finding).fingerprint
            except Exception:
                fp = f"{finding.get('file')}:{finding.get('rule_id')}:{finding.get('line')}"

        clean_provider = provider.lower().strip()
        cached = self.cache.get(fp, clean_provider, model_name)
        if cached:
            return cached

        prompt = PROMPT_TEMPLATE.format(
            file=finding.get("file", "unknown"),
            line=finding.get("line", 1),
            rule_id=finding.get("rule_id", "unknown"),
            category=finding.get("category", "Security"),
            severity=finding.get("severity", "Medium"),
            title=finding.get("title", "Issue"),
            vulnerable_code=finding.get("vulnerable_code", ""),
            context_snippet=finding.get("context_snippet", "")
        )

        llm = self.get_provider(clean_provider)
        start_time = time.perf_counter()

        try:
            raw_response = llm.complete(
                api_key=key.strip(),
                prompt=prompt,
                model_name=model_name,
                custom_endpoint=custom_endpoint
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            parsed = extract_json_from_response(raw_response)

            if parsed and isinstance(parsed, dict):
                provider_tag = f"{clean_provider.capitalize()} ({model_name or 'default'})"
                parsed["ai_provider"] = provider_tag
                parsed["latency_ms"] = elapsed_ms

                # Schema normalization
                if "file" not in parsed or not parsed["file"]:
                    parsed["file"] = finding.get("file", "unknown")
                if "line" not in parsed:
                    parsed["line"] = finding.get("line", 1)
                if "start_line" not in parsed or not parsed["start_line"]:
                    parsed["start_line"] = finding.get("line", 1)
                if "end_line" not in parsed or not parsed["end_line"]:
                    parsed["end_line"] = finding.get("line", 1)
                if "where_changed" not in parsed or not parsed["where_changed"]:
                    sl = parsed.get("start_line", finding.get("line", 1))
                    el = parsed.get("end_line", sl)
                    range_str = f"Line {sl}" if sl == el else f"Lines {sl} to {el}"
                    parsed["where_changed"] = f"In '{parsed['file']}' ({range_str})"
                if "what_changed" not in parsed or not parsed["what_changed"]:
                    parsed["what_changed"] = parsed.get("suggested_fix") or "Applied secure code refactoring to remediate the vulnerability."
                if "explainer_60_words" not in parsed or not parsed["explainer_60_words"]:
                    parsed["explainer_60_words"] = parsed.get("root_cause_explanation", "")
                if "copy_paste_instruction" not in parsed or not parsed["copy_paste_instruction"]:
                    parsed["copy_paste_instruction"] = f"In '{parsed['file']}', replace lines {parsed['start_line']}-{parsed['end_line']} with the snippet below."
                if "required_imports" not in parsed:
                    parsed["required_imports"] = "None"

                # Validation
                is_valid, errors = RemediationValidationPipeline.validate(parsed)
                parsed["validation_passed"] = is_valid
                parsed["validation_errors"] = errors

                # Cache successful response
                self.cache.set(fp, clean_provider, model_name, parsed)
                return parsed
            else:
                fallback = get_offline_heuristic_fix(finding)
                fallback["ai_provider"] = f"{clean_provider.capitalize()} (Unstructured Response Fallback)"
                return fallback

        except Exception as e:
            fallback = get_offline_heuristic_fix(finding)
            safe_err = SecretScrubber.mask_secrets(str(e))
            fallback["ai_provider"] = f"Heuristic Engine ({clean_provider.capitalize()} Notice: {safe_err[:60]})"
            return fallback

    def enrich_code_audit(
        self,
        file_path: str,
        raw_code: str,
        ast_findings: List[Dict[str, Any]],
        provider: str = "gemini",
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        custom_endpoint: Optional[str] = None
    ) -> Dict[str, Any]:
        """Enriches raw code and local AST findings using LLM analysis or deterministic engine."""
        key = api_key or os.environ.get("LLM_API_KEY") or os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("GROQ_API_KEY")

        if not key or key.strip() == "" or "your_" in key.lower():
            return get_offline_heuristic_enrichment(file_path, raw_code, ast_findings)

        findings_summary = [
            {
                "rule_id": f.get("rule_id"),
                "category": f.get("category"),
                "line_no": f.get("line_no", f.get("line")),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "vulnerable_code": f.get("vulnerable_code", f.get("before_code"))
            }
            for f in ast_findings
        ]

        prompt = ENHANCED_AUDIT_PROMPT_TEMPLATE.format(
            source_code=raw_code[:8000],  # Bounded input length to protect LLM context windows
            ast_findings_json=json.dumps(findings_summary, indent=2)
        )

        clean_provider = provider.lower().strip()
        llm = self.get_provider(clean_provider)

        try:
            raw_response = llm.complete(
                api_key=key.strip(),
                prompt=prompt,
                model_name=model_name,
                custom_endpoint=custom_endpoint
            )
            parsed = extract_json_from_response(raw_response)
            if (
                parsed and isinstance(parsed, dict)
                and "summary" in parsed
                and "health_score" in parsed
                and "detailed_findings" in parsed
                and isinstance(parsed["detailed_findings"], list)
            ):
                for itm in parsed["detailed_findings"]:
                    line_no = itm.get("line_no", 1)
                    itm["line"] = line_no
                    itm["file"] = file_path
                    if "before_code" in itm:
                        itm["vulnerable_code"] = itm["before_code"]
                    if "after_code" in itm:
                        itm["refactored_code_snippet"] = itm["after_code"]
                    if "explanation" in itm:
                        itm["explainer_60_words"] = itm["explanation"]
                    if "where_changed" not in itm:
                        itm["where_changed"] = f"In '{file_path}' (Line {line_no})"
                    if "what_changed" not in itm:
                        itm["what_changed"] = f"Refactored {itm.get('title', 'code pattern')} to adhere to best practices."

                return parsed

            return get_offline_heuristic_enrichment(file_path, raw_code, ast_findings)
        except Exception:
            return get_offline_heuristic_enrichment(file_path, raw_code, ast_findings)


# Global default manager
default_provider_manager = LLMProviderManager()

"""
Thread-safe in-memory cache for LLM remediations.
Keyed by finding SHA-256 fingerprint, provider, and model name.
Prevents duplicate API invocations and cost overruns.
"""
from __future__ import annotations
import threading
from typing import Any, Dict, Optional


class RemediationCache:
    """Thread-safe cache for AI remediation results."""
    def __init__(self, max_entries: int = 500):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries

    def _make_key(self, fingerprint: str, provider: str, model_name: Optional[str]) -> str:
        prov = (provider or "gemini").lower().strip()
        mod = (model_name or "default").lower().strip()
        return f"{fingerprint}:{prov}:{mod}"

    def get(self, fingerprint: str, provider: str, model_name: Optional[str]) -> Optional[Dict[str, Any]]:
        key = self._make_key(fingerprint, provider, model_name)
        with self._lock:
            cached = self._cache.get(key)
            if cached:
                # Return a shallow copy with cached=True flag
                res = dict(cached)
                res["cached"] = True
                return res
            return None

    def set(self, fingerprint: str, provider: str, model_name: Optional[str], result: Dict[str, Any]) -> None:
        key = self._make_key(fingerprint, provider, model_name)
        with self._lock:
            if len(self._cache) >= self._max_entries:
                # Evict oldest entry (FIFO)
                first_key = next(iter(self._cache))
                del self._cache[first_key]
            self._cache[key] = dict(result)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# Global default cache
default_remediation_cache = RemediationCache()

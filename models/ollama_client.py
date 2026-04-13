"""
Ollama client — async wrapper around the local Ollama REST API.
"""
import asyncio
import json
import logging
from typing import AsyncGenerator, Optional

import httpx

from config import (
    OLLAMA_BASE_URL, PRIMARY_MODEL, FALLBACK_MODEL,
    LLM_TIMEOUT, LLM_TEMPERATURE, LLM_MAX_TOKENS,
)

logger = logging.getLogger(__name__)


class OllamaClient:
    """Async client for local Ollama inference."""

    def __init__(self):
        self.base_url = OLLAMA_BASE_URL
        self.primary_model = PRIMARY_MODEL
        self.fallback_model = FALLBACK_MODEL
        self._client = httpx.AsyncClient(timeout=LLM_TIMEOUT)

    async def is_available(self) -> bool:
        try:
            r = await self._client.get(f"{self.base_url}/api/tags")
            return r.status_code == 200
        except Exception:
            return False

    async def active_model(self) -> str:
        """Return primary model if available, else fallback."""
        try:
            r = await self._client.get(f"{self.base_url}/api/tags")
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if any(self.primary_model in m for m in models):
                    return self.primary_model
                if any(self.fallback_model in m for m in models):
                    logger.warning("Primary model not found; using fallback %s", self.fallback_model)
                    return self.fallback_model
        except Exception as e:
            logger.error("Cannot reach Ollama: %s", e)
        return self.primary_model  # optimistic

    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = LLM_TEMPERATURE,
        max_tokens: int = LLM_MAX_TOKENS,
    ) -> str:
        """Non-streaming generation. Returns the full response text."""
        model = model or await self.active_model()
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "stop": ["</analysis>", "```\n\n"],
            },
        }
        if system:
            payload["system"] = system

        try:
            r = await self._client.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=LLM_TIMEOUT,
            )
            r.raise_for_status()
            return r.json().get("response", "")
        except httpx.TimeoutException:
            logger.error("LLM generation timed out (model=%s)", model)
            raise
        except Exception as e:
            logger.error("LLM generation failed: %s", e)
            raise

    async def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
    ) -> dict:
        """Generate and parse JSON response. Returns empty dict on parse failure."""
        raw = await self.generate(prompt, system=system, model=model)
        # Strip markdown fences if present
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Attempt to extract JSON object from prose
            import re
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except Exception:
                    pass
            logger.warning("JSON parse failed. Raw response: %s", raw[:300])
            return {}

    async def close(self):
        await self._client.aclose()

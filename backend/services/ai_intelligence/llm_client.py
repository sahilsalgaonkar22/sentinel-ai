from __future__ import annotations
import asyncio
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Prometheus fallback counter
try:
    from prometheus_client import Counter as _Counter
    _llm_degraded = _Counter(
        "llm_degraded_mode_total",
        "Number of times the LLM client started in fallback/static mode",
        ["reason"],
    )
except Exception:
    class _NoOpCounter:
        def labels(self, **_):
            return self
        def inc(self, _=1):
            pass
    _llm_degraded = _NoOpCounter()

# OpenAI import
try:
    import openai
    _OPENAI_AVAILABLE = True
except ImportError:
    openai = None
    _OPENAI_AVAILABLE = False

from backend.common.config import settings


class LLMClient:
    def __init__(self):
        self.client = None
        self.mode = "fallback"
        self.provider = os.getenv("LLM_PROVIDER", "gemini").lower()

        # =========================
        # GEMINI SETUP
        # =========================
        if self.provider == "gemini":
            try:
                import google.generativeai as genai

                if not settings.LLM_API_KEY:
                    raise ValueError("Missing Gemini API key")

                genai.configure(api_key=settings.LLM_API_KEY)
                self.client = genai.GenerativeModel(settings.LLM_MODEL)
                self.mode = "gemini"

                logger.info("[LLM] Gemini initialized model=%s", settings.LLM_MODEL)

            except Exception as e:
                logger.error("[LLM] Gemini init failed: %s", e)
                _llm_degraded.labels(reason="gemini_init_error").inc()

            return  # IMPORTANT

        # =========================
        # OPENAI SETUP
        # =========================
        if self.provider == "openai":
            if not _OPENAI_AVAILABLE:
                logger.warning("[LLM] openai not installed → fallback mode")
                _llm_degraded.labels(reason="no_package").inc()
                return

            if not settings.LLM_API_KEY:
                logger.warning("[LLM] No API key → fallback mode")
                _llm_degraded.labels(reason="no_api_key").inc()
                return

            try:
                self.client = openai.OpenAI(
                    api_key=settings.LLM_API_KEY,
                    base_url=settings.LLM_ENDPOINT,
                )
                self.mode = "openai"

                logger.info("[LLM] OpenAI initialized model=%s", settings.LLM_MODEL)

            except Exception as exc:
                logger.error("[LLM] OpenAI init failed: %s", exc)
                _llm_degraded.labels(reason="openai_init_error").inc()

            return

        # =========================
        # UNKNOWN PROVIDER
        # =========================
        logger.warning("[LLM] Unknown provider '%s' → fallback mode", self.provider)
        _llm_degraded.labels(reason="invalid_provider").inc()

    # =========================
    # CORE CALL (SAFE)
    # =========================
    async def _call_llm(
        self,
        prompt: str,
        default: str,
        max_tokens: int = 256,
        timeout: int = 15
    ) -> str:

        if not self.client:
            return default

        try:
            # GEMINI
            if self.mode == "gemini":
                def _gemini_call():
                    resp = self.client.generate_content(prompt)
                    # safer extraction
                    if hasattr(resp, "text") and resp.text:
                        return resp.text
                    if hasattr(resp, "candidates") and resp.candidates:
                        return resp.candidates[0].content.parts[0].text
                    return default

                return await asyncio.wait_for(
                    asyncio.to_thread(_gemini_call),
                    timeout=timeout
                )

            # OPENAI
            if self.mode == "openai":
                def _openai_call():
                    resp = self.client.chat.completions.create(
                        model=settings.LLM_MODEL,
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=max_tokens,
                        temperature=0.4,
                    )
                    return resp.choices[0].message.content.strip()

                return await asyncio.wait_for(
                    asyncio.to_thread(_openai_call),
                    timeout=timeout
                )

        except asyncio.TimeoutError:
            logger.error("[LLM] timeout after %ss", timeout)
            _llm_degraded.labels(reason="timeout").inc()
        except Exception as exc:
            logger.error("[LLM] API call failed: %s", exc)
            _llm_degraded.labels(reason="runtime_error").inc()

        return default

    # =========================
    # HIGH-LEVEL METHODS
    # =========================
    async def generate_remediation(self, finding_title: str, description: str) -> str:
        prompt = (
            f"Provide a concise 2-step remediation for this vulnerability.\n\n"
            f"Title: {finding_title}\n"
            f"Description: {description}\n\n"
            f"Return plain text."
        )
        default = "1. Patch the system.\n2. Restrict access."
        return await self._call_llm(prompt, default)

    async def generate_risk_explanation(self, finding_title: str, risk_score: float) -> str:
        prompt = (
            f"Explain briefly why '{finding_title}' has a risk score of {risk_score}/10.\n"
            f"Focus on impact and exploitability."
        )
        default = "Risk is based on severity and exploitability."
        return await self._call_llm(prompt, default)

    async def generate_attack_path_summary(self, path_nodes: list[str]) -> str:
        path_str = " -> ".join(path_nodes)
        prompt = f"Explain this attack path in simple terms:\n{path_str}"
        default = "Attacker chains vulnerabilities to reach final target."
        return await self._call_llm(prompt, default)


# Singleton
llm_client = LLMClient()
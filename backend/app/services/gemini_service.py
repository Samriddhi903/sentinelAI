"""Gemini API client for structured security report generation."""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.logging import get_logger
from app.prompts.security_report_prompt import (
    RESPONSE_SCHEMA,
    SYSTEM_PROMPT,
    build_user_prompt,
)
from app.schemas.report import GeminiReportContent

GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)


class GeminiServiceError(Exception):
    """Raised when the Gemini API returns an unexpected or failed response."""


class GeminiService:
    def __init__(self, api_key: str, *, timeout: float = 60.0) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._logger = get_logger(__name__)

    async def generate_security_report(
        self,
        *,
        detections: list[dict[str, Any]],
        risk_assessment: dict[str, Any],
        timeline: dict[str, Any],
        investigation: dict[str, Any],
    ) -> GeminiReportContent:
        if not self._api_key:
            raise GeminiServiceError("GEMINI_API_KEY is not configured")

        user_prompt = build_user_prompt(
            detections=detections,
            risk_assessment=risk_assessment,
            timeline=timeline,
            investigation=investigation,
        )
        payload = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": RESPONSE_SCHEMA,
            },
        }

        self._logger.info("gemini_report_generation_started")

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                GEMINI_API_URL,
                params={"key": self._api_key},
                json=payload,
            )

        if response.status_code != 200:
            self._logger.error(
                "gemini_api_error",
                extra={"status_code": response.status_code, "body": response.text[:500]},
            )
            raise GeminiServiceError(
                f"Gemini API request failed with status {response.status_code}"
            )

        raw_text = self._extract_text(response.json())
        parsed = json.loads(raw_text)
        content = GeminiReportContent.model_validate(parsed)

        self._logger.info("gemini_report_generation_completed")
        return content

    @staticmethod
    def _extract_text(response_body: dict[str, Any]) -> str:
        candidates = response_body.get("candidates") or []
        if not candidates:
            raise GeminiServiceError("Gemini response contained no candidates")

        parts = candidates[0].get("content", {}).get("parts") or []
        if not parts:
            raise GeminiServiceError("Gemini response contained no content parts")

        text = parts[0].get("text")
        if not text:
            raise GeminiServiceError("Gemini response contained empty text")

        return text

"""Optional GPT advisory layer; it never participates in allow/deny decisions."""

from __future__ import annotations

import json
import os

from .models import Advisory, RiskAssessment


class AdvisoryError(RuntimeError):
    """A configured advisory service failed and must fail the gate closed."""


class OpenAIAdvisoryProvider:
    def __init__(self, model: str = "gpt-5.6", timeout_seconds: float = 8) -> None:
        self.model = model
        self.timeout_seconds = timeout_seconds

    def explain(self, assessment: RiskAssessment) -> Advisory | None:
        if not os.environ.get("OPENAI_API_KEY"):
            return None
        try:
            from openai import OpenAI

            client = OpenAI(timeout=self.timeout_seconds)
            response = client.responses.create(
                model=self.model,
                input=[{
                    "role": "system",
                    "content": "You are a shell-command security advisor. Return JSON only with explanation and safer_alternative. Never say the command is safe. Keep each field concise.",
                }, {
                    "role": "user",
                    "content": f"Command: {assessment.command}\nRule findings: {assessment.explanation}",
                }],
            )
            data = json.loads(response.output_text)
            return Advisory(explanation=str(data["explanation"]), safer_alternative=data.get("safer_alternative"))
        except Exception as error:
            # A configured enhancement that cannot produce its safety explanation is fail-closed.
            raise AdvisoryError("AI safety advisory failed") from error

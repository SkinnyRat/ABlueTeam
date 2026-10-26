"""Tier 1/2 triage — turn a rule Finding into an analyst-grade verdict.

The LLM never *detects*; it classifies/explains/scores a Finding the rules
already raised, from the structured evidence handed to it. Backends are
pluggable so the local-7B-vs-API choice is a one-line config change:

  * HeuristicBackend — no LLM; runs today with zero deps/keys. Template verdict.
  * AnthropicBackend — Tier 1 default (Claude Haiku) / Tier 2 (Opus/Sonnet) via API.
  * OllamaBackend    — local Qwen2.5-7B / Llama-3.1-8B fallback (CPU, air-gapped).

All backends return the same dict so downstream code is backend-agnostic:
  {"confidence": 0-1, "verdict": "true_positive|false_positive|needs_review",
   "explanation": str, "recommended_action": str, "backend": str}
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any

from .models import Finding

SYSTEM_PROMPT = (
    "You are a blue-team SOC analyst triaging a network-IDS detection from an "
    "Active Directory lab (Suricata + Zeek, network-only telemetry; no host logs). "
    "The detection was already made by a rule — do NOT re-detect. Judge whether it "
    "is a true positive, assess confidence, explain the AD tradecraft in one or two "
    "sentences, and give one concrete next step. Remember wire-only blind spots: "
    "forged tickets, on-host cred dumping and encrypted payloads are invisible here. "
    'Reply ONLY as JSON: {"confidence": <0-1 float>, "verdict": '
    '"true_positive|false_positive|needs_review", "explanation": "...", '
    '"recommended_action": "..."}'
)

_VERDICTS = {"true_positive", "false_positive", "needs_review"}


def _build_user_prompt(f: Finding) -> str:
    return (
        f"Detector: {f.detector}\nSeverity: {f.severity}\nATT&CK: {', '.join(f.attack) or 'n/a'}\n"
        f"Title: {f.title}\nRule summary: {f.summary}\n"
        f"Source: {f.src_ip} -> {f.dst_ip}\n"
        f"Evidence (sensor records):\n{json.dumps(f.evidence[:5], indent=2)[:4000]}"
    )


def _coerce(obj: dict[str, Any], backend: str) -> dict[str, Any]:
    verdict = obj.get("verdict")
    if verdict not in _VERDICTS:
        verdict = "needs_review"
    try:
        conf = max(0.0, min(1.0, float(obj.get("confidence", 0.5))))
    except (TypeError, ValueError):
        conf = 0.5
    return {
        "confidence": conf,
        "verdict": verdict,
        "explanation": str(obj.get("explanation", ""))[:1000],
        "recommended_action": str(obj.get("recommended_action", ""))[:500],
        "backend": backend,
    }


class TriageBackend(ABC):
    @abstractmethod
    def triage(self, finding: Finding) -> dict[str, Any]: ...


class HeuristicBackend(TriageBackend):
    """No LLM. Confidence from severity; template explanation. Always available."""

    _CONF = {"critical": 0.95, "high": 0.8, "medium": 0.6, "low": 0.4, "info": 0.2}

    def triage(self, finding: Finding) -> dict[str, Any]:
        conf = self._CONF.get(finding.severity, 0.5)
        return _coerce(
            {
                "confidence": conf,
                "verdict": "true_positive" if conf >= 0.8 else "needs_review",
                "explanation": finding.summary or finding.title,
                "recommended_action": "Review evidence; correlate with host logs if available.",
            },
            backend="heuristic",
        )


class OllamaBackend(TriageBackend):
    """Local model via Ollama HTTP API (CPU). Default Qwen2.5-7B-instruct."""

    def __init__(self, model: str = "qwen2.5:7b-instruct",
                 host: str = "http://localhost:11434") -> None:
        self.model, self.host = model, host

    def triage(self, finding: Finding) -> dict[str, Any]:
        import urllib.request

        payload = json.dumps({
            "model": self.model, "stream": False, "format": "json",
            "think": False,                            # Qwen3-family thinking off (see LlamaCppBackend)
            "options": {"num_predict": 400},           # bound the reply
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(finding)},
            ],
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/api/chat", data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                content = json.loads(r.read())["message"]["content"]
            return _coerce(json.loads(content), backend=f"ollama:{self.model}")
        except Exception as e:  # noqa: BLE001 - never let triage crash the pipeline
            return _coerce({"explanation": f"ollama triage failed: {e}"}, backend="ollama:error")


class LlamaCppBackend(TriageBackend):
    """Local model via llama.cpp's `llama-server` (OpenAI-compatible endpoint).

    Runs directly off a raw GGUF — no Ollama Modelfile needed. Start the server:
        llama-server -m <model>.gguf -c 8192 -t 16 --host 127.0.0.1 --port 8080
    then point this backend at it (default http://localhost:8080).
    """

    def __init__(self, model: str = "local",
                 host: str = "http://localhost:8080") -> None:
        self.model, self.host = model, host

    def triage(self, finding: Finding) -> dict[str, Any]:
        import urllib.request

        payload = json.dumps({
            "model": self.model, "stream": False, "temperature": 0.2,
            "max_tokens": 400,                             # bound the reply
            "response_format": {"type": "json_object"},    # llama.cpp JSON mode
            # Qwen3-family "thinking" is ON by default: the model emits a long
            # <think> reasoning chain before the answer, which on CPU runs for
            # minutes and blows the request timeout (content comes back empty
            # because all tokens went into thinking). Turn it off so triage
            # returns the JSON verdict directly.
            "chat_template_kwargs": {"enable_thinking": False},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(finding)},
            ],
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/v1/chat/completions", data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                content = json.loads(r.read())["choices"][0]["message"]["content"]
            return _coerce(json.loads(content), backend=f"llamacpp:{self.model}")
        except Exception as e:  # noqa: BLE001 - never let triage crash the pipeline
            return _coerce({"explanation": f"llama.cpp triage failed: {e}"},
                           backend="llamacpp:error")


class AnthropicBackend(TriageBackend):
    """Claude via API. Tier 1 default = Haiku; Tier 2 = Opus/Sonnet."""

    def __init__(self, model: str = "claude-haiku-5-5") -> None:
        self.model = model

    def triage(self, finding: Finding) -> dict[str, Any]:
        try:
            import anthropic  # optional dep
        except ImportError:
            return _coerce({"explanation": "anthropic SDK not installed"}, backend="anthropic:error")
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return _coerce({"explanation": "ANTHROPIC_API_KEY not set"}, backend="anthropic:error")
        try:
            client = anthropic.Anthropic()
            msg = client.messages.create(
                model=self.model, max_tokens=512, system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": _build_user_prompt(finding)}],
            )
            text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
            start, end = text.find("{"), text.rfind("}")
            obj = json.loads(text[start:end + 1]) if start >= 0 else {}
            return _coerce(obj, backend=f"anthropic:{self.model}")
        except Exception as e:  # noqa: BLE001
            return _coerce({"explanation": f"anthropic triage failed: {e}"}, backend="anthropic:error")


def get_backend(name: str = "heuristic", **kw: Any) -> TriageBackend:
    name = (name or "heuristic").lower()
    if name == "heuristic":
        return HeuristicBackend()
    if name == "ollama":
        return OllamaBackend(**kw)
    if name in ("llamacpp", "llama", "llama.cpp"):
        return LlamaCppBackend(**kw)
    if name in ("anthropic", "api", "claude"):
        return AnthropicBackend(**kw)
    raise ValueError(f"unknown triage backend: {name!r}")

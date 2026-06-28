"""Target adapters — the LLM app/endpoint being scanned.

Speaks the OpenAI Chat Completions shape (works for OpenAI *and* Ollama's
/v1 endpoint) plus a native Anthropic Messages adapter. Bring-your-own-key:
the caller's own API key is read from the environment, so users of the tool
pay their own inference costs.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

_DEFAULT_BASES = {
    "openai": "https://api.openai.com/v1",
    "ollama": "http://localhost:11434/v1",  # free, runs on your laptop
    "anthropic": "https://api.anthropic.com/v1",
}
_KEY_ENVS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "ollama": "OLLAMA_API_KEY",  # usually unset/ignored for local Ollama
}


@dataclass
class Target:
    provider: str
    model: str
    base_url: str
    api_key: str | None = None
    system_prompt: str | None = None
    timeout: float = 60.0


def load_target(
    provider: str,
    model: str,
    base_url: str | None,
    system_prompt: str | None,
) -> Target:
    provider = provider.lower()
    if provider not in _DEFAULT_BASES:
        raise ValueError(f"unknown provider '{provider}' (use: openai | ollama | anthropic)")
    base = (base_url or _DEFAULT_BASES[provider]).rstrip("/")
    api_key = os.getenv(_KEY_ENVS[provider])
    return Target(provider=provider, model=model, base_url=base, api_key=api_key, system_prompt=system_prompt)


def query(target: Target, prompt: str) -> str:
    """Send one prompt to the target and return its text reply."""
    if target.provider == "anthropic":
        return _anthropic(target, prompt)
    return _openai_compatible(target, prompt)


def _openai_compatible(t: Target, prompt: str) -> str:
    messages = []
    if t.system_prompt:
        messages.append({"role": "system", "content": t.system_prompt})
    messages.append({"role": "user", "content": prompt})
    headers = {"Content-Type": "application/json"}
    if t.api_key:
        headers["Authorization"] = f"Bearer {t.api_key}"
    r = httpx.post(
        f"{t.base_url}/chat/completions",
        json={"model": t.model, "messages": messages, "temperature": 0},
        headers=headers,
        timeout=t.timeout,
    )
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"].get("content") or ""


def _anthropic(t: Target, prompt: str) -> str:
    headers = {
        "x-api-key": t.api_key or "",
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body: dict = {
        "model": t.model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    if t.system_prompt:
        body["system"] = t.system_prompt
    r = httpx.post(f"{t.base_url}/messages", json=body, headers=headers, timeout=t.timeout)
    r.raise_for_status()
    data = r.json()
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")

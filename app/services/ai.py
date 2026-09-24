"""Secure File Guard — optional LLM integration.

Only an anonymized structural summary is sent to the external endpoint
(never file contents, secret values, or server credentials). The API key is
stored AES-GCM-wrapped with the server master key; it is never returned in
cleartext by any API.
"""
from __future__ import annotations

import json
import time

import httpx

from .. import config, db, crypto

TIMEOUT = 60.0


def is_configured() -> bool:
    s = db.get_settings()
    return bool(s.get("ai_base_url")) and bool(s.get("ai_key_wrapped"))


def ensure_ai_from_env() -> None:
    """If SFG_AI_API_KEY is set in the environment, make it authoritative:
    wrap and store it (and optional base URL/model) into settings at startup.
    Keys are never printed or returned by any API."""
    from .. import crypto as _crypto
    key = config.AI_API_KEY
    if not key:
        return
    try:
        db.set_setting("ai_key_wrapped", _crypto.wrap_key(_crypto.master_key(), key.encode()), db.utcnow())
        if config.AI_BASE_URL:
            db.set_setting("ai_base_url", config.AI_BASE_URL.rstrip("/"), db.utcnow())
        if config.AI_MODEL:
            db.set_setting("ai_model", config.AI_MODEL, db.utcnow())
        if not db.get_settings().get("ai_base_url"):
            db.set_setting("ai_base_url", "https://api.openai.com/v1", db.utcnow())
        if not db.get_settings().get("ai_model"):
            db.set_setting("ai_model", "gpt-4o-mini", db.utcnow())
    except Exception:
        pass


def unwrap_ai_key() -> str | None:
    s = db.get_settings()
    wrapped = s.get("ai_key_wrapped", "")
    if not wrapped:
        return None
    try:
        return crypto.unwrap_key(crypto.master_key(), wrapped).decode()
    except Exception:
        return None


def wrap_ai_key(plain: str) -> str:
    return crypto.wrap_key(crypto.master_key(), plain.encode())


def call_llm(anonymized_summary: dict) -> dict | None:
    s = db.get_settings()
    base = (s.get("ai_base_url") or "").rstrip("/")
    key = unwrap_ai_key()
    if not base or not key:
        return None
    model = s.get("ai_model") or "gpt-4o-mini"
    url = base + ("/chat/completions" if not base.endswith("/chat/completions") else "")
    try:
        resp = httpx.post(
            url,
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system",
                     "content": "You are a web application protection analyst. Respond with strict JSON only."},
                    {"role": "user", "content": json.dumps(anonymized_summary)},
                ],
            },
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return None
        parsed["_model"] = model
        return parsed
    except Exception:
        return None

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

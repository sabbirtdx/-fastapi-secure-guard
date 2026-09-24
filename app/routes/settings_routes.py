"""Secure File Guard — system settings."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from .. import config, crypto, db
from ..security import ADMIN_ROLES, check_csrf, client_ip, require_role

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

WRITABLE = {
    "site_name", "license_server_url", "require_https", "verify_ttl_seconds",
    "grace_seconds", "max_upload_mb", "clock_tolerance_seconds",
    "ai_base_url", "ai_model", "verification_retention_days",
}


def _public(settings: dict) -> dict:
    out = {}
    for k, v in settings.items():
        if k == "ai_key_wrapped":
            out["ai_key_configured"] = bool(v)
            continue
        out[k] = v
    return out


@router.get("")
async def get_settings(request: Request):
    user = require_role(request, ADMIN_ROLES)
    return {"settings": _public(db.get_settings())}


@router.post("")
async def update_settings(request: Request):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    body = await request.json()
    changed = []
    settings = db.get_settings()
    for k, v in body.items():
        if k == "ai_key":
            # stored AES-GCM wrapped with the master key; never persisted plaintext
            plain = str(v or "").strip()
            if plain:
                settings["ai_key_wrapped"] = crypto.wrap_key(crypto.master_key(), plain.encode())
                db.set_setting("ai_key_wrapped", settings["ai_key_wrapped"], db.utcnow())
                changed.append("ai_key (wrapped)")
            else:
                db.set_setting("ai_key_wrapped", "", db.utcnow())
                changed.append("ai_key (cleared)")
            continue
        if k not in WRITABLE:
            continue
        val = str(v).strip()
        if k == "require_https":
            val = "1" if val in ("1", "true", "True") else "0"
        if k in ("verify_ttl_seconds", "grace_seconds", "max_upload_mb",
                 "clock_tolerance_seconds", "verification_retention_days"):
            try:
                val = str(int(val))
            except Exception:
                raise HTTPException(status_code=400, detail={"code": "BAD_INPUT", "message": f"{k} must be numeric."})
        if k == "site_name" and len(val) > 80:
            raise HTTPException(status_code=400, detail={"code": "BAD_INPUT", "message": "site_name too long."})
        db.set_setting(k, val, db.utcnow())
        changed.append(k)
    db.audit(user["id"], user["email"], "settings_updated", "settings", "",
             detail=", ".join(changed) or "none", ip=client_ip(request))
    return {"ok": True, "changed": changed, "settings": _public(db.get_settings())}

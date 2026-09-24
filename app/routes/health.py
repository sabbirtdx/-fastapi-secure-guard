"""Secure File Guard — system health (real checks only)."""
from __future__ import annotations

import shutil
import time

from fastapi import APIRouter, Request

from .. import config, crypto, db
from ..pipeline import build_service_status
from ..security import ADMIN_ROLES, require_role

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health")
async def system_health(request: Request):
    user = require_role(request, ADMIN_ROLES)
    # database
    dbh = db.db_health()
    # license API: internal self-check (signature round trip)
    tok = crypto.make_authz_token({"lic": "selftest", "prj": "selftest", "bld": "selftest",
                                   "ver": "0", "dom": "selftest", "iat": int(time.time()),
                                   "exp": int(time.time()) + 60, "ttl": 300, "jti": "selftest"})
    payload, err = crypto.decode_authz_token(tok)
    lic_api = {"status": "ok" if payload else "error", "detail": err or "sign/verify round-trip OK"}
    # build service
    bs = build_service_status()
    # storage
    usage = shutil.disk_usage(str(config.DATA_DIR))
    proj_used = 0
    nproj = 0
    for p in config.PROJECTS_DIR.iterdir() if config.PROJECTS_DIR.exists() else []:
        if p.is_dir():
            nproj += 1
            for f in p.rglob("*"):
                if f.is_file():
                    try:
                        proj_used += f.stat().st_size
                    except OSError:
                        pass
    storage = {
        "status": "ok" if usage.free > 200 * 1024 * 1024 else "warning",
        "free_mb": usage.free // (1024 * 1024),
        "total_mb": usage.total // (1024 * 1024),
        "projects_count": nproj,
        "projects_used_mb": proj_used // (1024 * 1024),
    }
    # AI service
    ai = {"status": "configured" if (db.get_settings().get("ai_base_url") and db.get_settings().get("ai_key_wrapped"))
          else "not_configured",
          "note": "Built-in static analysis engine is always active; LLM is optional."}
    # recent failures (last 24h)
    day = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 86400))
    recent_failures = db.rows_to_list(db.qall(
        "SELECT type, COUNT(*) c FROM security_events WHERE severity='critical' AND created_at>=? GROUP BY type ORDER BY c DESC LIMIT 10",
        (day,)))
    failed_verifs = db.qvalue("SELECT COUNT(*) FROM verification_logs WHERE result='failed' AND created_at>=?", (day,)) or 0
    # keys
    key_age_days = None
    try:
        key_age_days = int((time.time() - config.KEYS_DIR.joinpath("signing.key").stat().st_mtime) // 86400)
    except OSError:
        pass
    return {
        "system": {
            "name": config.APP_NAME,
            "version": config.APP_VERSION,
            "database": dbh,
            "license_api": lic_api,
            "build_service": bs,
            "storage": storage,
            "ai_service": ai,
            "signing_key_age_days": key_age_days,
            "recent_critical_events": recent_failures,
            "failed_verifications_24h": failed_verifs,
        },
    }

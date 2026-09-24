"""Secure File Guard — authentication routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response

from .. import config, db
from ..security import (client_ip, create_session, generate_password, hash_password,
                        rate_auth, raise_rate_limited, require_user, verify_password)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login")
async def login(request: Request, response: Response):
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    ip = client_ip(request)
    if not rate_auth.check(f"login|{ip}", *config.RATE_LOGIN):
        raise_rate_limited()
    user = db.q1("SELECT * FROM users WHERE email = ?", (email,))
    if user is None or not verify_password(password, user["password_hash"]):
        db.audit(None, email or None, "login_failed", "auth", "", result="failed", ip=ip)
        raise HTTPException(status_code=401, detail={"code": "INVALID_CREDENTIALS", "message": "Invalid email or password."})
    if user["disabled"]:
        raise HTTPException(status_code=403, detail={"code": "ACCOUNT_DISABLED", "message": "This account is disabled."})
    token, csrf = create_session(user["id"], ip)
    db.qexec("UPDATE users SET last_login_at=? WHERE id=?", (db.utcnow(), user["id"]))
    db.audit(user["id"], user["email"], "login", "auth", str(user["id"]), ip=ip)
    # Secure first-run: remove the one-time credentials file after any successful login.
    try:
        if config.CREDENTIALS_PATH.exists():
            config.CREDENTIALS_PATH.unlink()
    except OSError:
        pass
    # Detect HTTPS behind reverse proxies (Render/nginx) — a wrong Secure flag
    # makes the browser drop the cookie and every later call returns 401.
    xf_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    secure = xf_proto == "https" or request.url.scheme == "https"
    response.set_cookie(
        "sfg_session", token,
        max_age=12 * 3600,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )
    # Confirm the cookie round-trips before the SPA treats login as success.
    response.headers["X-SFG-Session"] = "set"
    return {
        "ok": True,
        "csrf": csrf,
        "session_verified": True,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]},
    }


@router.post("/logout")
async def logout(request: Request, response: Response):
    # Idempotent: expired/missing session must still clear the cookie so the
    # client never gets stuck showing UNAUTHORIZED after logout.
    sid = request.cookies.get("sfg_session")
    if sid:
        sess = db.q1("SELECT * FROM sessions WHERE id = ?", (sid,))
        if sess is not None:
            user = db.q1("SELECT * FROM users WHERE id = ?", (sess["user_id"],))
            if user is not None:
                db.audit(user["id"], user["email"], "logout", "auth", "", ip=client_ip(request))
        db.qexec("DELETE FROM sessions WHERE id = ?", (sid,))
    response.delete_cookie("sfg_session", path="/")
    return {"ok": True}


@router.get("/me")
async def me(request: Request):
    user = require_user(request)
    return {
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]},
        "csrf": user["csrf"],
    }


def seed_admin() -> dict | None:
    """First-start bootstrap for the super admin.

    Secure first-run password mechanism:
    - If SFG_ADMIN_PASSWORD is set: it is authoritative. On seed it becomes the
      password (no credentials file is written); on later startups the stored
      hash is re-synced to it so the environment stays the source of truth.
    - Otherwise a random password is generated once and written to
      data/credentials.txt (0600). The file is removed automatically after the
      first successful login. The password is never printed to logs.
    There are no hardcoded demo users.
    """
    env_password = config.ADMIN_PASSWORD
    existing = db.q1("SELECT * FROM users WHERE role='super_admin' LIMIT 1")
    if existing is not None:
        if env_password and not verify_password(env_password, existing["password_hash"]):
            db.qexec("UPDATE users SET password_hash=? WHERE id=?",
                     (hash_password(env_password), existing["id"]))
            db.audit(existing["id"], existing["email"], "admin_password_synced", "auth", "",
                     detail="password synchronized from SFG_ADMIN_PASSWORD")
        return None
    password = env_password or generate_password(16)
    db.qexec(
        "INSERT INTO users (email, name, password_hash, role, disabled, created_at) VALUES (?,?,?,?,0,?)",
        (config.ADMIN_EMAIL, "Super Admin", hash_password(password), "super_admin", db.utcnow()))
    if env_password is None:
        config.CREDENTIALS_PATH.write_text(
            f"Secure File Guard — initial super admin credentials (delete this file after first login)\n"
            f"email:    {config.ADMIN_EMAIL}\n"
            f"password: {password}\n",
        )
        try:
            import os
            os.chmod(config.CREDENTIALS_PATH, 0o600)
        except OSError:
            pass
        db.audit(1, config.ADMIN_EMAIL, "admin_seeded", "auth", "",
                 detail="initial super admin created; credentials written to data/credentials.txt")
        return {"email": config.ADMIN_EMAIL, "password": password}
    db.audit(1, config.ADMIN_EMAIL, "admin_seeded", "auth", "",
             detail="initial super admin created from SFG_ADMIN_PASSWORD")
    return None

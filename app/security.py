"""Secure File Guard — security primitives: passwords, sessions, CSRF, rate limits."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time

from fastapi import HTTPException, Request, Response

from . import config, db

SESSION_TTL = 12 * 3600


# ---------------- passwords (scrypt, per-user salt) ----------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def generate_password(length: int = 16) -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------- sessions ----------------

def create_session(user_id: int, ip: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = time.time()
    db.qexec(
        "INSERT INTO sessions (id, user_id, csrf, ip, created_at, expires_at) VALUES (?,?,?,?,?,?)",
        (token, user_id, csrf, ip, db.utcnow(),
         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + SESSION_TTL))),
    )
    return token, csrf


def get_session(session_id: str | None) -> dict | None:
    if not session_id:
        return None
    row = db.q1("SELECT * FROM sessions WHERE id = ?", (session_id,))
    if row is None:
        return None
    if row["expires_at"] < db.utcnow():
        db.qexec("DELETE FROM sessions WHERE id = ?", (session_id,))
        return None
    # Sliding expiration: active use keeps the session alive (full TTL from
    # last touch). Prevents mid-work UNAUTHORIZED after idle page use.
    new_exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + SESSION_TTL))
    if new_exp > row["expires_at"]:
        db.qexec("UPDATE sessions SET expires_at=? WHERE id=?", (new_exp, session_id))
        row = db.q1("SELECT * FROM sessions WHERE id = ?", (session_id,))
        if row is None:
            return None
    return dict(row)


def get_current_user(request: Request) -> dict | None:
    sid = request.cookies.get("sfg_session")
    sess = get_session(sid)
    if sess is None:
        return None
    user = db.q1("SELECT * FROM users WHERE id = ? AND disabled = 0", (sess["user_id"],))
    if user is None:
        return None
    u = dict(user)
    u["csrf"] = sess["csrf"]
    return u


def require_user(request: Request) -> dict:
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail={
            "code": "UNAUTHORIZED",
            "message": "Your session has expired or is invalid. Please sign in again.",
        })
    return user


def require_role(request: Request, roles: list[str]) -> dict:
    user = require_user(request)
    if user["role"] not in roles:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Insufficient permissions."})
    return user


ADMIN_ROLES = ["super_admin", "admin"]


def require_admin(request: Request) -> dict:
    return require_role(request, ADMIN_ROLES)


def check_csrf(request: Request, user: dict) -> None:
    """CSRF: state-changing API calls must present the per-session token header."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.headers.get("x-csrf-token", "")
    if not sent or not hmac.compare_digest(sent, user.get("csrf", "")):
        raise HTTPException(status_code=403, detail={"code": "CSRF_REJECTED", "message": "CSRF token missing or invalid."})


def client_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0].strip()


# ---------------- rate limiting (sliding window, in-memory) ----------------

class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


rate_auth = RateLimiter()
rate_verify = RateLimiter()
rate_activate = RateLimiter()
rate_public = RateLimiter()
rate_session = RateLimiter()


def raise_rate_limited() -> None:
    raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "message": "Too many requests. Slow down."})

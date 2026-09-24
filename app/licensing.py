"""Secure File Guard — licensing server core.

This module is the authoritative license state machine used by the public
verification API. The protected runtime never decides on its own — every
authorization decision is made here, against the database, and the result is
returned as an Ed25519-signed token.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time

from . import config, crypto, db
from .security import rate_activate, rate_public, rate_verify, raise_rate_limited

LICENSE_KEY_RX = re.compile(r"^SFG-[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$")


def generate_license_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I confusion
    groups = []
    for _ in range(4):
        groups.append("".join(secrets.choice(alphabet) for _ in range(4)))
    return "SFG-" + "-".join(groups)


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def mask_key(key: str) -> str:
    return f"SFG-{'XXXX-' * 3}{key.split('-')[-1]}"


def normalize_domain(raw: str) -> str:
    """Normalize a domain: lowercase, strip scheme/path/port, no wildcard."""
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split(":")[0] if ":" in d and d.count(":") == 1 else d  # strip :port (naive guard)
    d = d.strip(".")
    if not d or " " in d or "*" in d or len(d) > 253 or not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", d):
        return ""
    return d


def license_row(license_id: str | None = None, key: str | None = None):
    if license_id:
        return db.q1("SELECT * FROM licenses WHERE id = ?", (license_id,))
    if key:
        return db.q1("SELECT * FROM licenses WHERE key_hash = ?", (key_hash(key),))
    return None


def license_domains_rows(license_id: str) -> list[dict]:
    return db.rows_to_list(db.qall(
        "SELECT * FROM license_domains WHERE license_id = ? ORDER BY domain", (license_id,)))


def domain_matches_claimed(allowed: list[dict], claimed: str) -> bool:
    """claimed = normalized host from the runtime. Allowed rows carry policy."""
    claimed = normalize_domain(claimed)
    if not claimed:
        return False
    for row in allowed:
        if row["status"] == "blocked":
            continue
        if row["status"] not in ("verified", "active"):
            continue
        base = normalize_domain(row["domain"])
        if claimed == base:
            return True
        if base.startswith("www.") and claimed == base[4:]:
            return True
        if claimed.startswith("www.") and base == claimed[4:]:
            return True
        if row["allow_subdomains"] and claimed.endswith("." + base):
            return True
    return False


def check_license_fail_counter(license_id: str, ip: str) -> bool:
    """True if temporarily blocked due to repeated failures (15-min window)."""
    now = time.time()
    k = f"{license_id}|{ip}"
    row = db.q1("SELECT * FROM license_fail_counters WHERE key = ?", (k,))
    if row is None:
        return False
    if now - row["window_start"] > 900:
        return False
    return row["count"] >= config.REPEAT_FAIL_THRESHOLD


def register_license_fail(license_id: str, ip: str) -> int:
    now = time.time()
    k = f"{license_id}|{ip}"
    row = db.q1("SELECT * FROM license_fail_counters WHERE key = ?", (k,))
    if row is None or now - row["window_start"] > 900:
        count = 1
        db.qexec(
            "INSERT INTO license_fail_counters (key, count, window_start) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET count=1, window_start=excluded.window_start",
            (k, 1, now))
    else:
        count = row["count"] + 1
        db.qexec("UPDATE license_fail_counters SET count = ? WHERE key = ?", (count, k))
    if count == config.REPEAT_FAIL_THRESHOLD:
        lic = license_row(license_id=license_id)
        db.security_event(
            lic["project_id"] if lic else None, license_id,
            "repeated_verification_failures", "warning",
            f"{count} verification failures within 15 minutes from one source.", ip)
    return count


def clear_license_fails(license_id: str, ip: str) -> None:
    db.qexec("DELETE FROM license_fail_counters WHERE key LIKE ?", (f"{license_id}|{ip}",))


def verify_request(body: dict, ip: str) -> dict:
    """Full verification decision. Returns {ok, token?, error_code?, error_msg?}."""
    t0 = time.time()
    result = {"ok": False, "token": None, "error_code": "LICENSE_INVALID", "error_msg": "The license key is not valid.",
              "license_id": None, "project_id": None, "domain": None, "domain_ok": 0}

    key = (body.get("license") or "").strip()
    claimed_domain = (body.get("domain") or "").strip()
    project = (body.get("project") or "").strip()
    build_id = (body.get("build") or "").strip()
    version = (body.get("version") or "").strip()
    ts = body.get("ts")
    nonce = body.get("nonce") or ""

    # replay protection: fresh timestamp + unique nonce
    try:
        ts = int(ts)
    except Exception:
        ts = None
    tol = int(db.get_settings().get("clock_tolerance_seconds", str(config.CLOCK_TOLERANCE_SECONDS)))
    now = time.time()
    if ts is None or abs(now - ts) > tol:
        result.update(error_code="REPLAY_REJECTED", error_msg="Timestamp outside allowed window.")
        _finish(result, key, claimed_domain, project, build_id, ip, t0, kind="verify")
        return result
    if not re.match(r"^[a-f0-9]{8,64}$", nonce):
        result.update(error_code="REPLAY_REJECTED", error_msg="Missing nonce.")
        _finish(result, key, claimed_domain, project, build_id, ip, t0, kind="verify")
        return result
    if _remember_nonce(nonce):
        result.update(error_code="REPLAY_REJECTED", error_msg="Nonce was already used. Re-request a fresh token.")
        _finish(result, key, claimed_domain, project, build_id, ip, t0, kind="verify")
        return result

    lic = license_row(key=key)
    if lic is None:
        register_license_fail("unknown", ip)
        result.update(error_code="LICENSE_INVALID", error_msg="The license key is not valid.")
        db.security_event(None, None, "invalid_license", "warning",
                          f"Unknown license key presented from domain '{claimed_domain}'.", ip)
        _finish(result, key, claimed_domain, project, build_id, ip, t0, kind="verify")
        return result

    result["license_id"] = lic["id"]
    result["project_id"] = lic["project_id"]

    if check_license_fail_counter(lic["id"], ip):
        result.update(error_code="RATE_LIMITED", error_msg="Too many verification attempts. Try again later.")
        _finish(result, key, claimed_domain, project, build_id, ip, t0, kind="verify")
        return result

    # expiry (auto-transition)
    expires_at = _parse_ts(lic["expires_at"])
    if lic["status"] not in ("revoked",) and expires_at is not None and now > expires_at:
        db.qexec("UPDATE licenses SET status='expired' WHERE id=?", (lic["id"],))
        lic = license_row(license_id=lic["id"])
    if lic["status"] == "revoked":
        db.security_event(lic["project_id"], lic["id"], "revoked_license_attempt", "critical",
                          f"Verification attempted with revoked license from domain '{claimed_domain}'.", ip)
        _fail(result, "LICENSE_REVOKED", "This license has been revoked.", lic, claimed_domain, project, build_id, ip, t0)
        return result
    if lic["status"] == "suspended":
        _fail(result, "LICENSE_SUSPENDED", "This license is suspended.", lic, claimed_domain, project, build_id, ip, t0)
        return result
    if lic["status"] == "expired":
        _fail(result, "LICENSE_EXPIRED", "This license has expired.", lic, claimed_domain, project, build_id, ip, t0)
        return result

    # project binding
    if project and project != lic["project_id"]:
        _fail(result, "PROJECT_MISMATCH", "License does not match this project.",
              lic, claimed_domain, project, build_id, ip, t0)
        return result

    # domain binding (server-side authoritative)
    domains = license_domains_rows(lic["id"])
    domain_ok = domain_matches_claimed(domains, claimed_domain)
    result["domain"] = claimed_domain
    result["domain_ok"] = 1 if domain_ok else 0
    if not domain_ok:
        db.security_event(lic["project_id"], lic["id"], "unauthorized_domain", "critical",
                          f"Verification from unauthorized domain '{claimed_domain}'.", ip)
        _fail(result, "DOMAIN_NOT_AUTHORIZED", "Domain not authorized for this license.",
              lic, claimed_domain, project, build_id, ip, t0)
        return result

    # build + version checks
    build = db.q1("SELECT * FROM builds WHERE id = ? AND project_id = ?", (build_id, lic["project_id"])) if build_id else None
    if build is None:
        _fail(result, "BUILD_INVALID", "This build is invalid or has been disabled.",
              lic, claimed_domain, project, build_id, ip, t0)
        return result
    if build["status"] == "failed":
        _fail(result, "BUILD_INVALID", "This build did not pass validation.",
              lic, claimed_domain, project, build_id, ip, t0)
        return result
    if build["status"] == "disabled":
        _fail(result, "BUILD_INVALID", "This build has been disabled by an administrator.",
              lic, claimed_domain, project, build_id, ip, t0)
        return result
    if build["status"] != "completed":
        _fail(result, "BUILD_INVALID", "This build is not finalized yet.",
              lic, claimed_domain, project, build_id, ip, t0)
        return result
    ver_row = db.q1("SELECT * FROM project_versions WHERE id = ?", (build["version_id"],)) if build["version_id"] else None
    if ver_row is not None and ver_row["revoked"]:
        _fail(result, "VERSION_NOT_ALLOWED", "This build version has been revoked.",
              lic, claimed_domain, project, build_id, ip, t0)
        return result
    if lic["version_restrict"] and (version != lic["version_restrict"]):
        _fail(result, "VERSION_NOT_ALLOWED", "This build version is not allowed by the license.",
              lic, claimed_domain, project, build_id, ip, t0)
        return result

    # success
    db.qexec(
        "UPDATE licenses SET last_verified_at=?, status=CASE WHEN status='pending' THEN 'active' ELSE status END,"
        " activated=CASE WHEN activated=0 THEN 1 ELSE activated END,"
        " activated_at=CASE WHEN activated=0 THEN ? ELSE activated_at END WHERE id=?",
        (db.utcnow(), db.utcnow(), lic["id"]))
    db.qexec("UPDATE license_domains SET status=CASE WHEN status='verified' THEN 'active' ELSE status END,"
             " verified_at=COALESCE(verified_at, ?) WHERE license_id=? AND status IN ('verified','pending')",
             (db.utcnow(), lic["id"]))
    clear_license_fails(lic["id"], ip)

    settings = db.get_settings()
    token = crypto.make_authz_token({
        "lic": lic["id"],
        "prj": lic["project_id"],
        "bld": build["id"],
        "ver": version or build["version"],
        "dom": normalize_domain(claimed_domain),
        "iat": int(now),
        "exp": int(now) + config.AUTHZ_TOKEN_TTL_SECONDS,
        "ttl": int(settings.get("verify_ttl_seconds", str(config.DEFAULT_VERIFY_TTL_SECONDS))),
        "jti": secrets.token_hex(12),
    })
    result.update(ok=True, token=token, error_code="", error_msg="")
    _finish(result, key, claimed_domain, project, build_id, ip, t0, kind="verify", success=True)
    return result


def _fail(result: dict, code: str, msg: str, lic, claimed_domain, project, build_id, ip, t0) -> None:
    result.update(ok=False, error_code=code, error_msg=msg)
    register_license_fail(lic["id"], ip)
    _finish(result, result.get("_key", ""), claimed_domain, project, build_id, ip, t0, kind="verify", lic=lic)


def _finish(result: dict, key: str, claimed_domain: str, project: str, build_id: str,
            ip: str, t0: float, kind: str = "verify", success: bool | None = None, lic=None) -> None:
    if success is None:
        success = result.get("ok", False)
    latency = int((time.time() - t0) * 1000)
    db.verification_log(
        lic["id"] if lic else result.get("license_id"),
        result.get("project_id"),
        claimed_domain or None,
        result.get("domain_ok", 0),
        "ok" if success else "failed",
        result.get("error_code") or None,
        latency, ip, kind=kind)


def activate_request(body: dict, ip: str) -> dict:
    """Activation = verification + persistence of the first activation."""
    result = verify_request(body, ip)
    lic_id = result.get("license_id")
    if lic_id:
        db.qexec(
            "INSERT INTO activations (license_id, domain, ip, success, error_code, created_at) VALUES (?,?,?,?,?,?)",
            (lic_id, (body.get("domain") or "").strip() or None, ip,
             1 if result["ok"] else 0, result.get("error_code") or None, db.utcnow()))
    return result


def status_request(key: str, ip: str) -> dict:
    lic = license_row(key=(key or "").strip())
    if lic is None:
        return {"ok": False, "error_code": "LICENSE_INVALID", "error_msg": "The license key is not valid."}
    d = {
        "ok": True,
        "license": {"id": lic["id"], "project": lic["project_id"], "status": lic["status"],
                    "activated": bool(lic["activated"]), "expires_at": lic["expires_at"],
                    "last_verified_at": lic["last_verified_at"]},
        "domains": license_domains_rows(lic["id"]),
    }
    return d


def verify_token_request(token: str, ip: str) -> dict:
    """Used by the runtime file endpoint: validate a signed authorization token."""
    payload, err = crypto.decode_authz_token(token)
    if payload is None:
        return {"ok": False, "error_code": err, "payload": None}
    now = time.time()
    if int(payload.get("exp", 0)) <= now:
        return {"ok": False, "error_code": "LICENSE_EXPIRED", "payload": payload}
    lic = license_row(license_id=payload.get("lic"))
    if lic is None or lic["status"] not in ("active", "pending"):
        code = "LICENSE_REVOKED" if lic and lic["status"] == "revoked" else "LICENSE_INVALID"
        return {"ok": False, "error_code": code, "payload": payload}
    domain_ok = domain_matches_claimed(license_domains_rows(lic["id"]), payload.get("dom", ""))
    if not domain_ok:
        return {"ok": False, "error_code": "DOMAIN_NOT_AUTHORIZED", "payload": payload}
    build = db.q1("SELECT * FROM builds WHERE id = ?", (payload.get("bld"),))
    if build is None or build["status"] in ("failed", "disabled"):
        return {"ok": False, "error_code": "BUILD_INVALID", "payload": payload}
    return {"ok": True, "error_code": "", "payload": payload}


_NONCE_SEEN: dict[str, float] = {}


def _remember_nonce(nonce: str) -> bool:
    """Record a nonce. Returns True if it was already seen within the replay
    window (a replayed request that must be rejected)."""
    now = time.time()
    cutoff = now - config.REPLAY_WINDOW_SECONDS
    if nonce in _NONCE_SEEN and _NONCE_SEEN[nonce] >= cutoff:
        return True
    _NONCE_SEEN[nonce] = now
    if len(_NONCE_SEEN) > 20000:
        for k in [k for k, v in _NONCE_SEEN.items() if v < cutoff]:
            _NONCE_SEEN.pop(k, None)
    return False


def _parse_ts(s: str | None) -> float | None:
    if not s:
        return None
    try:
        import calendar
        return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return None

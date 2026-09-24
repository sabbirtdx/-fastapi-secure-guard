"""Secure File Guard — public licensing API (called by protected deployments).

No session cookies here: the security boundaries are the license key, the
domain claim, timestamps + nonces (replay protection), rate limiting, and
the Ed25519-signed responses. Structured errors only — never stack traces.
"""
from __future__ import annotations

import base64
import json
import time

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .. import config, crypto, db, licensing
from ..security import client_ip, rate_activate, rate_public, rate_verify, raise_rate_limited

router = APIRouter(prefix="/api/v1/public", tags=["public-api"])


def _err(code: str, message: str, status: int = 402) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


async def _json(request: Request) -> dict:
    """Parse request body as a dict. Accepts JSON (primary) and form-urlencoded
    (fallback for non-PHP clients). Never raises — returns {} on bad input."""
    raw = b""
    try:
        raw = await request.body()
    except Exception:
        return {}
    if not raw:
        return {}
    ctype = (request.headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype:
        try:
            from urllib.parse import parse_qsl
            return {k: v for k, v in parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True)}
        except Exception:
            return {}
    try:
        body = json.loads(raw.decode("utf-8"))
        return body if isinstance(body, dict) else {}
    except Exception:
        try:
            body = json.loads(raw)
            return body if isinstance(body, dict) else {}
        except Exception:
            return {}


@router.post("/licenses/verify")
async def verify(request: Request):
    ip = client_ip(request)
    if not rate_verify.check(f"verify|{ip}", *config.RATE_VERIFY):
        raise_rate_limited()
    body = await _json(request)
    try:
        result = licensing.verify_request(body if isinstance(body, dict) else {}, ip)
    except Exception:
        return _err("SERVER_ERROR", "Verification could not be completed.", 500)
    if not isinstance(result, dict) or not result.get("ok"):
        code = str((result or {}).get("error_code") or "LICENSE_INVALID")
        msg = str((result or {}).get("error_msg") or "Verification failed.")
        return _err(code, msg, 404 if code == "LICENSE_INVALID" else 403)
    return {"ok": True, "token": result.get("token"),
            "expires_at": int(time.time()) + config.AUTHZ_TOKEN_TTL_SECONDS}


@router.post("/licenses/activate")
async def activate(request: Request):
    ip = client_ip(request)
    if not rate_activate.check(f"activate|{ip}", *config.RATE_ACTIVATE):
        raise_rate_limited()
    body = await _json(request)
    try:
        result = licensing.activate_request(body if isinstance(body, dict) else {}, ip)
    except Exception:
        return _err("SERVER_ERROR", "Activation could not be completed.", 500)
    if not isinstance(result, dict) or not result.get("ok"):
        code = str((result or {}).get("error_code") or "LICENSE_INVALID")
        msg = str((result or {}).get("error_msg") or "Activation failed.")
        return _err(code, msg, 404 if code == "LICENSE_INVALID" else 403)
    return {"ok": True, "token": result.get("token")}


@router.post("/licenses/status")
async def status(request: Request):
    ip = client_ip(request)
    if not rate_public.check(f"status|{ip}", *config.RATE_PUBLIC_API):
        raise_rate_limited()
    body = await _json(request)
    result = licensing.status_request(body.get("license") or "", ip)
    if not result["ok"]:
        return _err(result["error_code"], result["error_msg"], 404)
    return result


@router.post("/domains/verify")
async def domains_verify(request: Request):
    ip = client_ip(request)
    if not rate_public.check(f"dom|{ip}", *config.RATE_PUBLIC_API):
        raise_rate_limited()
    body = await _json(request)
    lic = licensing.license_row(key=(body.get("license") or "").strip())
    if lic is None:
        return _err("LICENSE_INVALID", "The license key is not valid.", 404)
    claimed = licensing.normalize_domain(body.get("domain") or "")
    ok = licensing.domain_matches_claimed(licensing.license_domains_rows(lic["id"]), claimed)
    if not ok:
        return _err("DOMAIN_NOT_AUTHORIZED", "Domain not authorized for this license.", 403)
    return {"ok": True, "domain": claimed, "license_id": lic["id"], "project_id": lic["project_id"]}


@router.post("/versions/verify")
async def versions_verify(request: Request):
    ip = client_ip(request)
    if not rate_public.check(f"ver|{ip}", *config.RATE_PUBLIC_API):
        raise_rate_limited()
    body = await _json(request)
    lic = licensing.license_row(key=(body.get("license") or "").strip())
    if lic is None:
        return _err("LICENSE_INVALID", "The license key is not valid.", 404)
    version = (body.get("version") or "").strip()
    if lic["status"] not in ("active", "pending"):
        return _err(f"LICENSE_{lic['status'].upper()}", "License is not active.", 403)
    if lic["version_restrict"] and version != lic["version_restrict"]:
        return _err("VERSION_NOT_ALLOWED", "This version is not allowed by the license.", 403)
    build = db.q1("SELECT * FROM builds WHERE project_id=? AND version=?", (lic["project_id"], version))
    if build is None or build["status"] not in ("completed",):
        return _err("BUILD_INVALID", f"No completed build found for version {version}.", 403)
    ver_row = db.q1("SELECT * FROM project_versions WHERE id=?", (build["version_id"],)) if build["version_id"] else None
    if ver_row is not None and ver_row["revoked"]:
        return _err("VERSION_NOT_ALLOWED", "This version has been revoked.", 403)
    return {"ok": True, "version": version, "build_id": build["id"]}


@router.post("/integrity/verify")
async def integrity_verify(request: Request):
    ip = client_ip(request)
    if not rate_public.check(f"integ|{ip}", *config.RATE_PUBLIC_API):
        raise_rate_limited()
    body = await _json(request)
    lic = licensing.license_row(key=(body.get("license") or "").strip())
    if lic is None:
        return _err("LICENSE_INVALID", "The license key is not valid.", 404)
    build_id = (body.get("build") or "").strip()
    component = (body.get("component") or "").strip()
    claimed_sha = (body.get("sha256") or "").strip().lower()
    build = db.q1("SELECT * FROM builds WHERE id=? AND project_id=?", (build_id, lic["project_id"])) if build_id else None
    if build is None or build["status"] != "completed":
        return _err("BUILD_INVALID", "Build not found or not finalized.", 403)
    manifest_path = build["manifest_json"]
    if not manifest_path:
        return _err("BUILD_INVALID", "Manifest reference missing.", 500)
    try:
        from pathlib import Path
        manifest = json.loads(Path(manifest_path).read_text())
    except Exception:
        return _err("BUILD_INVALID", "Manifest unreadable on server.", 500)
    from ..pipeline import rawurlencode
    entry = (manifest.get("components") or {}).get(rawurlencode(component))
    if entry is None:
        return _err("INTEGRITY_FAILED", "Component is not part of this build.", 403)
    ok = claimed_sha == entry["plain_sha256"]
    return {
        "ok": ok,
        "component": component,
        "expected_plain_sha256": entry["plain_sha256"],
        "expected_ct_sha256": entry["ct_sha256"],
        "signature": crypto.sign_bytes(crypto.canonical_json(
            {"component": component, "plain_sha256": entry["plain_sha256"], "build": build_id})),
    }


@router.get("/runtime/file")
async def runtime_file(request: Request,
                       project: str = Query(...),
                       build: str = Query(...),
                       component: str = Query(...)):
    """Serve a protected component's plaintext to an authorized runtime.

    Authorization: Ed25519-signed token issued by /licenses/verify, checked
    here against the live license state (revocation takes effect immediately).
    """
    ip = client_ip(request)
    if not rate_public.check(f"file|{ip}", 240, 60):
        raise_rate_limited()
    auth = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
    if not auth:
        return _err("ACTIVATION_FAILED", "Missing authorization token.", 401)
    check = licensing.verify_token_request(auth, ip)
    if not check["ok"]:
        db.security_event(project, check.get("payload", {}).get("lic") if check.get("payload") else None,
                          "file_fetch_denied", "warning",
                          f"Component fetch denied: {check['error_code']}", ip)
        return _err(check["error_code"], "Authorization failed.", 403)
    payload = check["payload"]
    if payload.get("prj") != project or payload.get("bld") != build:
        return _err("PROJECT_MISMATCH", "Token does not match requested build.", 403)
    bdir = config.build_dir(project, build)
    from ..pipeline import rawurlencode
    from pathlib import Path
    # `component` is the raw project-relative path (e.g. "config/database.php");
    # one canonical encoding yields both the on-disk blob name and the manifest key.
    enc_name = rawurlencode(component)
    enc_path = bdir / "work" / "components" / f"{enc_name}.enc"
    if not enc_path.is_file():
        return _err("BUILD_INVALID", "Component not found.", 404)
    try:
        enc = json.loads(enc_path.read_text())
        cfg = json.loads(db.q1("SELECT config_json FROM builds WHERE id=?", (build,))["config_json"] or "{}")
        key = crypto.unwrap_key(crypto.master_key(), cfg["build_key_wrapped"])
        plain = crypto.aes_gcm_open(key, enc["nonce"], enc["ct"], aad=component.encode())
    except Exception:
        db.security_event(project, payload.get("lic"), "file_fetch_decrypt_error", "critical",
                          f"Decryption failure for component {component[:80]}", ip)
        return _err("BUILD_INVALID", "Component could not be processed.", 500)
    return {"data": base64.b64encode(plain).decode(),
            "sha256": crypto.sha256_hex(plain),
            "size": len(plain)}


@router.post("/events")
async def events_ingest(request: Request):
    """Best-effort tamper/authorization event reporting from runtimes."""
    ip = client_ip(request)
    if not rate_public.check(f"events|{ip}", 30, 300):
        raise_rate_limited()
    body = await _json(request)
    etype = (body.get("type") or "unknown").strip()[:80]
    project = (body.get("project") or "").strip()[:20]
    domain = (body.get("domain") or "").strip()[:253]
    detail = (body.get("detail") or "").strip()[:300]
    sev = "critical" if etype in ("integrity_failure", "invalid_signature") else "warning"
    db.security_event(project or None, None, etype[:60], sev,
                      f"runtime report: {detail}" + (f" (domain={domain})" if domain else ""), ip)
    return {"ok": True}


@router.get("/info")
async def info():
    return {"service": "Secure File Guard licensing API", "version": "v1",
            "public_key_fingerprint": crypto.public_key_fingerprint()}

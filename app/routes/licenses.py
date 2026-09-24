"""Secure File Guard — license management + domain management."""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Query, Request

from .. import config, db, licensing
from ..security import (ADMIN_ROLES, check_csrf, client_ip, require_user,
                        require_role)

router = APIRouter(prefix="/api/v1", tags=["licenses"])

SPECIAL_ROLES = ["super_admin"]


def _is_super(user: dict) -> bool:
    return user["role"] in SPECIAL_ROLES or user["role"] == "admin"


def _can_manage(user: dict, license_row: dict) -> bool:
    if user["role"] in ADMIN_ROLES:
        return True
    proj = db.q1("SELECT owner_id FROM projects WHERE id=?", (license_row["project_id"],))
    return proj is not None and proj["owner_id"] == user["id"]


def _lic_or_404(license_id: str) -> dict:
    row = db.q1("SELECT * FROM licenses WHERE id=?", (license_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "License not found."})
    return dict(row)


def _lic_view(row: dict, reveal_key: str | None = None) -> dict:
    out = dict(row)
    out["domains"] = licensing.license_domains_rows(row["id"])
    out["activated"] = bool(row["activated"])
    out["key"] = reveal_key  # plaintext shown exactly once, at creation
    return out


# ----------------------------------------------------------------------
# Licenses
# ----------------------------------------------------------------------

@router.get("/licenses")
async def list_licenses(request: Request, q: str = Query(default=""),
                        project_id: str = Query(default=""),
                        status: str = Query(default=""),
                        limit: int = Query(default=200, le=500)):
    user = require_user(request)
    sql = ("SELECT l.*, p.name project_name, u.email owner_email FROM licenses l"
           " LEFT JOIN projects p ON p.id = l.project_id"
           " LEFT JOIN users u ON u.id = p.owner_id WHERE 1=1")
    args: list = []
    if project_id:
        sql += " AND l.project_id = ?"
        args.append(project_id)
    if status:
        sql += " AND l.status = ?"
        args.append(status)
    if q:
        sql += " AND (l.id LIKE ? OR l.customer_name LIKE ? OR l.customer_email LIKE ? OR p.name LIKE ?)"
        like = f"%{q}%"
        args += [like, like, like, like]
    if user["role"] not in ADMIN_ROLES:
        sql += " AND l.project_id IN (SELECT id FROM projects WHERE owner_id = ?)"
        args.append(user["id"])
    sql += " ORDER BY l.created_at DESC LIMIT ?"
    args.append(limit)
    rows = db.rows_to_list(db.qall(sql, tuple(args)))
    for r in rows:
        r["domains"] = [d["domain"] for d in licensing.license_domains_rows(r["id"])][:6]
        r["key"] = None
    return {"licenses": rows}


@router.post("/licenses")
async def create_license(request: Request):
    user = require_user(request)
    check_csrf(request, user)
    body = await request.json()
    project_id = (body.get("project_id") or "").strip()
    proj = db.q1("SELECT * FROM projects WHERE id=?", (project_id,))
    if proj is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Project not found."})
    if user["role"] not in ADMIN_ROLES and user["id"] != proj["owner_id"]:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "You cannot create licenses for this project."})

    customer_name = (body.get("customer_name") or "").strip()[:120]
    customer_email = (body.get("customer_email") or "").strip()[:160]
    days = body.get("expiry_days")
    try:
        days = max(1, min(3650, int(days) if days is not None else 365))
    except Exception:
        days = 365
    domains_in = body.get("domains") or []
    if not isinstance(domains_in, (list, tuple)):
        domains_in = []
    domains = []
    allow_sub = bool(body.get("allow_subdomains"))
    for d in list(domains_in)[:10]:
        if not isinstance(d, (str, int, float)):
            continue
        nd = licensing.normalize_domain(str(d))
        if nd and nd not in domains:
            domains.append(nd)
    if not domains:
        raise HTTPException(status_code=400, detail={"code": "BAD_DOMAIN",
                                                     "message": "At least one valid authorized domain is required."})
    version_restrict = (body.get("version_restrict") or "").strip() or None

    key = licensing.generate_license_key()
    lid = config.new_id("LIC")
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + days * 86400))
    db.qexec(
        "INSERT INTO licenses (id, project_id, customer_name, customer_email, key_hash, status,"
        " activated, created_at, expires_at, version_restrict, created_by) VALUES (?,?,?,?,?, 'pending',0,?,?,?,?)",
        (lid, project_id, customer_name, customer_email, licensing.key_hash(key),
         db.utcnow(), expires, version_restrict, user["id"]))
    for d in domains:
        db.qexec("INSERT INTO license_domains (license_id, domain, status, allow_subdomains, verify_token, added_at)"
                 " VALUES (?, ?, 'pending', ?, ?, ?)",
                 (lid, d, 1 if allow_sub else 0, licensing.generate_license_key()[:8].upper(), db.utcnow()))
    db.audit(user["id"], user["email"], "license_created", "license", lid,
             detail=f"project={project_id} domains={','.join(domains[:4])} days={days}", ip=client_ip(request))
    # The plaintext key is shown exactly once.
    return {"license": _lic_view(_lic_or_404(lid), reveal_key=key)}


@router.get("/licenses/{license_id}")
async def get_license(request: Request, license_id: str):
    user = require_user(request)
    lic = _lic_or_404(license_id)
    if not _can_manage(user, lic):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access to this license."})
    out = _lic_view(lic)
    out["activations"] = db.rows_to_list(db.qall(
        "SELECT id, domain, ip, success, error_code, created_at FROM activations WHERE license_id=? ORDER BY id DESC LIMIT 50",
        (license_id,)))
    out["history"] = db.rows_to_list(db.qall(
        "SELECT id, domain, result, error_code, latency_ms, ip, created_at FROM verification_logs WHERE license_id=? ORDER BY id DESC LIMIT 100",
        (license_id,)))
    return {"license": out}


def _transition(license_id: str, new_status: str, action: str, user: dict, ip: str,
                require_current: tuple[str, ...] | None = None) -> None:
    lic = _lic_or_404(license_id)
    if require_current and lic["status"] not in require_current:
        raise HTTPException(status_code=409, detail={"code": "BAD_STATE",
                                                     "message": f"Cannot {action} a license in status '{lic['status']}'."})
    db.qexec("UPDATE licenses SET status=? WHERE id=?", (new_status, license_id))
    sev = "critical" if new_status in ("revoked",) else "warning"
    db.security_event(lic["project_id"], license_id, f"license_{action}", sev,
                      f"License status changed to '{new_status}'.")
    db.audit(user["id"], user["email"], f"license_{action}", "license", license_id, ip=ip)


@router.post("/licenses/{license_id}/suspend")
async def suspend_license(request: Request, license_id: str):
    user = require_user(request)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    if not _can_manage(user, lic):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access."})
    _transition(license_id, "suspended", "suspended", user, client_ip(request), require_current=("pending", "active"))
    return {"ok": True}


@router.post("/licenses/{license_id}/resume")
async def resume_license(request: Request, license_id: str):
    user = require_user(request)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    if not _can_manage(user, lic):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access."})
    _transition(license_id, "active", "resumed", user, client_ip(request), require_current=("suspended",))
    return {"ok": True}


@router.post("/licenses/{license_id}/revoke")
async def revoke_license(request: Request, license_id: str):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    if not _can_manage(user, lic):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access."})
    _transition(license_id, "revoked", "revoked", user, client_ip(request))
    return {"ok": True}


@router.post("/licenses/{license_id}/renew")
async def renew_license(request: Request, license_id: str):
    user = require_user(request)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    if not _can_manage(user, lic):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access."})
    body = await request.json()
    try:
        days = max(1, min(3650, int(body.get("days", 365))))
    except Exception:
        days = 365
    base = time.time()
    exp_now = licensing._parse_ts(lic["expires_at"]) or base
    new_exp = max(exp_now, base) + days * 86400
    new_status = "active" if lic["status"] in ("expired",) else lic["status"]
    db.qexec("UPDATE licenses SET expires_at=?, status=CASE WHEN status='expired' THEN 'active' ELSE status END WHERE id=?",
             (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(new_exp)), license_id))
    db.security_event(lic["project_id"], license_id, "license_renewed", "info", f"Renewed for {days} days.")
    db.audit(user["id"], user["email"], "license_renewed", "license", license_id,
             detail=f"+{days} days", ip=client_ip(request))
    return {"ok": True, "expires_at": db.qvalue("SELECT expires_at FROM licenses WHERE id=?", (license_id,))}


@router.post("/licenses/{license_id}/reset-activation")
async def reset_activation(request: Request, license_id: str):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    db.qexec("UPDATE licenses SET activated=0, activated_at=NULL, status=CASE WHEN status='active' THEN 'pending' ELSE status END WHERE id=?",
             (license_id,))
    db.audit(user["id"], user["email"], "license_activation_reset", "license", license_id, ip=client_ip(request))
    return {"ok": True}


@router.post("/licenses/{license_id}/rotate-key")
async def rotate_key(request: Request, license_id: str):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    key = licensing.generate_license_key()
    db.qexec("UPDATE licenses SET key_hash=? WHERE id=?", (licensing.key_hash(key), license_id))
    db.security_event(lic["project_id"], license_id, "license_key_rotated", "warning",
                      "License key rotated; previous key is now invalid.")
    db.audit(user["id"], user["email"], "license_key_rotated", "license", license_id, ip=client_ip(request))
    return {"key": key, "note": "Shown once — the previous key no longer works."}


# ----------------------------------------------------------------------
# Domains
# ----------------------------------------------------------------------

@router.get("/domains")
async def list_domains(request: Request, q: str = Query(default="")):
    user = require_user(request)
    sql = ("SELECT d.*, l.id license_id, l.project_id, l.status license_status, p.name project_name"
           " FROM license_domains d JOIN licenses l ON l.id = d.license_id"
           " LEFT JOIN projects p ON p.id = l.project_id WHERE 1=1")
    args: list = []
    if q:
        sql += " AND (d.domain LIKE ? OR l.project_id LIKE ?)"
        args += [f"%{q}%", f"%{q}%"]
    if user["role"] not in ADMIN_ROLES:
        sql += " AND l.project_id IN (SELECT id FROM projects WHERE owner_id = ?)"
        args.append(user["id"])
    sql += " ORDER BY d.domain LIMIT 500"
    rows = db.rows_to_list(db.qall(sql, tuple(args)))
    return {"domains": rows}


@router.post("/licenses/{license_id}/domains")
async def add_domain(request: Request, license_id: str):
    user = require_user(request)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    if not _can_manage(user, lic):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access."})
    body = await request.json()
    d = licensing.normalize_domain(str(body.get("domain") or ""))
    if not d:
        raise HTTPException(status_code=400, detail={"code": "BAD_DOMAIN", "message": "Invalid domain."})
    allow_sub = bool(body.get("allow_subdomains"))
    token = licensing.generate_license_key()[:8].upper()
    try:
        db.qexec("INSERT INTO license_domains (license_id, domain, status, allow_subdomains, verify_token, added_at)"
                 " VALUES (?, ?, 'pending', ?, ?, ?)", (license_id, d, 1 if allow_sub else 0, token, db.utcnow()))
    except Exception:
        raise HTTPException(status_code=409, detail={"code": "DUPLICATE", "message": "Domain already exists for this license."})
    db.audit(user["id"], user["email"], "domain_added", "domain", d, detail=f"license={license_id}", ip=client_ip(request))
    return {"ok": True, "domain": d, "verify_token": token,
            "dns_hint": f'Add a DNS TXT record:  _sfg-verify.{d}  "sfg-verify={token}"'}


@router.delete("/licenses/{license_id}/domains/{domain}")
async def remove_domain(request: Request, license_id: str, domain: str):
    user = require_user(request)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    if not _can_manage(user, lic):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access."})
    d = licensing.normalize_domain(domain)
    db.qexec("DELETE FROM license_domains WHERE license_id=? AND domain=?", (license_id, d))
    db.audit(user["id"], user["email"], "domain_removed", "domain", d, detail=f"license={license_id}", ip=client_ip(request))
    return {"ok": True}


@router.post("/licenses/{license_id}/domains/{domain}/verify")
async def verify_domain(request: Request, license_id: str, domain: str):
    """Verify ownership via DNS TXT record (real lookup), or manually approve."""
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    if not _can_manage(user, lic):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access."})
    d = licensing.normalize_domain(domain)
    row = db.q1("SELECT * FROM license_domains WHERE license_id=? AND domain=?", (license_id, d))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Domain not found for this license."})
    body = await request.json() if await request.body() else {}
    method = body.get("method", "dns")
    if method == "manual":
        db.qexec("UPDATE license_domains SET status='verified', verified_at=? WHERE id=?", (db.utcnow(), row["id"]))
        db.security_event(lic["project_id"], license_id, "domain_verified_manual", "info",
                          f"Domain {d} manually approved.")
        db.audit(user["id"], user["email"], "domain_verified", "domain", d, detail="manual", ip=client_ip(request))
        return {"ok": True, "status": "verified", "method": "manual"}
    from ..services.dnscheck import dns_txt
    expected = f"sfg-verify={row['verify_token']}"
    records = dns_txt(f"_sfg-verify.{d}")
    if records is None:
        db.audit(user["id"], user["email"], "domain_verify_failed", "domain", d,
                 result="failed", detail="DNS unreachable", ip=client_ip(request))
        raise HTTPException(status_code=502, detail={"code": "DNS_UNREACHABLE",
                                                     "message": "Could not reach DNS for this domain. Add the TXT record and retry, or approve manually."})
    if expected in records:
        db.qexec("UPDATE license_domains SET status='verified', verified_at=? WHERE id=?", (db.utcnow(), row["id"]))
        db.security_event(lic["project_id"], license_id, "domain_verified_dns", "info",
                          f"Domain {d} verified via DNS TXT record.")
        db.audit(user["id"], user["email"], "domain_verified", "domain", d, detail="dns", ip=client_ip(request))
        return {"ok": True, "status": "verified", "method": "dns"}
    db.audit(user["id"], user["email"], "domain_verify_failed", "domain", d,
             result="failed", detail="TXT record missing or mismatched", ip=client_ip(request))
    raise HTTPException(status_code=400, detail={"code": "DNS_MISMATCH",
                                                 "message": f'TXT record "sfg-verify={row["verify_token"]}" not found on _sfg-verify.{d}. Add it and retry.'})


@router.post("/licenses/{license_id}/domains/{domain}/block")
async def block_domain(request: Request, license_id: str, domain: str):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    lic = _lic_or_404(license_id)
    d = licensing.normalize_domain(domain)
    row = db.q1("SELECT * FROM license_domains WHERE license_id=? AND domain=?", (license_id, d))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Domain not found."})
    new = "active" if row["status"] == "blocked" else "blocked"
    db.qexec("UPDATE license_domains SET status=? WHERE id=?", (new, row["id"]))
    db.security_event(lic["project_id"], license_id, "domain_blocked" if new == "blocked" else "domain_unblocked",
                      "warning", f"Domain {d} {'blocked' if new == 'blocked' else 'unblocked'}.")
    db.audit(user["id"], user["email"], "domain_blocked" if new == "blocked" else "domain_unblocked",
             "domain", d, ip=client_ip(request))
    return {"ok": True, "status": new}

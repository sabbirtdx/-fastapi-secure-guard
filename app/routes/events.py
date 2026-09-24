"""Secure File Guard — security events, verification logs, audit logs."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from .. import db
from ..security import ADMIN_ROLES, require_role, require_user

router = APIRouter(prefix="/api/v1", tags=["events"])


def _range_filter(where: list[str], args: list, frm: str, to: str) -> None:
    if frm:
        where.append("created_at >= ?")
        args.append(frm[:19])
    if to:
        where.append("created_at <= ?")
        args.append(to[:19] + "T23:59:59Z" if len(to[:19]) == 10 else to[:19])


@router.get("/events")
async def list_events(request: Request,
                      q: str = Query(default=""),
                      type: str = Query(default=""),
                      severity: str = Query(default=""),
                      project_id: str = Query(default=""),
                      license_id: str = Query(default=""),
                      from_: str = Query(default="", alias="from"),
                      to: str = Query(default=""),
                      limit: int = Query(default=300, le=1000)):
    user = require_user(request)
    if user["role"] not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Admin only."})
    where = ["1=1"]
    args: list = []
    if q:
        where.append("(type LIKE ? OR detail LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    if type:
        where.append("type = ?")
        args.append(type)
    if severity:
        where.append("severity = ?")
        args.append(severity)
    if project_id:
        where.append("project_id = ?")
        args.append(project_id)
    if license_id:
        where.append("license_id = ?")
        args.append(license_id)
    _range_filter(where, args, from_, to)
    rows = db.rows_to_list(db.qall(
        "SELECT * FROM security_events WHERE " + " AND ".join(where) + " ORDER BY id DESC LIMIT ?",
        tuple(args + [limit])))
    types = db.rows_to_list(db.qall("SELECT type, COUNT(*) c FROM security_events GROUP BY type ORDER BY c DESC"))
    return {"events": rows, "type_counts": types}


@router.get("/events/export.csv")
async def export_events(request: Request,
                        type: str = Query(default=""),
                        severity: str = Query(default=""),
                        project_id: str = Query(default=""),
                        from_: str = Query(default="", alias="from"),
                        to: str = Query(default="")):
    user = require_role(request, ADMIN_ROLES)
    where = ["1=1"]
    args: list = []
    if type:
        where.append("type = ?"); args.append(type)
    if severity:
        where.append("severity = ?"); args.append(severity)
    if project_id:
        where.append("project_id = ?"); args.append(project_id)
    _range_filter(where, args, from_, to)
    rows = db.rows_to_list(db.qall(
        "SELECT id, created_at, type, severity, project_id, license_id, detail, ip FROM security_events"
        " WHERE " + " AND ".join(where) + " ORDER BY id DESC LIMIT 20000", tuple(args)))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_at", "type", "severity", "project_id", "license_id", "detail", "ip"])
    for r in rows:
        w.writerow([r["id"], r["created_at"], r["type"], r["severity"], r["project_id"], r["license_id"], r["detail"], r["ip"]])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                              headers={"Content-Disposition": "attachment; filename=security-events.csv"})


@router.get("/verifications")
async def list_verifications(request: Request,
                             license_id: str = Query(default=""),
                             project_id: str = Query(default=""),
                             result: str = Query(default=""),
                             error_code: str = Query(default=""),
                             from_: str = Query(default="", alias="from"),
                             to: str = Query(default=""),
                             limit: int = Query(default=300, le=1000)):
    user = require_user(request)
    if user["role"] not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Admin only."})
    where = ["1=1"]
    args: list = []
    if license_id:
        where.append("license_id = ?"); args.append(license_id)
    if project_id:
        where.append("project_id = ?"); args.append(project_id)
    if result:
        where.append("result = ?"); args.append(result)
    if error_code:
        where.append("error_code = ?"); args.append(error_code)
    _range_filter(where, args, from_, to)
    rows = db.rows_to_list(db.qall(
        "SELECT * FROM verification_logs WHERE " + " AND ".join(where) + " ORDER BY id DESC LIMIT ?",
        tuple(args + [limit])))
    return {"verifications": rows}


@router.get("/verifications/export.csv")
async def export_verifications(request: Request,
                               license_id: str = Query(default=""),
                               result: str = Query(default="")):
    user = require_role(request, ADMIN_ROLES)
    where = ["1=1"]
    args: list = []
    if license_id:
        where.append("license_id = ?"); args.append(license_id)
    if result:
        where.append("result = ?"); args.append(result)
    rows = db.rows_to_list(db.qall(
        "SELECT id, created_at, license_id, project_id, domain, result, error_code, latency_ms, ip, kind"
        " FROM verification_logs WHERE " + " AND ".join(where) + " ORDER BY id DESC LIMIT 20000", tuple(args)))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_at", "license_id", "project_id", "domain", "result", "error_code", "latency_ms", "ip", "kind"])
    for r in rows:
        w.writerow([r[k] for k in w.fieldnames])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                              headers={"Content-Disposition": "attachment; filename=verification-logs.csv"})


@router.get("/audit")
async def list_audit(request: Request,
                     q: str = Query(default=""),
                     action: str = Query(default=""),
                     actor: str = Query(default=""),
                     from_: str = Query(default="", alias="from"),
                     to: str = Query(default=""),
                     limit: int = Query(default=300, le=1000)):
    user = require_role(request, ADMIN_ROLES)
    where = ["1=1"]
    args: list = []
    if q:
        where.append("(resource_id LIKE ? OR detail LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    if action:
        where.append("action = ?"); args.append(action)
    if actor:
        where.append("actor_email LIKE ?"); args.append(f"%{actor}%")
    _range_filter(where, args, from_, to)
    rows = db.rows_to_list(db.qall(
        "SELECT * FROM audit_logs WHERE " + " AND ".join(where) + " ORDER BY id DESC LIMIT ?",
        tuple(args + [limit])))
    return {"audit": rows}

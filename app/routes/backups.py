"""Secure File Guard — backup & recovery routes."""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from ..security import ADMIN_ROLES, check_csrf, client_ip, require_role
from ..services import backup as backup_svc

router = APIRouter(prefix="/api/v1/backup", tags=["backup"])


@router.get("/export")
async def export(request: Request):
    user = require_role(request, ADMIN_ROLES)
    bundle = backup_svc.export_backup()
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": "attachment; filename=sfg-backup.json"})


@router.post("/restore")
async def restore(request: Request):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    try:
        bundle = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail={"code": "BAD_JSON", "message": "Invalid JSON bundle."})
    try:
        result = backup_svc.restore_backup(bundle, user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"code": "RESTORE_REJECTED", "message": str(e)})
    return result


@router.get("")
async def list_backups(request: Request):
    user = require_role(request, ADMIN_ROLES)
    return {"backups": backup_svc.backup_list()}

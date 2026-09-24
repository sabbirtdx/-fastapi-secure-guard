"""Secure File Guard — builds (live progress via SSE + polling)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse

from .. import config, db, pipeline
from ..security import (ADMIN_ROLES, check_csrf, client_ip, require_user,
                        require_role)

router = APIRouter(tags=["builds"])


def _project(user: dict, project_id: str) -> dict:
    if not config.is_valid_project_id(project_id):
        raise HTTPException(status_code=400, detail={"code": "BAD_ID", "message": "Invalid project id."})
    row = db.q1("SELECT * FROM projects WHERE id=?", (project_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Project not found."})
    if user["role"] not in ADMIN_ROLES and user["id"] != row["owner_id"]:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access to this project."})
    return dict(row)


def _build_or_404(build_id: str) -> dict:
    if not config.is_valid_build_id(build_id):
        raise HTTPException(status_code=400, detail={"code": "BAD_ID", "message": "Invalid build id."})
    row = db.q1("SELECT * FROM builds WHERE id=?", (build_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Build not found."})
    return dict(row)


@router.get("/api/v1/projects/{project_id}/builds")
async def list_builds(request: Request, project_id: str):
    user = require_user(request)
    _project(user, project_id)
    rows = db.rows_to_list(db.qall(
        "SELECT id, version, status, stage, stage_index, total_stages, validation_report_json, package_sha256,"
        " error, created_at, started_at, completed_at FROM builds WHERE project_id=? ORDER BY id DESC LIMIT 100",
        (project_id,)))
    for r in rows:
        r["validation_passed"] = None
        if r["validation_report_json"]:
            try:
                r["validation_passed"] = json.loads(r["validation_report_json"])["passed"]
            except Exception:
                pass
    return {"builds": rows}


@router.post("/api/v1/projects/{project_id}/builds")
async def create_build(request: Request, project_id: str):
    user = require_user(request)
    check_csrf(request, user)
    p = _project(user, project_id)
    body = await request.json()
    version = (body.get("version") or "1.0").strip()
    if not version or len(version) > 40:
        raise HTTPException(status_code=400, detail={"code": "BAD_INPUT", "message": "Invalid version."})
    opts = {
        "include": [s for s in (body.get("include") or []) if isinstance(s, str)][:500],
        "exclude": [s for s in (body.get("exclude") or []) if isinstance(s, str)][:500],
        "obfuscate": bool(body.get("obfuscate")),
    }
    files = db.qvalue("SELECT COUNT(*) FROM project_files WHERE project_id=?", (p["id"],))
    if not files:
        raise HTTPException(status_code=409, detail={"code": "EMPTY_PROJECT", "message": "Upload a project before building."})
    build_id = pipeline.create_build(p["id"], version, opts, user)
    try:
        await pipeline.start_build_async(build_id, p["id"], version, opts, user)
    except RuntimeError as e:
        db.qexec("UPDATE builds SET status='failed', error=? WHERE id=?", (str(e), build_id))
        raise HTTPException(status_code=503, detail={"code": "BUILD_SERVICE_BUSY", "message": str(e)})
    db.audit(user["id"], user["email"], "build_started", "build", build_id,
             detail=f"version={version} obfuscate={opts['obfuscate']}", ip=client_ip(request))
    return {"build_id": build_id}


def _build_view(b: dict) -> dict:
    out = dict(b)
    out["events"] = pipeline.progress_events(b["id"])[-100:]
    out["validation_report"] = json.loads(b["validation_report_json"]) if b["validation_report_json"] else None
    out["stages"] = [
        {"index": i + 1, "name": n} for i, n in enumerate(pipeline.STAGE_NAMES)
    ]
    return out


@router.get("/api/v1/builds/{build_id}")
async def get_build(request: Request, build_id: str):
    user = require_user(request)
    b = _build_or_404(build_id)
    if user["role"] not in ADMIN_ROLES and user["id"] != (
            db.qvalue("SELECT owner_id FROM projects WHERE id=?", (b["project_id"],)) or -1):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access to this build."})
    return {"build": _build_view(b)}


@router.get("/api/v1/builds/{build_id}/progress")
async def build_progress(request: Request, build_id: str):
    """SSE stream of real pipeline stage events."""
    user = require_user(request)
    b = _build_or_404(build_id)
    if user["role"] not in ADMIN_ROLES and user["id"] != (
            db.qvalue("SELECT owner_id FROM projects WHERE id=?", (b["project_id"],)) or -1):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access to this build."})

    async def gen():
        sent = 0
        poke = asyncio.Event()
        pipeline._pokes[build_id] = poke
        try:
            while True:
                events = pipeline.progress_events(build_id)
                while sent < len(events):
                    yield f"data: {json.dumps(events[sent])}\n\n"
                    sent += 1
                if sent == len(events):
                    row = db.q1("SELECT status FROM builds WHERE id=?", (build_id,))
                    if row and row["status"] in ("completed", "failed", "disabled"):
                        yield "event: done\ndata: {}\n\n"
                        return
                try:
                    await asyncio.wait_for(poke.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
                poke.clear()
        finally:
            pipeline._pokes.pop(build_id, None)

    return StreamingResponse(gen(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/api/v1/builds/{build_id}/download")
async def download_build(request: Request, build_id: str):
    user = require_user(request)
    b = _build_or_404(build_id)
    if user["role"] not in ADMIN_ROLES and user["id"] != (
            db.qvalue("SELECT owner_id FROM projects WHERE id=?", (b["project_id"],)) or -1):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "No access to this build."})
    if b["status"] != "completed" or not b["package_path"]:
        raise HTTPException(status_code=409, detail={"code": "BUILD_NOT_READY",
                                                     "message": "This build has no validated package."})
    path = Path(b["package_path"])
    if not path.is_file():
        raise HTTPException(status_code=410, detail={"code": "PACKAGE_MISSING",
                                                     "message": "Package file is missing from storage."})
    db.audit(user["id"], user["email"], "build_downloaded", "build", b["id"], ip=client_ip(request))
    return FileResponse(path, media_type="application/zip",
                        filename=f"{b['project_id']}-{b['version']}-protected.zip")


@router.post("/api/v1/builds/{build_id}/disable")
async def disable_build(request: Request, build_id: str):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    b = _build_or_404(build_id)
    if b["status"] != "completed":
        raise HTTPException(status_code=409, detail={"code": "BAD_STATE", "message": "Only completed builds can be disabled."})
    db.qexec("UPDATE builds SET status='disabled', error='Disabled by administrator' WHERE id=?", (build_id,))
    db.security_event(b["project_id"], None, "build_disabled", "warning",
                      f"Build {build_id} disabled; protected deployments using it will fail verification.")
    db.audit(user["id"], user["email"], "build_disabled", "build", b["id"], ip=client_ip(request))
    return {"ok": True}


@router.post("/api/v1/builds/{build_id}/enable")
async def enable_build(request: Request, build_id: str):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    b = _build_or_404(build_id)
    if b["status"] != "disabled":
        raise HTTPException(status_code=409, detail={"code": "BAD_STATE", "message": "Only disabled builds can be re-enabled."})
    if not b["package_path"] or not Path(b["package_path"]).is_file():
        raise HTTPException(status_code=409, detail={"code": "PACKAGE_MISSING",
                                                     "message": "Package file missing — cannot re-enable."})
    db.qexec("UPDATE builds SET status='completed', error=NULL WHERE id=?", (build_id,))
    db.audit(user["id"], user["email"], "build_enabled", "build", b["id"], ip=client_ip(request))
    return {"ok": True}


@router.delete("/api/v1/builds/{build_id}")
async def delete_build(request: Request, build_id: str):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    b = _build_or_404(build_id)
    if b["status"] == "running":
        raise HTTPException(status_code=409, detail={"code": "BUILD_RUNNING", "message": "Wait for the build to finish."})
    # delete workspace artifacts + row (cascade removes links)
    bdir = config.build_dir(b["project_id"], b["id"])
    if bdir.exists():
        import shutil
        shutil.rmtree(bdir, ignore_errors=True)
    db.qexec("DELETE FROM builds WHERE id=?", (build_id,))
    db.audit(user["id"], user["email"], "build_deleted", "build", b["id"], ip=client_ip(request))
    return {"ok": True}

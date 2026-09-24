"""Secure File Guard — project management + uploads (ZIP and direct folder)."""
from __future__ import annotations

import io
import json
import re
import shutil
import zipfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile

from .. import analyzer, config, db, scanner
from ..security import (ADMIN_ROLES, check_csrf, client_ip, require_user,
                        require_role)

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _project_or_404(project_id: str) -> dict:
    if not config.is_valid_project_id(project_id):
        raise HTTPException(status_code=400, detail={"code": "BAD_ID", "message": "Invalid project id."})
    row = db.q1("SELECT * FROM projects WHERE id=?", (project_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Project not found."})
    return dict(row)


def _can_access(user: dict, project: dict) -> bool:
    if user["role"] in ADMIN_ROLES:
        return True
    return user["id"] == project["owner_id"]


def _get_project(user: dict, project_id: str) -> dict:
    project = _project_or_404(project_id)
    if not _can_access(user, project):
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "You do not have access to this project."})
    return project


def _touch(project_id: str) -> None:
    db.qexec("UPDATE projects SET updated_at=? WHERE id=?", (db.utcnow(), project_id))


# ----------------------------------------------------------------------
# CRUD
# ----------------------------------------------------------------------

@router.get("")
async def list_projects(request: Request, q: str = Query(default=""), mine: bool = Query(default=False)):
    user = require_user(request)
    sql = "SELECT * FROM projects"
    args: list = []
    where = []
    # Non-admins only ever see their own projects (ownership is a hard boundary).
    if user["role"] not in ADMIN_ROLES:
        where.append("owner_id = ?")
        args.append(user["id"])
    elif mine:
        where.append("owner_id = ?")
        args.append(user["id"])
    if q:
        where.append("(id LIKE ? OR name LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC LIMIT 200"
    rows = db.rows_to_list(db.qall(sql, tuple(args)))
    for r in rows:
        r["file_count"] = db.qvalue("SELECT COUNT(*) FROM project_files WHERE project_id=?", (r["id"],))
        r["license_count"] = db.qvalue("SELECT COUNT(*) FROM licenses WHERE project_id=?", (r["id"],))
        r["build_count"] = db.qvalue("SELECT COUNT(*) FROM builds WHERE project_id=? AND status='completed'", (r["id"],))
    return {"projects": rows}


@router.post("")
async def create_project(request: Request):
    user = require_user(request)
    check_csrf(request, user)
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name or len(name) > 120:
        raise HTTPException(status_code=400, detail={"code": "BAD_INPUT", "message": "Project name is required (max 120 chars)."})
    pid = config.new_id("PRJ")
    config.project_dir(pid)
    db.qexec("INSERT INTO projects (id, name, owner_id, status, protection_level, created_at, updated_at)"
             " VALUES (?,?,?, 'active','standard',?,?)", (pid, name, user["id"], db.utcnow(), db.utcnow()))
    db.audit(user["id"], user["email"], "project_created", "project", pid, detail=name, ip=client_ip(request))
    return {"project": _project_or_404(pid)}


@router.get("/{project_id}")
async def get_project(request: Request, project_id: str):
    user = require_user(request)
    p = _get_project(user, project_id)
    out = dict(p)
    out["owner_email"] = db.qvalue("SELECT email FROM users WHERE id=?", (p["owner_id"],))
    out["file_count"] = db.qvalue("SELECT COUNT(*) FROM project_files WHERE project_id=?", (p["id"],))
    out["total_size"] = db.qvalue("SELECT COALESCE(SUM(size),0) FROM project_files WHERE project_id=?", (p["id"],))
    out["licenses"] = db.rows_to_list(db.qall(
        "SELECT id, status, expires_at, activated, created_at, customer_name, customer_email FROM licenses WHERE project_id=?",
        (p["id"],)))
    out["versions"] = db.rows_to_list(db.qall(
        "SELECT id, version, note, created_at, revoked FROM project_versions WHERE project_id=? ORDER BY id", (p["id"],)))
    return {"project": out}


@router.patch("/{project_id}")
async def update_project(request: Request, project_id: str):
    user = require_user(request)
    check_csrf(request, user)
    p = _get_project(user, project_id)
    body = await request.json()
    if user["role"] not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Only admins can edit project metadata."})
    name = body.get("name")
    level = body.get("protection_level")
    if name is not None:
        name = name.strip()
        if not name or len(name) > 120:
            raise HTTPException(status_code=400, detail={"code": "BAD_INPUT", "message": "Invalid project name."})
        db.qexec("UPDATE projects SET name=?, updated_at=? WHERE id=?", (name, db.utcnow(), p["id"]))
    if level in ("basic", "standard", "advanced"):
        db.qexec("UPDATE projects SET protection_level=?, updated_at=? WHERE id=?", (level, db.utcnow(), p["id"]))
    db.audit(user["id"], user["email"], "project_updated", "project", p["id"], ip=client_ip(request))
    return {"project": _project_or_404(p["id"])}


@router.post("/{project_id}/archive")
async def archive_project(request: Request, project_id: str):
    user = require_user(request)
    check_csrf(request, user)
    p = _get_project(user, project_id)
    if user["role"] not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Only admins can archive projects."})
    new_status = "active" if p["status"] == "archived" else "archived"
    db.qexec("UPDATE projects SET status=?, archived_at=COALESCE(archived_at, ?), updated_at=? WHERE id=?",
             (new_status, db.utcnow(), db.utcnow(), p["id"]))
    db.audit(user["id"], user["email"], "project_archived" if new_status == "archived" else "project_restored",
             "project", p["id"], ip=client_ip(request))
    return {"project": _project_or_404(p["id"])}


# ----------------------------------------------------------------------
# Files / scan / AI
# ----------------------------------------------------------------------

@router.get("/{project_id}/files")
async def project_files(request: Request, project_id: str):
    user = require_user(request)
    p = _get_project(user, project_id)
    rows = db.rows_to_list(db.qall(
        "SELECT relpath, size, kind, sensitive, secret_count FROM project_files WHERE project_id=? ORDER BY relpath LIMIT 20000",
        (p["id"],)))
    summary = db.rows_to_list(db.qall(
        "SELECT kind, COUNT(*) c, SUM(size) s FROM project_files WHERE project_id=? GROUP BY kind", (p["id"],)))
    return {"files": rows, "summary": summary}


@router.get("/{project_id}/scan")
async def project_scan(request: Request, project_id: str, rescan: bool = Query(default=False)):
    user = require_user(request)
    p = _get_project(user, project_id)
    if rescan:
        try:
            report = scanner.scan_project(p["id"])
        except Exception as e:
            raise HTTPException(status_code=500, detail={"code": "SCAN_FAILED", "message": f"Scan failed: {e.__class__.__name__}"})
    else:
        f = config.project_dir(p["id"]) / "analysis" / "scan.json"
        if not f.exists():
            raise HTTPException(status_code=404, detail={"code": "NO_SCAN", "message": "No scan available yet. Upload files or trigger a rescan."})
        report = json.loads(f.read_text())
    return {"scan": report}


@router.get("/{project_id}/ai-analysis")
async def project_ai(request: Request, project_id: str):
    user = require_user(request)
    p = _get_project(user, project_id)
    rows = db.rows_to_list(db.qall(
        "SELECT id, engine, model, created_at FROM ai_analysis WHERE project_id=? ORDER BY id DESC LIMIT 10", (p["id"],)))
    latest = db.q1("SELECT * FROM ai_analysis WHERE project_id=? ORDER BY id DESC LIMIT 1", (p["id"],))
    return {
        "history": rows,
        "latest": json.loads(latest["result_json"]) if latest else None,
        "llm_configured": bool(db.get_settings().get("ai_base_url") and db.get_settings().get("ai_key_wrapped")),
    }


@router.post("/{project_id}/ai-analysis")
async def project_ai_run(request: Request, project_id: str, engine: str = Query(default="builtin")):
    user = require_user(request)
    check_csrf(request, user)
    p = _get_project(user, project_id)
    try:
        if engine == "llm":
            result = analyzer.run_llm_analysis(p["id"])
        else:
            result = analyzer.analyze_project(p["id"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"code": "ANALYSIS_FAILED", "message": str(e)})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"code": "ANALYSIS_FAILED", "message": f"Analysis failed: {e.__class__.__name__}"})
    db.audit(user["id"], user["email"], "ai_analysis_run", "project", p["id"],
             detail=f"engine={engine}", ip=client_ip(request))
    return {"analysis": result}


# ----------------------------------------------------------------------
# Protection configuration
# ----------------------------------------------------------------------

@router.get("/{project_id}/protection-config")
async def protection_config_get(request: Request, project_id: str):
    user = require_user(request)
    p = _get_project(user, project_id)
    analysis = db.q1("SELECT result_json FROM ai_analysis WHERE project_id=? ORDER BY id DESC LIMIT 1", (p["id"],))
    recommended = json.loads(analysis["result_json"])["recommendation"] if analysis else {"protected_components": [], "protection_level": "standard"}
    cfg = db.q1("SELECT config_json FROM builds WHERE project_id=? AND status IN ('completed','failed','running','queued') ORDER BY id DESC LIMIT 1", (p["id"],))
    saved = json.loads(cfg["config_json"]) if cfg and cfg["config_json"] else {}
    return {
        "recommended_level": recommended.get("protection_level"),
        "recommended_components": recommended.get("protected_components", []),
        "saved": {k: saved.get(k) for k in ("include", "exclude", "obfuscate") if k in saved},
    }


# ----------------------------------------------------------------------
# Versions
# ----------------------------------------------------------------------

@router.get("/{project_id}/versions")
async def project_versions(request: Request, project_id: str):
    user = require_user(request)
    p = _get_project(user, project_id)
    rows = db.rows_to_list(db.qall(
        "SELECT id, version, note, created_at, revoked FROM project_versions WHERE project_id=? ORDER BY id", (p["id"],)))
    for r in rows:
        r["builds"] = db.qvalue("SELECT COUNT(*) FROM builds WHERE version_id=?", (r["id"],))
    return {"versions": rows}


@router.post("/{project_id}/versions")
async def project_version_create(request: Request, project_id: str):
    user = require_user(request)
    check_csrf(request, user)
    p = _get_project(user, project_id)
    body = await request.json()
    version = (body.get("version") or "").strip()
    note = (body.get("note") or "").strip()[:300]
    if not re.match(r"^\d+\.\d+(\.\d+)?$", version):
        raise HTTPException(status_code=400, detail={"code": "BAD_VERSION", "message": "Version must be numeric like 1.0 or 1.0.1."})
    try:
        vid = db.qexec("INSERT INTO project_versions (project_id, version, note, created_by, created_at)"
                       " VALUES (?,?,?,?,?)", (p["id"], version, note, user["id"], db.utcnow()))
    except Exception:
        raise HTTPException(status_code=409, detail={"code": "DUPLICATE", "message": f"Version {version} already exists."})
    db.audit(user["id"], user["email"], "version_created", "version", str(vid), detail=version, ip=client_ip(request))
    return {"version_id": vid, "version": version}


@router.post("/versions/{version_id}/revoke")
async def version_revoke(request: Request, version_id: int):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    row = db.q1("SELECT * FROM project_versions WHERE id=?", (version_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Version not found."})
    db.qexec("UPDATE project_versions SET revoked=? WHERE id=?", (0 if row["revoked"] else 1, version_id))
    db.security_event(row["project_id"], None, "version_revoked" if not row["revoked"] else "version_restored",
                      "warning", f"Version {row['version']} {'revoked' if not row['revoked'] else 'restored'}.")
    db.audit(user["id"], user["email"], "version_revoked" if not row["revoked"] else "version_restored",
             "version", str(version_id), ip=client_ip(request))
    return {"ok": True, "revoked": not bool(row["revoked"])}


# ----------------------------------------------------------------------
# Uploads: ZIP
# ----------------------------------------------------------------------

MAX_FILE_MB = 200


def _safe_zip_name(name: str) -> str | None:
    """Validate a zip entry name. Returns the sanitized relative path or None."""
    name = name.replace("\\", "/")
    if name.startswith("/") or name.startswith("\\"):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    if not parts:
        return None
    if re.match(r"^[A-Za-z]:", parts[0]):
        return None
    return "/".join(parts)


@router.post("/{project_id}/upload/zip")
async def upload_zip(request: Request, project_id: str, file: UploadFile = File(...)):
    user = require_user(request)
    check_csrf(request, user)
    p = _get_project(user, project_id)
    filename = file.filename or "upload.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail={"code": "BAD_EXTENSION", "message": "Only .zip files are accepted."})
    content_type = (file.content_type or "").lower()
    if content_type and content_type not in ("application/zip", "application/x-zip-compressed",
                                             "application/octet-stream", ""):
        raise HTTPException(status_code=400, detail={"code": "BAD_MIME", "message": "Unrecognized ZIP MIME type."})

    max_bytes = int(db.get_settings().get("max_upload_mb", str(MAX_FILE_MB))) * 1024 * 1024
    data = await file.read()
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail={"code": "TOO_LARGE", "message": f"File exceeds the {max_bytes // (1024*1024)} MB limit."})
    if len(data) == 0:
        raise HTTPException(status_code=400, detail={"code": "EMPTY", "message": "Uploaded file is empty."})

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        bad = zf.testzip()
        if bad is not None:
            raise ValueError(f"corrupt member: {bad}")
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail={"code": "BAD_ZIP", "message": "Not a valid ZIP archive."})
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"code": "BAD_ZIP", "message": f"Malformed archive: {e}"})

    infos = zf.infolist()
    if len(infos) > config.MAX_ZIP_ENTRIES:
        raise HTTPException(status_code=400, detail={"code": "TOO_MANY_FILES", "message": f"Archive has more than {config.MAX_ZIP_ENTRIES} files."})

    # PHASE 1 — validate the entire archive before touching the workspace,
    # so a rejected upload can never destroy a previously uploaded project.
    validated: list[tuple] = []
    seen: dict[str, str] = {}
    total_uncompressed = 0
    for info in infos:
        if info.is_dir():
            continue
        rel = _safe_zip_name(info.filename)
        if rel is None:
            raise HTTPException(status_code=400, detail={"code": "PATH_TRAVERSAL", "message": f"Archive entry with unsafe path rejected: {info.filename[:80]}"})
        if info.external_attr >> 28 in (2, 3, 10):  # symlink/device
            raise HTTPException(status_code=400, detail={"code": "UNSAFE_ENTRY", "message": "Archive contains a symlink or special file."})
        total_uncompressed += info.file_size
        if total_uncompressed > max_bytes * 4:
            raise HTTPException(status_code=400, detail={"code": "COMPRESSED_BOMB", "message": "Archive decompression ratio exceeds safety limit."})
        if rel in seen:
            raise HTTPException(status_code=400, detail={"code": "DUPLICATE_PATH", "message": f"Duplicate path in archive: {rel}"})
        seen[rel] = info.filename
        validated.append((info, rel))

    if not validated:
        raise HTTPException(status_code=400, detail={"code": "EMPTY_ZIP", "message": "Archive contains no files."})

    # PHASE 2 — archive is valid: replace the workspace and extract.
    src = config.project_dir(p["id"]) / "source"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True, exist_ok=True)

    extracted = 0
    for info, rel in validated:
        dest = src / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as fin, open(dest, "wb") as fout:
            shutil.copyfileobj(fin, fout, length=1 << 20)
        os_chmod_safe(dest)
        extracted += 1

    # single-root stripping: if everything is under one top folder, keep it
    report = scanner.scan_project(p["id"])
    _touch(p["id"])
    db.audit(user["id"], user["email"], "upload_zip", "project", p["id"],
             detail=f"{extracted} files from {filename[:60]}", ip=client_ip(request))
    return {
        "ok": True,
        "extracted": extracted,
        "scan_summary": {
            "file_count": report["file_count"],
            "by_kind": report["by_kind"],
            "sensitive_file_count": report["sensitive_file_count"],
            "secret_finding_count": report["secret_finding_count"],
        },
    }


def os_chmod_safe(path: Path) -> None:
    try:
        import os
        os.chmod(path, 0o644)
    except OSError:
        pass


# ----------------------------------------------------------------------
# Uploads: direct folder (per-file, browser webkitdirectory)
# ----------------------------------------------------------------------

@router.post("/{project_id}/upload/folder/start")
async def folder_start(request: Request, project_id: str):
    user = require_user(request)
    check_csrf(request, user)
    p = _get_project(user, project_id)
    body = await request.json()
    expected_count = int(body.get("file_count") or 0)
    if expected_count <= 0 or expected_count > config.MAX_ZIP_ENTRIES:
        raise HTTPException(status_code=400, detail={"code": "BAD_INPUT", "message": "Invalid file count."})
    src = config.project_dir(p["id"]) / "source"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True, exist_ok=True)
    # remember the expected count in a state file
    state = config.project_dir(p["id"]) / "analysis" / "upload_state.json"
    state.write_text(json.dumps({"expected": expected_count, "received": 0}))
    db.audit(user["id"], user["email"], "upload_folder_started", "project", p["id"],
             detail=f"expected {expected_count} files", ip=client_ip(request))
    return {"ok": True}


@router.post("/{project_id}/upload/file")
async def upload_single_file(request: Request, project_id: str,
                             relpath: str = Query(...), file: UploadFile = File(...)):
    user = require_user(request)
    check_csrf(request, user)
    p = _get_project(user, project_id)
    rel = _safe_zip_name(relpath)
    if rel is None:
        raise HTTPException(status_code=400, detail={"code": "PATH_TRAVERSAL", "message": "Unsafe relative path."})
    state_path = config.project_dir(p["id"]) / "analysis" / "upload_state.json"
    if not state_path.exists():
        raise HTTPException(status_code=409, detail={"code": "NO_UPLOAD_SESSION", "message": "Call upload/folder/start first."})
    state = json.loads(state_path.read_text())
    max_bytes = int(db.get_settings().get("max_upload_mb", str(MAX_FILE_MB))) * 1024 * 1024
    data = await file.read()
    if state.get("total_size", 0) + len(data) > max_bytes:
        raise HTTPException(status_code=413, detail={"code": "TOO_LARGE", "message": "Folder total size exceeds the limit."})
    src = config.project_dir(p["id"]) / "source"
    dest = src / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    os_chmod_safe(dest)
    state["received"] = state.get("received", 0) + 1
    state["total_size"] = state.get("total_size", 0) + len(data)
    state_path.write_text(json.dumps(state))
    return {"ok": True, "received": state["received"], "expected": state["expected"]}


@router.post("/{project_id}/upload/folder/finish")
async def folder_finish(request: Request, project_id: str):
    user = require_user(request)
    check_csrf(request, user)
    p = _get_project(user, project_id)
    state_path = config.project_dir(p["id"]) / "analysis" / "upload_state.json"
    if not state_path.exists():
        raise HTTPException(status_code=409, detail={"code": "NO_UPLOAD_SESSION", "message": "No folder upload in progress."})
    state = json.loads(state_path.read_text())
    if state["received"] != state["expected"]:
        raise HTTPException(status_code=409, detail={"code": "INCOMPLETE_UPLOAD",
                                                     "message": f"Received {state['received']}/{state['expected']} files. Start over or retry the missing files."})
    try:
        report = scanner.scan_project(p["id"])
    except Exception as e:
        raise HTTPException(status_code=500, detail={"code": "SCAN_FAILED", "message": f"Scan failed: {e.__class__.__name__}"})
    state_path.unlink(missing_ok=True)
    _touch(p["id"])
    db.audit(user["id"], user["email"], "upload_folder", "project", p["id"],
             detail=f"{state['received']} files", ip=client_ip(request))
    return {
        "ok": True,
        "extracted": state["received"],
        "scan_summary": {
            "file_count": report["file_count"],
            "by_kind": report["by_kind"],
            "sensitive_file_count": report["sensitive_file_count"],
            "secret_finding_count": report["secret_finding_count"],
        },
    }

"""Secure File Guard — user management (admin only)."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request

from .. import db
from ..security import (ADMIN_ROLES, check_csrf, client_ip, generate_password,
                        hash_password, require_role)

router = APIRouter(prefix="/api/v1/users", tags=["users"])

ROLES = ("super_admin", "admin", "user", "developer")
EMAIL_RX = re.compile(r"^[^@\s]{1,80}@[^@\s]{1,200}\.[^@\s]{1,40}$")


@router.get("")
async def list_users(request: Request):
    user = require_role(request, ADMIN_ROLES)
    rows = db.rows_to_list(db.qall(
        "SELECT id, email, name, role, disabled, created_at, last_login_at FROM users ORDER BY id"))
    for r in rows:
        r["disabled"] = bool(r["disabled"])
        r["project_count"] = db.qvalue("SELECT COUNT(*) FROM projects WHERE owner_id=?", (r["id"],))
    return {"users": rows}


@router.post("")
async def create_user(request: Request):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    name = (body.get("name") or "").strip()[:120]
    role = body.get("role") or "user"
    if not EMAIL_RX.match(email):
        raise HTTPException(status_code=400, detail={"code": "BAD_EMAIL", "message": "Invalid email."})
    if not name:
        raise HTTPException(status_code=400, detail={"code": "BAD_INPUT", "message": "Name is required."})
    if role not in ROLES:
        raise HTTPException(status_code=400, detail={"code": "BAD_ROLE", "message": "Invalid role."})
    if role == "super_admin" and user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Only a super admin can create super admins."})
    password = generate_password(16)
    try:
        uid = db.qexec(
            "INSERT INTO users (email, name, password_hash, role, disabled, created_at) VALUES (?,?,?,?,0,?)",
            (email, name, hash_password(password), role, db.utcnow()))
    except Exception:
        raise HTTPException(status_code=409, detail={"code": "DUPLICATE", "message": "Email already registered."})
    db.audit(user["id"], user["email"], "user_created", "user", str(uid),
             detail=f"role={role}", ip=client_ip(request))
    return {"user_id": uid, "email": email, "role": role,
            "password": password,
            "note": "Password shown once. The user can change it after first login."}


@router.patch("/{user_id}")
async def update_user(request: Request, user_id: int):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    target = db.q1("SELECT * FROM users WHERE id=?", (user_id,))
    if target is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "User not found."})
    body = await request.json()
    if "role" in body:
        role = body["role"]
        if role not in ROLES:
            raise HTTPException(status_code=400, detail={"code": "BAD_ROLE", "message": "Invalid role."})
        if role == "super_admin" and user["role"] != "super_admin":
            raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Only a super admin can grant super admin."})
        if target["id"] == user["id"] and role != user["role"]:
            raise HTTPException(status_code=400, detail={"code": "SELF_DEMOTE", "message": "You cannot change your own role."})
        db.qexec("UPDATE users SET role=? WHERE id=?", (role, user_id))
    if "name" in body:
        name = (body["name"] or "").strip()[:120]
        if name:
            db.qexec("UPDATE users SET name=? WHERE id=?", (name, user_id))
    if "disabled" in body:
        if target["id"] == user["id"]:
            raise HTTPException(status_code=400, detail={"code": "SELF_DISABLE", "message": "You cannot disable your own account."})
        db.qexec("UPDATE users SET disabled=? WHERE id=?", (1 if body["disabled"] else 0, user_id))
    db.audit(user["id"], user["email"], "user_updated", "user", str(user_id), ip=client_ip(request))
    return {"ok": True}


@router.post("/{user_id}/reset-password")
async def reset_password(request: Request, user_id: int):
    user = require_role(request, ADMIN_ROLES)
    check_csrf(request, user)
    target = db.q1("SELECT * FROM users WHERE id=?", (user_id,))
    if target is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "User not found."})
    password = generate_password(16)
    db.qexec("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), user_id))
    db.qexec("DELETE FROM sessions WHERE user_id=?", (user_id,))
    db.audit(user["id"], user["email"], "user_password_reset", "user", str(user_id), ip=client_ip(request))
    return {"email": target["email"], "password": password, "note": "Shown once."}

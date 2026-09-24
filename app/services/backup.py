"""Secure File Guard — metadata backup & recovery.

The backup bundle contains metadata only (projects, licenses with their
key HASHES — never plaintext keys, domains, build metadata, audit and
security logs). It is signed with the server Ed25519 key so a tampered
backup is rejected on restore. No secrets, no master keys, no file content.
"""
from __future__ import annotations

import json
import time

from .. import crypto, db

BACKUP_VERSION = 1


def export_backup() -> dict:
    rows = lambda sql: db.rows_to_list(db.qall(sql))
    bundle = {
        "backup_version": BACKUP_VERSION,
        "kind": "sfg-metadata",
        "created_at": db.utcnow(),
        "data": {
            "projects": rows("SELECT * FROM projects"),
            "project_files": rows("SELECT project_id, relpath, size, sha256, kind, sensitive, secret_count FROM project_files"),
            "project_versions": rows("SELECT * FROM project_versions"),
            "builds": rows("SELECT id, project_id, version_id, version, status, stage_index, total_stages,"
                            " config_json, manifest_json, package_sha256, validation_report_json,"
                            " created_at, completed_at FROM builds"),
            "licenses": rows("SELECT * FROM licenses"),
            "license_domains": rows("SELECT * FROM license_domains"),
            "security_events": rows("SELECT * FROM security_events ORDER BY id DESC LIMIT 5000"),
            "audit_logs": rows("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5000"),
        },
    }
    canonical = crypto.canonical_json(bundle)
    bundle["signature"] = crypto.sign_bytes(canonical)
    return bundle


def verify_backup(bundle: dict) -> tuple[bool, str]:
    if not isinstance(bundle, dict) or bundle.get("kind") != "sfg-metadata":
        return False, "Not a Secure File Guard backup bundle."
    if bundle.get("backup_version") != BACKUP_VERSION:
        return False, f"Unsupported backup version {bundle.get('backup_version')}."
    sig = bundle.pop("signature", None)
    if not sig:
        return False, "Missing signature."
    if not crypto.verify_bytes(crypto.canonical_json(bundle), sig):
        return False, "Signature verification failed — backup may have been tampered with."
    return True, "ok"


_REQUIRED_FIELDS = {
    "projects": ("id", "name", "owner_id", "status", "protection_level", "created_at", "updated_at"),
    "project_files": ("project_id", "relpath", "size", "sha256", "kind", "sensitive", "secret_count"),
    "project_versions": ("id", "project_id", "version", "created_at"),
    "builds": ("id", "project_id", "version", "status", "created_at"),
    "licenses": ("id", "project_id", "key_hash", "status", "created_at", "expires_at"),
    "license_domains": ("id", "license_id", "domain", "status", "added_at"),
    "security_events": ("id", "type", "created_at"),
    "audit_logs": ("id", "action", "created_at"),
}


def _validate_rows(data: dict) -> None:
    """Structural validation BEFORE any write — a malformed bundle is
    rejected with a clear error instead of crashing mid-restore."""
    if not isinstance(data, dict):
        raise ValueError("'data' is not an object")
    for table, keys in _REQUIRED_FIELDS.items():
        rows = data.get(table) or []
        if not isinstance(rows, list):
            raise ValueError(f"'{table}' is not a list")
        for i, r in enumerate(rows):
            if not isinstance(r, dict):
                raise ValueError(f"'{table}[{i}]' is not an object")
            for k in keys:
                if k not in r:
                    raise ValueError(f"'{table}[{i}]' is missing field '{k}'")


def restore_backup(bundle: dict, actor: dict) -> dict:
    ok, msg = verify_backup(bundle)
    if not ok:
        raise ValueError(msg)
    data = bundle.get("data")
    try:
        _validate_rows(data)
        return _restore_rows(data, bundle, actor)
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"Backup bundle is malformed: {e}")


def _restore_rows(data: dict, bundle: dict, actor: dict) -> dict:
    counts: dict[str, int] = {}
    with db.db() as c:
        for table in ("projects", "project_files", "project_versions", "builds",
                      "licenses", "license_domains", "security_events", "audit_logs"):
            rows = data.get(table) or []
            if not isinstance(rows, list):
                rows = []
            n = 0
            if table == "projects":
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    c.execute("INSERT OR IGNORE INTO projects (id, name, owner_id, status, protection_level,"
                              " created_at, updated_at, archived_at) VALUES (?,?,?,?,?,?,?,?)",
                              (r["id"], r["name"], r["owner_id"], r["status"], r["protection_level"],
                               r["created_at"], r["updated_at"], r.get("archived_at")))
                    n += 1
            elif table == "project_files":
                # Metadata-only restore: skip index rows whose source files are
                # not on disk (Render free disk wipe). Prevents FileNotFoundError
                # on the next build until the ZIP is re-uploaded.
                src_root = None
                try:
                    from .. import config as _cfg
                    src_root = _cfg.PROJECTS_DIR
                except Exception:
                    src_root = None
                for r in rows:
                    if src_root is not None:
                        fpath = src_root / r["project_id"] / "source" / r["relpath"]
                        try:
                            if not fpath.is_file():
                                continue
                        except OSError:
                            continue
                    c.execute("INSERT OR IGNORE INTO project_files (project_id, relpath, size, sha256, kind,"
                              " sensitive, secret_count, indexed_at) VALUES (?,?,?,?,?,?,?,?)",
                              (r["project_id"], r["relpath"], r["size"], r["sha256"], r["kind"],
                               r["sensitive"], r["secret_count"], r.get("indexed_at") or db.utcnow()))
                    n += 1
            elif table == "project_versions":
                for r in rows:
                    try:
                        c.execute("INSERT INTO project_versions (id, project_id, version, note, created_by,"
                                  " created_at, revoked) VALUES (?,?,?,?,?,?,?)",
                                  (r["id"], r["project_id"], r["version"], r.get("note"), r.get("created_by"),
                                   r["created_at"], r.get("revoked", 0)))
                        n += 1
                    except Exception:
                        pass
            elif table == "builds":
                for r in rows:
                    # Preserve status so license verify still sees completed builds
                    # after a Render disk wipe + restore (BUILD_INVALID otherwise).
                    c.execute("INSERT OR IGNORE INTO builds (id, project_id, version_id, version, status,"
                              " stage_index, total_stages, config_json, manifest_json, package_sha256,"
                              " validation_report_json, created_at, completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (r["id"], r["project_id"], r.get("version_id"), r["version"], r["status"],
                               r.get("stage_index", 0), r.get("total_stages", 12),
                               r.get("config_json") or "{}", r.get("manifest_json"),
                               r.get("package_sha256"), r.get("validation_report_json"),
                               r["created_at"], r.get("completed_at")))
                    n += 1
            elif table == "licenses":
                for r in rows:
                    c.execute("INSERT OR IGNORE INTO licenses (id, project_id, customer_name, customer_email,"
                              " key_hash, status, activated, activated_at, created_at, expires_at, last_verified_at,"
                              " version_restrict, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (r["id"], r["project_id"], r.get("customer_name"), r.get("customer_email"),
                               r["key_hash"], r["status"], r.get("activated", 0), r.get("activated_at"),
                               r["created_at"], r["expires_at"], r.get("last_verified_at"),
                               r.get("version_restrict"), r.get("created_by")))
                    n += 1
            elif table == "license_domains":
                for r in rows:
                    try:
                        c.execute("INSERT INTO license_domains (id, license_id, domain, status, allow_subdomains,"
                                  " verify_token, verified_at, added_at) VALUES (?,?,?,?,?,?,?,?)",
                                  (r["id"], r["license_id"], r["domain"], r["status"], r.get("allow_subdomains", 0),
                                   r.get("verify_token"), r.get("verified_at"), r["added_at"]))
                        n += 1
                    except Exception:
                        pass
            elif table == "security_events":
                for r in rows:
                    c.execute("INSERT OR IGNORE INTO security_events (id, project_id, license_id, type, severity,"
                              " detail, ip, created_at) VALUES (?,?,?,?,?,?,?,?)",
                              (r["id"], r.get("project_id"), r.get("license_id"), r["type"], r["severity"],
                               r.get("detail"), r.get("ip"), r["created_at"]))
                    n += 1
            elif table == "audit_logs":
                for r in rows:
                    c.execute("INSERT OR IGNORE INTO audit_logs (id, actor_id, actor_email, action, resource,"
                              " resource_id, result, detail, ip, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (r["id"], r.get("actor_id"), r.get("actor_email"), r["action"], r.get("resource"),
                               r.get("resource_id"), r.get("result", "ok"), r.get("detail"), r.get("ip"),
                               r["created_at"]))
                    n += 1
            counts[table] = n
            c.commit()
    entry_count = sum(counts.values())
    sha = crypto.sha256_hex(crypto.canonical_json(bundle))
    db.qexec("INSERT INTO backups (kind, sha256, entry_count, created_by, created_at) VALUES ('restore', ?, ?, ?, ?)",
             (sha, entry_count, actor["id"], db.utcnow()))
    db.audit(actor["id"], actor["email"], "backup_restored", "backup", sha[:16],
             detail=json.dumps(counts), ip="")
    return {"ok": True, "restored": counts, "entry_count": entry_count}


def backup_list() -> list[dict]:
    return db.rows_to_list(db.qall("SELECT * FROM backups ORDER BY id DESC LIMIT 50"))

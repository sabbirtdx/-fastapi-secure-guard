"""Secure File Guard — protection/build pipeline.

Every stage performs real work and is only marked complete after it actually
completes. Stage list (matches the UI):

  1  upload_validation   2  extraction        3  file_scan
  4  ai_analysis         5  protection        6  encryption
  7  obfuscation         8  integrity_manifest 9  license_binding
 10  signing            11  validation       12  packaging

If validation fails, NO downloadable package is produced.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import analyzer, config, crypto, db, scanner
from .scanner import SKIP_DIR_NAMES

STAGE_NAMES = [
    "Upload validation",
    "Extraction",
    "File scan",
    "AI analysis",
    "Protection",
    "Encryption",
    "Obfuscation",
    "Integrity generation",
    "License binding",
    "Signature generation",
    "Validation",
    "Package generation",
]

_builds_lock = asyncio.Lock()
_build_queue: dict[str, list[dict]] = {}
_active_builds = 0
BUILD_SERVICE_LIMIT = 2
_main_loop: asyncio.AbstractEventLoop | None = None


def init(main_loop: asyncio.AbstractEventLoop) -> None:
    """Called once at app startup with the main event loop (for cross-thread SSE wakes)."""
    global _main_loop
    _main_loop = main_loop


# ----------------------------------------------------------------------
# Progress plumbing (SSE + DB)
# ----------------------------------------------------------------------

def _emit(build_id: str, stage_index: int, status: str, message: str = "") -> None:
    ev = {
        "stage": stage_index,
        "name": STAGE_NAMES[stage_index - 1] if 1 <= stage_index <= len(STAGE_NAMES) else "",
        "status": status,
        "message": message[:500],
        "ts": time.time(),
    }
    _build_queue.setdefault(build_id, []).append(ev)
    if len(_build_queue[build_id]) > 500:
        _build_queue[build_id] = _build_queue[build_id][-500:]
    db.qexec(
        "UPDATE builds SET stage=?, stage_index=? WHERE id=?",
        (ev["name"], stage_index, build_id))
    # wake any SSE listener (runs from a worker thread)
    if _main_loop is not None:
        try:
            _main_loop.call_soon_threadsafe(_poke, build_id)
        except RuntimeError:
            pass


_pokes: dict[str, asyncio.Event] = {}


def _poke(build_id: str) -> None:
    ev = _pokes.get(build_id)
    if ev is not None:
        ev.set()


def progress_events(build_id: str) -> list[dict]:
    return list(_build_queue.get(build_id, []))


def run_build(project_id: str, build_id: str, version: str, opts: dict,
              user: dict) -> None:
    """Entry point (runs as a thread). Executes all stages."""
    global _active_builds
    ctx = BuildContext(project_id, build_id, version, opts, user)
    try:
        _set_status(build_id, "running")
        for i, (idx, stage_fn) in enumerate(ctx.stages, start=1):
            _emit(build_id, i, "start", f"Stage {i}/12: {STAGE_NAMES[i-1]}")
            stage_fn(ctx)
            _emit(build_id, i, "complete", Stage.message or f"{STAGE_NAMES[i-1]} complete.")
        _set_status(build_id, "completed", completed=True)
        _emit(build_id, 12, "done", "Build completed and package is ready for download.")
    except StageError as e:
        _set_status(build_id, "failed", error=str(e))
        _emit(build_id, e.stage, "failed", str(e))
        db.audit(user["id"], user["email"], "build_failed", "build", build_id,
                 result="failed", detail=str(e)[:300], ip="")
    except FileNotFoundError as e:
        msg = (f"Workspace file missing: {getattr(e, 'filename', None) or e}. "
               "Re-upload the project ZIP (backup restore does not include source files), then rebuild.")
        _set_status(build_id, "failed", error=msg)
        _emit(build_id, 2, "failed", msg)
        db.audit(user["id"], user["email"], "build_failed", "build", build_id,
                 result="failed", detail=f"missing file: {e}", ip="")
    except Exception as e:  # unexpected
        _set_status(build_id, "failed", error=f"Unexpected error: {e.__class__.__name__}: {e}")
        db.audit(user["id"], user["email"], "build_failed", "build", build_id,
                 result="failed", detail=f"unexpected: {e}", ip="")
    finally:
        _active_builds -= 1


class StageError(Exception):
    def __init__(self, stage: int, message: str):
        super().__init__(message)
        self.stage = stage


class Stage:
    index = 0
    message = ""

    def run(self, ctx: "BuildContext") -> None:
        raise NotImplementedError


class BuildContext:
    def __init__(self, project_id: str, build_id: str, version: str, opts: dict, user: dict):
        self.project_id = project_id
        self.build_id = build_id
        self.version = version
        self.opts = opts
        self.user = user
        self.bdir = config.build_dir(project_id, build_id)
        self.work = self.bdir / "work"
        self.package_tree = self.work / "package"
        self.components_dir = self.work / "components"
        self.guard_dir = self.package_tree / "guard"
        self.protected: list[str] = []
        self.public_count = 0
        self.build_key: bytes = b""
        self.manifest: dict = {}
        self.scan_report: dict = {}
        self.analysis: dict = {}
        self.validation_report: dict = {}
        self.package_path = self.bdir / "package" / "protected-build.zip"
        self.package_sha = ""
        self.stages = [
            (1, upload_validation),
            (2, extraction_check),
            (3, file_scan),
            (4, ai_analysis),
            (5, protection),
            (6, encryption),
            (7, obfuscation),
            (8, integrity_manifest),
            (9, license_binding),
            (10, signing),
            (11, validation),
            (12, packaging),
        ]


def _set_status(build_id: str, status: str, error: str | None = None, completed: bool = False) -> None:
    if completed:
        db.qexec("UPDATE builds SET status=?, error=?, completed_at=? WHERE id=?",
                 (status, error, db.utcnow(), build_id))
    else:
        db.qexec("UPDATE builds SET status=?, error=?, started_at=COALESCE(started_at,?) WHERE id=?",
                 (status, error, db.utcnow(), build_id))


# ----------------------------------------------------------------------
# Stages
# ----------------------------------------------------------------------

def upload_validation(ctx: BuildContext) -> None:
    src = config.project_dir(ctx.project_id) / "source"
    if not src.exists():
        raise StageError(1, "Project source workspace is missing. Re-upload the project ZIP.")
    files = []
    total = 0
    for p in src.rglob("*"):
        try:
            if p.is_file():
                files.append(p)
                total += p.stat().st_size
        except OSError:
            continue
    if not files:
        indexed = db.qvalue("SELECT COUNT(*) FROM project_files WHERE project_id=?", (ctx.project_id,)) or 0
        if indexed:
            raise StageError(1, "Source files are not on this server (disk wipe or metadata-only restore). "
                                 "Re-upload the project ZIP, then rebuild.")
        raise StageError(1, "No files found in the project. Upload a ZIP or folder first.")
    max_bytes = int(db.get_settings().get("max_upload_mb", "200")) * 1024 * 1024
    if total > max_bytes:
        raise StageError(1, f"Project size {total // (1024*1024)} MB exceeds the configured limit.")
    if len(files) > config.MAX_ZIP_ENTRIES:
        raise StageError(1, f"Project has more than {config.MAX_ZIP_ENTRIES} files.")
    for p in files[:2000]:
        rel = p.relative_to(src).as_posix()
        if rel.startswith("/") or ".." in rel.split("/"):
            raise StageError(1, f"Unsafe path in workspace: {rel}")
    Stage.message = f"{len(files)} files, {total // 1024} KB — within limits."
    ctx.public_count = len(files)


def extraction_check(ctx: BuildContext) -> None:
    """Verify the indexed file set still matches the on-disk workspace."""
    rows = db.rows_to_list(db.qall(
        "SELECT relpath, size, sha256 FROM project_files WHERE project_id=?", (ctx.project_id,)))
    if not rows:
        raise StageError(2, "File index is empty. Run an upload first.")
    src = config.project_dir(ctx.project_id) / "source"
    missing = 0
    mismatch = 0
    missing_sample = ""
    for r in rows[:20000]:
        try:
            p = src / r["relpath"]
            if not p.is_file():
                missing += 1
                if not missing_sample:
                    missing_sample = r["relpath"]
                continue
            if p.stat().st_size != r["size"]:
                mismatch += 1
        except OSError:
            missing += 1
            if not missing_sample:
                missing_sample = r.get("relpath") or ""
    if missing or mismatch:
        with contextlib.suppress(Exception):
            scanner.scan_project(ctx.project_id)  # re-index to what is actually on disk
        hint = ""
        if missing:
            hint = (f" First missing: {missing_sample}."
                    " If the disk was wiped (Render redeploy), re-upload the project ZIP.")
        raise StageError(2, f"Workspace drifted since upload ({missing} missing, {mismatch} size changes). "
                            f"Re-indexed; start the build again.{hint}")
    Stage.message = f"Workspace consistent with {len(rows)} indexed files."


def file_scan(ctx: BuildContext) -> None:
    ctx.scan_report = scanner.scan_project(ctx.project_id)
    s = ctx.scan_report
    Stage.message = (f"{s['file_count']} files scanned — {s['sensitive_file_count']} sensitive, "
                     f"{s['secret_finding_count']} credential-looking values (masked).")


def ai_analysis(ctx: BuildContext) -> None:
    rows = db.rows_to_list(db.qall(
        "SELECT created_at, result_json FROM ai_analysis WHERE project_id=? ORDER BY id DESC LIMIT 1",
        (ctx.project_id,)))
    fresh = False
    if rows and rows[0]["created_at"] > time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600)):
        ctx.analysis = json.loads(rows[0]["result_json"])
        fresh = True
    if not fresh:
        ctx.analysis = analyzer.analyze_project(ctx.project_id)
    rec = ctx.analysis.get("recommendation", {}) if isinstance(ctx.analysis, dict) else {}
    if not isinstance(rec, dict):
        rec = {}
    protected = rec.get("protected_components", [])
    if not isinstance(protected, list):
        protected = []
    ctx.recommended_protect: list[str] = [str(x) for x in protected if isinstance(x, (str, int, float))]
    ctx.recommended_level: str = rec.get("protection_level", "standard") or "standard"
    Stage.message = (f"Analysis ready — recommended level '{ctx.recommended_level}', "
                     f"{len(ctx.recommended_protect)} components recommended for protection.")


def protection(ctx: BuildContext) -> None:
    """Resolve the final protected component set and build the package tree."""
    rows = db.rows_to_list(db.qall(
        "SELECT relpath, kind, sensitive, secret_count FROM project_files WHERE project_id=?",
        (ctx.project_id,)))
    src = config.project_dir(ctx.project_id) / "source"
    included = {r["relpath"] for r in rows if isinstance(r, dict) and r.get("relpath")}
    opts = ctx.opts if isinstance(ctx.opts, dict) else {}
    raw_inc = opts.get("include") or []
    raw_exc = opts.get("exclude") or []
    if not isinstance(raw_inc, (list, tuple)):
        raw_inc = []
    if not isinstance(raw_exc, (list, tuple)):
        raw_exc = []
    inc_user = [u for u in raw_inc if isinstance(u, str) and u in included]
    exc_user = {u for u in raw_exc if isinstance(u, str)}
    assets = set(scanner.KIND_EXTENSIONS["asset"])
    protect = []
    for rel in ctx.recommended_protect or []:
        if not isinstance(rel, str) or rel not in included:
            continue
        ext = Path(rel).suffix.lower()
        if ext in assets:
            continue
        if rel in exc_user:
            continue
        protect.append(rel)
    for rel in inc_user:
        ext = Path(rel).suffix.lower()
        if ext in assets or rel in exc_user:
            continue
        if rel not in protect:
            protect.append(rel)
    # only .php and .env get automatic protection; other non-php files only if user-included
    auto_ok = [r for r in protect if Path(r).suffix.lower() in scanner.KIND_EXTENSIONS["php"] or Path(r).name.startswith(".env")]
    user_added = [r for r in protect if r not in auto_ok]
    if not (auto_ok or user_added):
        raise StageError(5, "No components selected for protection. Choose server-side files to protect.")
    final_protected = sorted(set(auto_ok) | set(user_added))[:config.MAX_PACKAGE_COMPONENTS]
    for rel in final_protected:
        if not (src / rel).is_file():
            raise StageError(5, f"Protected file missing from workspace: {rel}")
    ctx.protected = final_protected
    prot_set = set(final_protected)

    # Build the package tree: everything except exclusions; protected files replaced.
    if ctx.package_tree.exists():
        shutil.rmtree(ctx.package_tree)
    ctx.package_tree.mkdir(parents=True, exist_ok=True)
    copied = 0
    for p in src.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(src).as_posix()
        parts = rel.split("/")
        if parts[0] in SKIP_DIR_NAMES or ".git/" in f"{rel}/":
            continue
        if rel in prot_set:
            continue  # replaced below
        dest = ctx.package_tree / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)
        except FileNotFoundError:
            raise StageError(5, f"File disappeared during packaging: {rel}. Re-upload and rebuild.")
        except OSError as e:
            raise StageError(5, f"Could not copy {rel}: {e}")
        copied += 1

    stub_count = 0
    for rel in final_protected:
        dest = ctx.package_tree / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        ext = Path(rel).suffix.lower()
        if ext in scanner.KIND_EXTENSIONS["php"]:
            depth = rel.count("/")
            prefix = "../" * depth
            stub = (f"<?php\n// Secure File Guard — protected component stub for '{rel}'.\n"
                    f"require_once __DIR__ . '/{prefix}guard/guard.php';\n"
                    f"sfg_include('{rel}');\n")
            dest.write_text(stub)
            stub_count += 1
        elif Path(rel).name.startswith(".env") or Path(rel).name == ".env":
            dest.write_text("# Secure File Guard: this environment file is protected.\n"
                            "# Read values with sfg_env('NAME') or pass sfg_env_file() to your dotenv loader.\n")
        else:
            dest.write_text("")  # plaintext removed; fetch via sfg_fetch_file(rel)
    Stage.message = (f"{len(final_protected)} components protected "
                     f"({stub_count} PHP stubs), {copied} public files packaged.")


def _seal_component(ctx: BuildContext, rel: str, plaintext: bytes, obfuscated: bool) -> None:
    key = rawurlencode(rel)
    nonce_b64, ct_b64 = crypto.aes_gcm_seal(ctx.build_key, plaintext, aad=rel.encode())
    payload = {
        "nonce": nonce_b64,
        "ct": ct_b64,
        "size": len(plaintext),
        "plain_sha256": crypto.sha256_hex(plaintext),
        "obfuscated": obfuscated,
        "cipher": "AES-256-GCM",
    }
    out = ctx.components_dir / f"{key}.enc"
    out.write_text(json.dumps(payload, sort_keys=True))
    os.chmod(out, 0o600)
    ctx.manifest.setdefault("components", {})[key] = {
        "ct_sha256": crypto.sha256_file(out),
        "plain_sha256": payload["plain_sha256"],
        "size": len(plaintext),
        "obfuscated": obfuscated,
        "cipher": "AES-256-GCM",
    }


def encryption(ctx: BuildContext) -> None:
    src = config.project_dir(ctx.project_id) / "source"
    if ctx.build_key == b"":
        ctx.build_key = _new_build_key()
    ctx.components_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for rel in ctx.protected:
        try:
            data = (src / rel).read_bytes()
        except FileNotFoundError:
            raise StageError(6, f"Protected file missing from workspace: {rel}. Re-upload the project ZIP.")
        except OSError as e:
            raise StageError(6, f"Could not read {rel}: {e}")
        _seal_component(ctx, rel, data, obfuscated=False)
        n += 1
    if n == 0:
        raise StageError(6, "No components were available to encrypt.")
    wrapped = crypto.wrap_key(crypto.master_key(), ctx.build_key)
    db.qexec("UPDATE builds SET config_json = json_set(COALESCE(config_json,'{}'), '$.build_key_wrapped', ?) WHERE id=?",
             (wrapped, ctx.build_id))
    Stage.message = f"{n} components sealed with AES-256-GCM (per-build key wrapped by master key; key never leaves the server)."


def obfuscation(ctx: BuildContext) -> None:
    if not ctx.opts.get("obfuscate"):
        Stage.message = "Skipped — obfuscation is disabled for this build."
        return
    src = config.project_dir(ctx.project_id) / "source"
    n = 0
    for rel in ctx.protected:
        if Path(rel).suffix.lower() not in scanner.KIND_EXTENSIONS["php"]:
            continue
        try:
            plain = (src / rel).read_bytes()
        except OSError:
            continue
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            continue
        obf = php_obfuscate(text)
        if obf is not None:
            _seal_component(ctx, rel, obf.encode("utf-8"), obfuscated=True)
            n += 1
    Stage.message = (f"{n} PHP components obfuscated (comments stripped, string literals encoded) and re-sealed. "
                     "Obfuscation reduces readability — it is not encryption.")


def integrity_manifest(ctx: BuildContext) -> None:
    # copy the runtime templates into the package (before hashing them)
    _copy_guard_runtime(ctx)
    m = ctx.manifest
    m["manifest_version"] = config.MANIFEST_VERSION
    m["project"] = ctx.project_id
    m["build"] = ctx.build_id
    m["version"] = ctx.version
    m["created"] = db.utcnow()
    m["public_key_fingerprint"] = crypto.public_key_fingerprint()
    m["cipher"] = "AES-256-GCM"
    # runtime self-integrity entries (paths relative to project root, ASCII).
    # Note: guard/manifest.json is NOT self-hashed — a file cannot contain its
    # own hash. It is protected by the Ed25519 signature instead: any tamper
    # with manifest.json or manifest.sig fails signature verification first.
    runtime = {}
    for rel in ("guard/guard.php", "guard/activate.php", "guard/activate.html.tpl"):
        p = ctx.package_tree / rel
        if p.exists():
            runtime[rel] = crypto.sha256_file(p)
    m["runtime"] = runtime
    # stub + protected non-php placeholders hashed too
    stubs = {}
    for rel in ctx.protected:
        p = ctx.package_tree / rel
        if p.is_file():
            stubs[rawurlencode(rel)] = crypto.sha256_file(p)
    m["stubs"] = stubs
    mpath = ctx.work / "manifest.json"
    mpath.write_text(json.dumps(m, indent=1, sort_keys=True))
    ctx.manifest_path = mpath
    db.qexec("UPDATE builds SET manifest_json=? WHERE id=?", (str(mpath), ctx.build_id))
    Stage.message = (f"Manifest generated: {len(m.get('components', {}))} components, "
                     f"{len(runtime)} runtime files, {len(stubs)} stubs hashed.")


def license_binding(ctx: BuildContext) -> None:
    lic_rows = db.rows_to_list(db.qall(
        "SELECT id, status, expires_at FROM licenses WHERE project_id=? AND status IN ('pending','active')",
        (ctx.project_id,)))
    if not lic_rows:
        raise StageError(9, "This project has no active/pending license. Create a license with an authorized domain before building.")
    domains: set[str] = set()
    for lic in lic_rows:
        for d in db.rows_to_list(db.qall(
                "SELECT domain FROM license_domains WHERE license_id=? AND status IN ('verified','active','pending')",
                (lic["id"],))):
            domains.add(d["domain"])
    settings = db.get_settings()
    ctx.cfg_json = {
        "license_server": (settings.get("license_server_url") or "").rstrip("/"),
        "project": ctx.project_id,
        "build": ctx.build_id,
        "version": ctx.version,
        "public_key_pem": crypto.public_key_pem(),
        "public_key_raw": crypto.public_key_raw_b64(),
        "require_https": settings.get("require_https", "1") == "1",
        "verify_ttl": int(settings.get("verify_ttl_seconds", str(config.DEFAULT_VERIFY_TTL_SECONDS))),
        "grace_seconds": int(settings.get("grace_seconds", "0")),
        "authorized_domains": sorted(domains),
        "manifest_version": config.MANIFEST_VERSION,
        "runtime_version": 1,
    }
    (ctx.guard_dir).mkdir(parents=True, exist_ok=True)
    (ctx.guard_dir / "config.json").write_text(json.dumps(ctx.cfg_json, indent=1, sort_keys=True))
    (ctx.guard_dir / "cache").mkdir(parents=True, exist_ok=True)
    (ctx.guard_dir / "cache" / ".gitkeep").write_text("")
    # finalize the manifest now that config.json exists (config is self-integrity checked at runtime)
    ctx.manifest["runtime"]["guard/config.json"] = crypto.sha256_file(ctx.guard_dir / "config.json")
    ctx.manifest["authorized_domains"] = sorted(domains)
    mpath = ctx.work / "manifest.json"
    mpath.write_text(json.dumps(ctx.manifest, indent=1, sort_keys=True))
    Stage.message = (f"Bound to project with {len(lic_rows)} license(s), "
                     f"{len(domains)} authorized domain(s): {', '.join(sorted(domains)[:6])}")


def signing(ctx: BuildContext) -> None:
    mpath: Path = ctx.manifest_path
    canonical = crypto.canonical_json(json.loads(mpath.read_text()))
    sig = crypto.sign_bytes(canonical)
    (ctx.guard_dir / "manifest.sig").write_text(sig)
    if not crypto.verify_bytes(canonical, sig):
        raise StageError(10, "Internal error: signed manifest failed re-verification.")
    # ship the signed manifest itself in the package (verified via signature
    # before any hash from it is trusted)
    shutil.copy2(mpath, ctx.guard_dir / "manifest.json")
    Stage.message = "Manifest signed with the server Ed25519 key (private key never leaves the licensing server)."


def _copy_guard_runtime(ctx: BuildContext) -> None:
    """Copy runtime templates into the package (called before manifest hashing)."""
    tpl = config.GUARD_TEMPLATE_DIR
    ctx.guard_dir.mkdir(parents=True, exist_ok=True)
    for fn in ("guard.php", "activate.php", "activate.html.tpl"):
        shutil.copy2(tpl / fn, ctx.guard_dir / fn)
    # Extensionless /guard/activate works only with a rewrite; without it,
    # hosts like ProFreeHost return their branded 404 on the form POST.
    htaccess = (
        "<IfModule mod_rewrite.c>\n"
        "RewriteEngine On\n"
        "RewriteCond %{REQUEST_FILENAME} !-f\n"
        "RewriteCond %{REQUEST_FILENAME} !-d\n"
        "RewriteRule ^guard/activate/?$ guard/activate.php [L,QSA]\n"
        "</IfModule>\n"
    )
    (ctx.package_tree / ".htaccess").write_text(htaccess)
    readme = (
        "# Secure File Guard — protected deployment\n\n"
        f"Project: {ctx.project_id} · Build: {ctx.build_id} · Version: {ctx.version}\n\n"
        "## Install\n"
        "1. Upload this package to the authorized server.\n"
        "2. Point the web root at the package directory.\n"
        "3. Ensure every PHP entry file includes the guard. Simplest: add\n"
        "   `php_value auto_prepend_file guard/guard.php` (Apache) or set `auto_prepend_file`\n"
        "   in php.ini to `guard/guard.php`. For specific entries, add\n"
        "   `require __DIR__ . '/guard/guard.php';` at the top.\n"
        "4. Open https://your-domain/guard/activate.php and enter the license key.\n"
        "   (If files are in a subdirectory, use https://your-domain/subdir/guard/activate.php.\n"
        "   The activation form posts to itself — no rewrite rules are required.)\n\n"
        "## Protected components\n"
        "Protected PHP files are one-line stubs that stream the real (obfuscated)\n"
        "source from the licensing server through an authenticated, signed channel.\n"
        "Protected environment/config files are not present in cleartext: use\n"
        "`sfg_env('NAME')`, `sfg_env_file()`, or `sfg_fetch_file('path')`.\n\n"
        "## Security model (honest)\n"
        "- The license server is the root of trust: license state, domain binding,\n"
        "  signatures and revocation all live there. This package contains ONLY the\n"
        "  public verification key.\n"
        "- Protected components exist on disk only as AES-256-GCM ciphertext; the\n"
        "  per-build key is wrapped server-side and never shipped.\n"
        "- Every response from the server is verified (Ed25519 signature + SHA-256\n"
        "  integrity hashes) before use.\n"
        "- Limitation: an administrator with root access to this host can read or\n"
        "  delete files — nothing can physically prevent that. The guarantee is that\n"
        "  unauthorized modification or copying does not result in successful\n"
        "  authorized execution (integrity + remote authorization fail closed).\n"
        "- Client-side files (HTML/CSS/JS/images) are public by design; browsers can\n"
        "  always inspect delivered client code. Do not rely on them for secrets.\n"
    )
    (ctx.guard_dir / "README-deploy.md").write_text(readme)


def validation(ctx: BuildContext) -> None:
    """Real validation. If anything fails, the build is marked failed and no
    package is produced."""
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    # 1. signature re-verification against the written manifest
    mpath: Path = ctx.manifest_path
    manifest = json.loads(mpath.read_text())
    canonical = crypto.canonical_json(manifest)
    sig = (ctx.guard_dir / "manifest.sig").read_text()
    add("manifest_signature", crypto.verify_bytes(canonical, sig),
        "Ed25519 signature over canonical manifest JSON")

    # 2. canonical round-trip (file on disk re-serializes identically)
    add("canonical_roundtrip", crypto.canonical_json(json.loads(mpath.read_text())) == canonical,
        "manifest file re-serialization is stable")

    # 3. decrypt round-trip on all small components (sample 3 if many)
    key = crypto.unwrap_key(crypto.master_key(), _stored_wrapped_key(ctx.build_id))
    samples = ctx.protected if len(ctx.protected) <= 3 else ctx.protected[:2] + ctx.protected[-1:]
    ok = True
    detail = []
    for rel in samples:
        enc = json.loads((ctx.components_dir / f"{rawurlencode(rel)}.enc").read_text())
        plain = crypto.aes_gcm_open(key, enc["nonce"], enc["ct"], aad=rel.encode())
        good = crypto.sha256_hex(plain) == enc["plain_sha256"]
        ok = ok and good
        detail.append(f"{rel}:{'ok' if good else 'MISMATCH'}")
    add("decrypt_roundtrip", ok, "; ".join(detail))

    # 4. required files present + ciphertext hashes match manifest
    ok = True
    detail = ""
    for keyenc, entry in manifest.get("components", {}).items():
        blob = ctx.components_dir / f"{keyenc}.enc"
        if not blob.is_file() or crypto.sha256_file(blob) != entry["ct_sha256"]:
            ok = False
            detail = f"component blob mismatch: {keyenc}"
            break
    add("component_blobs", ok, detail or f"{len(manifest.get('components', {}))} blobs verified")

    ok = True
    for rel, h in manifest.get("runtime", {}).items():
        p = ctx.package_tree / rel
        if not p.is_file() or crypto.sha256_file(p) != h:
            ok = False
            detail = f"runtime file mismatch: {rel}"
            break
    add("runtime_files", ok, detail or "runtime files verified")

    ok = True
    for rel, h in manifest.get("stubs", {}).items():
        p = ctx.package_tree / rawurldecode(rel)
        if not p.is_file() or crypto.sha256_file(p) != h:
            ok = False
            detail = f"stub mismatch: {rel}"
            break
    add("stubs", ok, detail or f"{len(manifest.get('stubs', {}))} stubs verified")

    # 5. PHP lint on protected stubs + (if php available) obfuscated plaintext
    php = shutil.which("php")
    if php:
        ok = True
        detail = []
        for rel in ctx.protected:
            if Path(rel).suffix.lower() not in scanner.KIND_EXTENSIONS["php"]:
                continue
            stub = ctx.package_tree / rel
            r = subprocess.run([php, "-l", str(stub)], capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                ok = False
                detail.append(f"stub lint failed: {rel}: {r.stderr.strip()[:120]}")
                break
            enc = json.loads((ctx.components_dir / f"{rawurlencode(rel)}.enc").read_text())
            if enc.get("obfuscated"):
                tmpf = ctx.work / "_lint_tmp.php"
                plain = crypto.aes_gcm_open(key, enc["nonce"], enc["ct"], aad=rel.encode())
                tmpf.write_bytes(plain)
                r = subprocess.run([php, "-l", str(tmpf)], capture_output=True, text=True, timeout=30)
                tmpf.unlink(missing_ok=True)
                if r.returncode != 0:
                    ok = False
                    detail.append(f"obfuscated source lint failed: {rel}: {r.stderr.strip()[:120]}")
                    break
        add("php_lint", ok, "; ".join(detail) if detail else "stubs" + (" and obfuscated sources" if any(
            json.loads((ctx.components_dir / f'{rawurlencode(r)}.enc').read_text()).get("obfuscated")
            for r in ctx.protected if Path(r).suffix.lower() in scanner.KIND_EXTENSIONS["php"]) else ""))
    else:
        add("php_lint", True, "skipped — PHP CLI not available on this host")

    # 6. secret-leak check: no master/signing private material anywhere in the package
    master_hex = crypto.master_key().hex()
    priv_head = ""
    try:
        priv_head = config.KEYS_DIR.joinpath("signing.key").read_text()[:64]
    except OSError:
        pass
    ok = True
    detail = ""
    for p in ctx.package_tree.rglob("*"):
        if p.is_file() and p.suffix in (".json", ".php", ".tpl", ".md", ".txt"):
            head = p.read_bytes()[:4096]
            if master_hex[:32].encode() in head or priv_head.encode() in head:
                ok = False
                detail = f"private material found in package: {p.name}"
                break
    add("no_private_material", ok, detail or "package free of master/signing private material")

    # 7. config consistency
    cfg = json.loads((ctx.guard_dir / "config.json").read_text())
    ok = (cfg["project"] == ctx.project_id and cfg["build"] == ctx.build_id
          and cfg["version"] == ctx.version and "BEGIN PUBLIC KEY" in cfg["public_key_pem"])
    add("config_consistency", ok, "project/build/version + public key present")

    # 8. no protected plaintext in the package tree (PHP must be stubs only)
    src = config.project_dir(ctx.project_id) / "source"
    ok = True
    detail = ""
    for rel in ctx.protected:
        if Path(rel).suffix.lower() not in scanner.KIND_EXTENSIONS["php"]:
            continue
        stub = ctx.package_tree / rel
        original = src / rel
        if not stub.is_file() or not stub.read_text().startswith("<?php") or "sfg_include(" not in stub.read_text():
            ok = False
            detail = f"protected php not stubbed: {rel}"
            break
        if original.is_file():
            try:
                orig_bytes = original.read_bytes()
            except OSError:
                orig_bytes = b""
            if len(orig_bytes) > 0 and orig_bytes == stub.read_bytes():
                ok = False
                detail = f"plaintext not replaced: {rel}"
                break
    add("no_protected_plaintext", ok, detail or "all protected PHP replaced by gateway stubs")

    passed = all(c["ok"] for c in checks)
    ctx.validation_report = {"checks": checks, "passed": passed,
                             "failed": [c["name"] for c in checks if not c["ok"]]}
    db.qexec("UPDATE builds SET validation_report_json=? WHERE id=?",
             (json.dumps(ctx.validation_report), ctx.build_id))
    if not passed:
        names = ", ".join(c["name"] for c in checks if not c["ok"])
        raise StageError(11, f"Build validation failed: {names}. No package was produced. See the validation report for details.")
    Stage.message = f"All {len(checks)} validation checks passed."


def packaging(ctx: BuildContext) -> None:
    import zipfile
    zip_path = ctx.package_path
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in sorted(ctx.package_tree.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(ctx.package_tree).as_posix())
        # components ship inside the package under components/
        for p in sorted(ctx.components_dir.glob("*.enc")):
            z.write(p, f"components/{p.name}")
    ctx.package_sha = crypto.sha256_file(zip_path)
    db.qexec("UPDATE builds SET package_path=?, package_sha256=? WHERE id=?",
             (str(zip_path), ctx.package_sha, ctx.build_id))
    Stage.message = (f"Package {zip_path.name} ({zip_path.stat().st_size // 1024} KB, "
                     f"sha256 {ctx.package_sha[:16]}…)")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _new_build_key() -> bytes:
    import secrets as _s
    return _s.token_bytes(32)


def _stored_wrapped_key(build_id: str) -> str:
    row = db.q1("SELECT config_json FROM builds WHERE id=?", (build_id,))
    cfg = json.loads(row["config_json"] or "{}")
    return cfg["build_key_wrapped"]


def rawurlencode(s: str) -> str:
    from urllib.parse import quote
    return quote(s.replace("\\", "/"), safe="")


def rawurldecode(s: str) -> str:
    from urllib.parse import unquote
    return unquote(s)


# ----------------------------------------------------------------------
# PHP obfuscation (readability reduction — NOT encryption)
# ----------------------------------------------------------------------

_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _strip_comments(code: str) -> str | None:
    """Remove //, /* */ and # comments from a PHP code segment, respecting
    string literals. Returns None if the segment looks unsafe."""
    out: list[str] = []
    i, n = 0, len(code)
    in_s = None  # current quote char
    while i < n:
        ch = code[i]
        if in_s:
            out.append(ch)
            if ch == "\\":
                if i + 1 < n:
                    out.append(code[i + 1])
                    i += 2
                    continue
            elif ch == in_s:
                in_s = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_s = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and code[i + 1] == "/":
            while i < n and code[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and code[i + 1] == "*":
            end = code.find("*/", i + 2)
            if end == -1:
                return None  # unterminated comment — don't risk it
            i = end + 2
            continue
        if ch == "#":
            while i < n and code[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _enc_strings(code: str) -> str:
    """Encode plain double-quoted PHP literals (no interpolation/escapes,
    len >= 6) into base64_decode('...') wrappers. Applied to code segments only."""
    def _enc(m: re.Match) -> str:
        val = m.group(1)
        if "$" in val or "\\" in val:
            return m.group(0)
        b64 = base64.b64encode(val.encode("utf-8", "ignore")).decode()
        return f"base64_decode('{b64}')"

    return re.sub(r'"([^"$\\]{6,})"', _enc, code)


def php_obfuscate(src: str) -> str | None:
    """Best-effort, PHP tag-aware transforms.

    The file is split into PHP code segments (<?php … ?>, <?= … ?>) and plain
    HTML/text segments. Transforms are applied ONLY to code segments so that
    template markup, URLs and attribute values are never touched:

      - strip //, /* */ and # comments (string-aware)
      - encode simple double-quoted literals (no $ / no backslash)
      - collapse runs of blank lines

    Returns None if the input looks unsafe and should be left unobfuscated.
    """
    if "<?php" not in src[:200] and "<?=" not in src[:200]:
        return None
    parts = re.split(r"(<\?(?:php|=))", src)
    # parts alternates: [text, opener, code, text, opener, code, ...]
    out: list[str] = []
    i = 0
    while i < len(parts):
        seg = parts[i]
        if i % 2 == 0:
            out.append(seg)  # plain text / HTML — untouched
            i += 1
            continue
        # opener at parts[i], code at parts[i+1]
        opener = seg
        code = parts[i + 1] if i + 1 < len(parts) else ""
        # find closing tag; last segment may be unclosed (implicit close)
        m = re.search(r"\?>", code)
        if m:
            code_part, tail = code[:m.start()], code[m.start():]
        else:
            code_part, tail = code, ""
        stripped = _strip_comments(code_part)
        if stripped is None:
            return None
        out.append(opener + _enc_strings(stripped) + tail)
        i += 2
    text = "".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


# ----------------------------------------------------------------------
# Async runner
# ----------------------------------------------------------------------

def create_build(project_id: str, version: str, opts: dict, user: dict) -> str:
    build_id = config.new_id("BLD")
    ver_row = db.q1("SELECT * FROM project_versions WHERE project_id=? AND version=?",
                    (project_id, version))
    if ver_row is None:
        # Auto-create the version row so version management (list/revoke)
        # works for every build, not just pre-created versions.
        try:
            vid = db.qexec(
                "INSERT INTO project_versions (project_id, version, note, created_by, created_at)"
                " VALUES (?,?,?,?,?)",
                (project_id, version, "auto-created with build", user["id"], db.utcnow()))
            ver_row = db.q1("SELECT * FROM project_versions WHERE id=?", (vid,))
        except Exception:
            ver_row = db.q1("SELECT * FROM project_versions WHERE project_id=? AND version=?",
                            (project_id, version))
    version_id = ver_row["id"] if ver_row else None
    db.qexec(
        "INSERT INTO builds (id, project_id, version_id, version, status, stage_index, total_stages,"
        " config_json, created_by, created_at) VALUES (?,?,?,?, 'queued', 0, 12, ?, ?, ?)",
        (build_id, project_id, version_id, version,
         json.dumps({k: opts.get(k) for k in ("include", "exclude", "obfuscate")}, sort_keys=True),
         user["id"], db.utcnow()))
    db.audit(user["id"], user["email"], "build_created", "build", build_id,
             detail=f"version={version}", ip="")
    return build_id


async def start_build_async(build_id: str, project_id: str, version: str, opts: dict, user: dict) -> None:
    global _active_builds
    async with _builds_lock:
        if _active_builds >= BUILD_SERVICE_LIMIT:
            raise RuntimeError("Build service is busy. Try again shortly.")
        _active_builds += 1
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, run_build, project_id, build_id, version, opts, user)


def build_service_status() -> dict:
    return {"status": "ok", "active_builds": _active_builds, "limit": BUILD_SERVICE_LIMIT}


def mark_stale_builds_failed() -> int:
    rows = db.qall("SELECT id FROM builds WHERE status IN ('running','queued')")
    for r in rows:
        db.qexec("UPDATE builds SET status='failed', error='Server restarted mid-build. Start a new build.' WHERE id=?",
                 (r["id"],))
    return len(rows)

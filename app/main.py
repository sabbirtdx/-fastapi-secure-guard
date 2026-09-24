"""Secure File Guard — application assembly."""
from __future__ import annotations

import asyncio
import contextlib

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config, crypto, db, pipeline
from .routes import (auth, backups, builds, events, health, licenses,
                     projects, public, settings_routes, users)

app = FastAPI(title="Secure File Guard", version=config.APP_VERSION,
              description="License, protect and verify website builds.",
              docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],  # same-origin SPA; no cross-origin needed
    allow_credentials=True,
)


@app.on_event("startup")
async def startup():
    config.ensure_dirs()
    crypto.ensure_keys()
    db.connect()
    pipeline.init(asyncio.get_running_loop())
    pipeline.mark_stale_builds_failed()
    with contextlib.suppress(Exception):
        db.prune_old_logs()
    auth.seed_admin()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Never leak stack traces, paths, or credentials in production responses.
    import logging
    logging.getLogger("sfg").exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500,
                        content={"error": {"code": "SERVER_ERROR",
                                           "message": "An internal error occurred. Details are logged server-side."}})


# ----------------------------------------------------------------------
# Routers
# ----------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(builds.router)
app.include_router(licenses.router)
app.include_router(users.router)
app.include_router(events.router)
app.include_router(settings_routes.router)
app.include_router(health.router)
app.include_router(backups.router)
app.include_router(public.router)


@app.get("/api/healthz", include_in_schema=False)
async def healthz():
    return {"ok": True, "service": config.APP_NAME, "version": config.APP_VERSION}


@app.get("/api/openapi.json", include_in_schema=False)
async def openapi():
    return app.openapi()


API_DOC_HTML = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure File Guard — Licensing API</title>
<style>
 body{margin:0;background:#0b0f17;color:#e6edf7;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:32px}
 .wrap{max-width:960px;margin:0 auto}
 h1{font-size:22px}h2{font-size:16px;margin-top:34px;color:#7dd3fc}
 p{color:#93a1b8}
 .ep{background:#101827;border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:16px 18px;margin:12px 0}
 .m{display:inline-block;font:600 11px/1 ui-monospace,monospace;padding:4px 8px;border-radius:6px;margin-right:10px}
 .post{background:rgba(129,140,248,.15);color:#a5b4fc}.get{background:rgba(56,189,248,.15);color:#7dd3fc}
 code{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;background:#0b1220;padding:2px 6px;border-radius:5px;color:#cbd5e1}
 pre{background:#0b1220;border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:12px;overflow:auto;font-size:12px;color:#94a3b8}
 .note{border-left:3px solid #f59e0b;background:rgba(245,158,11,.07);padding:10px 14px;border-radius:6px;color:#d6bc8b;font-size:13px}
</style></head><body><div class="wrap">
<h1>Licensing API v1</h1>
<p>Base URL: <code>@@BASE@@</code> · All responses are JSON. Errors use
<code>{"error":{"code":"...","message":"..."}}</code>. Rate limits apply per IP.
Verification requests must include a fresh <code>ts</code> (±@@TOL@@ s) and a unique <code>nonce</code> (replay protection).</p>
<div class="note">Signed responses: <code>/licenses/verify</code> and <code>/licenses/activate</code> return an
Ed25519-signed authorization token. The protected runtime re-verifies the signature with the embedded
public key and checks the domain claim before use. There is no plain <code>VALID=true</code> path.</div>

<h2>License verification</h2>
<div class="ep"><span class="m post">POST</span><code>/api/v1/public/licenses/verify</code>
<p>Checks license key → status → expiry → project → domain → build → version; returns a signed token.</p>
<pre>{"license":"SFG-XXXX-XXXX-XXXX-XXXX","domain":"example.com","project":"PRJ-ABC12",
 "build":"BLD-XYZ78","version":"1.0.0","ts":1700000000,"nonce":"9f86d0819873378640000000"}</pre>
<p>200 → <code>{"ok":true,"token":"eyJ…","expires_at":…}</code> · 4xx → error codes:
LICENSE_INVALID, LICENSE_EXPIRED, LICENSE_REVOKED, LICENSE_SUSPENDED, DOMAIN_NOT_AUTHORIZED,
BUILD_INVALID, VERSION_NOT_ALLOWED, PROJECT_MISMATCH, REPLAY_REJECTED, RATE_LIMITED</p></div>

<div class="ep"><span class="m post">POST</span><code>/api/v1/public/licenses/activate</code>
<p>Same checks as verify; records the activation event and marks the license activated on first success.</p></div>

<div class="ep"><span class="m post">POST</span><code>/api/v1/public/licenses/status</code>
<p><code>{"license":"…"}</code> → license state + authorized domains. For tooling; the runtime uses verify/activate.</p></div>

<h2>Domain / version / integrity</h2>
<div class="ep"><span class="m post">POST</span><code>/api/v1/public/domains/verify</code>
<p><code>{"license":"…","domain":"example.com"}</code> → domain authorization check against license policy
(normalized host, www handling, subdomain policy).</p></div>

<div class="ep"><span class="m post">POST</span><code>/api/v1/public/versions/verify</code>
<p><code>{"license":"…","version":"1.0.0"}</code> → version restriction + completed build + version revocation checks.</p></div>

<div class="ep"><span class="m post">POST</span><code>/api/v1/public/integrity/verify</code>
<p><code>{"license":"…","build":"BLD-…","component":"config%2Fdatabase.php","sha256":"…"}</code> →
compares a claimed hash against the signed manifest and returns the expected hashes with a fresh signature.</p></div>

<h2>Protected runtime</h2>
<div class="ep"><span class="m get">GET</span><code>/api/v1/public/runtime/file?project=…&build=…&component=…</code>
<p>Serves a protected component's plaintext. Requires <code>Authorization: Bearer &lt;signed token&gt;</code>.
The token is re-checked against live license state (revocation is immediate) and the delivered payload
carries a SHA-256 the runtime verifies against the signed manifest.</p></div>

<div class="ep"><span class="m post">POST</span><code>/api/v1/public/events</code>
<p>Best-effort reporting from protected runtimes (tamper detection, repeated failures). Rate limited.</p></div>

<div class="ep"><span class="m get">GET</span><code>/api/v1/public/info</code>
<p>Service version + signing public-key fingerprint.</p></div>

<h2>Security properties</h2>
<p>• License keys stored as SHA-256 hashes only; plaintext is shown once at creation.<br>
• Every authorization decision is made server-side against the database — client-claimed status is never trusted.<br>
• Signed responses + signed manifest: the runtime independently verifies signatures with the public key.<br>
• Replay protection (timestamp window + nonce), per-IP rate limits, repeated-failure tracking per (license, ip).<br>
• The package contains only the public verification key — no private signing key, no master encryption key.</p>
</div></body></html>
"""


@app.get("/api/docs", response_class=HTMLResponse, include_in_schema=False)
async def api_docs(request: Request):
    base = str(request.base_url).rstrip("/")
    tol = db.get_settings().get("clock_tolerance_seconds", str(config.CLOCK_TOLERANCE_SECONDS))
    return API_DOC_HTML.replace("@@BASE@@", base).replace("@@TOL@@", str(tol))


# ----------------------------------------------------------------------
# Static frontend (last, so /api/* wins)
# ----------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")


@app.get("/{path:path}", include_in_schema=False)
async def spa(path: str):
    if path.startswith("api/"):
        return JSONResponse({"error": {"code": "NOT_FOUND", "message": "Unknown API endpoint."}}, status_code=404)
    return FileResponse(str(config.STATIC_DIR / "index.html"))

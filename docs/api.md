# API Reference

Base: `http(s)://<host>:8000`

Two families:

- **Session API** — `Authorization` via the `sfg_session` http-only cookie
  (set by `POST /api/v1/auth/login`). Mutating requests require the
  `X-CSRF-Token` header (value returned at login, tied to the session).
- **Public licensing API** — `/api/v1/public/*`, no session; secured by the
  license key, domain claim, replay protection, rate limits, and
  Ed25519-signed responses. This is what protected deployments call.

All errors are structured:

```json
{ "error": { "code": "DOMAIN_NOT_AUTHORIZED", "message": "Domain not authorized for this license." } }
```

Stable codes: `LICENSE_INVALID`, `LICENSE_EXPIRED`, `LICENSE_REVOKED`,
`LICENSE_SUSPENDED`, `DOMAIN_NOT_AUTHORIZED`, `SIGNATURE_INVALID`,
`INTEGRITY_FAILED`, `BUILD_INVALID`, `VERSION_NOT_ALLOWED`,
`PROJECT_MISMATCH`, `REPLAY_REJECTED`, `RATE_LIMITED`, `ACTIVATION_FAILED`,
`SERVER_UNAVAILABLE`, `HTTP_REQUIRED`, `PATH_TRAVERSAL`, `UNSAFE_ENTRY`,
`COMPRESSED_BOMB`, `DUPLICATE_PATH`, `TOO_MANY_FILES`, `EMPTY_ZIP`,
`RESTORE_REJECTED`, `BAD_DOMAIN`, `DNS_UNREACHABLE`, `FORBIDDEN`,
`NOT_FOUND`, `UNAUTHENTICATED`, `INVALID_CREDENTIALS`, `SERVER_ERROR`.

A live, clickable reference with a curl console is served at **`/api/docs`**.

---

## Session API

### Auth

| Method & path | Description |
|---|---|
| `POST /api/v1/auth/login` | `{email, password}` → `200 {ok, csrf, user}` + `Set-Cookie sfg_session` (12 h). Wrong credentials → `401 INVALID_CREDENTIALS` (rate-limited 5/60 s per IP) |
| `POST /api/v1/auth/logout` | Destroy the session |
| `GET /api/v1/auth/me` | Current user + role |

### Projects

| Method & path | Description |
|---|---|
| `GET /api/v1/projects?q=&mine=` | List projects. Non-admins see **only their own** (hard boundary). `mine` additionally filters admins |
| `POST /api/v1/projects` | `{name}` → create (owner = caller) |
| `GET /api/v1/projects/{id}` | Detail incl. file/license/build counts (owner/admin) |
| `POST /api/v1/projects/{id}/archive` | Soft-archive |
| `GET /api/v1/projects/{id}/files` | Indexed file list (relpath, kind, size, sha256, flags) |
| `GET /api/v1/projects/{id}/scan` | Scan report: file counts by kind, sensitive files, **masked** secret findings |
| `GET /api/v1/projects/{id}/ai-analysis` | Latest analysis (engine, overview, technologies, risks, recommendation) |
| `POST /api/v1/projects/{id}/ai-analysis` | `{engine: "builtin"|"llm"}` run analysis (LLM only if configured in Settings) |
| `GET /api/v1/projects/{id}/protection-config` | Effective protected set + recommendation |
| `GET /api/v1/projects/{id}/versions` | Version list (with revoked flags) |
| `POST /api/v1/projects/{id}/versions` | `{version, note}` create version |
| `POST /api/v1/projects/versions/{vid}/revoke` | Revoke a version → its builds fail verification with `VERSION_NOT_ALLOWED` |
| `POST /api/v1/projects/{id}/upload/zip` | `multipart` field `file`. Guards: size, entry count, traversal (`PATH_TRAVERSAL`), symlinks/devices (`UNSAFE_ENTRY`), bomb ratio (`COMPRESSED_BOMB`), duplicates (`DUPLICATE_PATH`), empty (`EMPTY_ZIP`). Validates **fully before** replacing the workspace. Returns extract stats + scan summary |
| `POST /api/v1/projects/{id}/upload/folder/start` | `{file_count, total_size}` → session-scoped upload slot (used by the browser folder picker) |
| `POST /api/v1/projects/{id}/upload/file` | `multipart` `path` + `file`; one file of a folder upload (size/type guards per file) |
| `POST /api/v1/projects/{id}/upload/folder/finish` | Finalize the folder upload (scans + indexes) |

Upload rules: max upload size (default 200 MB, Settings), max 5 000 files,
decompression ratio ≤ 4×, per-file limits. Uploaded code is **never executed**
during scanning.

### Builds

| Method & path | Description |
|---|---|
| `GET /api/v1/projects/{id}/builds` | List builds for the project |
| `POST /api/v1/projects/{id}/builds` | `{version, obfuscate, include[], exclude[]}` → `202 {build_id}`; runs asynchronously (max 2 concurrent) |
| `GET /api/v1/builds/{id}` | Status, current stage (1–12), error, validation report, package sha256 |
| `GET /api/v1/builds/{id}/progress` | **SSE** stream of stage events (`start`/`complete`/`failed`/`done`) |
| `GET /api/v1/builds/{id}/download` | The protected ZIP — only for `completed` builds; failed/disabled builds are rejected with the real reason |
| `POST /api/v1/builds/{id}/disable` / `enable` | Admin: disable a build (verification then returns `BUILD_INVALID`) |
| `DELETE /api/v1/builds/{id}` | Admin: delete a build (package + work dirs removed) |

### Licenses

| Method & path | Description |
|---|---|
| `GET /api/v1/licenses` | List (own for non-admins) |
| `POST /api/v1/licenses` | `{project_id, customer_name, customer_email, domains[], expiry_days, allow_subdomains, version_restrict}` → license with the **plaintext key shown exactly once** |
| `GET /api/v1/licenses/{id}` | Detail; `key` is always `null` after creation (SHA-256 stored) |
| `POST /api/v1/licenses/{id}/suspend` / `resume` | Suspend → verifications return `LICENSE_SUSPENDED`; resume restores |
| `POST /api/v1/licenses/{id}/revoke` | Terminal revocation → `LICENSE_REVOKED` everywhere |
| `POST /api/v1/licenses/{id}/renew` | `{days}` extend expiry (expired → active) |
| `POST /api/v1/licenses/{id}/reset-activation` | Forget activation state |
| `POST /api/v1/licenses/{id}/rotate-key` | New key (old one invalidated); shown once |
| `GET /api/v1/domains` | All license domains (admin) |
| `POST /api/v1/licenses/{id}/domains` | `{domain, allow_subdomains}` → `pending` + `dns_hint` (`_sfg-verify.<domain> TXT "sfg-verify=<token>"`) |
| `DELETE /api/v1/licenses/{id}/domains/{d}` | Remove a domain |
| `POST /api/v1/licenses/{id}/domains/{d}/verify` | `{method: "dns"|"manual"}` — DNS does a real TXT lookup (`502 DNS_UNREACHABLE` if DNS is unreachable, then use `manual`); success → `verified` |
| `POST /api/v1/licenses/{id}/domains/{d}/block` | Block a domain (matching always fails) |

### Users (admin)

| Method & path | Description |
|---|---|
| `GET /api/v1/users` | List users |
| `POST /api/v1/users` | `{email, name, role}` → created with a **random password shown once** |
| `POST /api/v1/users/{id}/reset-password` | New random password, shown once |

Roles: `super_admin` (everything incl. admin management), `admin`
(projects/licenses/users/events/health/backups/settings), `user` (own
projects + their licenses), `developer` (own projects, build-oriented subset).

### Observability & platform

| Method & path | Description |
|---|---|
| `GET /api/v1/events?limit=` | Security events (admin) |
| `GET /api/v1/events/export.csv` | CSV export |
| `GET /api/v1/verifications?limit=` | Public verify attempts with result/code (admin) |
| `GET /api/v1/verifications/export.csv` | CSV export |
| `GET /api/v1/audit?limit=` | Audit log (who/what/resource/result/IP) (admin) |
| `GET /api/v1/health` | Admin: DB status + integrity check, key material, license API self-check, build service, rate limiter state |
| `GET /api/v1/settings` / `POST /api/v1/settings` | Read/update platform settings (AI key is stored wrapped; never returned raw) |
| `GET /api/v1/backup/export` | Signed **metadata-only** bundle (no file contents, no keys) |
| `POST /api/v1/backup/restore` | Restore; tampered bundles → `400 RESTORE_REJECTED`; structural validation before any write |
| `GET /api/v1/backup` | Backup history |

Settings keys: `license_server_url`, `require_https` (0/1),
`verify_ttl_seconds` (client authz cache TTL, default 300),
`grace_seconds` (offline grace, default 0), `clock_tolerance_seconds`
(default 300), `max_upload_mb` (default 200), AI settings (`ai_enabled`,
`ai_base_url`, `ai_model`, `ai_key_wrapped`).

---

## Public licensing API (`/api/v1/public/*`)

No session. Per-IP rate limits: verify 60/60 s, activate 10/300 s,
status/domains/versions/integrity 120/60 s, runtime file 240/60 s,
events 30/300 s.

Replay protection (verify/activate): `ts` within ±`clock_tolerance_seconds`
and a unique hex `nonce` (8–64 chars), else `403 REPLAY_REJECTED`.

### `POST /api/v1/public/licenses/verify`

```json
{ "license": "SFG-XXXX-XXXX-XXXX-XXXX", "domain": "shop.example.com",
  "project": "PRJ-…", "build": "BLD-…", "version": "1.0",
  "ts": 1714000000, "nonce": "0123456789abcdef" }
```

Decision order: replay → key exists (`404 LICENSE_INVALID`) → fail-counter
throttle (`RATE_LIMITED`) → status (`LICENSE_REVOKED` / `LICENSE_SUSPENDED` /
`LICENSE_EXPIRED`, 403) → project binding (`PROJECT_MISMATCH`) → domain
(`DOMAIN_NOT_AUTHORIZED`) → build exists/status (`BUILD_INVALID`) → version
(`VERSION_NOT_ALLOWED`).

Success → `200 {ok: true, token, expires_at}` where **token** is the
Ed25519-signed authorization token (self-verifiable with the public key in
`guard/config.json`; payload keys `lic, prj, bld, ver, dom, iat, exp, ttl,
jti`). A successful verify also transitions `pending → active` (license) and
`verified/pending → active` (domain).

### `POST /api/v1/public/licenses/activate`

Same body; used by the activation page. Returns the signed token (the
runtime stores the key locally only after this succeeds).

### `POST /api/v1/public/licenses/status`

`{license}` → `{ok, status, expires_at, activated, domains[]}` or
`404 LICENSE_INVALID`.

### `POST /api/v1/public/domains/verify`

`{license, domain}` → `200 {ok: true, domain, license_id, project_id}` or
`403 DOMAIN_NOT_AUTHORIZED` / `404 LICENSE_INVALID`.

### `POST /api/v1/public/versions/verify`

`{license, version}` → checks license status, version restriction, completed
build, and version revocation → `200 {ok, version, build_id}` or
`VERSION_NOT_ALLOWED` / `BUILD_INVALID`.

### `POST /api/v1/public/integrity/verify`

`{license, build, component, sha256}` → server-side attestation of a
component's plaintext hash, returned with a fresh Ed25519 signature:
`{ok, component, expected_plain_sha256, expected_ct_sha256, signature}`.

### `POST /api/v1/public/events`

Best-effort runtime reporting: `{type, project, build, domain, detail}` →
`{ok: true}`. Recorded to `security_events` (severity derived from type).

### `GET /api/v1/public/runtime/file?project&build&component`

Streams a protected component's plaintext. Requires
`Authorization: Bearer <signed token>`; the token signature **and** the live
license state (status, domain, build) are re-checked on **every** call —
revocation takes effect immediately. Returns
`{data: base64, sha256, size}`. Errors: `ACTIVATION_FAILED` (401, no token),
`LICENSE_*` / `DOMAIN_NOT_AUTHORIZED` / `PROJECT_MISMATCH` (403),
`BUILD_INVALID` (404/500).

### `GET /api/v1/public/info`

`{service, version, public_key_fingerprint}` — no auth; useful for
connectivity checks.

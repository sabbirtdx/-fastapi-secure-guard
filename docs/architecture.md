# Architecture

## Components

| Component | Responsibility |
|---|---|
| **FastAPI app** (`app/main.py`) | All session- and public-API routes, static SPA, startup/teardown, global error handling (never leaks stack traces or internals to clients) |
| **SQLite (WAL)** (`app/db.py`) | Single authoritative state store: users, sessions, projects, files, versions, builds, licenses, domains, activations, verification logs, security events, AI analyses, settings, audit log, backups, fail counters. Thread-safe via a module-level RLock + `check_same_thread=False`; short transactions |
| **Crypto core** (`app/crypto.py`) | Key hierarchy, Ed25519 (signing), AES-256-GCM (data keys), canonical JSON, authorization tokens |
| **Scanner** (`app/scanner.py`) | File-type classification, sensitive-path heuristics, 13 credential-pattern detectors. **Reads bytes only — never executes uploaded code.** All findings expose masked values |
| **Analyzer** (`app/analyzer.py` + `services/ai.py`) | Builtin deterministic engine (always on) + optional external LLM (OpenAI-compatible). The LLM receives an anonymized structural summary only (paths, kinds, counts — never contents) and its output is schema-validated and advisory |
| **Pipeline** (`app/pipeline.py`) | 12-stage async build with SSE progress; concurrency limit (2 builds); a failed stage marks the build failed with the real reason and produces **no package** |
| **Licensing** (`app/licensing.py`) | License state machine, server-side domain matching, replay protection, fail counters, signed authorization tokens |
| **PHP runtime** (`app/guard/guard.php`) | Shipped in every package; enforces integrity + authorization on every request; streams protected files; reports tamper/authorization failures back to the platform |
| **Public API** (`routes/public.py`) | The only surface the deployment talks to: verify/activate/status, domain/version/integrity checks, event ingest, protected-file streaming |

## Key hierarchy

All private material lives only on the platform (`data/keys/`, mode 0600):

```
master.key          32 random bytes (secrets.token_bytes)
                    └─ wraps: per-build data keys, AI API key, backups
signing.key         Ed25519 private (PKCS8 PEM)
                    └─ signs: build manifests, authorization tokens,
                              integrity attestations, backup bundles
signing.pub         Ed25519 public (SPKI PEM + raw 32-byte, base64)
                    └─ shipped in every package (public material, safe)

per build:
  build key         32 random bytes, AES-256-GCM data key
                    stored ONLY as  wrap = AESGCM(master).encrypt(key)
                    never written to disk unwrapped, never shipped
```

Property: leaking an entire package (or the whole `data/projects` tree)
discloses **no** key material and reveals **no** protected plaintext.
Losing `data/` loses the ability to decrypt existing builds — by design.

## The 12 build stages

Each stage does real work and is marked complete only after it completes.
Any failure → `status=failed`, `error=<real reason>`, no package, admin sees
the exact stage + reason in the UI.

| # | Stage | Real work performed |
|---|---|---|
| 1 | Upload validation | workspace exists, file/size/entry limits, no unsafe paths |
| 2 | Extraction check | on-disk tree matches the file index (size + count); re-indexes on drift |
| 3 | File scan | full rescan; file kinds, sensitive files, masked secret findings |
| 4 | AI analysis | reuses <1h analysis or runs the engine; recommendation + protected set |
| 5 | Protection | resolves final protected set (recommended ∪ user-included ∖ user-excluded, minus public assets); builds package tree; replaces protected PHP with gateway stubs, `.env` with placeholder, other protected files with empty placeholders |
| 6 | Encryption | fresh per-build key; every protected component sealed AES-256-GCM with the relpath as AAD; wrapped key stored in `builds.config_json` |
| 7 | Obfuscation | optional; PHP-tag-aware transforms on code segments only (comment stripping, plain double-quoted literal encoding); re-seals + lints; never touches HTML markup/URLs |
| 8 | Integrity generation | copies the runtime (guard.php, activate.php, activate.html.tpl) into the package; hashes runtime files + stubs + component ciphertexts into the manifest |
| 9 | License binding | requires ≥1 active/pending license; writes `guard/config.json` (public key PEM + raw key, license-server URL, TTLs, authorized domains); finalizes manifest |
| 10 | Signature generation | Ed25519 signature over canonical JSON of the manifest; re-verified before shipping; manifest copied into the package |
| 11 | Validation | 10 independent checks (below); any failure → no package |
| 12 | Package generation | ZIP with sha256 recorded; work dirs retained (needed by the streaming endpoint) |

### Validation checks (stage 11)

1. `manifest_signature` — Ed25519 signature over canonical manifest verifies
2. `canonical_roundtrip` — manifest file re-serializes byte-identically
3. `decrypt_roundtrip` — sample components decrypt + hash-match
4. `component_blobs` — every `.enc` on disk matches its manifest ciphertext hash
5. `runtime_files` — every hashed runtime file matches
6. `stubs` — every stub matches its hash
7. `php_lint` — `php -l` on all stubs **and** on obfuscated plaintext
8. `no_private_material` — no master/signing private material anywhere in the package
9. `config_consistency` — config.json project/build/version + public key coherent
10. `no_protected_plaintext` — protected PHP in the tree is gateway-only

## Protected package layout

```
<root>/
  index.php            ← stub:  require_once …/guard/guard.php; sfg_include('index.php');
  admin/index.php      ← stub (depth-aware guard path)
  config/database.php  ← stub
  .env                 ← placeholder (values only via sfg_env / sfg_env_file)
  assets/…             ← public files, untouched (browsers may inspect them)
  components/
    index.php.enc                 AES-256-GCM blob (JSON: nonce, ct, sizes, hashes)
    config%2Fdatabase.php.enc
    …
  guard/
    guard.php            runtime bootstrap (self-integrity first)
    activate.php         activation endpoint (thin shim → guard.php)
    activate.html.tpl    activation page template
    config.json          public key (PEM + raw), license server, TTLs, domains
    manifest.json        signed manifest (components, runtime, stubs, domains)
    manifest.sig         base64 Ed25519 signature (standard base64)
    cache/               runtime state (authz token, fail counters) — 0600
    README-deploy.md     install + security model (honest)
```

Nothing in this tree can decrypt `components/` or verify-forge the manifest
without the platform's private keys.

## Runtime lifecycle (every request)

`guard.php` (included by every protected entry point / `auto_prepend_file`):

1. **Self-integrity (fail closed):** verify `manifest.sig` over the canonical
   `manifest.json` with the embedded public key (libsodium
   `sodium_crypto_sign_verify_detached`); then re-hash every listed runtime
   file. Any mismatch → report + halt (`SIGNATURE_INVALID` / `INTEGRITY_FAILED`,
   HTTP 503, professional page, no internals).
2. **Activation page:** `/guard/activate.php` (and `/guard/activate` when a
   rewrite maps it) renders the key-entry page and, on POST, verifies the key
   with the licensing server and stores it (0600) only if it succeeds.
3. **Authorization:** resolve the deployment host **server-side**
   (`HTTP_HOST`/`SERVER_NAME`, port stripped, lowercased — never a form field).
   Enforce HTTPS policy if configured. Use a locally cached signed token if
   fresh (TTL from config, token re-verified with the public key, domain
   re-matched); otherwise call `POST /licenses/verify` with
   `{license, domain, project, build, version, ts, nonce}`.
   - Explicit denials (revoked / expired / suspended / unauthorized domain /
     invalid signature / replay) **fail immediately**.
   - A grace window applies **only** to `SERVER_UNAVAILABLE` (network outage),
     never to deliberate license decisions.
   - Success → signed token cached (0600).
4. **Protected file gateway:** `sfg_include(rel)` / `sfg_env(name)` /
   `sfg_fetch_file(rel)` verify the local blob's ciphertext hash against the
   manifest, then fetch plaintext from `GET /runtime/file` with the signed
   token as `Bearer`. The server re-checks the token signature **and the live
   license state** on every fetch (revocation takes effect immediately) and
   decrypts with the per-build key. The runtime re-hashes delivered plaintext
   against the manifest before executing it. `__DIR__`/`__FILE__` in protected
   sources are rewritten (outside strings/comments) so apps keep working
   despite execution from a temp file; the temp file is 0600 and removed at
   shutdown.

### Authorization token

`base64url(header).base64url(payload).base64url(Ed25519 signature over
"header.payload")`, header `{alg:"Ed25519", typ:"sfg-authz-v1"}`, payload keys
`lic, prj, bld, ver, dom, iat, exp, ttl, jti`. Self-contained: the runtime can
verify offline between refreshes, and every fetch is re-authorized live.

## Licensing API (public, no session)

- Per-IP rate limits (separate buckets), structured errors only.
- **Replay protection:** `ts` within a configured tolerance (default 300 s)
  and a unique `nonce` (memoized).
- Every decision is logged to `verification_logs` (with result + error code)
  and adverse ones to `security_events`.
- Response to a successful verify is an **Ed25519-signed token** — the
  runtime never trusts raw success flags.

Endpoints (details in [`api.md`](api.md)):
`POST /api/v1/public/licenses/verify|activate|status`,
`POST /api/v1/public/domains/verify`, `POST /api/v1/public/versions/verify`,
`POST /api/v1/public/integrity/verify`, `POST /api/v1/public/events`,
`GET /api/v1/public/runtime/file`, `GET /api/v1/public/info`.

## Domain verification & matching

- Domains are normalized (lowercase; scheme, path, query, port, trailing dot
  stripped; ASCII validated) on every entry point.
- Ownership proof: DNS TXT `_sfg-verify.<domain> = "sfg-verify=<token>"`
  (real lookup via dnspython with a raw-UDP fallback; unreachable DNS →
  502 `DNS_UNREACHABLE`, then manual approval by an admin) or manual approval
  (admin action, audited).
- Matching is server-side and policy-aware: exact match, optional `www.`
  normalization in both directions, optional subdomain wildcard per domain
  row. Blocked domains always lose.
- A domain in `pending` state does **not** authorize; it becomes
  `verified`→`active` only through the verification flow.

## Database (16 tables)

`users, sessions, projects, project_files, project_versions, builds,
licenses, license_domains, activations, verification_logs, security_events,
ai_analysis, system_settings, audit_logs, backups, license_fail_counters`

- Passwords: scrypt (N=2¹⁴, r=8, p=1, 16-byte salt) — never plaintext,
  never reversible.
- License keys: stored as SHA-256 only; the key string is returned **once**
  at creation.
- Builds: `config_json` (wrapped build key, options), `manifest_json` (server
  path), `validation_report_json` (all checks + results).
- Security events carry severity + detail (no secrets), IP, and links to
  project/license.
- Backups are **metadata only** (never file contents, never keys) and
  Ed25519-signed; restore rejects tampered bundles (`RESTORE_REJECTED`) and
  validates structure before writing.

## Error handling & observability

- API errors: `{"error": {"code", "message"}}` with stable codes
  (`LICENSE_INVALID`, `LICENSE_EXPIRED`, `LICENSE_REVOKED`,
  `LICENSE_SUSPENDED`, `DOMAIN_NOT_AUTHORIZED`, `SIGNATURE_INVALID`,
  `INTEGRITY_FAILED`, `BUILD_INVALID`, `VERSION_NOT_ALLOWED`,
  `PROJECT_MISMATCH`, `REPLAY_REJECTED`, `RATE_LIMITED`,
  `ACTIVATION_FAILED`, `SERVER_UNAVAILABLE`, …).
- Unhandled exceptions → generic `SERVER_ERROR` to the client; full details
  only in server logs.
- Audit log: every admin mutation (who, what, resource, result, IP).
- Verification log: every public verify attempt (key fingerprint, domain,
  build, result, code, IP, latency).
- Health endpoint (admin): DB integrity, key material presence, license API
  self-check, build service state, rate-limit status.

## Concurrency & resource limits

- Builds: global lock, max 2 concurrent (async worker threads + SSE wake
  from the main loop); stale builds (server restarted mid-build) marked
  failed at startup.
- Uploads: max ZIP size (configurable, default 200 MB), max entries,
  decompression-ratio bomb check, per-file size cap.
- Public API: per-IP sliding buckets (verify 60/60s, activate 10/300s,
  generic 120/60s, runtime file 240/60s, events 30/300s, login 5/60s).
- License fail counters: repeated verification failures from one
  license+IP pair are temporarily throttled (15-min window).

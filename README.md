# Secure File Guard

A production web platform for **protecting server-side components of website
projects**: upload a project, scan it, let the analysis engine recommend what
to protect, build a signed protected package, and license its deployment to
specific domains. A cryptographic runtime (`guard.php`) shipped inside the
package enforces license state, domain binding, and build integrity on every
request — and fails closed when anything is wrong.

```
┌─────────────────────────┐   build    ┌──────────────────────────────┐
│  Secure File Guard      │ ─────────► │  Protected package           │
│  (licensing platform)   │            │  public assets + stubs +     │
│                         │            │  AES-256-GCM blobs + guard/  │
│  · project scan/analysis│            └──────────────┬───────────────┘
│  · signed builds        │                           │ deploy to authorized host
│  · license lifecycle    │   verify/stream           ▼
│  · events & audit       │ ◄────────────────  ┌──────────────────────┐
└─────────────────────────┘  (Ed25519-signed)  │  Customer's PHP host │
                                               │  guard.php runtime   │
                                               └──────────────────────┘
```

**Root-of-trust principle.** Protected packages may be distributed freely, but
the master private signing key, the master encryption key, and the
authoritative license state **never leave the platform**. A package contains
only the Ed25519 *public* key, encrypted component blobs (decrypted only by
the platform), and the runtime.

---

## What it does

| Capability | How it works (no mocks) |
|---|---|
| Upload & validate projects | ZIP or browser folder upload; path-traversal / symlink / zip-bomb / duplicate / size / entry-count guards; isolated per-project workspaces |
| File & secret scanning | File-type classification; 13 credential-pattern detectors; values **masked** in every report; uploaded code is never executed |
| AI-assisted analysis | Deterministic builtin static-analysis engine (structure, technologies, risks, protection recommendation) + optional external OpenAI-compatible model that receives an **anonymized structural summary only** (no file contents) |
| Protection build | 12 real stages; protected PHP becomes stubs that stream the real (optionally obfuscated) source through an authenticated channel; protected env/config removed from disk; public assets untouched |
| Integrity manifest | Every component + runtime file SHA-256-hashed into a manifest signed with the server Ed25519 key |
| License lifecycle | Create / activate / suspend / resume / revoke / renew / rotate-key / reset-activation; domain allow-list with DNS-TXT or manual verification; expiry; version restriction |
| Domain binding | Normalized server-side domain checks (scheme / trailing dot / case / www); the claimed host comes from the HTTP request on the deployment, not from any client field |
| Licensing API | `verify` / `activate` / `status` / `domains/verify` / `versions/verify` / `integrity/verify` / `events` / `runtime/file`; replay protection (timestamp window + unique nonce), per-IP rate limits, Ed25519-signed authorization tokens |
| Tamper response | Defensive only: stop functionality, log a security event, optionally report to the platform. Never deletes files, never damages data, no persistence |
| Dashboards | Admin & user dashboards, project detail (scan / AI / files / versions / builds / licenses), build progress over SSE, security events, verification logs, audit log (CSV export), system health (admin), signed metadata backup / restore |
| Access control | Roles `super_admin` / `admin` / `user` / `developer`; every endpoint enforces auth + role + ownership; per-session CSRF tokens; http-only session cookies |

## Honest security model

- **Goal:** unauthorized modification or copying of a protected deployment
  must not result in successful *authorized* execution.
- **Not a goal (and not claimed):** preventing a host administrator with root
  from reading or deleting files. That is physically impossible to prevent.
- Client-side files (HTML/CSS/JS/images) are public by design — browsers can
  always inspect delivered client code. The platform says so in every report.
- Protected server-side components exist on the deployment **only as
  ciphertext**; plaintext is streamed from the licensing server per request
  under a signed, live-verified license. Stop the license (suspend/revoke),
  block the domain, or tamper with any file, and the application stops
  working with a professional error page (no internal details).
- Obfuscation (optional) reduces readability; it is explicitly *not*
  encryption and is labeled as such in every build report.

## Quick start

```bash
# 1. Install
pip install -r requirements.txt        # Python 3.11+
# PHP 8.1+ with openssl + sodium (for testing deployments locally)

# 2. Secure admin (recommended — no credentials file, never logged)
export SFG_ADMIN_EMAIL='admin@example.com'
export SFG_ADMIN_PASSWORD='<strong-password>'

# 3. Run
./run.sh                               # or: python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

On first start the platform **automatically**:

- creates `data/` and all SQLite tables (WAL mode),
- generates a master key + Ed25519 signing key pair (private key stays in
  `data/keys/`, 0600),
- seeds the **super admin** from `SFG_ADMIN_EMAIL` / `SFG_ADMIN_PASSWORD`
  (install-script style). If `SFG_ADMIN_PASSWORD` is unset, a random password
  is written once to `data/credentials.txt` (0600) and removed after the
  first successful login. Passwords are never printed to logs.

Open `http://localhost:8000`, log in, and follow the wizard:
create project → upload ZIP (or folder) → review scan & AI analysis →
create a license with the customer's domain → approve the domain (DNS TXT
record `_sfg-verify.<domain> = "sfg-verify=<token>"` or manual approval) →
start a build → watch the 12 stages → download the protected package.

Set **Settings → License server URL** to the public URL of this platform
(e.g. `https://guard.example.com`) before building production packages — the
deployments call back to it.

### Try the sample project

`sample/restaurant-website.zip` is a small PHP site with deliberate
findings (a root `.env` and a hardcoded DB password in
`config/database.php`). Upload it to exercise the full pipeline end to end.

## End-to-end tests

```bash
python3 tests/e2e_api.py     # ~50 API checks: auth/CSRF, upload guards, scan
                             # masking, analysis, license lifecycle, build,
                             # package content, public verify API, events,
                             # health, backup tamper-rejection, RBAC isolation
python3 tests/e2e_deploy.py  # downloads the real package, serves it with a
                             # real `php -S`, and drives: activation flow,
                             # real page rendering through the streaming
                             # gateway, unauthorized-domain blocking, www
                             # normalization, component/runtime/signature
                             # tamper detection, revocation, event reporting,
                             # license re-issuance
```

Both scripts require a running platform with a fresh database and read
`data/credentials.txt`. They are the same flows a customer would perform.

## Repository layout

```
app/
  main.py            FastAPI app, routers, startup, error handling, /api/docs
  config.py          paths, limits, rate-limit tuples, id helpers
  db.py              SQLite (WAL) schema + access helpers, audit, settings
  crypto.py          key hierarchy, Ed25519 sign/verify, AES-256-GCM, tokens
  security.py        scrypt password hashing, sessions, CSRF, rate limiting
  scanner.py         file classification + secret detection (masked output)
  analyzer.py        builtin static-analysis engine (+ optional LLM adapter)
  licensing.py       license state machine, domain matching, replay protection
  pipeline.py        the 12-stage build pipeline (async worker, SSE)
  guard/             the PHP runtime shipped in every package (guard.php,
                     activate.php, activate.html.tpl)
  routes/            auth, projects, builds, licenses, users, events,
                     settings, health, backups, public licensing API
  services/          ai (wrapped-key LLM), dnscheck (dnspython + UDP fallback),
                     backup (signed metadata-only bundles)
static/              dark-theme SPA (vanilla JS, no build step, no CDN)
sample/              demo restaurant-website project + .zip
tests/               e2e_api.py, e2e_deploy.py
docs/                architecture, API reference, security, deployment guides
```

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — components, key hierarchy,
  build pipeline, manifest format, runtime lifecycle, database
- [`docs/api.md`](docs/api.md) — full API reference (also served live at
  `/api/docs` with a runnable curl console)
- [`docs/security.md`](docs/security.md) — threat model, defenses, honest
  limitations, operational hardening checklist
- [`docs/deployment.md`](docs/deployment.md) — deploying & activating a
  protected package, web-server configuration, troubleshooting
- [`docs/cloud-deploy.md`](docs/cloud-deploy.md) — free Render/Railway
  deploy: GitHub push, start command, env vars, step by step

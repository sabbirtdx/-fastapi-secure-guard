# Free cloud deploy (Render / Railway) — step by step

Go from a local Git repo to a public HTTPS URL. The app is pure Python +
SQLite; **no separate database service is required** for a free tier.

## What already happens on startup (no install.php needed)

| Step | Code |
|------|------|
| Create folders + all tables | `app/main.py` → `config.ensure_dirs()` + `db.connect()` (`CREATE TABLE IF NOT EXISTS …`) |
| Crypto keys | `crypto.ensure_keys()` → `data/keys/` (0600) |
| Super admin from env | `auth.seed_admin()` reads `SFG_ADMIN_EMAIL` + `SFG_ADMIN_PASSWORD` |

If `SFG_ADMIN_PASSWORD` is set, it is **authoritative**: used on first seed
and re-synced on every restart (safe to change the env var to rotate).
No password is ever written to stdout.

---

## 0. Prerequisites

- Python 3.11+ locally
- A GitHub account
- Free [Render](https://render.com) **or** [Railway](https://railway.app) account

---

## 1. Prepare the Git repository

From the project root:

```bash
cd /mnt/sdcard/Download/new.websj/secure-file-guard

# One-time identity (if needed)
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

git init
git add .
git commit -m "Secure File Guard initial deploy"

# Create an empty repo on GitHub, then:
git remote add origin https://github.com/YOUR_USER/secure-file-guard.git
git branch -M main
git push -u origin main
```

**Never commit** `data/`, `*.db`, `credentials.txt`, or `.env` — already in
`.gitignore`.

---

## 2A. Deploy on Render (recommended free web service)

1. Sign in at <https://dashboard.render.com> → **New +** → **Web Service**.
2. **Connect a repository** → GitHub → select `secure-file-guard`.
3. Fill the form:

   | Field | Value |
   |-------|--------|
   | Name | `secure-file-guard` |
   | Runtime | `Python 3` |
   | Build Command | `pip install -r requirements.txt` |
   | Start Command | `python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips '*'` |
   | Instance Type | **Free** |

   (Or use the included `render.yaml` blueprint: **New + → Blueprint** → pick the repo.)

4. **Environment** → **Add Environment Variable**:

   | Key | Example value |
   |-----|----------------|
   | `SFG_ADMIN_EMAIL` | `you@gmail.com` |
   | `SFG_ADMIN_PASSWORD` | `a-long-random-password` |

5. **Create Web Service** → wait for build → open
   `https://<your-name>.onrender.com`.

6. Health check: `https://<your-name>.onrender.com/api/healthz` → `{"ok":true,...}`.

7. Log in at the root URL with the email/password from step 4.

### Render free-tier notes

- Disk is **ephemeral**: redeploy/restart wipes `data/` (DB + keys). For a
  durable demo, add a **Disk** (paid) and set `SFG_DATA_DIR=/data`.
- First cold start can take ~30–60s (free instance sleeps).

---

## 2B. Deploy on Railway (alternative)

1. <https://railway.app> → **New Project** → **Deploy from GitHub repo**.
2. Select the repository.
3. **Settings → Service**:
   - **Start Command:**
     ```bash
     pip install -r requirements.txt && python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips '*'
     ```
   - Or add a root `Procfile` (already in this repo) and Railway will detect it.
4. **Variables**:

   | Key | Value |
   |-----|--------|
   | `SFG_ADMIN_EMAIL` | `you@gmail.com` |
   | `SFG_ADMIN_PASSWORD` | `a-strong-password` |

5. **Settings → Networking → Generate Domain** → public URL like
   `https://secure-file-guard-xxxx.up.railway.app`.

---

## 3. After first deploy (required)

1. Open the public URL → login with `SFG_ADMIN_EMAIL` / `SFG_ADMIN_PASSWORD`.
2. **Settings → License server URL** → set it to your public origin, e.g.
   `https://<your-name>.onrender.com` (no trailing slash).
   Protected packages call this URL for verify/stream — it must be HTTPS and public.
3. Upload a sample project (`sample/restaurant-website.zip`) and run a build
   to confirm the full pipeline.

---

## 4. Rotating the admin password

1. Change `SFG_ADMIN_PASSWORD` in the host dashboard.
2. Redeploy / restart the service.
3. On startup `seed_admin()` re-syncs the hash. Log in with the new password.

---

## 5. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Build fails on pip | Confirm `requirements.txt` is at repo root; Python 3.11+ |
| `ADDRESS already in use` / boot timeout | Start command must use `$PORT`, not hard-coded `8000` |
| Login fails after redeploy (Render free) | Ephemeral disk wiped DB → env password re-seeds empty DB on next boot; log in again with same env credentials |
| 500 on upload | Free plans often cap body size; raise plan or lower `SFG_MAX_UPLOAD_MB` |
| Package verify fails from customer site | Set **License server URL** to the exact public HTTPS origin |
| `credentials.txt` missing | Expected when `SFG_ADMIN_PASSWORD` is set — use the env password |

---

## Local smoke test before push

```bash
export SFG_ADMIN_EMAIL='admin@example.com'
export SFG_ADMIN_PASSWORD='test-password-123'
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
# → open http://127.0.0.1:8000 and log in
```

"""Secure File Guard — application configuration and path management."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SFG_DATA_DIR", str(APP_ROOT / "data")))
KEYS_DIR = DATA_DIR / "keys"
PROJECTS_DIR = DATA_DIR / "projects"
TEMP_DIR = DATA_DIR / "tmp"
STATIC_DIR = APP_ROOT / "static"
GUARD_TEMPLATE_DIR = APP_ROOT / "app" / "guard"

DB_PATH = DATA_DIR / "sfg.db"
CREDENTIALS_PATH = DATA_DIR / "credentials.txt"

# Limits (overridable via env for deployment)
MAX_UPLOAD_BYTES = int(os.environ.get("SFG_MAX_UPLOAD_MB", "200")) * 1024 * 1024
MAX_ZIP_ENTRIES = 20000
MAX_SCAN_FILE_BYTES = 1024 * 1024          # content-scan cap per file
MAX_PACKAGE_COMPONENTS = 4000
VERIFICATION_LOG_RETENTION_DAYS = 90

# Crypto / license policy
CLOCK_TOLERANCE_SECONDS = 300
DEFAULT_VERIFY_TTL_SECONDS = 300           # client-side authz cache TTL
AUTHZ_TOKEN_TTL_SECONDS = 3600             # server-issued token lifetime
REPLAY_WINDOW_SECONDS = 600
REPEAT_FAIL_THRESHOLD = 5                  # within 15 min per (license, ip)

# Rate limits (requests / window / seconds)
RATE_LOGIN = (5, 60)
RATE_VERIFY = (60, 60)
RATE_ACTIVATE = (10, 300)
RATE_PUBLIC_API = (120, 60)
RATE_SESSION_API = (300, 60)

APP_NAME = "Secure File Guard"
APP_VERSION = "1.0.0"
MANIFEST_VERSION = 1

ADMIN_EMAIL = os.environ.get("SFG_ADMIN_EMAIL", "admin@securefileguard.local")
# Optional secure first-run: when set, this password is authoritative for the
# super admin (seeded or re-synced at startup) and no credentials file is written.
ADMIN_PASSWORD = os.environ.get("SFG_ADMIN_PASSWORD") or None

# Optional AI/LLM (authoritative when set — re-synced into settings at startup).
# Never commit real keys; set them only in the host environment (Render/Railway).
AI_API_KEY = os.environ.get("SFG_AI_API_KEY") or None
AI_BASE_URL = os.environ.get("SFG_AI_BASE_URL") or ""
AI_MODEL = os.environ.get("SFG_AI_MODEL") or ""


def ensure_dirs() -> None:
    for d in (DATA_DIR, KEYS_DIR, PROJECTS_DIR, TEMP_DIR, STATIC_DIR):
        d.mkdir(parents=True, exist_ok=True)


def project_dir(project_id: str) -> Path:
    """Isolated workspace for one project. Never shared across projects."""
    base = PROJECTS_DIR / project_id
    for sub in ("source", "analysis", "build", "logs"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    return base


def build_dir(project_id: str, build_id: str) -> Path:
    d = PROJECTS_DIR / project_id / "build" / build_id
    for sub in ("work", "package"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    return d


def is_valid_project_id(pid: str) -> bool:
    return bool(pid) and "/" not in pid and "\\" not in pid and ".." not in pid


def is_valid_build_id(bid: str) -> bool:
    return bool(bid) and "/" not in bid and "\\" not in bid and ".." not in bid


def new_id(prefix: str, length: int = 5) -> str:
    return f"{prefix}-{secrets.token_hex(length // 2 + 1)[:length].upper()}"

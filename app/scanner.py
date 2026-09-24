"""Secure File Guard — project scanner.

Walks the isolated project source, classifies every file, and detects
credential-like values. Detected secret VALUES are never stored — only a
masked preview (first/last few chars) and metadata. Uploaded code is never
executed: this is pure static byte/regex analysis.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import config, db

KIND_EXTENSIONS = {
    "php": {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8"},
    "html": {".html", ".htm", ".xhtml"},
    "css": {".css", ".less", ".scss", ".sass"},
    "js": {".js", ".mjs", ".cjs", ".jsx", ".ts"},
    "json": {".json"},
    "xml": {".xml", ".svg", ".plist"},
    "env": set(),  # by name
    "config": set(),  # partial
    "asset": {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp",
              ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm",
              ".mp3", ".wav", ".pdf", ".zip", ".gz", ".tar", ".rar",
              ".map", ".webmanifest"},
    "other": set(),
}

ENV_NAMES = {".env", ".env.local", ".env.production", ".env.example", ".env.sample"}
CONFIG_STEM_HINTS = ("config", "database", "db-config", "secrets", "credentials",
                     "connection", "settings", "app-settings")
CONFIG_EXTENSIONS = {".ini", ".yaml", ".yml", ".toml", ".conf", ".cfg"}
SERVER_DIRS = ("config", "app", "inc", "includes", "lib", "libs", "core", "server",
               "backend", "api", "src/server")

# (name, severity, compiled regex) — credential-looking patterns.
SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("aws_access_key_id", "high", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("aws_secret_access_key", "high", re.compile(r"(?i)aws.{0,25}?(?:secret|private).{0,10}?['\"][0-9A-Za-z/+=]{40}['\"]")),
    ("private_key_block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt_token", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("generic_password_assignment", "high", re.compile(r"(?i)\b(?:password|passwd|pwd|db_password|dbpass)\b\s*[:=]\s*['\"]([^'\"]{4,})['\"]")),
    ("generic_api_key_assignment", "high", re.compile(r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|app[_-]?secret)\b\s*[:=]\s*['\"]([^'\"]{6,})['\"]")),
    ("connection_string", "high", re.compile(r"\b(?:mysql|postgresql|postgres|mongodb(\+srv)?|redis|amqp)://[^:\s'\"]+:[^@\s'\"]{4,}@[\w.\-]+")),
    ("github_token", "high", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b")),
    ("slack_token", "high", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("google_api_key", "high", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("stripe_secret_key", "high", re.compile(r"\b(sk_live_[0-9a-zA-Z]{16,})\b")),
    ("openai_api_key", "high", re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b")),
    ("bearer_token", "medium", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{20,}={0,2})\b")),
]

PLACEHOLDER_VALUES = re.compile(
    r"(?i)^(?:changeme|change_me|change-me|password|secret|your[_-]?[\w-]*|xxx+|placeholder|"
    r"example|test123|abc123|qwerty|123456{0,4}|todo|fixme|dummy|sample|\$?\{[^}]*\}|%24\{[^}]*\})$")

SKIP_DIR_NAMES = {".git", ".svn", ".hg", "node_modules", "__MACOSX", ".DS_Store",
                  ".idea", ".vscode", "vendor", "dist", "build", ".next"}


def classify(path: Path, relpath: str, head: bytes) -> str:
    ext = path.suffix.lower()
    name = path.name.lower()
    if name in ENV_NAMES or name.endswith(".env") or (ext == "" and name.startswith(".env")):
        return "env"
    if ext in KIND_EXTENSIONS["php"]:
        return "php"
    if ext in KIND_EXTENSIONS["html"]:
        return "html"
    if ext in KIND_EXTENSIONS["css"]:
        return "css"
    if ext in KIND_EXTENSIONS["js"]:
        return "js"
    if ext in KIND_EXTENSIONS["json"]:
        return "json"
    if ext in KIND_EXTENSIONS["xml"]:
        return "xml"
    if ext in KIND_EXTENSIONS["asset"]:
        return "asset"
    stem = name.rsplit(".", 1)[0]
    if ext in CONFIG_EXTENSIONS or any(h in stem for h in CONFIG_STEM_HINTS):
        return "config"
    parts = [p.lower() for p in relpath.split("/")]
    if parts and parts[0] in SERVER_DIRS and ext in (".php", ".py", ".inc"):
        return "php" if ext == ".php" else "config"
    return "other"


def is_binary(head: bytes) -> bool:
    return b"\x00" in head[:8192]


def mask_value(value: str) -> str:
    """Masked preview only. Never returns the full secret for values >= 8 chars."""
    v = value.strip()
    if len(v) <= 4:
        return "****"
    if len(v) <= 8:
        return v[0] + "*" * (len(v) - 2) + v[-1]
    return f"{v[:4]}…{v[-4:]} (len={len(v)})"


def scan_text_for_secrets(text: str) -> list[dict]:
    findings: list[dict] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if len(line) > 20000:
            line = line[:20000]
        for name, severity, rx in SECRET_PATTERNS:
            for m in rx.finditer(line):
                value = m.group(1) if m.lastindex else m.group(0)
                if PLACEHOLDER_VALUES.match(value):
                    continue
                findings.append({
                    "type": name,
                    "severity": severity,
                    "line": i + 1,
                    "masked": mask_value(value),
                    "value_length": len(value),
                })
    return findings


def sensitive_path_reasons(relpath: str) -> list[str]:
    reasons = []
    name = relpath.split("/")[-1].lower()
    if name.startswith(".env") or name == ".env":
        reasons.append("environment file")
    if any(h in name for h in ("secret", "credential", "private", "key")):
        reasons.append("name indicates secret material")
    if name in ("config.php", "database.php", "db.php", "configuration.php", "settings.php"):
        reasons.append("likely application configuration")
    top = relpath.split("/")[0].lower()
    if top in ("config", "conf") and ("." in name):
        reasons.append("inside configuration directory")
    if name.endswith(".pem") or name.endswith(".key"):
        reasons.append("key/certificate file")
    return reasons


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_project(project_id: str) -> dict:
    """Full scan of the project source. Returns report dict and persists index."""
    src = config.project_dir(project_id) / "source"
    stats: dict[str, int] = {}
    total_size = 0
    truncated = False
    rows: list[tuple] = []
    sensitive_files: list[dict] = []
    all_findings: list[dict] = []
    file_count = 0

    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
        for fn in files:
            file_count += 1
            if file_count > config.MAX_ZIP_ENTRIES:
                truncated = True
                break
            full = Path(root) / fn
            relpath = full.relative_to(src).as_posix()
            try:
                size = full.stat().st_size
            except OSError:
                continue
            total_size += size
            try:
                digest = sha256_file(full)
            except OSError:
                continue
            with open(full, "rb") as f:
                head = f.read(8192)
            kind = classify(full, relpath, head)
            stats[kind] = stats.get(kind, 0) + 1
            sensitive_reasons = sensitive_path_reasons(relpath)
            secret_count = 0
            if not is_binary(head) and size <= config.MAX_SCAN_FILE_BYTES and \
                    kind in ("php", "js", "json", "xml", "env", "config", "html", "other"):
                try:
                    text = head.decode("utf-8", errors="ignore")
                    if size > len(head):
                        with open(full, "r", encoding="utf-8", errors="ignore") as f:
                            text = f.read(config.MAX_SCAN_FILE_BYTES)
                    finds = scan_text_for_secrets(text)
                except Exception:
                    finds = []
                if finds:
                    secret_count = len(finds)
                    for fnd in finds:
                        all_findings.append({**fnd, "file": relpath})
            if sensitive_reasons or secret_count:
                if len(sensitive_files) < 500:
                    sensitive_files.append({
                        "file": relpath, "reasons": sensitive_reasons,
                        "secret_count": secret_count, "size": size,
                    })
            rows.append((project_id, relpath, size, digest, kind,
                         1 if (sensitive_reasons or secret_count) else 0,
                         secret_count, db.utcnow()))

    # Replace previous index for this project
    with db.db() as c:
        c.execute("DELETE FROM project_files WHERE project_id = ?", (project_id,))
        c.executemany(
            "INSERT INTO project_files (project_id, relpath, size, sha256, kind, sensitive,"
            " secret_count, indexed_at) VALUES (?,?,?,?,?,?,?,?)", rows)

    kind_order = ["php", "html", "css", "js", "json", "xml", "env", "config", "asset", "other"]
    by_kind = {k: stats.get(k, 0) for k in kind_order if stats.get(k, 0)}
    report = {
        "project": project_id,
        "scanned_at": db.utcnow(),
        "file_count": file_count,
        "truncated": truncated,
        "total_size": total_size,
        "by_kind": by_kind,
        "sensitive_file_count": len(sensitive_files),
        "sensitive_files": sensitive_files[:100],
        "secret_finding_count": len(all_findings),
        "secret_findings": all_findings[:200],
        "note": "Secret values are masked; full values are never stored or logged.",
    }
    out = config.project_dir(project_id) / "analysis" / "scan.json"
    out.write_text(json.dumps(report, indent=1))
    return report

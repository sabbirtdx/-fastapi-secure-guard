"""Secure File Guard — analysis layer.

Two engines:
  * builtin — a deterministic static-analysis engine (structure, technologies,
    dependency references, sensitive components, risk findings, protection
    recommendation). Always available, no network needed.
  * llm — optional external model (OpenAI-compatible endpoint configured in
    Settings). Receives ONLY an anonymized structural summary: file counts,
    file paths, detected technologies. It never receives file contents,
    secret values, master keys, or any credential material. Its output is
    schema-validated before storage and is advisory, never a guarantee.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import config, db
from . import scanner as scanner_mod

INCLUDE_RX = re.compile(r"""(?i)\b(?:require|include|require_once|include_once)\s*\(?\s*['"]([^'"]+\.php)['"]""")
JS_IMPORT_RX = re.compile(r"""(?i)\b(?:import|require\(|from\s+|src=|href=)['"]([^'"]+\.(?:js|css))['"]""")
HTML_REF_RX = re.compile(r"""(?i)(?:src|href)=['"]([^'"]+\.(?:js|css|png|jpe?g|webp|svg|woff2?))['"]""")
PHP8_HINTS = (":= ", "match (", "fn (", "readonly ", "enum ", "never", "int<", "str<")
FRAMEWORK_HINTS = {
    "bootstrap": re.compile(r"(?i)bootstrap[\w.-]*\.(?:css|js|min\.css|min\.js)"),
    "tailwind": re.compile(r"(?i)tailwind"),
    "jquery": re.compile(r"(?i)jquery[\w.-]*\.js"),
    "react": re.compile(r"(?i)react(?:\.|-|_)?(dom|production|development)?\.(?:min\.)?js"),
}


def _read_text(path: Path, limit: int = 200_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def _entry_points(rows: list[dict], src: Path) -> list[str]:
    eps = []
    names = {r["relpath"] for r in rows}
    for cand in ("index.php", "index.html", "index.htm", "public/index.php",
                 "public/index.html", "app.php", "main.php", "wp-load.php"):
        if cand in names:
            eps.append(cand)
    if not eps:
        for r in rows:
            if r["relpath"].count("/") == 0 and r["kind"] in ("php", "html"):
                eps.append(r["relpath"])
    return eps[:8]


def _extract_refs(src: Path, rows: list[dict], limit: int = 4000) -> dict[str, list[str]]:
    refs: dict[str, set[str]] = {}
    considered = [r for r in rows if r["kind"] in ("php", "js", "html")][:limit]
    for r in considered:
        p = src / r["relpath"]
        if not p.is_file():
            continue
        text = _read_text(p)
        found: set[str] = set()
        if r["kind"] == "php":
            found = set(INCLUDE_RX.findall(text))
        elif r["kind"] == "js":
            found = set(JS_IMPORT_RX.findall(text))
        else:
            found = set(HTML_REF_RX.findall(text))
        for f in found:
            norm = f.lstrip("./")
            refs.setdefault(r["relpath"], set()).add(norm)
    return {k: sorted(v)[:20] for k, v in refs.items()}


def analyze_project(project_id: str, force: bool = False) -> dict:
    """Run the builtin engine and persist the result. Returns the analysis."""
    src = config.project_dir(project_id) / "source"
    rows = db.rows_to_list(db.qall(
        "SELECT * FROM project_files WHERE project_id = ? ORDER BY relpath", (project_id,)))
    if not rows:
        raise ValueError("No files indexed for this project. Upload first.")

    by_kind: dict[str, int] = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    total_size = sum(r["size"] for r in rows)
    entries = _entry_points(rows, src)
    refs = _extract_refs(src, rows)

    # Technology detection
    technologies: dict[str, list] = {}
    php_files = [r for r in rows if r["kind"] == "php"]
    php8 = False
    for r in php_files[:30]:
        text = _read_text(src / r["relpath"])
        if any(h in text for h in PHP8_HINTS):
            php8 = True
            break
    technologies["language"] = ["PHP" if php_files else None, "JavaScript" if by_kind.get("js") else None,
                                "CSS" if by_kind.get("css") else None, "HTML" if by_kind.get("html") else None]
    technologies["language"] = [t for t in technologies["language"] if t]
    if php_files:
        technologies["php"] = {"files": len(php_files), "php8_features_detected": php8}
    fw = []
    sample = []
    for r in rows:
        if r["kind"] in ("html", "js", "css") and len(sample) < 400:
            sample.append(r)
    for r in sample:
        text = _read_text(src / r["relpath"], 60_000)
        for name, rx in FRAMEWORK_HINTS.items():
            if rx.search(text) and name not in fw:
                fw.append(name)
    if fw:
        technologies["frontend_libraries"] = fw

    # Sensitive components
    sensitive = []
    for r in rows:
        if r["sensitive"]:
            reasons = scanner_mod.sensitive_path_reasons(r["relpath"])
            if r["secret_count"]:
                reasons.append(f"{r['secret_count']} credential-looking value(s) detected (masked)")
            sensitive.append({"file": r["relpath"], "kind": r["kind"], "reasons": reasons})
    sensitive = sensitive[:150]

    # Risk findings (heuristic, honest)
    risks: list[dict] = []
    for r in rows:
        name = r["relpath"].lower()
        if r["kind"] == "env" and "/" not in name:
            risks.append({"id": "ENV_PUBLIC_ROOT", "title": "Environment file at project root",
                          "severity": "high",
                          "detail": f"{r['relpath']} may be directly reachable depending on the web root; its values are treated as protected."})
        if r["secret_count"] and r["kind"] in ("php", "config"):
            risks.append({"id": "HARDCODED_CREDENTIAL", "title": "Credential-looking value in application file",
                          "severity": "high", "file": r["relpath"],
                          "detail": f"{r['secret_count']} credential-looking value(s); values are masked in this report."})
        if name.startswith("admin/") and r["kind"] == "php":
            risks.append({"id": "ADMIN_PANEL_EXPOSED", "title": "Admin interface in web-accessible path",
                          "severity": "medium", "file": r["relpath"],
                          "detail": "Admin entry points should be protected server-side; consider including them in the protected component set."})
            break
    dupes = set()
    deduped = []
    for risk in risks:
        k = (risk["id"], risk.get("file", ""))
        if k in dupes:
            continue
        dupes.add(k)
        deduped.append(risk)
        if len(deduped) >= 25:
            break
    risks = deduped

    # Protection recommendation
    protect_set: list[str] = []
    for r in rows:
        rel = r["relpath"]
        ext = Path(rel).suffix.lower()
        if ext in scanner_mod.KIND_EXTENSIONS["asset"]:
            continue
        if r["kind"] in ("php", "env", "config"):
            protect_set.append(rel)
        elif r["sensitive"]:
            protect_set.append(rel)
    protect_set = protect_set[:config.MAX_PACKAGE_COMPONENTS]
    secret_score = sum(r["secret_count"] for r in rows)
    level = "basic"
    if secret_score >= 1 or by_kind.get("php", 0) > 0:
        level = "standard"
    if secret_score >= 3 or len(sensitive) >= 5:
        level = "advanced"

    result = {
        "engine": "builtin",
        "model": "sfg-static-v1",
        "project": project_id,
        "generated_at": db.utcnow(),
        "overview": {
            "file_count": len(rows),
            "total_size": total_size,
            "by_kind": by_kind,
            "entry_points": entries,
        },
        "technologies": technologies,
        "dependencies": {
            "referring_files": len(refs),
            "sample_refs": dict(list(refs.items())[:40]),
            "note": "Static reference extraction (require/include/import/src). Not a complete runtime graph.",
        },
        "sensitive_components": sensitive,
        "risks": risks,
        "recommendation": {
            "protection_level": level,
            "protected_components": protect_set,
            "public_components_note": "Images, fonts, CSS/JS and other public assets stay public — browsers can always inspect delivered client-side code, and that is expected.",
            "rationale": (
                "Recommendation is heuristic: server-side PHP, configuration and environment files are "
                "protected; public assets are left readable. It is an analysis aid, not a security guarantee."),
        },
        "disclaimer": "Automated heuristic analysis. Findings are advisory and do not constitute a security guarantee.",
    }

    analysis_id = db.qexec(
        "INSERT INTO ai_analysis (project_id, engine, model, input_summary, result_json, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (project_id, "builtin", result["model"],
         json.dumps({"files": len(rows), "kinds": by_kind}),
         json.dumps(result), db.utcnow()))
    result["id"] = analysis_id
    return result


def anonymized_summary_for_llm(project_id: str) -> dict:
    """The ONLY data sent to an external LLM: structure, never content."""
    rows = db.rows_to_list(db.qall(
        "SELECT relpath, kind, size, sensitive, secret_count FROM project_files WHERE project_id = ? LIMIT 2000",
        (project_id,)))
    by_kind: dict[str, int] = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    return {
        "purpose": "advisory protection analysis for a website project",
        "file_count": len(rows),
        "by_kind": by_kind,
        "files": [{"path": r["relpath"], "kind": r["kind"],
                   "sensitive_flag": bool(r["sensitive"])} for r in rows[:800]],
        "instruction": ("Return JSON: {overview: string, technologies: [string], risks: [{title, severity, detail}],"
                        " recommendation: {protection_level: basic|standard|advanced, protected_components: [path],"
                        " rationale: string}}. Advisory only. Never request or echo secret values."),
    }


def run_llm_analysis(project_id: str) -> dict:
    """Call the configured LLM (if any) with an anonymized summary."""
    from .services.ai import call_llm
    summary = anonymized_summary_for_llm(project_id)
    data = call_llm(summary)
    if data is None:
        raise ValueError("LLM analysis failed. Check AI settings and connectivity.")
    result = {
        "engine": "llm",
        "model": data.pop("_model", "unknown"),
        "project": project_id,
        "generated_at": db.utcnow(),
        "input": "anonymized structural summary only (no file contents, no secret values)",
        **data,
        "disclaimer": "External model output. Advisory only — verify before acting. Not a security guarantee.",
    }
    analysis_id = db.qexec(
        "INSERT INTO ai_analysis (project_id, engine, model, input_summary, result_json, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (project_id, "llm", result["model"], "anonymized summary",
         json.dumps(result), db.utcnow()))
    result["id"] = analysis_id
    return result

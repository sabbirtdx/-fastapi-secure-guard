"""E2E API test: full admin workflow up to a completed, validated build."""
import io, json, os, pathlib, sys, time, uuid, zipfile

import httpx

BASE = "http://127.0.0.1:8000"
# Prefer environment credentials (authoritative when SFG_ADMIN_PASSWORD is set
# on the server). Fall back to the one-time credentials file for first-run setups.
email = os.environ.get("SFG_ADMIN_EMAIL", "")
password = os.environ.get("SFG_ADMIN_PASSWORD", "")
if not password:
    cred_path = pathlib.Path("data/credentials.txt")
    if cred_path.exists():
        cred = cred_path.read_text()
        email = [l.split(":", 1)[1].strip() for l in cred.splitlines() if l.startswith("email")][0]
        password = [l.split(":", 1)[1].strip() for l in cred.splitlines() if l.startswith("password")][0]
if not password:
    sys.exit("FAIL: no admin credentials. Set SFG_ADMIN_PASSWORD (and SFG_ADMIN_EMAIL) or ensure data/credentials.txt exists.")
if not email:
    email = "admin@securefileguard.local"

client = httpx.Client(base_url=BASE, timeout=60, follow_redirects=False)
csrf = None

def req(method, path, body=None, files=None, fields=None):
    h = {}
    if csrf and method.upper() not in ("GET", "HEAD"):
        h["X-CSRF-Token"] = csrf
    r = client.request(method, path, json=body, files=files, data=fields, headers=h)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"_raw": r.text[:300]}

def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra else ""))
    if not cond:
        sys.exit(1)

# 1. login
r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
st, d = r.status_code, r.json()
check("login", st == 200 and d.get("ok"), str(d)[:120])
csrf = d["csrf"]

# bad login is rejected
r = client.post("/api/v1/auth/login", json={"email": email, "password": "wrong-pass-123"})
check("bad login rejected", r.status_code == 401)

def sreq(method, path, body=None, **kw):
    r = client.request(method, path, json=body, headers={"X-CSRF-Token": csrf} if method != "GET" else {}, **kw)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"_raw": r.text[:300]}

# 2. create project
st, d = sreq("POST", "/api/v1/projects", {"name": "Restaurant Website"})
check("create project", st == 200 and d["project"]["id"].startswith("PRJ"), str(d)[:120])
pid = d["project"]["id"]

# 3. upload zip
zdata = pathlib.Path("sample/restaurant-website.zip").read_bytes()
r = client.post(f"/api/v1/projects/{pid}/upload/zip",
                files={"file": ("project.zip", zdata, "application/zip")},
                headers={"X-CSRF-Token": csrf})
st, d = r.status_code, r.json()
check("zip upload", st == 200 and d.get("extracted", 0) >= 10, str(d)[:200])
ss = d.get("scan_summary", {})
check("scan summary has kinds", ss.get("by_kind", {}).get("php", 0) >= 5, str(ss))
check("scan found secrets", ss.get("secret_finding_count", 0) >= 1, str(ss.get("secret_finding_count")))

# zip with path traversal is rejected
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr("../../etc/evil.txt", "pwn")
r = client.post(f"/api/v1/projects/{pid}/upload/zip",
                files={"file": ("evil.zip", buf.getvalue(), "application/zip")},
                headers={"X-CSRF-Token": csrf})
check("path traversal rejected", r.status_code == 400 and r.json()["detail"]["code"] == "PATH_TRAVERSAL",
      str(r.json())[:150])

# 4. scan report
st, d = sreq("GET", f"/api/v1/projects/{pid}/scan")
scan = d["scan"]
check("scan report", st == 200 and scan["file_count"] >= 10, str(scan["file_count"]))
masked = [f for f in scan["secret_findings"] if "…" in f["masked"] or "****" in f["masked"]]
check("secrets masked in report", len(masked) >= 1, str(len(scan["secret_findings"])))
check("no raw secret in report", "Tr0ub4dor" not in json.dumps(scan) and "sk_live_51Hx8yK" not in json.dumps(scan))

# 5. AI analysis
st, d = sreq("POST", f"/api/v1/projects/{pid}/ai-analysis", {})
a = d["analysis"]
check("ai analysis", st == 200 and a["engine"] == "builtin" and a["overview"]["file_count"] >= 10)
check("ai recommends level", a["recommendation"]["protection_level"] in ("standard", "advanced"),
      a["recommendation"]["protection_level"])
check("ai lists protected components", len(a["recommendation"]["protected_components"]) >= 3)

# 6. license
st, d = sreq("POST", "/api/v1/licenses", {
    "project_id": pid, "customer_name": "Test Deploy Co", "customer_email": "ops@testdeploy.dev",
    "domains": ["example.com"], "expiry_days": 365, "allow_subdomains": False,
})
check("create license", st == 200 and d["license"]["key"].startswith("SFG-"), str(d)[:150])
LIC_KEY = d["license"]["key"]
LID = d["license"]["id"]

st, d = sreq("GET", f"/api/v1/licenses/{LID}")
check("key not re-disclosed", d["license"].get("key") is None)

# customer set the DNS TXT record (simulated) — admin approves the domain
st, d = sreq("POST", f"/api/v1/licenses/{LID}/domains/example.com/verify", {"method": "manual"})
check("domain approved manually", st == 200 and d.get("status") == "verified", str(d)[:120])

# 6b. runtime policy: point the build at this licensing server, http for local test,
# short cache TTL so revocation is felt within seconds (real deployments use defaults)
st, d = sreq("POST", "/api/v1/settings", {
    "license_server_url": "http://127.0.0.1:8000", "require_https": "0", "verify_ttl_seconds": "5",
})
check("settings updated for build", st == 200, str(d.get("changed")))

# 7. build
st, d = sreq("POST", f"/api/v1/projects/{pid}/builds", {"version": "1.0", "obfuscate": True})
check("build started", st == 200 and d["build_id"].startswith("BLD"), str(d))
bid = d["build_id"]

deadline = time.time() + 300
status, d = None, {}
while time.time() < deadline:
    st, d = sreq("GET", f"/api/v1/builds/{bid}")
    status = d["build"]["status"]
    if status in ("completed", "failed"):
        break
    time.sleep(2)
check("build completed", status == "completed", f"status={status} error={d['build'].get('error')}")
rep = d["build"]["validation_report"]
check("validation report present", rep is not None and rep["passed"] is True, json.dumps(rep.get("failed", [])))
check("validation checks ran", len(rep["checks"]) >= 10, str(len(rep["checks"])))

# 8. download package
r = client.get(f"/api/v1/builds/{bid}/download")
check("package downloaded", r.status_code == 200 and len(r.content) > 2000, str(len(r.content)))
zpkg = zipfile.ZipFile(io.BytesIO(r.content))
names = zpkg.namelist()
check("package has guard runtime", "guard/guard.php" in names and "guard/manifest.sig" in names)
check("package has components", any(n.startswith("components/") and n.endswith(".enc") for n in names))
blob = zpkg.read(".env").decode() if ".env" in names else ""
check(".env placeholder only", "sfg_env" in blob and "Tr0ub4dor" not in blob, blob[:80])
alltext = ""
for n in names:
    if n.endswith((".json", ".php", ".sig", ".tpl", ".md")):
        alltext += zpkg.read(n).decode(errors="ignore")
check("config has public key only", "BEGIN PUBLIC KEY" in alltext and "PRIVATE KEY" not in alltext)
check("no raw secrets in package", "Tr0ub4dor" not in alltext and "sk_live_51Hx8yK" not in alltext)
idx_stub = zpkg.read("index.php").decode()
check("protected php is a stub", "sfg_include(" in idx_stub and "Bistro" not in idx_stub, idx_stub[:100])

# 9. public API checks
def verify(domain, key=LIC_KEY, ts_off=0):
    return client.post("/api/v1/public/licenses/verify", json={
        "license": key, "domain": domain, "project": pid, "build": bid, "version": "1.0",
        "ts": int(time.time()) + ts_off, "nonce": uuid.uuid4().hex,
    })

r = verify("example.com")
check("verify ok on authorized domain", r.status_code == 200 and r.json().get("ok") is True, str(r.json())[:200])
TOKEN = r.json().get("token", "")

r = verify("evil.com")
check("verify rejects unauthorized domain", r.status_code == 403 and r.json()["error"]["code"] == "DOMAIN_NOT_AUTHORIZED",
      str(r.json())[:150])

r = verify("example.com", key="SFG-ZZZZ-ZZZZ-ZZZZ-ZZZZ")
check("verify rejects unknown key", r.status_code == 404 and r.json()["error"]["code"] == "LICENSE_INVALID",
      str(r.json())[:150])

r = verify("example.com", ts_off=-9000)
check("replay rejected (stale ts)", r.status_code == 403 and r.json()["error"]["code"] == "REPLAY_REJECTED",
      str(r.json())[:150])

# token re-verified with the public key (simulate runtime)
from cryptography.hazmat.primitives import serialization
cfg = json.loads(zpkg.read("guard/config.json").decode())
pub = serialization.load_pem_public_key(cfg["public_key_pem"].encode())
h64, p64, s64 = TOKEN.split(".")
pad = lambda s: s + "=" * (-len(s) % 4)
try:
    pub.verify(__import__("base64").urlsafe_b64decode(pad(s64)), f"{h64}.{p64}".encode())
    sig_ok = True
except Exception:
    sig_ok = False
check("token verifies with package public key", sig_ok)

# 10. events + audit + verification logs recorded
st, d = sreq("GET", "/api/v1/events?limit=50")
types = [e["type"] for e in d["events"]]
check("security events recorded", ("unauthorized_domain" in types) or ("invalid_license" in types), str(types)[:120])
st, d = sreq("GET", "/api/v1/verifications?limit=50")
check("verification logs recorded", len(d["verifications"]) >= 3, str(len(d["verifications"])))
check("failed verifications logged", "failed" in {v["result"] for v in d["verifications"]})
st, d = sreq("GET", "/api/v1/audit?limit=100")
acts = {a["action"] for a in d["audit"]}
check("audit logged admin actions", {"login", "project_created", "build_started", "license_created"} <= acts,
      str(acts)[:150])

# 11. license suspend -> verify fails
sreq("POST", f"/api/v1/licenses/{LID}/suspend", {})
r = verify("example.com")
check("suspended license rejected", r.status_code == 403 and r.json()["error"]["code"] == "LICENSE_SUSPENDED",
      str(r.json())[:150])
sreq("POST", f"/api/v1/licenses/{LID}/resume", {})
r = verify("example.com")
check("resumed license works again", r.status_code == 200 and r.json().get("ok"))

# 11b. expired license rejected (set expires_at in the past via the test DB)
import sqlite3 as _sq
_c = _sq.connect("data/sfg.db")
_c.execute("UPDATE licenses SET expires_at='2000-01-01T00:00:00Z' WHERE id=?", (LID,))
_c.commit(); _c.close()
r = verify("example.com")
check("expired license rejected", r.status_code == 403 and r.json()["error"]["code"] == "LICENSE_EXPIRED",
      str(r.json())[:150])
_c = _sq.connect("data/sfg.db")
_c.execute("UPDATE licenses SET expires_at=?, status='active' WHERE id=?",
           (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 365 * 86400)), LID))
_c.commit(); _c.close()
r = verify("example.com")
check("license usable after expiry restored", r.status_code == 200 and r.json().get("ok"), str(r.json())[:150])

# 12. domain management: add + block
st, d = sreq("POST", f"/api/v1/licenses/{LID}/domains", {"domain": "staging.example.com"})
check("domain added", st == 200 and d.get("dns_hint"), str(d)[:150])
st, d = sreq("POST", f"/api/v1/licenses/{LID}/domains/staging.example.com/block", {})
check("domain blocked", st == 200 and d["status"] == "blocked")
r = client.post("/api/v1/public/domains/verify", json={"license": LIC_KEY, "domain": "staging.example.com"})
check("blocked domain rejected", r.status_code == 403, str(r.json())[:120])

# 12b. version management: auto-created version row, revoke -> VERSION_NOT_ALLOWED, restore
st, d = sreq("GET", f"/api/v1/projects/{pid}/versions")
vers = d.get("versions", [])
v1 = next((v for v in vers if v["version"] == "1.0"), None)
check("build version auto-registered", v1 is not None and v1["builds"] >= 1, str(vers)[:150])
r = client.post("/api/v1/public/versions/verify",
                json={"license": LIC_KEY, "version": "1.0"})
check("version 1.0 verifies pre-revocation", r.status_code == 200 and r.json().get("ok") is True, str(r.json())[:120])
st, d = sreq("POST", f"/api/v1/projects/versions/{v1['id']}/revoke", {})
check("version revoked", st == 200 and d.get("revoked") is True, str(d))
r = verify("example.com")
check("revoked version rejected", r.status_code == 403 and r.json()["error"]["code"] == "VERSION_NOT_ALLOWED",
      str(r.json())[:150])
st, d = sreq("POST", f"/api/v1/projects/versions/{v1['id']}/revoke", {})
check("version restored", st == 200 and d.get("revoked") is False, str(d))
r = verify("example.com")
check("restored version verifies again", r.status_code == 200 and r.json().get("ok") is True)

# 12c. failed build: no protected components -> real failure reason, no package
st, d = sreq("POST", "/api/v1/projects", {"name": "E2E Fail Build"})
fpid = d["project"]["id"]
import zipfile as _zf
_buf = io.BytesIO()
with _zf.ZipFile(_buf, "w") as _z:
    _z.writestr("style.css", "body{color:red}")
    _z.writestr("index.html", "<html><body>hi</body></html>")
st, d = req("POST", f"/api/v1/projects/{fpid}/upload/zip",
            files={"file": ("plain.zip", _buf.getvalue(), "application/zip")})
check("plain project uploaded", st == 200, str(d)[:120])
st, d = sreq("POST", f"/api/v1/projects/{fpid}/builds", {"version": "1.0"})
fbd = d["build_id"]
fstatus, fd = None, {}
fdeadline = time.time() + 120
while time.time() < fdeadline:
    st, fd = sreq("GET", f"/api/v1/builds/{fbd}")
    fstatus = fd["build"]["status"]
    if fstatus in ("completed", "failed"):
        break
    time.sleep(1)
check("build with nothing protectable fails", fstatus == "failed" and bool(fd["build"].get("error")),
      str(fd["build"].get("error"))[:120])
r = client.get(f"/api/v1/builds/{fbd}/download")
check("failed build has no downloadable package", r.status_code in (400, 403, 404, 409), str(r.status_code))

# 13. system health + settings + backup
st, d = sreq("GET", "/api/v1/health")
check("health: db ok", d["system"]["database"]["status"] == "ok")
check("health: license api ok", d["system"]["license_api"]["status"] == "ok")
st, d = sreq("GET", "/api/v1/settings")
check("settings exposed (no raw ai key)", "ai_key_wrapped" not in json.dumps(d), "")
st, d = sreq("GET", "/api/v1/backup/export")
check("backup export signed", st == 200 and d.get("signature"), str(d.get("kind")))
bundle = json.loads(json.dumps(d))
tampered = json.loads(json.dumps(bundle))
# guaranteed-meaningful tamper (customer_name, not the license status which
# may already equal the target value)
if tampered["data"]["licenses"]:
    tampered["data"]["licenses"][0]["customer_name"] = "TAMPERED BY ATTACKER"
st, d = sreq("POST", "/api/v1/backup/restore", tampered)
check("tampered backup rejected", st == 400 and d["detail"]["code"] == "RESTORE_REJECTED", str(d)[:150])
st, d = sreq("POST", "/api/v1/backup/restore", bundle)
check("valid backup restores", st == 200 and d.get("ok"), str(d)[:150])

# 14. user isolation
st, d = sreq("POST", "/api/v1/users", {"email": "dev@example.com", "name": "Dev", "role": "developer"})
check("create user", st == 200 and d.get("password"), str(d)[:120])
devpass = d["password"]

dc = httpx.Client(base_url=BASE, timeout=60)
r = dc.post("/api/v1/auth/login", json={"email": "dev@example.com", "password": devpass})
check("dev login", r.status_code == 200)
devcsrf = r.json()["csrf"]
r = dc.get("/api/v1/events")
check("dev cannot read events", r.status_code == 403, str(r.status_code))
r = dc.get("/api/v1/projects?q=")
check("dev sees only own projects", all(p["owner_id"] != 1 for p in r.json()["projects"]))
r = dc.post("/api/v1/projects", json={"name": "Dev Project"}, headers={"X-CSRF-Token": devcsrf})
check("dev creates own project", r.status_code == 200)
r = dc.get(f"/api/v1/projects/{pid}/files")
check("dev cannot read other user's project", r.status_code == 403, str(r.status_code))
r = dc.post("/api/v1/licenses", json={"project_id": pid, "domains": ["x.com"]},
            headers={"X-CSRF-Token": devcsrf})
check("dev cannot license other user's project", r.status_code == 403, str(r.status_code))

# 15. CSRF enforcement
r = client.post("/api/v1/projects", json={"name": "nope"})
check("CSRF enforced (missing token rejected)", r.status_code == 403, str(r.status_code))

print("\nALL API E2E CHECKS PASSED")
print(f"PROJECT={pid} LICENSE={LID} BUILD={bid} KEY={LIC_KEY}")
pathlib.Path("tests/last_run.json").write_text(json.dumps({"pid": pid, "lid": LID, "bid": bid, "key": LIC_KEY}))

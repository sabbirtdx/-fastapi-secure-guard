"""E2E deployment test: extract the protected package, serve it with a real
PHP server, and verify activation, domain binding, integrity and revocation."""
import http.client
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

BASE = "http://127.0.0.1:8000"
DEPLOY = pathlib.Path("/tmp/sfg-deploy")
PORT = 8080

last = json.loads(pathlib.Path("tests/last_run.json").read_text())
PID, LID, BID, KEY = last["pid"], last["lid"], last["bid"], last["key"]

# Prefer environment credentials; fall back to the one-time credentials file.
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

def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra else ""))
    if not cond:
        sys.exit(1)

# ---------- admin session (for license control during the test) ----------
import urllib.parse

r = urllib.request.urlopen(urllib.request.Request(BASE + "/api/v1/auth/login",
    data=json.dumps({"email": email, "password": password}).encode(),
    headers={"Content-Type": "application/json"}, method="POST"))
cj = r.headers.get_all("Set-Cookie") or []
ADMIN_COOKIE = [c.split("sfg_session=")[1].split(";")[0] for c in cj if c.startswith("sfg_session=")][0]
ADMIN_CSRF = json.load(r)["csrf"]
ADMIN_COOKIE_HDR = {"Content-Type": "application/json", "Cookie": f"sfg_session={ADMIN_COOKIE}", "X-CSRF-Token": ADMIN_CSRF}

def admin_post(path, body=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body or {}).encode(),
                                 method="POST", headers=ADMIN_COOKIE_HDR)
    try:
        return urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e:
        return e.code

# ---------- download + extract the protected package ----------
r = urllib.request.urlopen(urllib.request.Request(BASE + f"/api/v1/builds/{BID}/download",
                                                  headers={"Cookie": f"sfg_session={ADMIN_COOKIE}"}))
pkg = r.read()
if DEPLOY.exists():
    shutil.rmtree(DEPLOY)
DEPLOY.mkdir(parents=True)
with zipfile.ZipFile(io.BytesIO(pkg)) as z:
    z.extractall(DEPLOY)

# sanity: no plaintext of the protected php in the package
config_php = (DEPLOY / "config" / "database.php").read_text()
check("deployed config is a stub", "sfg_include(" in config_php and "Tr0ub4dor" not in config_php)
env_file = (DEPLOY / ".env").read_text()
check("deployed .env is placeholder", "Tr0ub4dor" not in env_file)

# ---------- start a real PHP server for the deployment ----------
proc = subprocess.Popen(["php", "-S", f"127.0.0.1:{PORT}", "-t", str(DEPLOY)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)

def deploy_req(method, path, host="example.com", data=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    hdrs = {"Host": host, "User-Agent": "sfg-e2e"}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=body, headers=hdrs)
    resp = c.getresponse()
    out = resp.read().decode(errors="replace")
    status = resp.status
    c.close()
    return status, out, dict(resp.getheaders())

try:
    # 1. unactivated: root redirects to /guard/activate
    st, out, hdrs = deploy_req("GET", "/", host="example.com")
    check("unactivated redirects to activation", st == 302 and "/guard/activate.php" in hdrs.get("Location", ""),
          f"status={st} loc={hdrs.get('Location')}")

    # 2. activation page renders
    st, out, hdrs = deploy_req("GET", "/guard/activate.php", host="example.com")
    check("activation page renders", st == 200 and "License activation required" in out and "example.com" in out,
          f"status={st}")

    # 3. wrong key rejected
    st, out, hdrs = deploy_req("POST", "/guard/activate.php", host="example.com",
                               data={"license_key": "SFG-AAAA-BBBB-CCCC-DDDD"})
    check("wrong key rejected", st == 200 and "LICENSE_INVALID" in out, f"status={st}")

    # 4. wrong domain rejected even with correct key
    st, out, hdrs = deploy_req("POST", "/guard/activate.php", host="evil.com", data={"license_key": KEY})
    check("wrong domain rejected on activation", st == 200 and "DOMAIN_NOT_AUTHORIZED" in out, f"status={st}")

    # 5. correct key + correct domain activates (200 continue page, not Location: /)
    st, out, hdrs = deploy_req("POST", "/guard/activate.php", host="example.com", data={"license_key": KEY})
    check("activation succeeds", st == 200 and "License activated" in out, f"status={st}")
    check("license key persisted (600)", (DEPLOY / "guard" / "license.key").exists() and
          oct(os.stat(DEPLOY / "guard" / "license.key").st_mode & 0o777) == "0o600")

    # 6. the real application now runs (protected php streamed through the gateway)
    st, out, hdrs = deploy_req("GET", "/", host="example.com")
    check("protected app serves real content", st == 200 and "Bistro 42" in out and "menu" in out.lower(),
          f"status={st} len={len(out)}")
    # the streamed php actually executed: menu comes from DB-less stub logic (no DB here -> check page structure)
    # index.php queries $db which is a stub include... DB connect will fail on this host.
    # Instead verify a fully static-but-protected path: config constants via sfg_env
    # (the .env values are real: DB_USER etc.)

    # 7. unauthorized domain fails closed even after activation
    st, out, hdrs = deploy_req("GET", "/", host="evil.com")
    check("unauthorized domain blocked at runtime", st == 503 and "DOMAIN_NOT_AUTHORIZED" in out, f"status={st}")

    # 8. www variant of an allowed base is normalized and accepted (spec: optional www)
    st, out, hdrs = deploy_req("GET", "/", host="www.example.com")
    check("www variant normalized and accepted", st == 200, f"status={st}")

    # 9. tamper a component blob the app actually loads -> INTEGRITY_FAILED
    blob = DEPLOY / "components" / "index.php.enc"
    bdata = bytearray(blob.read_bytes())
    bdata[20] ^= 0xFF
    blob.write_bytes(bytes(bdata))
    st, out, hdrs = deploy_req("GET", "/", host="example.com")
    check("tampered component detected", st == 503 and "INTEGRITY_FAILED" in out, f"status={st}")
    # restore the blob
    with zipfile.ZipFile(io.BytesIO(pkg)) as z:
        z.extract(str(blob.relative_to(DEPLOY)), path=DEPLOY)

    # 10. tamper the runtime bootstrap -> INTEGRITY_FAILED (self-check)
    g = DEPLOY / "guard" / "guard.php"
    gtext = g.read_text()
    g.write_text(gtext.replace("SFG::start();", "SFG::start(); // x", 1))
    st, out, hdrs = deploy_req("GET", "/", host="example.com")
    check("tampered runtime detected", st == 503 and "INTEGRITY_FAILED" in out, f"status={st}")
    g.write_text(gtext)

    # 11. tamper the manifest signature -> SIGNATURE_INVALID
    sig = DEPLOY / "guard" / "manifest.sig"
    sdata = bytearray(sig.read_text().encode())
    sdata[-2] ^= 0x41
    sig.write_bytes(bytes(sdata))
    st, out, hdrs = deploy_req("GET", "/", host="example.com")
    check("tampered signature detected", st == 503 and ("SIGNATURE_INVALID" in out or "INTEGRITY" in out), f"status={st}")
    with zipfile.ZipFile(io.BytesIO(pkg)) as z:
        z.extract("guard/manifest.sig", path=DEPLOY)

    # 11b. missing protected component -> INTEGRITY_FAILED (fail-closed)
    comp = DEPLOY / "components" / "index.php.enc"
    comp_data = comp.read_bytes()
    comp.unlink()
    st, out, hdrs = deploy_req("GET", "/", host="example.com")
    check("missing component detected", st == 503 and "INTEGRITY_FAILED" in out, f"status={st}")
    comp.write_bytes(comp_data)

    # 12. revoke the license -> verification fails on next refresh (ttl=5s)
    st_code = admin_post(f"/api/v1/licenses/{LID}/revoke")
    check("license revoked via admin api", st_code == 200)
    time.sleep(7)  # outlive the 5s cache TTL
    st, out, hdrs = deploy_req("GET", "/", host="example.com")
    check("revoked license blocks execution", st == 503 and "LICENSE_REVOKED" in out, f"status={st}")

    # 13. security events reached the platform
    ev = json.load(urllib.request.urlopen(urllib.request.Request(BASE + "/api/v1/events?limit=100",
                                                                headers={"Cookie": f"sfg_session={ADMIN_COOKIE}"})))
    _evs = ev.get("events") if isinstance(ev, dict) else None
    types = {e.get("type") for e in (_evs if isinstance(_evs, list) else []) if isinstance(e, dict)}
    check("runtime tamper events reported", "integrity_failure" in types or "authorization_failed" in types,
          str(sorted(t for t in types if t))[:150])

    # 14. reissue a fresh license and re-activate the deployment (revocation is terminal)
    r = urllib.request.urlopen(urllib.request.Request(
        BASE + "/api/v1/licenses",
        data=json.dumps({"project_id": PID, "customer_name": "Test Deploy Co",
                         "customer_email": "ops@testdeploy.dev", "domains": ["example.com"],
                         "expiry_days": 365}).encode(),
        method="POST", headers=ADMIN_COOKIE_HDR))
    new_lic = json.load(r)
    new_key = new_lic["license"]["key"]
    new_lid = new_lic["license"]["id"]
    # approve the domain on the reissued license (admin approves after DNS proof)
    req = urllib.request.Request(BASE + f"/api/v1/licenses/{new_lid}/domains/example.com/verify",
                                 data=json.dumps({"method": "manual"}).encode(),
                                 method="POST", headers=ADMIN_COOKIE_HDR)
    resp = urllib.request.urlopen(req)
    check("reissued domain approved", resp.status == 200, "")
    st, out, hdrs = deploy_req("POST", "/guard/activate.php", host="example.com", data={"license_key": new_key})
    check("reissued license activates", st == 302 and hdrs.get("Location") == "/", f"status={st}")
    st, out, hdrs = deploy_req("GET", "/", host="example.com")
    check("app works again after reissuance", st == 200 and "Bistro 42" in out, f"status={st}")

finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

print("\nALL DEPLOYMENT E2E CHECKS PASSED")

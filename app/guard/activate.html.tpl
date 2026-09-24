<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure File Guard — Activation</title>
<style>
 :root { color-scheme: dark; }
 * { box-sizing: border-box; }
 body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
   background: radial-gradient(1200px 600px at 70% -10%, #16233d 0%, #0b0f17 55%);
   font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
   color:#e6edf7; padding:24px; }
 .card { width:100%; max-width:460px; background:#101827; border:1px solid rgba(255,255,255,.08);
   border-radius:14px; padding:34px 32px; box-shadow:0 24px 80px rgba(0,0,0,.5); }
 .badge { display:inline-flex; align-items:center; gap:8px; font-size:12px; letter-spacing:.08em;
   text-transform:uppercase; color:#7dd3fc; background:rgba(56,189,248,.08);
   border:1px solid rgba(56,189,248,.25); padding:5px 10px; border-radius:999px; }
 h1 { font-size:20px; margin:18px 0 6px; font-weight:650; }
 p.sub { color:#93a1b8; font-size:13.5px; line-height:1.55; margin:0 0 22px; }
 label { display:block; font-size:12.5px; color:#93a1b8; margin:0 0 6px; letter-spacing:.02em; }
 input[type=text] { width:100%; background:#0b1220; color:#e6edf7; border:1px solid rgba(255,255,255,.12);
   border-radius:9px; padding:11px 13px; font-size:14px; font-family:ui-monospace,Menlo,monospace;
   letter-spacing:.04em; }
 input[type=text]:focus { outline:none; border-color:#38bdf8; box-shadow:0 0 0 3px rgba(56,189,248,.15); }
 button { margin-top:16px; width:100%; border:0; border-radius:9px; padding:12px; font-size:14.5px;
   font-weight:600; color:#04121d; background:linear-gradient(135deg,#38bdf8,#818cf8); cursor:pointer; }
 button:hover { filter:brightness(1.08); }
 .err { margin-top:14px; font-size:13px; color:#fca5a5; background:rgba(248,113,113,.08);
   border:1px solid rgba(248,113,113,.3); border-radius:9px; padding:10px 12px; }
 .hint { margin-top:10px; font-size:12px; color:#64748b; }
 .meta { margin-top:22px; padding-top:16px; border-top:1px solid rgba(255,255,255,.07);
   font-size:11.5px; color:#64748b; font-family:ui-monospace,Menlo,monospace; line-height:1.7; word-break:break-all; }
</style></head>
<body>
 <div class="card">
  <span class="badge">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#7dd3fc" stroke-width="2">
      <path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/>
    </svg>
    Secure File Guard
  </span>
  <h1>License activation required</h1>
  <p class="sub">Enter the license / API key issued for this build to authorize the application on
  <strong>__DOMAIN__</strong>. Verification is performed by the licensing server, which checks the
  license, this domain, the signature and build integrity.</p>
  <form method="post" action="/guard/activate">
    <label for="lk">License / API key</label>
    <input type="text" id="lk" name="license_key" required autocomplete="off" spellcheck="false"
      placeholder="SFG-XXXX-XXXX-XXXX-XXXX">
    __ERROR__
    <button type="submit">Activate</button>
  </form>
  <div class="hint">A valid key is shown only once, at license creation, in the Secure File Guard admin panel.</div>
  <div class="meta">
    project: __PROJECT__<br>
    build: __BUILD__ · version: __VERSION__<br>
    detected domain: __DOMAIN__
  </div>
 </div>
</body></html>

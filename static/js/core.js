/* Secure File Guard — SPA core: API client, router, UI toolkit */
"use strict";

const SFG = {
  user: null,
  csrf: "",
  route: null,
  pages: {},
  toastQueue: [],
};

/* ---------------- helpers ---------------- */
const qs = (sel, root = document) => root.querySelector(sel);
const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));
const fmtDate = (s) => {
  if (!s) return "—";
  const d = new Date(s.includes("T") ? s : s.replace(" ", "T") + "Z");
  if (isNaN(d)) return s;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};
const fmtBytes = (n) => {
  if (n == null) return "—";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
};
const fmtAgo = (s) => {
  if (!s) return "—";
  const t = new Date(s.includes("T") ? s : s.replace(" ", "T") + "Z").getTime();
  const diff = Math.max(0, Date.now() - t) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return Math.floor(diff / 60) + " min ago";
  if (diff < 86400) return Math.floor(diff / 3600) + " h ago";
  return Math.floor(diff / 86400) + " d ago";
};

/* ---------------- icons ---------------- */
const I = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/><path d="M9 12l2 2 4-4"/></svg>',
  grid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
  folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/></svg>',
  upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4m0 0l-4 4m4-4l4 4"/><path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3"/></svg>',
  box: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M21 8l-9-5-9 5v8l9 5 9-5V8z"/><path d="M3 8l9 5 9-5M12 13v8"/></svg>',
  key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="8" cy="14" r="4"/><path d="M11 11l8-8m-3 3l3 3m-6 0l2 2"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.9 5.7 3.9 9S14.5 18.4 12 21c-2.5-2.6-3.9-5.7-3.9-9S9.5 5.6 12 3z"/></svg>',
  users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.8-3.2 3.4-5 6.5-5s5.7 1.8 6.5 5"/><circle cx="17.5" cy="9" r="2.6"/><path d="M16 15.2c2.6.3 4.6 1.9 5.3 4.8"/></svg>',
  brain: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 4a3 3 0 00-3 3v10a3 3 0 006 0V7a3 3 0 00-3-3z"/><path d="M9 8H7a3 3 0 000 6h2M15 8h2a3 3 0 010 6h-2M9 12H6M15 12h3"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 3l10 17H2L12 3z"/><path d="M12 10v4m0 3.5v.5"/></svg>',
  list: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M8 6h13M8 12h13M8 18h13M3.5 6h.5M3.5 12h.5M3.5 18h.5"/></svg>',
  tag: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M3 12V4a1 1 0 011-1h8l9 9-9 9-9-9z"/><circle cx="8" cy="8" r="1.5"/></svg>',
  gear: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3.2"/><path d="M12 2.8l1.2 2.6 2.8-.6 1 2.7 2.8.7-.6 2.8 2 2-2 2 .6 2.8-2.8.7-1 2.7-2.8-.6L12 21.2l-1.2-2.6-2.8.6-1-2.7-2.8-.7.6-2.8-2-2 2-2-.6-2.8 2.8-.7 1-2.7 2.8.6L12 2.8z"/></svg>',
  api: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M8 9l-4 3 4 3m8-6l4 3-4 3M13 5l-2 14"/></svg>',
  pulse: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2.5-7 5 14L17 12h4"/></svg>',
  db: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
  logout: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>',
  download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 4v12m0 0l-4-4m4 4l4-4M4 20h16"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M20 11a8 8 0 10.9 4M20 4v7h-7"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="2.8"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M4 12.5l5 5L20 6.5"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/></svg>',
  search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.8-3.8"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z"/><path d="M14 3v5h5"/></svg>',
  play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M7 4l13 8-13 8V4z"/></svg>',
};

/* ---------------- API client ---------------- */
async function api(method, path, body, opts = {}) {
  const headers = { };
  const isForm = body instanceof FormData;
  if (!isForm) headers["Content-Type"] = "application/json";
  if (SFG.csrf && !["GET", "HEAD"].includes(method)) headers["X-CSRF-Token"] = SFG.csrf;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: isForm ? body : body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    data = await res.json().catch(() => null);
  } else if (!opts.raw) {
    data = { _nonjson: true };
  }
  if (!res.ok) {
    const detail = data && data.detail ? data.detail : (data && data.error ? data.error : {});
    const err = new Error(detail.message || `Request failed (${res.status})`);
    err.code = detail.code || ("HTTP_" + res.status);
    err.status = res.status;
    throw err;
  }
  return data;
}

/* ---------------- toasts / modals ---------------- */
function toast(msg, kind = "info", ms = 4200) {
  let wrap = qs(".toasts");
  if (!wrap) { wrap = document.createElement("div"); wrap.className = "toasts"; document.body.appendChild(wrap); }
  const t = document.createElement("div");
  t.className = "toast " + kind;
  t.textContent = msg;
  wrap.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .3s"; setTimeout(() => t.remove(), 320); }, ms);
}

function modal({ title, sub, body, actions, wide = false, onClose }) {
  closeModals();
  const bd = document.createElement("div");
  bd.className = "modal-backdrop";
  bd.innerHTML = `<div class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true">
    <h3>${esc(title)}</h3>${sub ? `<p class="sub">${esc(sub)}</p>` : ""}
    <div class="mbody">${body}</div>
    <div class="actions"></div></div>`;
  document.body.appendChild(bd);
  const actionsEl = qs(".actions", bd);
  (actions || []).forEach((a) => {
    const b = document.createElement("button");
    b.className = "btn " + (a.kind || "");
    b.innerHTML = a.label;
    b.onclick = () => a.onClick(bd);
    actionsEl.appendChild(b);
  });
  bd.addEventListener("mousedown", (e) => { if (e.target === bd) { closeModals(); onClose && onClose(); } });
  const escH = (e) => { if (e.key === "Escape") { closeModals(); onClose && onClose(); } };
  document.addEventListener("keydown", escH);
  bd._escH = escH;
  return bd;
}

function closeModals() {
  qsa(".modal-backdrop").forEach((m) => {
    const h = m._escH; if (h) document.removeEventListener("keydown", h);
    m.remove();
  });
}

function confirmModal({ title, message, confirmLabel = "Confirm", danger = false, onConfirm }) {
  const bd = modal({
    title,
    body: `<p style="margin:0;color:var(--muted);font-size:13.5px">${esc(message)}</p>`,
    actions: [
      { label: "Cancel", onClick: () => closeModals() },
      {
        label: confirmLabel, kind: danger ? "danger" : "primary",
        onClick: () => { closeModals(); onConfirm(); },
      },
    ],
  });
  return bd;
}

function emptyState(icon, title, desc, actionHtml = "") {
  return `<div class="empty"><div>${I[icon] || I.box}</div>
    <div class="t">${esc(title)}</div>${desc ? `<div class="d">${esc(desc)}</div>` : ""}${actionHtml}</div>`;
}

function badge(cls, label) {
  return `<span class="badge ${cls}">${esc(label || cls)}</span>`;
}

function errBox(err) {
  return `<div class="callout red"><strong>${esc(err.code || "ERROR")}</strong> — ${esc(err.message || "Request failed")}</div>`;
}

/* ---------------- routing ---------------- */
function nav(hash) { location.hash = hash; }

function parseRoute() {
  const h = location.hash.replace(/^#/, "") || "/dashboard";
  const [path, query] = h.split("?");
  const params = new URLSearchParams(query || "");
  const parts = path.split("/").filter(Boolean);
  return { path: "/" + parts.join("/"), parts, params };
}

async function router() {
  const r = parseRoute();
  SFG.route = r;
  const page = SFG.pages[r.path] || (r.parts[0] === "projects" && r.parts[1] ? SFG.pages["/projects/:id"] : null)
    || (r.parts[0] === "builds" && r.parts[1] ? SFG.pages["/builds/:id"] : null);
  const content = qs(".content");
  const titleEl = qs(".topbar h1");
  if (!page) {
    content.innerHTML = emptyState("alert", "Page not found", "The page you requested does not exist.",
      `<button class="btn" onclick="location.hash='#/dashboard'">Back to dashboard</button>`);
    titleEl.textContent = "Not found";
    return;
  }
  try {
    content.innerHTML = `<div class="loading-row"><span class="spinner"></span>Loading…</div>`;
    const out = await page(r);
    if (out && out.title) titleEl.textContent = out.title;
    content.innerHTML = out.html || "";
    if (out.onReady) out.onReady();
  } catch (e) {
    content.innerHTML = `<div class="card">${errBox(e)}</div>`;
  }
}

/* ---------------- shell ---------------- */
const NAV = {
  admin: [
    ["Overview", [["/dashboard", "Dashboard", "grid"], ["/ai", "AI Analysis", "brain"], ["/health", "System Health", "pulse"]]],
    ["Platform", [["/projects", "Projects", "folder"], ["/upload", "Uploads", "upload"], ["/builds", "Builds", "box"], ["/versions", "Versions", "tag"]]],
    ["Licensing", [["/licenses", "Licenses", "key"], ["/domains", "Domains", "globe"]]],
    ["Operations", [["/events", "Security Events", "alert"], ["/verifications", "Verification Logs", "list"], ["/audit", "Audit Log", "list"], ["/backups", "Backups", "db"]]],
    ["Administration", [["/users", "Users", "users"], ["/api", "API", "api"], ["/settings", "Settings", "gear"]]],
  ],
  user: [
    ["Workspace", [["/dashboard", "Dashboard", "grid"], ["/projects", "My Projects", "folder"], ["/upload", "Uploads", "upload"], ["/builds", "Builds", "box"]]],
    ["Licensing", [["/licenses", "My Licenses", "key"], ["/ai", "AI Analysis", "brain"]]],
  ],
};

function renderShell() {
  const isAdmin = ["super_admin", "admin"].includes(SFG.user.role);
  const groups = isAdmin ? NAV.admin : NAV.user;
  const current = (location.hash.replace(/^#/, "") || "/dashboard").split("?")[0];
  const navHtml = groups.map(([label, items]) => `
    <div class="nav-group">${esc(label)}</div>
    ${items.map(([href, name, icon]) => `
      <a href="#${href}" data-nav="${href}" class="${current === href ? "active" : ""}">
        ${I[icon]}<span>${esc(name)}</span></a>`).join("")}`).join("");
  const initials = (SFG.user.name || SFG.user.email).split(/\s+/).map((s) => s[0]).slice(0, 2).join("").toUpperCase();
  const root = document.createElement("div");
  root.className = "app";
  root.innerHTML = `
    <div class="scrim" id="scrim"></div>
    <aside class="sidebar" id="sidebar">
      <div class="brand">
        <div class="logo">${I.shield}</div>
        <div><div class="name">Secure File Guard</div><div class="sub">License · Protect · Verify</div></div>
      </div>
      <nav class="nav">${navHtml}</nav>
      <div class="foot">
        <div class="userchip">
          <div class="avatar">${esc(initials)}</div>
          <div class="who"><div class="n">${esc(SFG.user.name)}</div><div class="r">${esc(SFG.user.role.replace("_", " "))}</div></div>
          <button id="logoutBtn" title="Log out">${I.logout}</button>
        </div>
      </div>
    </aside>
    <div class="main">
      <div class="topbar">
        <button class="hamburger" id="hamburger">☰</button>
        <h1 id="pageTitle">Dashboard</h1>
        <div class="spacer"></div>
        <a class="btn sm ghost" href="/api/docs" target="_blank" rel="noopener">API docs</a>
      </div>
      <div class="content" id="content"></div>
    </div>`;
  document.body.innerHTML = "";
  document.body.appendChild(root);
  qs("#hamburger").onclick = () => { qs("#sidebar").classList.toggle("open"); qs("#scrim").classList.toggle("show"); };
  qs("#scrim").onclick = () => { qs("#sidebar").classList.remove("open"); qs("#scrim").classList.remove("show"); };
  qs("#logoutBtn").onclick = async () => {
    try { await api("POST", "/api/v1/auth/logout"); } catch (e) { }
    SFG.user = null; SFG.csrf = "";
    location.hash = "#/login";
  };
}

/* ---------------- login page ---------------- */
async function loginPage() {
  const body = `
    <div class="login-wrap">
      <div class="login-card card">
        <div class="brand" style="padding:0 0 18px">
          <div class="logo">${I.shield}</div>
          <div><div class="name">Secure File Guard</div><div class="sub">License · Protect · Verify</div></div>
        </div>
        <form id="loginForm">
          <label class="f" for="le">Email</label>
          <input class="input" id="le" name="email" type="email" required autocomplete="username" value="">
          <label class="f" for="lp">Password</label>
          <input class="input" id="lp" name="password" type="password" required autocomplete="current-password">
          <div id="loginErr"></div>
          <button class="btn primary" style="width:100%;margin-top:18px" id="loginBtn" type="submit">Sign in</button>
        </form>
      </div>
    </div>`;
  document.body.innerHTML = body;
  const qsT = (s) => document.querySelector(s);
  qsT("#loginForm").onsubmit = async (e) => {
    e.preventDefault();
    const btn = qsT("#loginBtn");
    btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Signing in…';
    try {
      const data = await api("POST", "/api/v1/auth/login", {
        email: qsT("#le").value, password: qsT("#lp").value,
      });
      SFG.user = data.user; SFG.csrf = data.csrf;
      renderShell();
      location.hash = "#/dashboard";
    } catch (err) {
      qsT("#loginErr").innerHTML = errBox(err);
      btn.disabled = false; btn.textContent = "Sign in";
    }
  };
  return { title: "Sign in" };
}

/* ---------------- boot ---------------- */
async function boot() {
  try {
    const me = await api("GET", "/api/v1/auth/me");
    SFG.user = me.user; SFG.csrf = me.csrf;
  } catch (e) {
    SFG.user = null; SFG.csrf = "";
  }
  window.addEventListener("hashchange", router);
  if (!SFG.user) {
    if (location.hash !== "#/login") location.hash = "#/login";
    else loginPage();
  } else {
    SFG.pages["/login"] = loginPage;
    renderShell();
    router();
  }
}

document.addEventListener("DOMContentLoaded", boot);

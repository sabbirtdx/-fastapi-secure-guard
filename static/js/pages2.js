/* Secure File Guard — project detail (tabbed) */
"use strict";

SFG.pages["/projects/:id"] = async (r) => {
  const pid = r.parts[1];
  const tab = r.params.get("tab") || "overview";
  const proj = await api("GET", `/api/v1/projects/${pid}`);
  const p = proj.project;
  const isAdmin = ["super_admin", "admin"].includes(SFG.user.role);
  const tabs = [
    ["overview", "Overview"], ["files", "Files"], ["scan", "Scan"], ["ai", "AI Analysis"],
    ["protection", "Protection"], ["versions", "Versions"], ["builds", "Builds"],
    ["licenses", "Licenses"], ["domains", "Domains"], ["events", "Events"],
  ];
  const tabLink = (id, label) =>
    `<button class="${tab === id ? "active" : ""}" data-tab="${id}">${label}</button>`;

  const loaders = {
    overview: () => tabOverview(p, isAdmin),
    files: () => tabFiles(p),
    scan: () => tabScan(p),
    ai: () => tabAI(p),
    protection: () => tabProtection(p, isAdmin),
    versions: () => tabVersions(p, isAdmin),
    builds: () => tabBuilds(p, isAdmin),
    licenses: () => tabLicenses(p, isAdmin),
    domains: () => tabDomains(p, isAdmin),
    events: () => tabEvents(p, isAdmin),
  };
  const body = await loaders[tab]();

  return {
    title: p.name,
    html: `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">
        <a class="btn sm ghost" href="#/projects">← Projects</a>
        <span class="mono" style="color:var(--accent)">${esc(p.id)}</span>
        ${badge(p.status === "active" ? "ok" : "muted", p.status)}
        ${badge("muted", (p.protection_level || "basic") + " protection")}
        <span class="faint small">owner: ${esc(p.owner_email || "—")} · created ${fmtDate(p.created_at)}</span>
        <div style="flex:1"></div>
        ${isAdmin ? `<button class="btn sm" id="archBtn">${p.status === "archived" ? "Restore" : "Archive"}</button>` : ""}
        <a class="btn primary sm" href="#/projects/${esc(p.id)}?tab=builds">${I.play} Build</a>
      </div>
      <div class="tabs">${tabs.map(([id, l]) => tabLink(id, l)).join("")}</div>
      <div id="tabBody">${body}</div>`,
    onReady: () => {
      qsa(".tabs [data-tab]").forEach((b) => (b.onclick = () => nav(`/projects/${pid}?tab=${b.dataset.tab}`)));
      const ab = qs("#archBtn");
      if (ab) ab.onclick = () => {
        const arch = p.status !== "archived";
        confirmModal({
          title: arch ? "Archive project" : "Restore project",
          message: arch ? "Archive this project? The project will be marked archived." : "Restore this project to active?",
          confirmLabel: arch ? "Archive" : "Restore",
          onConfirm: async () => {
            try { await api("POST", `/api/v1/projects/${pid}/archive`); toast("OK", "ok"); router(); }
            catch (e) { toast(e.message, "err"); }
          },
        });
      };
      bindOverview(p, isAdmin);
      bindScan(p);
      bindAI(p);
      bindProtection(p);
      bindVersions(p);
      bindBuilds(p, isAdmin);
      bindLicenses(p, isAdmin);
      bindDomains(p, isAdmin);
      bindEvents(p, isAdmin);
    },
  };
}

/* ---------------- tab bodies (return HTML strings) ---------------- */

function tabOverview(p, isAdmin) {
  const licenseCount = asList(p, "licenses").length;
  return `
    <div class="grid cards-2">
      <div class="card">
        <h3>Project details</h3>
        <div class="detail-grid">
          <div class="item"><div class="k">Project ID</div><div class="v mono">${esc(p.id)}</div></div>
            <div class="item"><div class="k">Name</div><div class="v">${esc(p.name || "")}</div></div>
          <div class="item"><div class="k">Owner</div><div class="v">${esc(p.owner_email || "—")}</div></div>
            <div class="item"><div class="k">Files</div><div class="v">${p.file_count ?? 0}</div></div>
            <div class="item"><div class="k">Total size</div><div class="v">${fmtBytes(p.total_size)}</div></div>
            <div class="item"><div class="k">Protection level</div><div class="v">${esc(p.protection_level || "basic")}</div></div>
          <div class="item"><div class="k">Created</div><div class="v">${fmtDate(p.created_at)}</div></div>
          <div class="item"><div class="k">Updated</div><div class="v">${fmtDate(p.updated_at)}</div></div>
        </div>
        ${isAdmin ? `<form id="metaForm" style="margin-top:18px;display:flex;gap:10px;flex-wrap:wrap">
          <input class="input" id="mName" value="${esc(p.name)}" style="max-width:260px">
          <select class="input" id="mLevel" style="max-width:170px">
            ${["basic", "standard", "advanced"].map((l) => `<option ${p.protection_level === l ? "selected" : ""}>${l}</option>`).join("")}
          </select>
          <button class="btn" type="submit">Save</button>
        </form>` : ""}
      </div>
      <div class="card">
        <h3>Licenses (${licenseCount})</h3>
        ${licenseCount ? `<div class="tbl-wrap" style="border:0"><table class="tbl" style="min-width:0">
          <thead><tr><th>License</th><th>Status</th><th>Expiry</th></tr></thead>
          <tbody>${asList(p, "licenses").map((l) => `<tr>
            <td><span class="mono small">${esc(l.id)}</span>
              <div class="faint small">${esc(l.customer_name || l.customer_email || "")}</div></td>
            <td>${badge({ active: "ok", pending: "warn", suspended: "info", expired: "warn", revoked: "danger" }[l.status] || "muted", l.status)}</td>
            <td class="mono small">${esc(l.expires_at)}</td></tr>`).join("")}</tbody></table></div>`
          : emptyState("key", "No licenses", "Create a license bound to an authorized domain, then build the protected package.",
            `<a class="btn" href="#/projects/${esc(p.id)}?tab=licenses">Create license</a>`)}
      </div>
    </div>`;
}

function tabFiles(p) {
  return `<div id="filesWrap"><div class="loading-row"><span class="spinner"></span>Loading file index…</div></div>`;
}

function tabScan(p) {
  return `<div id="scanWrap"><div class="loading-row"><span class="spinner"></span>Loading scan report…</div></div>`;
}

function tabAI(p) {
  return `<div id="aiWrap"><div class="loading-row"><span class="spinner"></span>Loading analysis…</div></div>`;
}

function tabProtection(p, isAdmin) {
  const rec = (p.recommended_components_cache || []);
  return `<div id="protWrap">
    <div class="card">
      <h3>Protection configuration</h3>
      <p class="muted small" style="margin-top:0">
        Components matching the analysis recommendation (server-side PHP, config, environment files) are protected by default:
        their plaintext leaves the build as <strong>AES-256-GCM ciphertext</strong>, streamed through the signed runtime gateway.
        Public assets (images, fonts, CSS/JS) stay public — browsers can always inspect delivered client-side code.
      </p>
      <div id="protBody"><div class="loading-row"><span class="spinner"></span>Loading recommendation…</div></div>
    </div></div>`;
}

function tabVersions(p, isAdmin) {
  const row = (v) => `<tr>
    <td class="mono">${esc(v.version)}</td>
    <td>${v.revoked ? badge("danger", "revoked") : badge("ok", "active")}</td>
    <td class="num">${v.builds}</td>
    <td class="muted small">${esc(v.note || "—")}</td>
    <td class="muted small">${fmtDate(v.created_at)}</td>
    <td><div class="row-actions">
      <button class="btn sm ${v.revoked ? "" : "danger"}" data-vact="${v.revoked ? "restore" : "revoke"}" data-vid="${v.id}">
        ${v.revoked ? "Restore" : "Revoke"}</button></div></td></tr>`;
  return `
    <div class="card" style="margin-bottom:16px">
      <h3>Create version</h3>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <input class="input" id="vVer" placeholder="e.g. 1.1" style="max-width:130px">
        <input class="input" id="vNote" placeholder="Note (optional)" style="max-width:300px">
        <button class="btn primary" id="vCreate">${I.plus} Create</button>
      </div>
    </div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Version</th><th>Status</th><th>Builds</th><th>Note</th><th>Created</th><th></th></tr></thead>
      <tbody>${(p.versions || []).map(row).join("") || `<tr><td colspan="6">${emptyState("tag", "No versions", "Create a version to attach builds to.")}</td></tr>`}</tbody>
    </table></div>`;
}

function tabBuilds(p, isAdmin) {
  return `<div id="buildsWrap"><div class="loading-row"><span class="spinner"></span>Loading builds…</div></div>`;
}

function tabLicenses(p, isAdmin) {
  return `
    <div class="card" style="margin-bottom:16px">
      <h3>Create license for this project</h3>
      <div class="grid cards-2">
        <div>
          <label class="f">Customer name</label><input class="input" id="lName" placeholder="Acme Ltd.">
          <label class="f">Customer email</label><input class="input" id="lEmail" placeholder="ops@acme.com">
          <label class="f">Authorized domain(s) — one per line</label>
          <textarea class="input mono" id="lDomains" rows="3" placeholder="example.com&#10;www.example.com"></textarea>
        </div>
        <div>
          <label class="f">Validity (days)</label><input class="input" id="lDays" type="number" value="365" min="1" max="3650" style="max-width:130px">
          <label class="f" style="margin-top:14px">Version restriction (optional)</label>
          <input class="input mono" id="lVer" placeholder="e.g. 1.0" style="max-width:130px">
          <label class="check" style="margin-top:14px"><input type="checkbox" id="lSub"> Allow subdomains of listed domains</label>
          <div style="margin-top:20px"><button class="btn primary" id="lCreate">${I.key} Generate license</button></div>
          <div id="lMsg"></div>
        </div>
      </div>
    </div>
    <div id="licWrap"><div class="loading-row"><span class="spinner"></span>Loading licenses…</div></div>`;
}

function tabDomains(p, isAdmin) {
  return `<div id="domWrap"><div class="loading-row"><span class="spinner"></span>Loading domains…</div></div>`;
}

function tabEvents(p, isAdmin) {
  if (!isAdmin) return emptyState("lock", "Admin only", "Project security events are visible to admin accounts.");
  return `<div id="evWrap"><div class="loading-row"><span class="spinner"></span>Loading events…</div></div>`;
}

/* ---------------- tab data + bindings ---------------- */

async function bindOverview(p, isAdmin) {
  const f = qs("#metaForm");
  if (!f) return;
  f.onsubmit = async (e) => {
    e.preventDefault();
    try {
      await api("PATCH", `/api/v1/projects/${p.id}`, {
        name: qs("#mName")?.value || p.name, protection_level: qs("#mLevel")?.value || p.protection_level,
      });
      toast("Project updated", "ok"); router();
    } catch (err) { toast(err.message, "err"); }
  };
}

async function bindScan(p) {
  const wrap = qs("#scanWrap");
  if (!wrap) return;
  try {
    const d = await api("GET", `/api/v1/projects/${p.id}/scan`);
    const s = d.scan || {};
    const kindCards = Object.entries(s.by_kind || {}).map(([k, v]) =>
      `<div class="item"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`).join("");
    const sensFiles = asList(s, "sensitive_files");
    const sensFindings = asList(s, "secret_findings");
    wrap.innerHTML = `
      <div class="card" style="margin-bottom:16px">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <h3 style="margin:0">Scan report</h3>
          <span class="muted small">scanned ${fmtDate(s.scanned_at)} · ${s.file_count ?? 0} files · ${fmtBytes(s.total_size)}</span>
          <div style="flex:1"></div>
          <button class="btn sm" id="rescan">${I.refresh} Rescan</button>
        </div>
        <div class="detail-grid" style="margin-top:16px">${kindCards}
          <div class="item"><div class="k">Sensitive files</div><div class="v" style="color:var(--warn)">${s.sensitive_file_count}</div></div>
          <div class="item"><div class="k">Credential-looking values</div><div class="v" style="color:var(--danger)">${s.secret_finding_count}</div></div>
        </div>
        <div class="callout blue">Secret values are <strong>masked</strong> in all reports. Full values are never stored, logged or transmitted.</div>
      </div>
      <div class="grid cards-2">
        <div class="card"><h3>Potential sensitive files</h3>
          ${sensFiles.length ? `<div class="tbl-wrap" style="border:0"><table class="tbl" style="min-width:0">
            <thead><tr><th>File</th><th>Why</th><th>Secrets</th></tr></thead>
            <tbody>${sensFiles.map((f) => `<tr>
              <td class="mono small">${esc(f.file)}</td>
              <td class="muted small">${esc((f.reasons || []).join(", ") || "—")}</td>
              <td class="num">${f.secret_count || 0}</td></tr>`).join("")}</tbody></table></div>`
            : emptyState("check", "No sensitive files detected", "")}
        </div>
        <div class="card"><h3>Credential-looking values (masked)</h3>
          ${sensFindings.length ? `<div class="tbl-wrap" style="border:0"><table class="tbl" style="min-width:0">
            <thead><tr><th>File:line</th><th>Type</th><th>Masked value</th></tr></thead>
            <tbody>${sensFindings.slice(0, 100).map((f) => `<tr>
              <td class="mono small">${esc(f.file)}:${f.line}</td>
              <td><span class="sev-${esc(f.severity)}">${esc(f.type)}</span></td>
              <td class="mono small">${esc(f.masked)}</td></tr>`).join("")}</tbody></table></div>`
            : emptyState("check", "No credential-looking values", "")}
        </div>
      </div>`;
    const rs = qs("#rescan", wrap);
    if (rs) rs.onclick = async () => {
      rs.disabled = true;
      try { await api("GET", `/api/v1/projects/${p.id}/scan?rescan=true`); toast("Rescanned", "ok"); router(); }
      catch (e) { toast(e.message, "err"); rs.disabled = false; }
    };
  } catch (e) {
    if (e.code === "NO_SCAN") {
      wrap.innerHTML = emptyState("search", "No scan yet", "Upload files, then this report will appear.",
        `<a class="btn" href="#/upload">Upload files</a>`);
    } else wrap.innerHTML = errBox(e);
  }
}

async function bindAI(p) {
  const wrap = qs("#aiWrap");
  if (!wrap) return;
  try {
    const d = await api("GET", `/api/v1/projects/${p.id}/ai-analysis`);
    const a = d.latest;
    if (!a) {
      wrap.innerHTML = emptyState("brain", "No analysis yet",
        "Run the analysis to get technology detection, sensitive component findings and a protection recommendation.",
        `<button class="btn primary" id="aiRun">${I.play} Run analysis</button>`);
    } else {
      wrap.innerHTML = `
        <div class="card" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <h3 style="margin:0">AI analysis</h3>
            ${badge(a.engine === "llm" ? "info" : "muted", (a.engine || "builtin") + " engine")}
            <span class="muted small">${esc(a.model || "")} · ${fmtDate(a.generated_at)}</span>
            <div style="flex:1"></div>
            <button class="btn sm" id="aiRun">${I.refresh} Re-run (builtin)</button>
            ${d.llm_configured ? `<button class="btn sm" id="aiLLM">${I.brain} Run LLM analysis</button>`
              : `<span class="faint small">LLM not configured <a href="#/settings">→ settings</a></span>`}
          </div>
          <div class="grid cards-2" style="margin-top:16px">
            <div>
              <h3>Project overview</h3>
              <div class="detail-grid">
                <div class="item"><div class="k">Files</div><div class="v">${a.overview?.file_count ?? "—"}</div></div>
                <div class="item"><div class="k">Size</div><div class="v">${fmtBytes(a.overview?.total_size)}</div></div>
                <div class="item" style="grid-column:1/-1"><div class="k">Entry points</div>
                  <div class="v mono small">${(a.overview?.entry_points || []).map(esc).join(", ") || "—"}</div></div>
              </div>
              <h3 style="margin-top:16px">Technologies</h3>
              <pre class="code" style="margin:0">${esc(JSON.stringify(a.technologies || {}, null, 2))}</pre>
            </div>
            <div>
              <h3>Recommended protection level</h3>
              <div style="margin:6px 0 14px">${badge("warn", a.recommendation?.protection_level || "standard")}</div>
              <h3>Risks</h3>
              ${(a.risks || []).length ? (a.risks || []).map((rk) => `<div style="margin-bottom:10px">
                <div>${badge({ high: "danger", medium: "warn", low: "info" }[rk.severity] || "muted", rk.severity)}
                <strong class="small" style="margin-left:6px">${esc(rk.title)}</strong></div>
                <div class="muted small" style="margin-top:2px">${esc(rk.detail || "")}</div></div>`).join("")
                : `<div class="muted small">No heuristic risks flagged.</div>`}
            </div>
          </div>
          <div class="callout">${esc(a.disclaimer || "")}</div>
        </div>
        <div class="grid cards-2">
          <div class="card"><h3>Recommended components for protection (${(a.recommendation?.protected_components || []).length})</h3>
            <pre class="code" style="max-height:300px;overflow:auto;margin:0">${esc((a.recommendation?.protected_components || []).join("\n") || "—")}</pre>
            <div class="faint small" style="margin-top:10px">${esc(a.recommendation?.public_components_note || "")}</div>
          </div>
          <div class="card"><h3>Sensitive component findings</h3>
            ${(a.sensitive_components || []).length ? `<div style="max-height:300px;overflow:auto"><div class="tbl-wrap" style="border:0"><table class="tbl" style="min-width:0">
              <thead><tr><th>File</th><th>Reasons</th></tr></thead>
              <tbody>${a.sensitive_components.slice(0, 60).map((f) => `<tr>
                <td class="mono small">${esc(f.file)}</td><td class="muted small">${esc((f.reasons || []).join(", "))}</td></tr>`).join("")}</tbody></table></div></div>`
              : `<div class="muted small">None flagged.</div>`}
          </div>
        </div>`;
    }
    const run = qs("#aiRun", wrap);
    if (run) run.onclick = async () => {
      run.disabled = true; run.innerHTML = '<span class="spinner"></span> Analyzing…';
      try { await api("POST", `/api/v1/projects/${p.id}/ai-analysis`); toast("Analysis complete", "ok"); router(); }
      catch (e) { toast(e.message, "err"); run.disabled = false; }
    };
    const llm = qs("#aiLLM", wrap);
    if (llm) llm.onclick = async () => {
      llm.disabled = true; llm.innerHTML = '<span class="spinner"></span> Querying model…';
      try { await api("POST", `/api/v1/projects/${p.id}/ai-analysis?engine=llm`); toast("LLM analysis stored", "ok"); router(); }
      catch (e) { toast(e.message, "err"); llm.disabled = false; }
    };
  } catch (e) { wrap.innerHTML = errBox(e); }
}

async function bindProtection(p) {
  const body = qs("#protBody");
  if (!body) return;
  try {
    const d = await api("GET", `/api/v1/projects/${p.id}/protection-config`);
    const rec = d.recommended_components || [];
    body.innerHTML = `
      <div class="grid cards-2">
        <div>
          <label class="f">Recommended components (${rec.length})</label>
          <pre class="code" style="max-height:240px;overflow:auto;margin:0">${esc(rec.slice(0, 150).join("\n") || "—")}</pre>
          <label class="f">Extra files to protect (one per line)</label>
          <textarea class="input mono" id="incList" rows="4" placeholder="includes/auth.php"></textarea>
          <label class="f">Exclude files (one per line)</label>
          <textarea class="input mono" id="excList" rows="4" placeholder="public/keep-public.php"></textarea>
        </div>
        <div>
          <label class="f" style="margin-top:0">Options</label>
          <label class="check" style="margin-bottom:10px"><input type="checkbox" id="obfChk" ${d.saved?.obfuscate ? "checked" : ""}>
            Obfuscate protected PHP (comment stripping, string encoding) — readability reduction, not encryption</label>
          <label class="f">Build version</label>
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <select class="input" id="verSel" style="max-width:150px">
              ${(p.versions || []).map((v) => `<option value="${esc(v.version)}">${esc(v.version)}</option>`).join("") || `<option value="1.0">1.0</option>`}
            </select>
            <input class="input mono" id="newVer" placeholder="or new, e.g. 1.1" style="max-width:150px">
          </div>
          <div style="margin-top:22px"><button class="btn primary" id="startBuild">${I.play} Start protected build</button></div>
          <div id="buildStartMsg" style="margin-top:12px"></div>
        </div>
      </div>`;
    const start = qs("#startBuild", body);
    if (start) start.onclick = async () => {
      const ver = (qs("#newVer", body)?.value?.trim()) || qs("#verSel", body)?.value || "1.0";
      const inc = (qs("#incList", body)?.value || "").split("\n").map((s) => s.trim()).filter(Boolean);
      const exc = (qs("#excList", body)?.value || "").split("\n").map((s) => s.trim()).filter(Boolean);
      const msg = qs("#buildStartMsg", body);
      start.disabled = true;
      try {
        let versionId = null;
        if (!(p.versions || []).some((v) => v.version === ver)) {
          try {
            await api("POST", `/api/v1/projects/${p.id}/versions`, { version: ver, note: "created at build time" });
          } catch (e) { if (e.code !== "DUPLICATE") throw e; }
        }
        const obf = qs("#obfChk", body);
        const d2 = await api("POST", `/api/v1/projects/${p.id}/builds`, { version: ver, include: inc, exclude: exc, obfuscate: !!(obf && obf.checked) });
        if (msg) msg.innerHTML = `<span class="badge ok">Build ${esc(d2.build_id)} started</span>`;
        toast("Build started", "ok");
        setTimeout(() => nav(`/builds/${d2.build_id}`), 500);
      } catch (e) {
        if (msg) msg.innerHTML = errBox(e);
        start.disabled = false;
      }
    };
  } catch (e) { body.innerHTML = errBox(e); }
}

function bindVersions(p) {
  const create = qs("#vCreate");
  if (create) create.onclick = async () => {
    const version = qs("#vVer")?.value?.trim() || "";
    if (!/^\d+\.\d+(\.\d+)?$/.test(version)) return toast("Version must look like 1.0 or 1.0.1", "warn");
    try {
      await api("POST", `/api/v1/projects/${p.id}/versions`, { version, note: qs("#vNote")?.value?.trim() || "" });
      toast("Version created", "ok"); router();
    } catch (e) { toast(e.message, "err"); }
  };
  qsa("[data-vact]").forEach((b) => (b.onclick = () => {
    const revoke = b.dataset.vact === "revoke";
    confirmModal({
      title: revoke ? "Revoke version" : "Restore version",
      message: revoke
        ? "Revoking a version blocks all builds of that version from passing verification. Continue?"
        : "Restore this version so its builds can pass verification again?",
      confirmLabel: revoke ? "Revoke" : "Restore", danger: revoke,
      onConfirm: async () => {
        try { await api("POST", `/api/v1/projects/versions/${b.dataset.vid}/revoke`); toast("OK", "ok"); router(); }
        catch (e) { toast(e.message, "err"); }
      },
    });
  }));
}

async function bindBuilds(p, isAdmin) {
  const wrap = qs("#buildsWrap");
  if (!wrap) return;
  try {
    const d = await api("GET", `/api/v1/projects/${p.id}/builds`);
    const buildRows = asList(d, "builds");
    if (!buildRows.length) {
      wrap.innerHTML = emptyState("box", "No builds yet", "Configure protection and start the first protected build.",
        `<a class="btn primary" href="#/projects/${esc(p.id)}?tab=protection">Configure protection</a>`);
      return;
    }
    const row = (b) => `<tr>
      <td><a class="mono" href="#/builds/${esc(b.id)}" style="color:var(--accent)">${esc(b.id)}</a></td>
      <td class="mono">${esc(b.version)}</td>
      <td>${badge({ completed: "ok", running: "warn", queued: "warn", failed: "danger", disabled: "muted" }[b.status] || "muted", b.status)}</td>
      <td class="muted small">${esc(b.stage || "—")}</td>
      <td>${b.validation_passed == null ? "" : badge(b.validation_passed ? "ok" : "danger", b.validation_passed ? "passed" : "failed")}</td>
      <td class="muted small">${fmtDate(b.completed_at || b.created_at)}</td>
      <td><div class="row-actions">
        ${b.status === "completed" ? `<a class="btn sm" href="/api/v1/builds/${esc(b.id)}/download">${I.download} ZIP</a>` : ""}
        ${b.status === "completed" && isAdmin ? `<button class="btn sm danger" data-bdis="${esc(b.id)}">Disable</button>` : ""}
        ${b.status === "disabled" && isAdmin ? `<button class="btn sm" data-ben="${esc(b.id)}">Enable</button>` : ""}
      </div></td></tr>`;
    wrap.innerHTML = `<div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Build</th><th>Version</th><th>Status</th><th>Stage</th><th>Validation</th><th>Time</th><th></th></tr></thead>
      <tbody>${buildRows.map(row).join("")}</tbody></table></div>`;
    qsa("[data-bdis]", wrap).forEach((b) => (b.onclick = () => confirmModal({
      title: "Disable build", danger: true, confirmLabel: "Disable",
      message: "Disabled builds immediately fail license verification for all deployments using them.",
      onConfirm: async () => {
        try { await api("POST", `/api/v1/builds/${b.dataset.bdis}/disable`); toast("Build disabled", "ok"); router(); }
        catch (e) { toast(e.message, "err"); }
      },
    })));
    qsa("[data-ben]", wrap).forEach((b) => (b.onclick = async () => {
      try { await api("POST", `/api/v1/builds/${b.dataset.ben}/enable`); toast("Build enabled", "ok"); router(); }
      catch (e) { toast(e.message, "err"); }
    }));
  } catch (e) { wrap.innerHTML = errBox(e); }
}

async function bindLicenses(p, isAdmin) {
  const wrap = qs("#licWrap");
  if (!wrap) return;
  const load = async () => {
    const d = await api("GET", `/api/v1/licenses?project_id=${p.id}`);
    const rows = asList(d, "licenses");
    if (!rows.length) {
      wrap.innerHTML = `<div class="tbl-wrap"><div style="padding:20px">${emptyState("key", "No licenses for this project", "")}</div></div>`;
      return;
    }
    const row = (l) => `<tr>
      <td><span class="mono small">${esc(l.id)}</span>
        <div class="faint small">${esc(l.customer_name || l.customer_email || "—")}</div></td>
      <td>${(l.domains || []).map((x) => `<span class="mono small">${esc(x)}</span>`).join(" ") || "—"}</td>
      <td>${badge({ active: "ok", pending: "warn", suspended: "info", expired: "warn", revoked: "danger" }[l.status] || "muted", l.status)}</td>
      <td class="mono small">${esc(l.expires_at)}</td>
      <td class="muted small">${l.last_verified_at ? fmtAgo(l.last_verified_at) : "never"}</td>
    </tr>`;
    wrap.innerHTML = `<div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>License</th><th>Domains</th><th>Status</th><th>Expiry</th><th>Last verified</th></tr></thead>
      <tbody>${rows.map(row).join("")}</tbody></table></div>`;
  };
  load().catch((e) => (wrap.innerHTML = errBox(e)));
  const create = qs("#lCreate");
  if (create) create.onclick = async () => {
    const domains = (qs("#lDomains")?.value || "").split("\n").map((s) => s.trim()).filter(Boolean);
    if (!domains.length) return toast("Enter at least one authorized domain", "warn");
    try {
      const sub = qs("#lSub");
      const d = await api("POST", "/api/v1/licenses", {
        project_id: p.id,
        customer_name: qs("#lName")?.value?.trim() || "",
        customer_email: qs("#lEmail")?.value?.trim() || "",
        domains,
        allow_subdomains: !!(sub && sub.checked),
        expiry_days: parseInt(qs("#lDays")?.value, 10) || 365,
        version_restrict: qs("#lVer")?.value?.trim() || null,
      });
      const key = d.license.key;
      confirmModal({
        title: "License created — copy the key now",
        message: "This key is shown only once. It is stored server-side as a hash.",
        body: `<div class="keyline"><div class="code">${esc(key)}</div>
          <button class="btn" id="copyKey">${I.check} Copy</button></div>
          <div class="callout">Give this key to the deployer. They enter it at /guard/activate on the authorized domain.</div>`,
        actions: [{ label: "Done", kind: "primary", onClick: () => { closeModals(); load(); router(); } }],
      });
      qs("#copyKey") && (qs("#copyKey").onclick = async () => {
        try { await navigator.clipboard.writeText(key); toast("Copied", "ok"); }
        catch (e) { toast("Select the key manually to copy", "warn"); }
      });
      load();
    } catch (e) { toast(e.message, "err"); }
  };
}

async function bindDomains(p, isAdmin) {
  const wrap = qs("#domWrap");
  if (!wrap) return;
  try {
    const d = await api("GET", "/api/v1/domains");
    const rows = asList(d, "domains").filter((x) => x && x.project_id === p.id);
    if (!rows.length) {
      wrap.innerHTML = emptyState("globe", "No domains yet", "Domains are attached to licenses. Create a license in the Licenses tab.",
        `<a class="btn" href="#/projects/${esc(p.id)}?tab=licenses">Go to licenses</a>`);
      return;
    }
    wrap.innerHTML = `<div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Domain</th><th>License</th><th>Status</th><th>Subdomains</th><th>Added</th><th>Last verified</th></tr></thead>
      <tbody>${rows.map((x) => `<tr>
        <td class="mono">${esc(x.domain)}</td>
        <td class="mono small">${esc(x.license_id)}</td>
        <td>${badge({ active: "ok", verified: "ok", pending: "warn", blocked: "danger" }[x.status], x.status)}</td>
        <td>${x.allow_subdomains ? "yes" : "no"}</td>
        <td class="muted small">${fmtDate(x.added_at)}</td>
        <td class="muted small">${x.verified_at ? fmtDate(x.verified_at) : "—"}</td></tr>`).join("")}</tbody></table></div>
      <div class="faint small" style="margin-top:10px">Full domain management (add / verify / block) is on the Domains page.</div>`;
  } catch (e) { wrap.innerHTML = errBox(e); }
}

async function bindEvents(p, isAdmin) {
  const wrap = qs("#evWrap");
  if (!wrap || !isAdmin) return;
  try {
    const d = await api("GET", `/api/v1/events?project_id=${p.id}&limit=200`);
    const eventRows = asList(d, "events");
    if (!eventRows.length) {
      wrap.innerHTML = emptyState("shield", "No security events for this project", "Failures and tamper detections will be recorded here.");
      return;
    }
    wrap.innerHTML = `<div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Severity</th><th>Type</th><th>Detail</th><th>License</th><th>When</th></tr></thead>
      <tbody>${eventRows.map((e) => `<tr>
        <td>${badge({ critical: "danger", warning: "warn", info: "info" }[e.severity] || "muted", e.severity)}</td>
        <td class="mono small">${esc(e.type)}</td>
        <td class="muted small">${esc(e.detail || "")}</td>
        <td class="mono small">${esc(e.license_id || "—")}</td>
        <td class="muted small">${fmtDate(e.created_at)}</td></tr>`).join("")}</tbody></table></div>`;
  } catch (e) { wrap.innerHTML = errBox(e); }
}

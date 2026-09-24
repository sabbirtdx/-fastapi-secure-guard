/* Secure File Guard — pages: builds, licenses, domains, admin */
"use strict";

/* ================= BUILD DETAIL (live progress) ================= */
SFG.pages["/builds/:id"] = async (r) => {
  const bid = r.parts[1];
  const d = await api("GET", `/api/v1/builds/${bid}`);
  const b = d.build;
  const proj = await api("GET", `/api/v1/projects/${b.project_id}`);
  const stageStates = {}; // index -> {status, message}
  const applyEvent = (ev) => {
    const st = stageStates[ev.stage] || {};
    if (ev.status === "start") { st.status = "active"; st.message = ""; }
    else if (ev.status === "complete") { st.status = "done"; st.message = ev.message; }
    else if (ev.status === "failed") { st.status = "failed"; st.message = ev.message; }
    else if (ev.status === "done") { }
    stageStates[ev.stage] = st;
    renderStages();
  };
  const stageList = asList(b, "stages");
  const renderStages = () => {
    const el = qs("#stages");
    if (!el) return;
    el.innerHTML = stageList.map((s) => {
      const st = stageStates[s.index];
      let cls = "", mark = s.index;
      if (st) { cls = st.status; mark = st.status === "done" ? "✓" : st.status === "failed" ? "✕" : s.index; }
      return `<div class="stage ${cls}"><div class="dot">${mark}</div>
        <div><div class="sname">${s.index}. ${esc(s.name)}</div>
        ${st?.message ? `<div class="smsg">${esc(st.message)}</div>` : ""}</div></div>`;
    }).join("");
  };
  const renderReport = () => {
    const el = qs("#report");
    if (!el) return;
    const rep = b.validation_report;
    if (!rep) { el.innerHTML = ""; return; }
    el.innerHTML = `<h3>Validation report</h3>
      <div style="margin-bottom:12px">${badge(rep.passed ? "ok" : "danger", rep.passed ? "All checks passed" : "Validation failed — no package produced")}</div>
      <div class="tbl-wrap" style="border:0"><table class="tbl" style="min-width:0">
      <thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
      <tbody>${rep.checks.map((c) => `<tr>
        <td class="small">${esc(c.name)}</td>
        <td>${badge(c.ok ? "ok" : "danger", c.ok ? "pass" : "fail")}</td>
        <td class="muted small" style="word-break:break-all">${esc(c.detail || "")}</td></tr>`).join("")}</tbody></table></div>`;
  };
  const renderStatus = () => {
    const el = qs("#bstatus");
    if (!el) return;
    el.innerHTML = `
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        ${badge({ completed: "ok", running: "warn", queued: "warn", failed: "danger", disabled: "muted" }[b.status] || "muted", b.status)}
        <span class="muted small">build ${esc(b.id)} · project <a href="#/projects/${esc(b.project_id)}" class="mono">${esc(b.project_id)}</a> · version ${esc(b.version)}</span>
        <div style="flex:1"></div>
        ${b.status === "completed" ? `<a class="btn primary" href="/api/v1/builds/${esc(b.id)}/download">${I.download} Download protected ZIP</a>` : ""}
        ${b.status === "failed" && b.error ? `<span class="faint small mono">${esc(b.error)}</span>` : ""}
      </div>
      <div class="pbar" style="margin-top:12px"><div id="bbar" style="width:${Math.round(((b.stage_index || 0) / 12) * 100)}%"></div></div>`;
  };
  (function init() {
    renderStatus();
    renderStages();
    renderReport();
    if (["running", "queued", "completed", "failed", "disabled"].includes(b.status)) {
      (b.events || []).forEach(applyEvent);
    }
    if (b.status === "running" || b.status === "queued") {
      const es = new EventSource(`/api/v1/builds/${bid}/progress`);
      es.onmessage = (m) => { try { applyEvent(JSON.parse(m.data)); } catch (e) { } };
      es.addEventListener("done", () => { es.close(); refresh(); });
      es.onerror = () => { /* polling fallback keeps UI honest */ };
      const poll = setInterval(async () => {
        try {
          const fresh = await api("GET", `/api/v1/builds/${bid}`);
          if (["completed", "failed", "disabled"].includes(fresh.build.status)) {
            es.close(); clearInterval(poll); refresh();
          } else {
            b.stage_index = fresh.build.stage_index;
            const bar = qs("#bbar");
            if (bar) bar.style.width = Math.round(((b.stage_index || 0) / 12) * 100) + "%";
          }
        } catch (e) { }
      }, 2500);
      document._buildCleanup = () => { es.close(); clearInterval(poll); };
    }
    function refresh() {
      api("GET", `/api/v1/builds/${bid}`).then((d2) => {
        b.status = d2.build.status; b.stage_index = d2.build.stage_index;
        b.validation_report = d2.build.validation_report;
        (d2.build.events || []).forEach(applyEvent);
        renderStatus(); renderReport();
        const bar = qs("#bbar");
        if (bar) bar.style.width = Math.round(((b.stage_index || 0) / 12) * 100) + "%";
      });
    }
  })();
  return {
    title: `Build ${b.id}`,
    html: `
      <a class="btn sm ghost" href="#/builds">← All builds</a>
      <div class="card" style="margin-top:14px" id="bstatus"></div>
      <div class="grid cards-2" style="margin-top:16px">
        <div class="card"><h3>Pipeline</h3><div class="stages" id="stages"></div></div>
        <div class="card" id="reportCard"><h3>Validation report</h3>
          <div class="muted small" id="report">Appears after the validation stage completes.</div></div>
      </div>`,
  };
};

/* ================= ALL BUILDS ================= */
SFG.pages["/builds"] = async () => {
  const projects = await api("GET", "/api/v1/projects");
  const isAdmin = ["super_admin", "admin"].includes(SFG.user.role);
  const allProjects = asList(projects, "projects");
  const myProjects = isAdmin ? allProjects : allProjects.filter((p) => p && p.owner_id === SFG.user.id);
  const all = [];
  for (const p of myProjects) {
    if (!p || !p.id) continue;
    try {
      const d = await api("GET", `/api/v1/projects/${p.id}/builds`);
      asList(d, "builds").forEach((b) => all.push({ ...b, project_id: p.id, project_name: p.name }));
    } catch (e) { }
  }
  all.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  const row = (b) => `<tr>
    <td><a class="mono" href="#/builds/${esc(b.id)}" style="color:var(--accent)">${esc(b.id)}</a>
      <div class="faint small">${esc(b.project_id)} · ${esc(b.project_name || "")}</div></td>
    <td class="mono">${esc(b.version)}</td>
    <td>${badge({ completed: "ok", running: "warn", queued: "warn", failed: "danger", disabled: "muted" }[b.status] || "muted", b.status)}</td>
    <td class="muted small">${esc(b.stage || "—")}</td>
    <td>${b.validation_passed == null ? "" : badge(b.validation_passed ? "ok" : "danger", b.validation_passed ? "passed" : "failed")}</td>
    <td class="muted small">${fmtDate(b.completed_at || b.created_at)}</td>
    <td><div class="row-actions">${b.status === "completed" ? `<a class="btn sm" href="/api/v1/builds/${esc(b.id)}/download">${I.download}</a>` : ""}</div></td>
  </tr>`;
  return {
    title: "Builds",
    html: all.length ? `<div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Build</th><th>Version</th><th>Status</th><th>Stage</th><th>Validation</th><th>Time</th><th></th></tr></thead>
      <tbody>${all.slice(0, 100).map(row).join("")}</tbody></table></div>`
      : emptyState("box", "No builds yet", "Open a project → Protection tab and start a protected build.",
        `<a class="btn primary" href="#/projects">Go to projects</a>`),
  };
};

/* ================= LICENSES ================= */
SFG.pages["/licenses"] = async (r) => {
  const status = r.params.get("status") || "";
  const q = r.params.get("q") || "";
  const d = await api("GET", `/api/v1/licenses?status=${encodeURIComponent(status)}&q=${encodeURIComponent(q)}`);
  const licenseRows = asList(d, "licenses");
  const row = (l) => `<tr>
    <td><span class="mono small">${esc(l.id)}</span>
      <div class="faint small">${esc(l.customer_name || l.customer_email || "—")}</div></td>
    <td class="mono small">${esc(l.project_id)}<div class="faint">${esc(l.project_name || "")}</div></td>
    <td class="mono small">${(l.domains || []).map(esc).join(", ") || "—"}</td>
    <td>${badge({ active: "ok", pending: "warn", suspended: "info", expired: "warn", revoked: "danger" }[l.status] || "muted", l.status)}</td>
    <td class="muted small">${l.activated ? fmtDate(l.activated_at) : "—"}</td>
    <td class="mono small">${esc(l.expires_at)}</td>
    <td class="muted small">${l.last_verified_at ? fmtAgo(l.last_verified_at) : "never"}</td>
    <td><div class="row-actions"><button class="btn sm" data-lv="${esc(l.id)}">Manage</button></div></td>
  </tr>`;
  return {
    title: "Licenses",
    html: `
      <div class="filterbar">
        <input class="input" id="lq" placeholder="Search license, customer, domain…" value="${esc(q)}" style="min-width:240px">
        <select class="input" id="lstatus">
          ${["", "pending", "active", "suspended", "expired", "revoked"].map((s) =>
            `<option value="${s}" ${status === s ? "selected" : ""}>${s || "All statuses"}</option>`).join("")}
        </select>
        <div class="spacer"></div>
        <span class="faint small">${licenseRows.length} shown</span>
      </div>
      ${licenseRows.length ? `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>License / customer</th><th>Project</th><th>Domains</th><th>Status</th><th>Activated</th><th>Expiry</th><th>Last verified</th><th></th></tr></thead>
        <tbody>${licenseRows.map(row).join("")}</tbody></table></div>`
        : emptyState("key", "No licenses", "Licenses are created per project with one or more authorized domains.",
          `<a class="btn primary" href="#/projects">Go to projects</a>`)}
      <div id="licModalMount"></div>`,
    onReady: () => {
      let t;
      bind("#lq", "oninput", (e) => {
        clearTimeout(t);
        t = setTimeout(() => nav("/licenses?q=" + encodeURIComponent(e.target.value) + (status ? "&status=" + status : "")), 350);
      });
      bind("#lstatus", "onchange", (e) => nav("/licenses" + (e.target.value ? "?status=" + e.target.value : "")));
      qsa("[data-lv]").forEach((b) => (b.onclick = () => licenseModal(b.dataset.lv)));
    },
  };
}

async function licenseModal(lid) {
  const d = await api("GET", `/api/v1/licenses/${lid}`);
  const l = d.license;
  const isAdmin = ["super_admin", "admin"].includes(SFG.user.role);
  const act = (label, path, opts = {}) => `<button class="btn sm ${opts.kind || ""}" data-la="${path}">${label}</button>`;
  const domRows = asList(l, "domains");
  const body = `
    <div class="kv">
      <div class="k">License ID</div><div class="v mono">${esc(l.id)}</div>
      <div class="k">Project</div><div class="v mono">${esc(l.project_id)}</div>
      <div class="k">Customer</div><div class="v">${esc(l.customer_name || "—")} ${l.customer_email ? `<span class="faint">${esc(l.customer_email)}</span>` : ""}</div>
      <div class="k">Status</div><div class="v">${badge({ active: "ok", pending: "warn", suspended: "info", expired: "warn", revoked: "danger" }[l.status] || "muted", l.status)}</div>
      <div class="k">Activated</div><div class="v">${l.activated ? fmtDate(l.activated_at) : "not yet"}</div>
      <div class="k">Created</div><div class="v">${fmtDate(l.created_at)}</div>
      <div class="k">Expires</div><div class="v mono">${esc(l.expires_at)}</div>
      <div class="k">Version restrict</div><div class="v mono">${esc(l.version_restrict || "any")}</div>
      <div class="k">Last verified</div><div class="v">${l.last_verified_at ? fmtAgo(l.last_verified_at) : "never"}</div>
    </div>
    <h3 style="margin-top:18px">Authorized domains</h3>
    <div class="tbl-wrap" style="border:0"><table class="tbl" style="min-width:0">
      <thead><tr><th>Domain</th><th>Status</th><th>Subdomains</th><th>Verified</th><th></th></tr></thead>
      <tbody>${domRows.map((dm) => `<tr>
        <td class="mono small">${esc(dm.domain)}</td>
        <td>${badge({ active: "ok", verified: "ok", pending: "warn", blocked: "danger" }[dm.status] || "muted", dm.status)}</td>
        <td class="small">${dm.allow_subdomains ? "yes" : "no"}</td>
        <td class="muted small">${dm.verified_at ? fmtDate(dm.verified_at) : "—"}</td>
        <td><div class="row-actions">
          ${dm.status === "pending" && isAdmin ? act("Verify DNS", "domverify") : ""}
          ${dm.status === "pending" && isAdmin ? act("Approve", "dommanual", { kind: "ghost" }) : ""}
          ${dm.status === "blocked" && isAdmin ? act("Unblock", "domunblock", { kind: "ghost" }) : isAdmin ? act("Block", "domblock", { kind: "ghost" }) : ""}
          ${isAdmin ? act("Remove", "domremove", { kind: "danger" }) : ""}
        </div></td></tr>`).join("")}</tbody></table></div>
    <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap">
      <input class="input mono" id="newDom" placeholder="new-domain.com" style="max-width:200px">
      <button class="btn sm" id="addDom">${I.plus} Add domain</button>
    </div>
    ${asList(l, "activations").length ? `
    <h3 style="margin-top:20px">Recent activations</h3>
    <div class="tbl-wrap" style="border:0;max-height:180px;overflow:auto"><table class="tbl" style="min-width:0">
      <thead><tr><th>Domain</th><th>Result</th><th>Code</th><th>When</th></tr></thead>
      <tbody>${asList(l, "activations").slice(0, 10).map((a) => `<tr>
        <td class="mono small">${esc(a.domain || "—")}</td>
        <td>${a.success ? badge("ok", "success") : badge("danger", "failed")}</td>
        <td class="mono faint small">${esc(a.error_code || "—")}</td>
        <td class="muted small">${fmtDate(a.created_at)}</td></tr>`).join("")}</tbody></table></div>` : ""}
    <h3 style="margin-top:18px">Actions</h3>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      ${l.status === "pending" || l.status === "active" ? act("Suspend", "suspend", { kind: "danger" }) : ""}
      ${l.status === "suspended" ? act("Resume", "resume", { kind: "primary" }) : ""}
      ${l.status === "expired" || l.status === "active" ? act("Renew +365d", "renew") : ""}
      ${isAdmin && l.status !== "revoked" ? act("Revoke", "revoke", { kind: "danger" }) : ""}
      ${isAdmin ? act("Reset activation", "reset") : ""}
      ${isAdmin ? act("Rotate key", "rotate", { kind: "danger" }) : ""}
    </div>`;
  const bd = modal({
    title: `License ${l.id}`,
    sub: "License state is authoritative here. Revocation/suspension takes effect on the next verification.",
    body, wide: true,
    actions: [{ label: "Close", onClick: () => closeModals() }],
  });
  const doAction = async (action) => {
    const pathMap = {
      suspend: [`/api/v1/licenses/${lid}/suspend`, "Suspend this license? Deployments will fail on next verification."],
      resume: [`/api/v1/licenses/${lid}/resume`, "Resume this license?"],
      revoke: [`/api/v1/licenses/${lid}/revoke`, "REVOKE this license? This immediately blocks all protected deployments. Cannot be undone."],
      renew: [`/api/v1/licenses/${lid}/renew`, "Renew the license for 365 days?"],
      reset: [`/api/v1/licenses/${lid}/reset-activation`, "Reset activation state? The license returns to 'pending' until next activation."],
      rotate: [`/api/v1/licenses/${lid}/rotate-key`, "Rotate the key? The previous key stops working immediately."],
      domverify: [`/api/v1/licenses/${lid}/domains/DOMAIN/verify`, ""],
      dommanual: [`/api/v1/licenses/${lid}/domains/DOMAIN/verify`, ""],
      domblock: [`/api/v1/licenses/${lid}/domains/DOMAIN/block`, ""],
      domunblock: [`/api/v1/licenses/${lid}/domains/DOMAIN/block`, ""],
      domremove: [`/api/v1/licenses/${lid}/domains/DOMAIN/delete`, ""],
    };
    const dom = (dataEl) => { const tr = dataEl && dataEl.closest ? dataEl.closest("tr") : null; return tr ? qs(".mono", tr)?.textContent || "" : ""; };
    let target = action;
    if (target.startsWith("dom")) {
      const el = bd.querySelector(`[data-la="${target}"]`);
      const domain = dom(el);
      const kind = target.split("dom")[1].toLowerCase();
      if (kind === "verify" || kind === "manual") {
        target = `/api/v1/licenses/${lid}/domains/${encodeURIComponent(domain)}/verify`;
      } else if (kind === "block" || kind === "unblock") {
        target = `/api/v1/licenses/${lid}/domains/${encodeURIComponent(domain)}/block`;
      } else if (kind === "remove") {
        target = `/api/v1/licenses/${lid}/domains/${encodeURIComponent(domain)}`;
      }
    }
    const [path, msg] = pathMap[action] || [null, ""];
    const finalPath = action.startsWith("dom") ? target : (path || target);
    const confirmMsg = msg || `Perform this action?`;
    const doIt = async () => {
      try {
        if (action === "renew") await api("POST", finalPath, { days: 365 });
        else if (action === "domverify") await api("POST", finalPath, { method: "dns" });
        else if (action === "dommanual") await api("POST", finalPath, { method: "manual" });
        else if (action === "domremove") await api("DELETE", finalPath);
        else await api("POST", finalPath);
        if (action === "rotate") {
          const d2 = await api("GET", `/api/v1/licenses/${lid}`); // key already rotated; show new from response
        }
        toast("Action complete", "ok");
        closeModals();
        const evt = new Event("sfg-refresh");
        document.dispatchEvent(evt);
        router();
      } catch (e) {
        if (e.code === "DNS_MISMATCH" || e.code === "DNS_UNREACHABLE") {
          confirmModal({
            title: "DNS verification failed", message: e.message + " — approve manually instead?",
            confirmLabel: "Approve manually",
            onConfirm: async () => {
              try { await api("POST", finalPath, { method: "manual" }); toast("Domain approved", "ok"); closeModals(); router(); }
              catch (e2) { toast(e2.message, "err"); }
            },
          });
          return;
        }
        toast(e.message, "err");
      }
    };
    if (action === "rotate") {
      confirmModal({
        title: "Rotate license key", danger: true, confirmLabel: "Rotate",
        message: msg,
        onConfirm: async () => {
          try {
            const r = await api("POST", finalPath);
            modal({
              title: "New license key",
              body: `<div class="keyline"><div class="code">${esc(r.key)}</div>
                <button class="btn" id="copyKey2">${I.check} Copy</button></div>
                <div class="callout">${esc(r.note || "")}</div>`,
              actions: [{ label: "Done", kind: "primary", onClick: () => { closeModals(); router(); } }],
            });
            qs("#copyKey2") && (qs("#copyKey2").onclick = async () => { try { await navigator.clipboard.writeText(r.key); toast("Copied", "ok"); } catch (e) { } });
          } catch (e) { toast(e.message, "err"); }
        },
      });
      return;
    }
    if (["revoke", "suspend", "rotate", "domremove"].includes(action)) {
      confirmModal({ title: "Confirm action", message: confirmMsg, danger: true, confirmLabel: "Confirm", onConfirm: doIt });
    } else {
      doIt();
    }
  };
  bd.querySelectorAll("[data-la]").forEach((b) => (b.onclick = () => doAction(b.dataset.la)));
  const addDom = qs("#addDom", bd);
  if (addDom) addDom.onclick = async () => {
    const v = qs("#newDom", bd)?.value?.trim();
    if (!v) return;
    try {
      const r = await api("POST", `/api/v1/licenses/${lid}/domains`, { domain: v });
      modal({
        title: "Domain added — verify ownership",
        body: `<p class="muted small">Add this DNS TXT record, then verify:</p>
          <div class="code">${r.dns_hint}</div>`,
        actions: [{ label: "Close", onClick: () => closeModals() }],
      });
      router();
    } catch (e) { toast(e.message, "err"); }
  };
}

/* ================= DOMAINS ================= */
SFG.pages["/domains"] = async (r) => {
  const q = r.params.get("q") || "";
  const d = await api("GET", `/api/v1/domains?q=${encodeURIComponent(q)}`);
  const domainRows = asList(d, "domains");
  const row = (x) => `<tr>
    <td class="mono small">${esc(x.domain)}</td>
    <td class="mono small">${esc(x.project_id)}<div class="faint">${esc(x.project_name || "")}</div></td>
    <td class="mono small">${esc(x.license_id)}</td>
    <td>${badge({ active: "ok", verified: "ok", pending: "warn", blocked: "danger" }[x.status] || "muted", x.status)}</td>
    <td class="muted small">${fmtDate(x.added_at)}</td>
    <td class="muted small">${x.verified_at ? fmtDate(x.verified_at) : "—"}</td>
    <td><div class="row-actions">
      ${x.status === "pending" ? `<button class="btn sm" data-dv="${esc(x.license_id)}|${esc(x.domain)}">Verify</button>` : ""}
      ${x.status !== "blocked" ? `<button class="btn sm ghost" data-db="${esc(x.license_id)}|${esc(x.domain)}">Block</button>`
        : `<button class="btn sm ghost" data-db="${esc(x.license_id)}|${esc(x.domain)}">Unblock</button>`}
    </div></td>
  </tr>`;
  return {
    title: "Domains",
    html: `
      <div class="filterbar">
        <input class="input" id="dq" placeholder="Search domains or projects…" value="${esc(q)}">
        <div class="spacer"></div><span class="faint small">${domainRows.length} domains</span>
      </div>
      ${domainRows.length ? `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Domain</th><th>Project</th><th>License</th><th>Status</th><th>Added</th><th>Last verified</th><th></th></tr></thead>
        <tbody>${domainRows.map(row).join("")}</tbody></table></div>`
        : emptyState("globe", "No domains", "Domains are added when licenses are created.",
          `<a class="btn primary" href="#/licenses">Go to licenses</a>`)}
      <div class="faint small" style="margin-top:10px">Verification uses a real DNS TXT lookup (<span class="mono">_sfg-verify.&lt;domain&gt;</span>) with manual approval as fallback. Blocked domains fail all verifications immediately.</div>`,
    onReady: () => {
      let t;
      bind("#dq", "oninput", (e) => {
        clearTimeout(t);
        t = setTimeout(() => nav("/domains?q=" + encodeURIComponent(e.target.value)), 350);
      });
      qsa("[data-dv]").forEach((b) => (b.onclick = async () => {
        const [lid, dom] = b.dataset.dv.split("|");
        try {
          await api("POST", `/api/v1/licenses/${lid}/domains/${encodeURIComponent(dom)}/verify`, { method: "dns" });
          toast("Domain verified via DNS", "ok"); router();
        } catch (e) {
          confirmModal({
            title: "DNS verification failed",
            message: e.message + " — approve manually instead?",
            confirmLabel: "Approve manually",
            onConfirm: async () => {
              try { await api("POST", `/api/v1/licenses/${lid}/domains/${encodeURIComponent(dom)}/verify`, { method: "manual" }); toast("Approved", "ok"); router(); }
              catch (e2) { toast(e2.message, "err"); }
            },
          });
        }
      }));
      qsa("[data-db]").forEach((b) => (b.onclick = async () => {
        const [lid, dom] = b.dataset.db.split("|");
        try { await api("POST", `/api/v1/licenses/${lid}/domains/${encodeURIComponent(dom)}/block`); toast("OK", "ok"); router(); }
        catch (e) { toast(e.message, "err"); }
      }));
    },
  };
};

/* ================= USERS ================= */
SFG.pages["/users"] = async () => {
  const d = await api("GET", "/api/v1/users");
  const userRows = asList(d, "users");
  const row = (u) => `<tr>
    <td class="mono small">${esc(u.email)}</td>
    <td>${esc(u.name || "")}</td>
    <td>${badge(u.role === "super_admin" ? "danger" : u.role === "admin" ? "warn" : "info", String(u.role || "user").replace("_", " "))}</td>
    <td class="num">${u.project_count ?? 0}</td>
    <td>${u.disabled ? badge("muted", "disabled") : badge("ok", "enabled")}</td>
    <td class="muted small">${u.last_login_at ? fmtAgo(u.last_login_at) : "never"}</td>
    <td><div class="row-actions">
      <button class="btn sm" data-ur="${u.id}" data-role="${u.role}">Role</button>
      <button class="btn sm" data-up="${u.id}">Reset PW</button>
      ${!u.disabled ? `<button class="btn sm danger" data-ud="${u.id}">Disable</button>` : `<button class="btn sm" data-ud="${u.id}">Enable</button>`}
    </div></td>
  </tr>`;
  return {
    title: "Users",
    html: `
      <div class="card" style="margin-bottom:16px">
        <h3>Create user</h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <input class="input" id="uEmail" placeholder="email" style="max-width:220px">
          <input class="input" id="uName" placeholder="name" style="max-width:180px">
          <select class="input" id="uRole" style="max-width:160px">
            ${["user", "developer", "admin"].map((r) => `<option>${r}</option>`).join("")}
          </select>
          <button class="btn primary" id="uCreate">${I.plus} Create</button>
        </div>
        <div id="uMsg"></div>
      </div>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Projects</th><th>Status</th><th>Last login</th><th></th></tr></thead>
        <tbody>${userRows.map(row).join("")}</tbody></table></div>`,
    onReady: () => {
      bind("#uCreate", "onclick", async () => {
        try {
          const r = await api("POST", "/api/v1/users", {
            email: qs("#uEmail")?.value?.trim() || "", name: qs("#uName")?.value?.trim() || "", role: qs("#uRole")?.value || "user",
          });
          modal({
            title: "User created",
            body: `<div class="kv"><div class="k">Email</div><div class="v">${esc(r.email)}</div>
              <div class="k">Role</div><div class="v">${esc(r.role)}</div>
              <div class="k">Temporary password</div><div class="v mono">${esc(r.password)}</div></div>
              <div class="callout">${esc(r.note)}</div>`,
            actions: [{ label: "Done", kind: "primary", onClick: () => closeModals() }],
          });
        } catch (e) { toast(e.message, "err"); }
      });
      qsa("[data-ur]").forEach((b) => (b.onclick = () => {
        modal({
          title: "Change role",
          body: `<label class="f">Role</label><select class="input" id="roleSel">
            ${["user", "developer", "admin", "super_admin"].filter((r) => r !== b.dataset.role).map((r) => `<option>${r}</option>`).join("")}
          </select>`,
          actions: [
            { label: "Cancel", onClick: () => closeModals() },
            {
              label: "Save", kind: "primary",
              onClick: async () => {
                try { await api("PATCH", `/api/v1/users/${b.dataset.ur}`, { role: qs("#roleSel")?.value || "user" }); toast("Role updated", "ok"); closeModals(); router(); }
                catch (e) { toast(e.message, "err"); }
              },
            },
          ],
        });
      }));
      qsa("[data-up]").forEach((b) => (b.onclick = async () => {
        try {
          const r = await api("POST", `/api/v1/users/${b.dataset.up}/reset-password`);
          modal({
            title: "Password reset",
            body: `<div class="kv"><div class="k">Email</div><div class="v">${esc(r.email)}</div>
              <div class="k">New password</div><div class="v mono">${esc(r.password)}</div></div>
              <div class="callout">Shown once. Existing sessions for this user were terminated.</div>`,
            actions: [{ label: "Done", kind: "primary", onClick: () => closeModals() }],
          });
        } catch (e) { toast(e.message, "err"); }
      }));
      qsa("[data-ud]").forEach((b) => (b.onclick = () => confirmModal({
        title: b.textContent.trim() === "Disable" ? "Disable user" : "Enable user",
        message: b.textContent.trim() === "Disable" ? "This user will no longer be able to sign in." : "Re-enable this user?",
        confirmLabel: b.textContent.trim(),
        onConfirm: async () => {
          try { await api("PATCH", `/api/v1/users/${b.dataset.ud}`, { disabled: b.textContent.trim() === "Disable" ? true : false }); toast("OK", "ok"); router(); }
          catch (e) { toast(e.message, "err"); }
        },
      })));
    },
  };
};

/* ================= AI ANALYSIS (cross-project) ================= */
SFG.pages["/ai"] = async () => {
  const projects = await api("GET", "/api/v1/projects");
  const projectList = asList(projects, "projects");
  const withAnalysis = [];
  for (const p of projectList) {
    if (!p || !p.id) continue;
    try {
      const d = await api("GET", `/api/v1/projects/${p.id}/ai-analysis`);
      if (d.latest) withAnalysis.push({ project: p, latest: d.latest });
    } catch (e) { }
  }
  const card = (x) => `
    <div class="card">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <a class="mono" href="#/projects/${esc(x.project.id)}?tab=ai" style="color:var(--accent)">${esc(x.project.id)}</a>
        ${badge(x.latest.engine === "llm" ? "info" : "muted", x.latest.engine || "builtin")}
        <span class="faint small">${esc(x.latest.model || "")} · ${fmtAgo(x.latest.generated_at)}</span>
        <div style="flex:1"></div>
        ${badge("warn", x.latest.recommendation?.protection_level || "standard")}
      </div>
      <div class="muted small" style="margin-top:10px">${esc((x.latest.overview?.entry_points || []).join(", ") || "")}</div>
      <div class="small" style="margin-top:8px">
        ${x.latest.sensitive_components?.length || 0} sensitive components ·
        ${(x.latest.risks || []).length} risks ·
        ${(x.latest.recommendation?.protected_components || []).length} recommended for protection
      </div>
    </div>`;
  return {
    title: "AI Analysis",
    html: `
      <div class="callout blue" style="margin-bottom:16px">
        The built-in engine performs deterministic static analysis (structure, technologies, dependencies,
        credential heuristics, protection recommendation). An external LLM is optional (Settings → AI) and
        receives <strong>only an anonymized structural summary</strong> — never file contents or secrets.
        All recommendations are advisory, never a security guarantee.
      </div>
      ${withAnalysis.length ? `<div class="grid cards-2">${withAnalysis.map(card).join("")}</div>`
        : emptyState("brain", "No analyses yet", "Open a project's AI Analysis tab and run the analysis.",
          `<a class="btn primary" href="#/projects">Go to projects</a>`)}
      ${projectList.length ? "" : emptyState("folder", "No projects", "Upload a project first.",
        `<a class="btn primary" href="#/upload">Upload</a>`)}
      <div class="grid cards-2" style="margin-top:16px">
        <div class="card"><h3>Engine input (LLM mode)</h3>
          <pre class="code" style="margin:0">{ "purpose": "advisory protection analysis",
  "file_count": 96, "by_kind": { "php": 47, "js": 18, "html": 12, … },
  "files": [ { "path": "index.php", "kind": "php", "sensitive_flag": false }, … ],
  "instruction": "Return JSON: {overview, technologies, risks, recommendation} — advisory only" }</pre>
        </div>
        <div class="card"><h3>What the AI never sees</h3>
          <ul class="muted small" style="margin:0;padding-left:18px;line-height:2">
            <li>File contents of any project</li>
            <li>Detected secret values (masked before analysis)</li>
            <li>Master encryption keys / signing keys</li>
            <li>License database credentials</li>
            <li>Other users' projects or data</li>
            <li>License keys or API secrets</li>
          </ul>
        </div>
      </div>`,
  };
};

/* ================= SECURITY EVENTS ================= */
SFG.pages["/events"] = async (r) => {
  const [type, severity, project_id, from, to] = ["type", "severity", "project_id", "from", "to"].map((k) => r.params.get(k) || "");
  const d = await api("GET", `/api/v1/events?type=${encodeURIComponent(type)}&severity=${encodeURIComponent(severity)}&project_id=${encodeURIComponent(project_id)}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
  const eventRows = asList(d, "events");
  const typeCounts = asList(d, "type_counts");
  const row = (e) => `<tr>
    <td>${badge({ critical: "danger", warning: "warn", info: "info" }[e.severity] || "muted", e.severity)}</td>
    <td class="mono small">${esc(e.type)}</td>
    <td class="mono small">${esc(e.project_id || "—")}</td>
    <td class="mono small">${esc(e.license_id || "—")}</td>
    <td class="muted small" style="max-width:380px;word-break:break-word">${esc(e.detail || "")}</td>
    <td class="mono faint small">${esc(e.ip || "")}</td>
    <td class="muted small">${fmtDate(e.created_at)}</td>
  </tr>`;
  return {
    title: "Security Events",
    html: `
      <div class="filterbar">
        <input class="input" id="eq" placeholder="Search type/detail…" value="${esc(r.params.get("q") || "")}">
        <select class="input" id="etype">
          <option value="">All types</option>
          ${typeCounts.map((t) => `<option value="${esc(t.type)}" ${type === t.type ? "selected" : ""}>${esc(t.type)} (${t.c})</option>`).join("")}
        </select>
        <select class="input" id="esev">
          ${["", "info", "warning", "critical"].map((s) => `<option value="${s}" ${severity === s ? "selected" : ""}>${s || "All severities"}</option>`).join("")}
        </select>
        <input class="input" type="date" id="efrom" value="${esc(from)}">
        <input class="input" type="date" id="eto" value="${esc(to)}">
        <div class="spacer"></div>
        <a class="btn sm" href="/api/v1/events/export.csv?type=${encodeURIComponent(type)}&severity=${encodeURIComponent(severity)}&project_id=${encodeURIComponent(project_id)}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}">${I.download} CSV</a>
      </div>
      ${eventRows.length ? `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Severity</th><th>Type</th><th>Project</th><th>License</th><th>Detail</th><th>IP</th><th>When</th></tr></thead>
        <tbody>${eventRows.map(row).join("")}</tbody></table></div>
        <div class="faint small" style="margin-top:10px">${eventRows.length} events (capped at 1000 per page)</div>`
        : emptyState("shield", "No security events", "Verification failures, unauthorized domains, signature and integrity failures are recorded here.")}
      <div class="faint small" style="margin-top:10px">Credential values are never logged. IPs and masked details only.</div>`,
    onReady: () => {
      const go = () => {
        const et = qs("#etype")?.value || "";
        const es = qs("#esev")?.value || "";
        const ef = qs("#efrom")?.value || "";
        const eo = qs("#eto")?.value || "";
        const eq = qs("#eq")?.value || "";
        nav(`/events?type=${encodeURIComponent(et)}&severity=${encodeURIComponent(es)}&project_id=${encodeURIComponent(project_id)}&from=${encodeURIComponent(ef)}&to=${encodeURIComponent(eo)}&q=${encodeURIComponent(eq)}`);
      };
      ["#etype", "#esev"].forEach((s) => bind(s, "onchange", go));
      ["#efrom", "#eto"].forEach((s) => bind(s, "onchange", go));
      let t;
      bind("#eq", "oninput", () => { clearTimeout(t); t = setTimeout(go, 350); });
    },
  };
};

/* ================= VERIFICATION LOGS ================= */
SFG.pages["/verifications"] = async (r) => {
  const [result, error_code, license_id] = [r.params.get("result") || "", r.params.get("error_code") || "", r.params.get("license_id") || ""];
  const d = await api("GET", `/api/v1/verifications?result=${encodeURIComponent(result)}&error_code=${encodeURIComponent(error_code)}&license_id=${encodeURIComponent(license_id)}`);
  const verifRows = asList(d, "verifications");
  const row = (v) => `<tr>
    <td class="mono small">${esc(v.license_id || "—")}</td>
    <td class="mono small">${esc(v.project_id || "—")}</td>
    <td class="mono small">${esc(v.domain || "—")}</td>
    <td>${badge(v.result === "ok" ? "ok" : "danger", v.result || "unknown")}</td>
    <td class="mono small">${esc(v.error_code || "—")}</td>
    <td class="num small">${v.latency_ms ?? 0} ms</td>
    <td class="mono faint small">${esc(v.ip || "")}</td>
    <td class="muted small">${fmtDate(v.created_at)}</td>
  </tr>`;
  return {
    title: "Verification Logs",
    html: `
      <div class="filterbar">
        <select class="input" id="vres">
          ${["", "ok", "failed"].map((s) => `<option value="${s}" ${result === s ? "selected" : ""}>${s || "All results"}</option>`).join("")}
        </select>
        <input class="input" id="vlc" placeholder="License ID" value="${esc(license_id)}" style="max-width:160px">
        <div class="spacer"></div>
        <a class="btn sm" href="/api/v1/verifications/export.csv?result=${encodeURIComponent(result)}&license_id=${encodeURIComponent(license_id)}">${I.download} CSV</a>
      </div>
      ${verifRows.length ? `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>License</th><th>Project</th><th>Domain</th><th>Result</th><th>Error</th><th>Latency</th><th>IP</th><th>When</th></tr></thead>
        <tbody>${verifRows.map(row).join("")}</tbody></table></div>`
        : emptyState("list", "No verification activity", "Every /licenses/verify and /activate call is logged here with result, latency and error code.")}
      <div class="faint small" style="margin-top:10px">Retention is configurable in Settings (default 90 days).</div>`,
    onReady: () => {
      const go = () => {
        const res = qs("#vres")?.value || "";
        const lc = qs("#vlc")?.value || "";
        nav(`/verifications?result=${encodeURIComponent(res)}&license_id=${encodeURIComponent(lc)}`);
      };
      bind("#vres", "onchange", go);
      let t;
      bind("#vlc", "oninput", () => { clearTimeout(t); t = setTimeout(go, 350); });
    },
  };
};

/* ================= AUDIT LOG ================= */
SFG.pages["/audit"] = async (r) => {
  const q = r.params.get("q") || "";
  const d = await api("GET", `/api/v1/audit?q=${encodeURIComponent(q)}`);
  const auditRows = asList(d, "audit");
  const row = (a) => `<tr>
    <td class="mono small">${esc(a.actor_email || "system")}</td>
    <td class="mono small">${esc(a.action)}</td>
    <td class="small">${esc(a.resource || "")} <span class="faint mono">${esc(a.resource_id || "")}</span></td>
    <td>${badge(a.result === "ok" ? "ok" : "danger", a.result)}</td>
    <td class="muted small" style="max-width:340px;word-break:break-word">${esc(a.detail || "")}</td>
    <td class="muted small">${fmtDate(a.created_at)}</td>
  </tr>`;
  return {
    title: "Audit Log",
    html: `
      <div class="filterbar"><input class="input" id="aq" placeholder="Search resource / detail…" value="${esc(q)}"></div>
      ${auditRows.length ? `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Actor</th><th>Action</th><th>Resource</th><th>Result</th><th>Detail</th><th>When</th></tr></thead>
        <tbody>${auditRows.map(row).join("")}</tbody></table></div>`
        : emptyState("list", "No audit entries", "Administrative actions (logins, builds, license changes, domain changes, settings) are recorded here.")}
      <div class="faint small" style="margin-top:10px">Passwords and private keys are never written to the audit log.</div>`,
    onReady: () => {
      let t;
      bind("#aq", "oninput", (e) => {
        clearTimeout(t);
        t = setTimeout(() => nav("/audit?q=" + encodeURIComponent(e.target.value)), 350);
      });
    },
  };
};

/* ================= VERSIONS (global) ================= */
SFG.pages["/versions"] = async () => {
  const projects = await api("GET", "/api/v1/projects");
  const rows = [];
  for (const p of asList(projects, "projects")) {
    if (!p || !p.id) continue;
    for (const v of asList(p, "versions")) rows.push({ ...v, project_id: p.id, project_name: p.name });
  }
  const row = (v) => `<tr>
    <td class="mono small">${esc(v.project_id)}<div class="faint">${esc(v.project_name || "")}</div></td>
    <td class="mono">${esc(v.version)}</td>
    <td>${v.revoked ? badge("danger", "revoked") : badge("ok", "active")}</td>
    <td class="num">${v.builds}</td>
    <td class="muted small">${esc(v.note || "—")}</td>
    <td class="muted small">${fmtDate(v.created_at)}</td>
    <td><div class="row-actions">
      <a class="btn sm ghost" href="#/projects/${esc(v.project_id)}?tab=versions">Open</a></div></td>
  </tr>`;
  return {
    title: "Versions",
    html: rows.length ? `<div class="tbl-wrap"><table class="tbl">
    <thead><tr><th>Project</th><th>Version</th><th>Status</th><th>Builds</th><th>Note</th><th>Created</th><th></th></tr></thead>
    <tbody>${rows.map(row).join("")}</tbody></table></div>`
    : emptyState("tag", "No versions", "Versions are created per project (automatically at build time). Revoke a version from the project page."),
  };
};

/* ================= SETTINGS ================= */
SFG.pages["/settings"] = async () => {
  let s = {};
  try {
    const d = await api("GET", "/api/v1/settings");
    s = (d && d.settings) || {};
  } catch (e) {
    return {
      title: "Settings",
      html: `<div class="card">${errBox(e)}</div>
        <div class="callout blue" style="margin-top:12px">Settings require an admin account. Log in with ${esc(SFG.user?.email || "admin")} if your role is admin/super_admin.</div>`,
    };
  }
  const field = (key, label, type = "text", placeholder = "") => `
    <label class="f">${label}</label>
    <input class="input mono" data-set="${key}" type="${type}" value="${esc(s[key] ?? "")}" placeholder="${placeholder}">`;
  return {
    title: "Settings",
    html: `
      <div class="grid cards-2">
        <div class="card">
          <h3>Platform</h3>
          ${field("site_name", "Site name")}
          ${field("license_server_url", "License server base URL (empty = auto-detect from request)", "text", "https://license.example.com")}
          <label class="f">HTTPS enforcement for protected deployments</label>
          <select class="input" data-set="require_https" style="max-width:160px">
            <option value="1" ${s.require_https === "1" ? "selected" : ""}>required</option>
            <option value="0" ${s.require_https === "0" ? "selected" : ""}>not required</option>
          </select>
          <label class="f">Verification clock tolerance (seconds)</label>
          <input class="input mono" data-set="clock_tolerance_seconds" type="number" value="${esc(s.clock_tolerance_seconds)}" style="max-width:140px">
          <label class="f">Max upload size (MB)</label>
          <input class="input mono" data-set="max_upload_mb" type="number" value="${esc(s.max_upload_mb)}" style="max-width:140px">
          <label class="f">Verification log retention (days)</label>
          <input class="input mono" data-set="verification_retention_days" type="number" value="${esc(s.verification_retention_days)}" style="max-width:140px">
        </div>
        <div>
          <div class="card">
            <h3>Protected runtime policy</h3>
            ${field("verify_ttl_seconds", "Client-side authorization cache TTL (seconds)", "number")}
            ${field("grace_seconds", "Grace period while license server unreachable (seconds, 0 = strict fail-closed)", "number")}
            <div class="callout blue">The runtime fails closed: without a recent signed authorization (and beyond the grace window) protected functionality stops with a professional error page.</div>
          </div>
          <div class="card" style="margin-top:16px">
            <h3>AI / LLM integration (optional)</h3>
            <label class="f">OpenAI-compatible base URL</label>
            <input class="input mono" data-set="ai_base_url" value="${esc(s.ai_base_url)}" placeholder="https://api.openai.com/v1">
            <label class="f">Model</label>
            <input class="input mono" data-set="ai_model" value="${esc(s.ai_model)}" placeholder="gpt-4o-mini">
            <label class="f">API key ${s.ai_key_configured ? '<span class="badge ok">configured</span>' : ""}</label>
            <input class="input mono" id="aiKey" type="password" placeholder="${s.ai_key_configured ? "•••••••• (leave blank to keep)" : "sk-…"}">
            <div class="callout">Stored AES-256-GCM wrapped with the server master key; never returned in cleartext. On Render, prefer env <code>SFG_AI_API_KEY</code> (permanent across redeploys). The LLM only ever receives an anonymized structural summary — never file contents or secrets.</div>
          </div>
          <div class="card" style="margin-top:16px">
            <h3>Backup (keep data after redeploy)</h3>
            <div class="callout warn">Render free disk is wiped on redeploy/restart. Export a signed metadata backup before every deploy, then restore after login.</div>
            <div class="row" style="gap:8px;flex-wrap:wrap">
              <button class="btn" id="dlBackup">Download backup.json</button>
              <label class="btn" style="cursor:pointer">Restore backup…<input type="file" id="upBackup" accept="application/json,.json" style="display:none"></label>
            </div>
            <div class="faint small" id="backupMsg" style="margin-top:8px"></div>
          </div>
          <div style="margin-top:16px"><button class="btn primary" id="saveSettings">Save settings</button>
          <span class="faint small" id="saveMsg" style="margin-left:10px"></span></div>
        </div>
      </div>`,
    onReady: () => {
      bind("#saveSettings", "onclick", async () => {
        const body = {};
        qsa("[data-set]").forEach((el) => { body[el.dataset.set] = el.value; });
        const key = qs("#aiKey")?.value?.trim();
        if (key) body.ai_key = key;
        try {
          const r = await api("POST", "/api/v1/settings", body);
          const msg = qs("#saveMsg");
          if (msg) msg.textContent = "Saved: " + (r.changed || []).join(", ");
          toast("Settings saved", "ok");
        } catch (e) { toast(e.message, "err"); }
      });

      bind("#dlBackup", "onclick", async () => {
        try {
          const r = await fetch("/api/v1/backup/export", { credentials: "include" });
          if (!r.ok) throw new Error("Backup export failed");
          const blob = await r.blob();
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = "sfg-backup-" + new Date().toISOString().slice(0, 10) + ".json";
          a.click();
          URL.revokeObjectURL(a.href);
          const m = qs("#backupMsg");
          if (m) m.textContent = "Downloaded. Keep this file safe.";
          toast("Backup downloaded", "ok");
        } catch (e) { toast(e.message, "err"); }
      });

      bind("#upBackup", "onchange", async (e) => {
        const f = e.target.files[0];
        if (!f) return;
        try {
          const text = await f.text();
          const bundle = JSON.parse(text);
          const r = await api("POST", "/api/v1/backup/restore", bundle);
          const m = qs("#backupMsg");
          if (m) m.textContent = "Restored " + (r.entry_count || 0) + " entries.";
          toast("Backup restored", "ok");
          router();
        } catch (err) { toast(err.message || "Restore failed", "err"); }
      });
    },
  };
};

/* ================= HEALTH ================= */
SFG.pages["/health"] = async () => {
  const d = await api("GET", "/api/v1/health");
  const s = d.system || {};
  const item = (name, st, detail = "") => `
    <div style="display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid rgba(148,163,184,.07)">
      ${badge({ ok: "ok", configured: "ok", not_configured: "muted", warning: "warn", error: "danger" }[st?.status] || "muted", st?.status || "unknown")}
      <div style="flex:1"><div class="small" style="font-weight:600">${name}</div>
      ${detail ? `<div class="faint small">${detail}</div>` : ""}</div>
    </div>`;
  return {
    title: "System Health",
    html: `
      <div class="grid cards-2">
        <div class="card">
          <h3>Services</h3>
          ${item("Database (SQLite)", s.database?.status || "not_configured", `${s.database?.tables ?? 0} tables · ${s.database?.detail || ""}`)}
          ${item("License API (signature round-trip)", s.license_api?.status || "not_configured", s.license_api?.detail || "")}
          ${item("Build service", s.build_service?.status || "not_configured", `${s.build_service?.active_builds ?? 0}/${s.build_service?.limit ?? 0} active builds`)}
          ${item("Storage", s.storage?.status || "not_configured", `${s.storage?.free_mb ?? 0} MB free · ${s.storage?.projects_count ?? 0} project workspaces · ${s.storage?.projects_used_mb ?? 0} MB`)}
          ${item("AI service", s.ai_service?.status || "not_configured", s.ai_service?.note || "")}
        </div>
        <div class="card">
          <h3>Key material & recent problems</h3>
          <div class="detail-grid" style="margin-top:6px">
            <div class="item"><div class="k">System</div><div class="v">${esc(s.name || "Secure File Guard")} v${esc(s.version || "")}</div></div>
            <div class="item"><div class="k">Signing key age</div><div class="v">${s.signing_key_age_days != null ? s.signing_key_age_days + " days" : "—"}</div></div>
            <div class="item"><div class="k">Failed verifications (24h)</div><div class="v" style="color:${s.failed_verifications_24h ? "var(--danger)" : "inherit"}">${s.failed_verifications_24h ?? 0}</div></div>
          </div>
          <h3 style="margin-top:18px">Recent critical event types (24h)</h3>
          ${asList(s, "recent_critical_events").length ? asList(s, "recent_critical_events").map((e) =>
            `<div class="small" style="display:flex;justify-content:space-between;padding:5px 0">
              <span class="mono">${esc(e.type)}</span><span class="muted">${e.c}</span></div>`).join("")
            : `<div class="muted small">None.</div>`}
          <div class="callout" style="margin-top:16px">No sensitive infrastructure details (paths, credentials, internal endpoints) are exposed to non-admin users.</div>
        </div>
      </div>`,
  };
};

/* ================= BACKUPS ================= */
SFG.pages["/backups"] = async () => {
  const d = await api("GET", "/api/v1/backup");
  const backupRows = asList(d, "backups");
  return {
    title: "Backups",
    html: `
      <div class="callout blue" style="margin-bottom:16px">
        Metadata backup & recovery: projects, licenses (key <strong>hashes</strong> only — never plaintext keys),
        domains, build metadata, security and audit logs. Each bundle is Ed25519-signed; tampered bundles are
        rejected on restore. No secrets, no master keys, no file content is included.
      </div>
      <div class="card" style="margin-bottom:16px">
        <h3>Export</h3>
        <p class="muted small" style="margin-top:0">Download a signed metadata bundle (JSON).</p>
        <a class="btn primary" href="/api/v1/backup/export">${I.download} Export backup</a>
      </div>
      <div class="card">
        <h3>Restore</h3>
        <p class="muted small" style="margin-top:0">Upload a previously exported bundle. Existing rows are kept (INSERT OR IGNORE); the signature is verified before anything is written.</p>
        <div class="dropzone" id="restoreDz" style="padding:26px">
          ${I.upload}<div class="big">Choose sfg-backup.json to restore</div>
        </div>
        <input type="file" id="restoreInput" accept=".json,application/json" style="display:none">
        <div id="restoreMsg" style="margin-top:12px"></div>
      </div>
      <div class="card" style="margin-top:16px">
        <h3>Backup history</h3>
        ${backupRows.length ? `<div class="tbl-wrap" style="border:0"><table class="tbl" style="min-width:0">
          <thead><tr><th>Kind</th><th>Entries</th><th>SHA-256</th><th>When</th></tr></thead>
          <tbody>${backupRows.map((b) => `<tr>
            <td>${esc(b.kind)}</td><td class="num">${b.entry_count ?? 0}</td>
            <td class="mono small">${esc(String(b.sha256 || "").slice(0, 20))}…</td>
            <td class="muted small">${fmtDate(b.created_at)}</td></tr>`).join("")}</tbody></table></div>`
          : `<div class="muted small">No restores performed yet.</div>`}
      </div>`,
    onReady: () => {
      const dz = qs("#restoreDz"), inp = qs("#restoreInput");
      if (dz && inp) {
        dz.onclick = () => inp.click();
        inp.onchange = async () => {
          const f = inp.files[0];
          if (!f) return;
          const msg = qs("#restoreMsg");
          if (msg) msg.innerHTML = `<div class="loading-row"><span class="spinner"></span>Verifying signature…</div>`;
          try {
            const bundle = JSON.parse(await f.text());
            const r = await api("POST", "/api/v1/backup/restore", bundle);
            if (msg) msg.innerHTML = `<div class="callout" style="border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.07);color:#6ee7b7">
              Restored ${r.entry_count} entries: ${esc(Object.entries(r.restored || {}).map(([k, v]) => `${k}: ${v}`).join(", "))}</div>`;
            toast("Restore complete", "ok");
          } catch (e) {
            if (msg) msg.innerHTML = errBox(e);
          }
        };
      }
    },
  };
};

/* ================= API DOCS (in-app) ================= */
SFG.pages["/api"] = async () => {
  return {
    title: "API",
    html: `
      <div class="card">
        <h3>Licensing API v1</h3>
        <p class="muted small" style="margin-top:0">
          Public, documented endpoints used by protected deployments and tooling: verification, activation,
          domain/version/integrity checks, protected component delivery and event reporting.
          All verification responses are Ed25519-signed; replay protection (timestamp + nonce) and per-IP
          rate limits are enforced server-side.
        </p>
        <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap">
          <a class="btn primary" href="/api/docs" target="_blank" rel="noopener">Open full API reference</a>
          <a class="btn" href="/api/openapi.json" target="_blank" rel="noopener">OpenAPI JSON</a>
          <a class="btn ghost" href="/api/healthz" target="_blank" rel="noopener">Health probe</a>
        </div>
        <pre class="code" style="margin-top:16px">POST /api/v1/public/licenses/verify
{ "license": "SFG-XXXX-XXXX-XXXX-XXXX",
  "domain":  "example.com",
  "project": "PRJ-ABC12",
  "build":   "BLD-XYZ78",
  "version": "1.0.0",
  "ts": 1700000000,
  "nonce": "9f86d0819873378640000000" }

200 → { "ok": true, "token": "&lt;Ed25519-signed authorization token&gt;", "expires_at": … }
4xx → { "error": { "code": "DOMAIN_NOT_AUTHORIZED", "message": "…" } }

GET /api/v1/public/runtime/file?project=…&build=…&component=…
Authorization: Bearer &lt;signed token&gt;
→ { "data": "&lt;base64 plaintext&gt;", "sha256": "…", "size": 1234 }</pre>
        <div class="callout">Full endpoint list with error codes: <a href="/api/docs" target="_blank" rel="noopener">/api/docs</a></div>
      </div>`,
  };
};

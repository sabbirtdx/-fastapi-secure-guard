/* Secure File Guard — pages: dashboard, projects, project detail, uploads */
"use strict";

/* ================= DASHBOARD ================= */
SFG.pages["/dashboard"] = async () => {
  const isAdmin = ["super_admin", "admin"].includes(SFG.user.role);
  const [projects] = await Promise.all([api("GET", "/api/v1/projects")]);
  const extras = isAdmin
    ? await Promise.all([
        api("GET", "/api/v1/licenses?limit=500"),
        api("GET", "/api/v1/events?limit=500"),
        api("GET", "/api/v1/verifications?limit=500"),
      ])
    : [];
  const projectList = asList(projects, "projects");
  const licenses = isAdmin ? asList(extras[0], "licenses") : [];
  const events = isAdmin ? asList(extras[1], "events") : [];
  const verifs = isAdmin ? asList(extras[2], "verifications") : [];
  const today = new Date().toISOString().slice(0, 10);
  const todayVerifs = verifs.filter((v) => v && (v.created_at || "").startsWith(today));
  const cnt = (arr, f) => arr.filter(f).length;
  const active = cnt(licenses, (l) => l && l.status === "active");
  const expired = cnt(licenses, (l) => l && l.status === "expired");
  const revoked = cnt(licenses, (l) => l && l.status === "revoked");
  const activeProjects = cnt(projectList, (p) => p && p.status === "active");
  const recentEvents = events.slice(0, 8);

  const cards = `
    <div class="grid cards-4">
      <div class="card stat"><div class="label">Projects</div><div class="value">${projectList.length}</div>
        <div class="delta">${activeProjects} active</div><div class="ico blue">${I.folder}</div></div>
      <div class="card stat"><div class="label">Active licenses</div><div class="value">${active}</div>
        <div class="delta">${cnt(licenses, (l) => l.status === "pending")} pending</div><div class="ico green">${I.key}</div></div>
      <div class="card stat"><div class="label">Expired / revoked</div><div class="value">${expired + revoked}</div>
        <div class="delta">${expired} expired · ${revoked} revoked</div><div class="ico amber">${I.alert}</div></div>
      <div class="card stat"><div class="label">Verifications today</div><div class="value">${todayVerifs.length}</div>
        <div class="delta">${cnt(todayVerifs, (v) => v.result === "failed")} failed</div><div class="ico violet">${I.pulse}</div></div>
    </div>`;

  const eventRow = (e) => `<tr>
    <td><span class="sev-${esc(e.severity)}">${badge({ critical: "danger", warning: "warn", info: "info" }[e.severity] || "muted", e.severity)}</span></td>
    <td class="mono">${esc(e.type)}</td>
    <td class="muted small">${esc((e.detail || "").slice(0, 90))}</td>
    <td class="mono">${esc(e.project_id || "—")}</td>
    <td class="muted">${fmtAgo(e.created_at)}</td></tr>`;

  const projRow = (p) => `<tr>
    <td><a href="#/projects/${esc(p.id)}" class="mono" style="color:var(--accent)">${esc(p.id)}</a>
        <div class="faint small">${esc(p.name)}</div></td>
    <td>${badge("muted", p.status)}</td>
    <td class="num">${p.file_count}</td>
    <td class="num">${p.license_count}</td>
    <td class="num">${p.build_count}</td>
    <td class="muted">${fmtAgo(p.updated_at)}</td></tr>`;

  return {
    title: "Dashboard",
    html: `
      ${cards}
      <div class="grid cards-2" style="margin-top:16px">
        <div class="card">
          <h3>Recent projects</h3>
          ${projectList.length ? `<div class="tbl-wrap" style="border:0"><table class="tbl">
            <thead><tr><th>Project</th><th>Status</th><th>Files</th><th>Licenses</th><th>Builds</th><th>Updated</th></tr></thead>
            <tbody>${projectList.slice(0, 6).map(projRow).join("")}</tbody></table></div>`
            : emptyState("folder", "No projects yet", "Create a project and upload a website to get started.",
              `<a class="btn primary" href="#/upload">${I.plus} New project</a>`)}
        </div>
        <div class="card">
          <h3>Latest security events</h3>
          ${isAdmin
            ? (recentEvents.length ? `<div class="tbl-wrap" style="border:0"><table class="tbl">
                <thead><tr><th>Sev</th><th>Type</th><th>Detail</th><th>Project</th><th>When</th></tr></thead>
                <tbody>${recentEvents.map(eventRow).join("")}</tbody></table></div>
                <div style="margin-top:12px"><a class="btn sm" href="#/events">View all events</a></div>`
              : emptyState("shield", "No security events", "Verification failures, tamper detections and admin actions will appear here."))
            : emptyState("lock", "Admin only", "Security event monitoring is available to admin accounts.")}
        </div>
      </div>`,
  };
};

/* ================= PROJECTS LIST ================= */
SFG.pages["/projects"] = async (r) => {
  const data = await api("GET", "/api/v1/projects?q=" + encodeURIComponent(r.params.get("q") || ""));
  const projectList = asList(data, "projects");
  const isAdmin = ["super_admin", "admin"].includes(SFG.user.role);
  const row = (p) => `<tr>
    <td><a href="#/projects/${esc(p.id)}" class="mono" style="color:var(--accent)">${esc(p.id)}</a>
      <div class="faint small">${esc(p.name)}</div></td>
    <td>${badge(p.status === "active" ? "ok" : "muted", p.status)}</td>
    <td>${badge("muted", p.protection_level)}</td>
    <td class="num">${p.file_count}</td>
    <td class="num">${p.license_count}</td>
    <td class="num">${p.build_count}</td>
    <td class="mono">${esc(p.owner_email || "—")}</td>
    <td class="muted">${fmtDate(p.created_at)}</td>
    <td><div class="row-actions">
      <a class="btn sm ghost" href="#/projects/${esc(p.id)}?tab=builds">${I.play}</a>
      ${isAdmin ? `<button class="btn sm ghost" data-act="archive" data-id="${esc(p.id)}" data-status="${esc(p.status)}" title="${p.status === "archived" ? "Restore" : "Archive"}">${I.box}</button>` : ""}
    </div></td></tr>`;
  return {
    title: "Projects",
    html: `
      <div class="filterbar">
        <input class="input" id="pq" placeholder="Search projects…" value="${esc(r.params.get("q") || "")}">
        <div class="spacer"></div>
        <a class="btn primary" href="#/upload">${I.plus} New project</a>
      </div>
      ${projectList.length ? `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Project</th><th>Status</th><th>Protection</th><th>Files</th><th>Licenses</th><th>Builds</th><th>Owner</th><th>Created</th><th></th></tr></thead>
        <tbody>${projectList.map(row).join("")}</tbody></table></div>`
        : emptyState("folder", "No projects found", "Upload a website project (ZIP or folder) to scan, protect and license it.",
          `<a class="btn primary" href="#/upload">${I.upload} Upload a project</a>`)}
      <div id="projActions"></div>`,
    onReady: () => {
      const inp = qs("#pq");
      let t;
      inp.oninput = () => { clearTimeout(t); t = setTimeout(() => nav("/projects?q=" + encodeURIComponent(inp.value)), 350); };
      qsa("[data-act=archive]").forEach((b) => (b.onclick = () => {
        const arch = b.dataset.status !== "archived";
        confirmModal({
          title: arch ? "Archive project" : "Restore project",
          message: arch ? "Archived projects are excluded from normal workflows. Continue?" : "Restore this project to active?",
          confirmLabel: arch ? "Archive" : "Restore",
          onConfirm: async () => {
            try { await api("POST", `/api/v1/projects/${b.dataset.id}/archive`); toast("Project " + (arch ? "archived" : "restored"), "ok"); router(); }
            catch (e) { toast(e.message, "err"); }
          },
        });
      }));
    },
  };
};

/* ================= UPLOAD WIZARD ================= */
SFG.pages["/upload"] = async () => {
  const projects = await api("GET", "/api/v1/projects?mine=true");
  const list = asList(projects, "projects").filter((p) => p && p.status === "active");
  return {
    title: "Upload project",
    html: `
      <div class="grid cards-2">
        <div class="card">
          <h3>1 · Project</h3>
          <label class="f">Target project</label>
          <select class="input" id="upProject">
            ${list.map((p) => `<option value="${esc(p.id)}">${esc(p.id)} — ${esc(p.name)}</option>`).join("") ||
              `<option value="">Create a project first</option>`}
          </select>
          ${list.length ? "" : `<div class="callout blue">No active projects. <a href="#/projects">Create one</a> (or use “Quick create” below).</div>`}
          ${list.length ? "" : `
            <label class="f">Quick create — name</label>
            <input class="input" id="quickName" placeholder="e.g. Restaurant Website">
            <div style="margin-top:12px"><button class="btn" id="quickCreate">Create project</button></div>`}
          <div class="callout blue">A new upload replaces the project's current source files. The previous file index is kept for comparison.</div>
        </div>
        <div class="card">
          <h3>2 · Upload method</h3>
          <div id="upZipWrap">
            <label class="f">ZIP upload <span class="faint">(always available — recommended on mobile)</span></label>
            <div class="dropzone" id="dz">
              ${I.upload}
              <div class="big">Drop ZIP here or click to browse</div>
              <div class="sm">Max size from settings · path traversal &amp; duplicate entries are rejected</div>
            </div>
            <input type="file" id="zipInput" accept=".zip,application/zip" style="display:none">
            <div id="zipProgress" style="margin-top:14px"></div>
          </div>
          <hr style="border:0;border-top:1px solid var(--border);margin:20px 0">
          <div id="upFolderWrap">
            <label class="f">Select folder <span class="faint">(desktop browsers; falls back to ZIP otherwise)</span></label>
            <div style="display:flex;gap:10px;align-items:center">
              <input type="file" id="dirInput" webkitdirectory multiple style="display:none">
              <button class="btn" id="pickDir">${I.folder} Select folder</button>
              <span class="muted small" id="dirStatus"></span>
            </div>
            <div id="dirProgress" style="margin-top:14px"></div>
          </div>
        </div>
      </div>
      <div class="card" id="upResult" style="margin-top:16px;display:none"></div>`,
    onReady: () => {
      const projectId = () => qs("#upProject")?.value;
      if (qs("#quickCreate")) qs("#quickCreate").onclick = async () => {
        const name = qs("#quickName").value.trim();
        if (!name) return toast("Enter a project name", "warn");
        try {
          const d = await api("POST", "/api/v1/projects", { name });
          const sel = qs("#upProject");
          const opt = document.createElement("option");
          opt.value = d.project.id; opt.textContent = d.project.id + " — " + d.project.name;
          sel.appendChild(opt); sel.value = d.project.id;
          toast("Project created", "ok");
        } catch (e) { toast(e.message, "err"); }
      };

      const result = (d) => {
        const el = qs("#upResult");
        el.style.display = "block";
        el.innerHTML = `<h3>Upload complete</h3>
          <div class="detail-grid">
            <div class="item"><div class="k">Files extracted</div><div class="v">${d.extracted}</div></div>
            <div class="item"><div class="k">Files scanned</div><div class="v">${d.scan_summary.file_count}</div></div>
            <div class="item"><div class="k">Sensitive files</div><div class="v">${d.scan_summary.sensitive_file_count}</div></div>
            <div class="item"><div class="k">Credential-looking values</div><div class="v">${d.scan_summary.secret_finding_count} <span class="faint">(masked)</span></div></div>
          </div>
          <div style="margin-top:16px;display:flex;gap:10px">
            <a class="btn primary" href="#/projects/${esc(projectId())}?tab=scan">${I.search} View scan report</a>
            <a class="btn" href="#/projects/${esc(projectId())}?tab=protection">${I.shield} Configure protection</a>
          </div>`;
      };

      /* --- ZIP upload --- */
      const dz = qs("#dz"), zipInput = qs("#zipInput");
      dz.onclick = () => zipInput.click();
      ["dragover", "dragenter"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("over"); }));
      ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("over"); }));
      dz.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) doZip(f); });
      zipInput.onchange = () => { if (zipInput.files[0]) doZip(zipInput.files[0]); };

      async function doZip(file) {
        const pid = projectId();
        if (!pid) return toast("Select a project first", "warn");
        if (!file.name.toLowerCase().endsWith(".zip")) return toast("Only .zip files are accepted", "err");
        const bar = qs("#zipProgress");
        const xhr = new XMLHttpRequest();
        bar.innerHTML = `<div class="small muted">Uploading ${esc(file.name)} (${fmtBytes(file.size)})…</div>
          <div class="pbar" style="margin-top:8px"><div style="width:0%"></div></div>`;
        const fd = new FormData(); fd.append("file", file);
        xhr.open("POST", `/api/v1/projects/${pid}/upload/zip`);
        xhr.withCredentials = true;
        xhr.setRequestHeader("X-CSRF-Token", SFG.csrf);
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) qs(".pbar > div", bar).style.width = Math.round((e.loaded / e.total) * 100) + "%";
        };
        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            bar.innerHTML = `<div class="small" style="color:var(--ok)">${I.check} Upload complete — scanning…</div>`;
            try { result(JSON.parse(xhr.responseText)); } catch (e) { }
          } else {
            let msg = "Upload failed";
            try { msg = JSON.parse(xhr.responseText).detail?.message || msg; } catch (e) { }
            bar.innerHTML = `<div class="callout red">${esc(msg)}</div>`;
            toast(msg, "err");
          }
        };
        xhr.onerror = () => { bar.innerHTML = `<div class="callout red">Network error during upload.</div>`; };
        xhr.send(fd);
      }

      /* --- folder upload --- */
      const dirInput = qs("#dirInput");
      qs("#pickDir").onclick = () => dirInput.click();
      dirInput.onchange = async () => {
        const files = Array.from(dirInput.files || []);
        const st = qs("#dirStatus");
        if (!files.length) return;
        if (!("webkitdirectory" in dirInput) && files.every((f) => f.webkitRelativePath === undefined)) {
          st.textContent = "This browser does not support folder upload — use ZIP upload instead.";
          return toast("Folder upload not supported here; ZIP upload remains available.", "warn");
        }
        const total = files.reduce((s, f) => s + f.size, 0);
        const pid = projectId();
        if (!pid) return toast("Select a project first", "warn");
        st.textContent = `${files.length} files · ${fmtBytes(total)} — starting…`;
        try {
          await api("POST", `/api/v1/projects/${pid}/upload/folder/start`, { file_count: files.length });
        } catch (e) { st.textContent = e.message; return; }
        const bar = qs("#dirProgress");
        bar.innerHTML = `<div class="pbar"><div style="width:0%"></div></div>
          <div class="small muted" style="margin-top:8px" id="dirMsg">0 / ${files.length} uploaded</div>`;
        let done = 0;
        const BATCH = 4;
        let failed = 0;
        for (let i = 0; i < files.length; i += BATCH) {
          const chunk = files.slice(i, i + BATCH);
          const results = await Promise.all(chunk.map(async (f) => {
            const fd = new FormData();
            fd.append("relpath", f.webkitRelativePath || f.name);
            fd.append("file", f);
            try {
              await api("POST", `/api/v1/projects/${pid}/upload/file?relpath=${encodeURIComponent(f.webkitRelativePath || f.name)}`, fd);
              return true;
            } catch (e) { return false; }
          }));
          done += results.filter(Boolean).length;
          failed += results.filter((x) => !x).length;
          qs(".pbar > div", bar).style.width = Math.round(((i + chunk.length) / files.length) * 100) + "%";
          qs("#dirMsg").textContent = `${i + chunk.length} / ${files.length} uploaded${failed ? ` · ${failed} failed` : ""}`;
        }
        if (failed) { st.textContent = `${failed} file(s) failed — start over to keep the folder consistent.`; toast("Some files failed", "err"); return; }
        try {
          const d = await api("POST", `/api/v1/projects/${pid}/upload/folder/finish`, {});
          result(d);
          st.textContent = "Complete";
        } catch (e) { toast(e.message, "err"); }
      };
    },
  };
};

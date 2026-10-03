/* Sentinel-AI dashboard.
 *
 * Vanilla JS, no build step, served from the same origin as the API so there
 * is no CORS layer to reason about. Charts are hand-rolled inline SVG: there
 * are three of them, and a charting library would be more code than the charts.
 *
 * Risk bands use the reserved STATUS palette and always carry their text
 * label -- a band is a state, not a series, and a status colour must never be
 * the only channel carrying meaning.
 */

const BANDS = ["critical", "high", "medium", "low"];

/* Bands map to the reserved STATUS slots, not categorical ones: a band is a
 * state, not a series.
 *
 * The palette validator FAILs two checks on these four, both by design and
 * both documented in the palette reference: `warning` and `serious` are
 * sub-3:1 on the light surface, and the warning<->serious pair measures
 * normal-vision Delta E 13.6, under the 15 floor. The mandated mitigation is
 * that colour is never the only channel.
 *
 * So: every band is rendered with its NAME as text -- `bandChip()` emits the
 * label beside the dot, and the band chart labels each row. Do not remove
 * those labels to "clean up"; they are the accessibility channel, not
 * decoration. Run:
 *   node scripts/validate_palette.js "#d03b3b,#ec835a,#fab219,#0ca30c" --mode light
 */
const BAND_COLOR = {
  critical: "var(--critical)", high: "var(--serious)",
  medium: "var(--warning)", low: "var(--good)",
};

const $ = (sel, root = document) => root.querySelector(sel);
const fmt = (n) => (n == null ? "—" : Number(n).toLocaleString());
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, params) {
  const url = new URL(path, location.origin);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  });
  const res = await fetch(url);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail ?? detail; } catch { /* non-JSON */ }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}

const bandChip = (b) =>
  `<span class="band ${esc(b)}"><span class="dot"></span>${esc(b)}</span>`;

/* ---------------------------------------------------------------- charts -- */

/** Horizontal bars. Each row is directly labelled, so no legend box.
 *
 *  Bars carry a minimum visible width. These counts span 438 to 62,580 -- a
 *  143x range -- so a purely proportional bar renders `critical` as a hairline,
 *  making the most important band the least visible. The number beside each bar
 *  is the precise channel; the bar is the comparison, and a floor keeps every
 *  category present without distorting the ones that matter.
 */
function hbars(rows, { value, label, color, note }) {
  const max = Math.max(...rows.map(value), 1);
  const rowH = 30, barH = 10, labelW = 90, valueW = 74;
  const MIN_PCT = 1.5;                       // floor so no category vanishes
  const h = rows.length * rowH;
  const bars = rows.map((r, i) => {
    const y = i * rowH + (rowH - barH) / 2;
    const raw = (value(r) / max) * 100;
    const pct = value(r) > 0 ? Math.max(raw, MIN_PCT) : 0;
    return `
      <text x="0" y="${y + barH / 2 + 4}" style="fill:var(--ink-2)">${esc(label(r))}</text>
      <rect class="mark" x="${labelW}" y="${y}" rx="4" height="${barH}"
            width="calc((100% - ${labelW + valueW}px) * ${pct / 100})"
            fill="${color(r)}"><title>${esc(label(r))}: ${fmt(value(r))}</title></rect>
      <text class="val" x="100%" y="${y + barH / 2 + 4}" text-anchor="end"
        >${fmt(value(r))}</text>`;
  }).join("");
  return `<svg class="chart" style="height:${h}px" role="img"
            aria-label="${esc(note || "")}">${bars}</svg>`;
}

/** Vertical bars, one series. The title names it, so no legend.
 *
 *  The bars are SVG; the x-axis labels are HTML in a flex row underneath.
 *  SVG <text x> does not accept calc() -- unlike <rect>, whose x/width are CSS
 *  geometry properties -- so calc-positioned labels all collapse to x=0 and
 *  overlap. Laying them out in HTML also keeps them at native size instead of
 *  scaling with a viewBox.
 */
function vbars(rows, { value, label, note }) {
  const max = Math.max(...rows.map(value), 1);
  const h = 170, top = 10, gutter = 54;
  const plot = h - top;
  const n = rows.length || 1;
  const slot = 100 / n, gap = 2;             // 2px surface gap between bars

  const ticks = [0, 0.5, 1].map((t) => {
    const y = top + plot * (1 - t);
    return `<line class="gridline" x1="0" y1="${y}" y2="${y}"
              x2="calc(100% - ${gutter}px)"/>
            <text class="val" x="100%" y="${y + 3}" text-anchor="end"
              >${fmt(Math.round(max * t))}</text>`;
  }).join("");

  const bars = rows.map((r, i) => {
    const v = value(r);
    const bh = v > 0 ? Math.max((v / max) * plot, 2) : 0;
    return `<rect class="mark" rx="4" fill="var(--blue)"
              x="calc((100% - ${gutter}px) * ${i * slot / 100} + ${gap}px)"
              width="calc((100% - ${gutter}px) * ${slot / 100} - ${gap * 2}px)"
              y="${top + plot - bh}" height="${bh}"
              ><title>${esc(label(r))}: ${fmt(v)}</title></rect>`;
  }).join("");

  const axis = `<div style="display:flex;padding-right:${gutter}px;margin-top:4px">
    ${rows.map((r) => `<span style="flex:1;text-align:center;font-size:11px;
      color:var(--ink-muted);overflow:hidden">${esc(label(r))}</span>`).join("")}
  </div>`;

  return `<svg class="chart" style="height:${h}px;margin-bottom:0" role="img"
            aria-label="${esc(note || "")}">${ticks}
            <line class="baseline" x1="0" x2="calc(100% - ${gutter}px)"
              y1="${top + plot}" y2="${top + plot}"/>
            ${bars}</svg>${axis}`;
}

/* -------------------------------------------------------------- overview -- */

async function renderOverview() {
  const el = $("#view-overview");
  el.innerHTML = `<div class="loading">Loading…</div>`;
  try {
    const [stats, bands, backlog, health] = await Promise.all([
      api("/stats", { include_fix_actions: true }),
      api("/stats/bands"),
      api("/stats/backlog", { weeks: 10 }),
      api("/health"),
    ]);
    const crit = bands.find((b) => b.band === "critical") || { findings: 0, kev: 0 };
    const overdue = bands.reduce((a, b) => a + b.overdue, 0);
    const ratio = stats.fix_actions
      ? (stats.findings_open / stats.fix_actions).toFixed(0) : "—";

    el.innerHTML = `
      <h1>Overview</h1>
      <p class="sub">A scanner over this fleet produced ${fmt(stats.findings_open)} open
        findings. Nobody triages that. Everything below is about turning it into
        work someone actually does.</p>

      <div class="banner">
        <div><b>First time here?</b>
          <p>The interactive tutorial walks the real data and shows why each stage exists.</p></div>
        <button class="btn primary" id="banner-tour">Start tutorial</button>
      </div>

      <div class="tiles">
        <div class="card tile"><div class="label">Open findings</div>
          <div class="value">${fmt(stats.findings_open)}</div>
          <div class="note">across ${fmt(stats.assets)} hosts</div></div>
        <div class="card tile"><div class="label">Fix actions</div>
          <div class="value">${fmt(stats.fix_actions)}</div>
          <div class="note">${ratio}× fewer things to do</div></div>
        <div class="card tile"><div class="label">Critical</div>
          <div class="value" style="color:var(--critical)">${fmt(crit.findings)}</div>
          <div class="note">${fmt(crit.kev)} known-exploited</div></div>
        <div class="card tile"><div class="label">Overdue</div>
          <div class="value">${fmt(overdue)}</div>
          <div class="note">past their policy SLA</div></div>
        <div class="card tile"><div class="label">Plans</div>
          <div class="value">${fmt(stats.plans_grounded)}</div>
          <div class="note">of ${fmt(stats.plans)} passed grounding</div></div>
      </div>

      <div class="grid-2" style="margin-top:10px">
        <div class="card">
          <div class="chart-title">Open findings by risk band</div>
          <div class="chart-note">Band is computed by policy from CVSS, KEV, EPSS,
            exposure and asset value — never by a model.</div>
          ${hbars(bands, {
            value: (r) => r.findings, label: (r) => r.band,
            color: (r) => BAND_COLOR[r.band],
            note: "Open findings by risk band",
          })}
        </div>
        <div class="card">
          <div class="chart-title">Due-date backlog</div>
          <div class="chart-note">Findings bucketed by the week they fall due.</div>
          ${backlog.length
            ? vbars(backlog, {
                value: (r) => r.findings,
                label: (r) => r.week.slice(5),
                note: "Open findings by due week",
              })
            : `<div class="empty">No findings due in this window.</div>`}
        </div>
      </div>

      <h2>Pipeline health</h2>
      <div class="card">
        <table><tbody>
          <tr><td>Postgres</td><td class="num">${health.postgres
            ? '<span class="pill ok">up</span>' : '<span class="pill kev">down</span>'}</td></tr>
          <tr><td>Qdrant <span style="color:var(--ink-muted)">(optional — pgvector is primary)</span></td>
            <td class="num">${health.qdrant
              ? '<span class="pill ok">up</span>' : '<span class="pill">not running</span>'}</td></tr>
          <tr><td>Corpus chunks</td><td class="num">${fmt(health.corpus_chunks)}</td></tr>
          <tr><td>Schema revision</td><td class="num mono">${esc(health.migration || "—")}</td></tr>
          <tr><td>Enriched CVEs</td><td class="num">${fmt(stats.cves)}
            <span style="color:var(--ink-muted)">(${fmt(stats.kev_cves)} in CISA KEV)</span></td></tr>
        </tbody></table>
      </div>`;
    $("#banner-tour").onclick = startTour;
  } catch (e) {
    el.innerHTML = `<h1>Overview</h1><p class="err">Could not load: ${esc(e.message)}</p>`;
  }
}

/* ---------------------------------------------------------------- triage -- */

const triageState = { band: "", team: "", sort: "risk", kev_only: false, overdue_only: false };

async function renderTriage() {
  const el = $("#view-triage");
  if (!$("#triage-table")) {
    el.innerHTML = `
      <h1>Triage queue</h1>
      <p class="sub">Open findings, most urgent first. Priority combines severity with
        whether the flaw is <em>actually</em> being exploited — a CVSS 9.8 nobody has
        weaponised ranks below a CVSS 7.2 in CISA KEV.</p>
      <div class="filters">
        <select id="f-band"><option value="">All bands</option>
          ${BANDS.map((b) => `<option value="${b}">${b}</option>`).join("")}</select>
        <select id="f-team"><option value="">All teams</option></select>
        <select id="f-sort">
          <option value="risk">Sort: risk score</option>
          <option value="due_date">Sort: due date</option>
          <option value="epss">Sort: exploit probability</option></select>
        <label class="inline"><input type="checkbox" id="f-kev"> KEV only</label>
        <label class="inline"><input type="checkbox" id="f-overdue"> Overdue only</label>
      </div>
      <div class="card scroll-x" id="triage-table"><div class="loading">Loading…</div></div>
      <details class="help"><summary>What do these columns mean?</summary>
        <div><b>Risk</b> is 0–100 from four capped components (severity 40, exploitation 30,
        exposure 15, asset value 15). <b>EPSS</b> is the probability of exploitation in the
        next 30 days. <b>KEV</b> means CISA has observed it exploited in the wild. <b>Due</b>
        is computed from first detection by policy. Click any row to see the arithmetic.</div>
      </details>`;
    $("#f-band").onchange = (e) => { triageState.band = e.target.value; loadTriage(); };
    $("#f-team").onchange = (e) => { triageState.team = e.target.value; loadTriage(); };
    $("#f-sort").onchange = (e) => { triageState.sort = e.target.value; loadTriage(); };
    $("#f-kev").onchange = (e) => { triageState.kev_only = e.target.checked; loadTriage(); };
    $("#f-overdue").onchange = (e) => { triageState.overdue_only = e.target.checked; loadTriage(); };
    api("/teams").then((teams) => {
      $("#f-team").insertAdjacentHTML("beforeend",
        teams.map((t) => `<option value="${esc(t.owner_team)}">${esc(t.owner_team)}</option>`).join(""));
    }).catch(() => {});
  }
  loadTriage();
}

async function loadTriage() {
  const host = $("#triage-table");
  host.innerHTML = `<div class="loading">Loading…</div>`;
  try {
    const rows = await api("/findings", { ...triageState, limit: 60 });
    if (!rows.length) { host.innerHTML = `<div class="empty">No findings match.</div>`; return; }
    host.innerHTML = `<table><thead><tr>
        <th>Host</th><th>CVE</th><th>Package</th><th class="num">Risk</th><th>Band</th>
        <th class="num">CVSS</th><th class="num">EPSS</th><th>Flags</th>
        <th>Due</th><th>Team</th></tr></thead><tbody>
      ${rows.map((r) => `
        <tr class="clickable" data-finding="${r.finding_id}">
          <td class="mono">${esc(r.hostname)}</td>
          <td class="mono">${esc(r.cve_id)}</td>
          <td class="truncate" title="${esc(r.package_name)}">${esc(r.package_name)}</td>
          <td class="num"><b>${r.risk_score.toFixed(1)}</b></td>
          <td>${bandChip(r.risk_band)}</td>
          <td class="num">${r.cvss_v31_score ?? "—"}</td>
          <td class="num">${r.epss_score != null ? r.epss_score.toFixed(3) : "—"}</td>
          <td>${r.kev_listed ? '<span class="pill kev">KEV</span>' : ""}
              ${r.internet_facing ? '<span class="pill">internet</span>' : ""}</td>
          <td class="num">${esc(r.due_date)}${r.overdue
            ? ' <span class="pill kev">overdue</span>' : ""}</td>
          <td>${esc(r.owner_team)}</td>
        </tr>`).join("")}
      </tbody></table>`;
    host.querySelectorAll("tr[data-finding]").forEach((tr) => {
      tr.onclick = () => showFactors(tr.dataset.finding);
    });
  } catch (e) {
    host.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  }
}

/* --------------------------------------------------------------- drawer --- */

function openDrawer(html) {
  $("#drawer-root").innerHTML =
    `<div class="drawer-back"></div><aside class="drawer" role="dialog" aria-modal="true">
       <button class="btn close" id="drawer-close">Close</button>${html}</aside>`;
  const shut = () => { $("#drawer-root").innerHTML = ""; };
  $("#drawer-close").onclick = shut;
  $(".drawer-back").onclick = shut;
  document.addEventListener("keydown", function onEsc(ev) {
    if (ev.key === "Escape") { shut(); document.removeEventListener("keydown", onEsc); }
  });
}

async function showFactors(findingId) {
  openDrawer(`<div class="loading">Loading…</div>`);
  try {
    const f = await api(`/findings/${findingId}/factors`);
    const c = f.factors.components || {};
    const total = Object.values(c).reduce((a, x) => a + (x.points || 0), 0);
    const MAXES = { severity: 40, exploit: 30, exposure: 15, asset: 15 };
    const rows = Object.entries(c).map(([name, d]) => `
      <div class="factor-row">
        <span style="color:var(--ink-2)">${esc(name)}</span>
        <span class="factor-bar"><i style="width:${(d.points / MAXES[name]) * 100}%"></i></span>
        <span class="num mono">${d.points}/${MAXES[name]}</span>
      </div>
      <div style="font-size:12px;color:var(--ink-muted);margin:-2px 0 10px 102px">
        ${esc(d.reason || d.cvss_source || "")}</div>`).join("");
    const sla = f.factors.sla || {};
    const floor = f.factors.band_floor;
    openDrawer(`
      <h3>Why this priority</h3>
      <p class="sub" style="margin:4px 0 0">Finding ${f.finding_id} · policy
        <span class="mono">${esc(f.policy_version)}</span></p>
      <dl class="kv">
        <dt>Risk score</dt><dd><b>${f.risk_score}</b> / 100 → ${bandChip(f.risk_band)}</dd>
        <dt>Due date</dt><dd>${esc(f.due_date)} (${f.sla_days}-day SLA)</dd>
        <dt>SLA rule</dt><dd class="mono">${esc(sla.rule || "—")}</dd>
      </dl>
      <h2 style="margin-top:4px">Components</h2>
      ${rows}
      <div style="border-top:1px solid var(--hairline);padding-top:10px;margin-top:6px">
        <div class="factor-row"><b>total</b><span></span>
          <span class="num mono"><b>${total.toFixed(2)}</b></span></div>
      </div>
      ${floor ? `<p class="sub" style="margin-top:14px">The additive score put this in
        <b>${esc(floor.scored_band)}</b>; the <span class="mono">${esc(floor.rule)}</span>
        floor raised it to <b>${esc(f.risk_band)}</b>. Evidence of active exploitation
        is not allowed to be diluted by low exposure.</p>` : ""}
      ${sla.kev_deadline_passed ? `<p class="sub">CISA's deadline for this CVE was
        <b>${esc(sla.kev_due_date)}</b> — already past when we detected it. That is
        recorded as a compliance breach, but the due date above is a window the
        owner can actually hit.</p>` : ""}
      <h2>Raw factors</h2>
      <pre class="block">${esc(JSON.stringify(f.factors, null, 2))}</pre>`);
  } catch (e) {
    openDrawer(`<h3>Error</h3><p class="err">${esc(e.message)}</p>`);
  }
}

async function showPlan(pkg, version, title) {
  openDrawer(`<div class="loading">Loading…</div>`);
  try {
    const plans = await api("/plans", { grounded_only: false, limit: 200 });
    const p = plans.find((x) => x.package_name === pkg && x.fixed_version === version)
           || plans.find((x) => x.package_name === pkg);
    if (!p) {
      openDrawer(`<h3>${esc(title)}</h3>
        <p class="sub">No remediation plan generated for this package yet.</p>
        <p class="sub">Run <code class="inline">sentinel plan run --band critical</code>
          to generate them. Plans are cached by
          <code class="inline">(cve, package, os_family, fixed_version)</code>, so the
          whole fleet costs about 108 model calls.</p>`);
      return;
    }
    openDrawer(`
      <h3>${esc(p.package_name)} → ${esc(p.fixed_version || "no fix")}</h3>
      <p class="sub" style="margin:4px 0 0">${esc(p.cve_id)} · ${esc(p.os_family)} ·
        model <span class="mono">${esc(p.model)}</span></p>
      <dl class="kv">
        <dt>Grounding</dt><dd>${p.grounding_passed
          ? '<span class="pill ok">passed</span> every CVE id and version appears verbatim in retrieved context'
          : '<span class="pill kev">failed</span> not attached to any ticket'}</dd>
        ${p.grounding_report?.checked_versions?.length
          ? `<dt>Versions checked</dt><dd class="mono">${
              p.grounding_report.checked_versions.map(esc).join(", ")}</dd>` : ""}
        ${p.requires_reboot != null
          ? `<dt>Reboot</dt><dd>${p.requires_reboot ? "required" : "not required"}</dd>` : ""}
      </dl>
      <h2>Plan</h2>
      <pre class="block">${esc(p.plan_markdown)}</pre>
      ${p.grounding_report && !p.grounding_passed
        ? `<h2>Why it was rejected</h2><pre class="block">${
            esc(JSON.stringify(p.grounding_report, null, 2))}</pre>` : ""}`);
  } catch (e) {
    openDrawer(`<h3>Error</h3><p class="err">${esc(e.message)}</p>`);
  }
}

/* ----------------------------------------------------------- fix actions -- */

const actionState = { band: "critical" };

async function renderActions() {
  const el = $("#view-actions");
  if (!$("#actions-table")) {
    el.innerHTML = `
      <h1>Fix actions</h1>
      <p class="sub">The unit a human acts on is the <em>upgrade</em>, not the finding.
        One <code class="inline">apt-get install curl=…</code> closes 15 CVEs on a host,
        so findings are grouped by
        <code class="inline">(team, package, os_family, risk_band)</code>.</p>
      <div class="filters">
        <div class="seg" id="a-band">
          ${["critical", "high", "medium", "low", ""].map((b) =>
            `<button data-band="${b}" aria-pressed="${b === "critical"}">${b || "all"}</button>`).join("")}
        </div>
      </div>
      <div class="card scroll-x" id="actions-table"><div class="loading">Loading…</div></div>
      <details class="help"><summary>Why does the target version differ from the CVE's?</summary>
        <div>Each CVE names the release that first fixed it, but nobody upgrades a package
        seven times. The target is the <b>highest</b> version required across the whole
        package, which is safe for every member; the deadline stays per band. So the
        critical and the low ticket name the same version with different dates — doing the
        urgent one closes the rest. <code class="inline">os_family</code> is in the key too:
        Alpine and Debian version strings are different namespaces.</div>
      </details>`;
    $("#a-band").querySelectorAll("button").forEach((b) => {
      b.onclick = () => {
        $("#a-band").querySelectorAll("button").forEach((x) =>
          x.setAttribute("aria-pressed", x === b));
        actionState.band = b.dataset.band;
        loadActions();
      };
    });
  }
  loadActions();
}

async function loadActions() {
  const host = $("#actions-table");
  host.innerHTML = `<div class="loading">Loading…</div>`;
  try {
    const rows = await api("/fix-actions", { band: actionState.band, limit: 60 });
    if (!rows.length) { host.innerHTML = `<div class="empty">No fix actions.</div>`; return; }
    host.innerHTML = `<table><thead><tr>
        <th>Action</th><th>Band</th><th class="num">Hosts</th><th class="num">CVEs</th>
        <th class="num">Findings</th><th>Due</th><th>Team</th><th>Plan</th></tr></thead><tbody>
      ${rows.map((r) => `
        <tr class="clickable" data-pkg="${esc(r.package_name)}"
            data-ver="${esc(r.fixed_version || "")}" data-title="${esc(r.title)}">
          <td><div class="truncate" title="${esc(r.package_name)}"><b>${esc(r.package_name)}</b></div>
            <div style="color:var(--ink-muted);font-size:12px">
              → ${esc(r.fixed_version || "no fix available")} · ${esc(r.os_family)}</div></td>
          <td>${bandChip(r.risk_band)}</td>
          <td class="num">${fmt(r.asset_count)}${r.internet_facing_count
            ? ` <span class="pill">${r.internet_facing_count} inet</span>` : ""}</td>
          <td class="num">${fmt(r.cve_ids.length)}${r.kev_cve_ids.length
            ? ` <span class="pill kev">${r.kev_cve_ids.length} KEV</span>` : ""}</td>
          <td class="num">${fmt(r.finding_count)}</td>
          <td class="num">${esc(r.due_date)}</td>
          <td>${esc(r.owner_team)}</td>
          <td>${r.plan_grounded ? '<span class="pill ok">grounded</span>'
                : r.has_plan ? '<span class="pill kev">ungrounded</span>'
                : '<span class="pill">none</span>'}</td>
        </tr>`).join("")}
      </tbody></table>`;
    host.querySelectorAll("tr[data-pkg]").forEach((tr) => {
      tr.onclick = () => showPlan(tr.dataset.pkg, tr.dataset.ver || null, tr.dataset.title);
    });
  } catch (e) {
    host.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  }
}

/* -------------------------------------------------------------- retrieval -- */

const searchState = { mode: "hybrid", prefilter: true, backend: "pgvector" };

function renderSearch() {
  const el = $("#view-search");
  if ($("#s-q")) return;
  el.innerHTML = `
    <h1>Retrieval</h1>
    <p class="sub">The corpus the planner reads from. Try
      <b>CVE-2021-44228</b> with <b>dense</b> mode and the prefilter off — it returns
      unrelated <em>vim</em> CVEs, because the Log4j family's descriptions sit at
      0.79–0.84 cosine similarity to each other. Embeddings are weakest at exact
      identifiers, and this domain is made of them.</p>
    <div class="filters">
      <input type="search" id="s-q" value="CVE-2021-44228"
             placeholder="a CVE id, or plain English…">
      <div class="seg" id="s-mode">
        ${["hybrid", "dense", "lexical"].map((m) =>
          `<button data-mode="${m}" aria-pressed="${m === "hybrid"}">${m}</button>`).join("")}
      </div>
      <div class="seg" id="s-backend">
        ${["pgvector", "qdrant"].map((b) =>
          `<button data-backend="${b}" aria-pressed="${b === "pgvector"}">${b}</button>`).join("")}
      </div>
      <label class="inline"><input type="checkbox" id="s-pre" checked> CVE prefilter</label>
      <button class="btn primary" id="s-go">Search</button>
      <button class="btn" id="s-compare">Compare all modes</button>
    </div>
    <div id="s-out"></div>`;
  $("#s-mode").querySelectorAll("button").forEach((b) => {
    b.onclick = () => {
      $("#s-mode").querySelectorAll("button").forEach((x) =>
        x.setAttribute("aria-pressed", x === b));
      searchState.mode = b.dataset.mode; doSearch();
    };
  });
  $("#s-backend").querySelectorAll("button").forEach((b) => {
    b.onclick = () => {
      $("#s-backend").querySelectorAll("button").forEach((x) =>
        x.setAttribute("aria-pressed", x === b));
      searchState.backend = b.dataset.backend; doSearch();
    };
  });
  $("#s-pre").onchange = (e) => { searchState.prefilter = e.target.checked; doSearch(); };
  $("#s-go").onclick = doSearch;
  $("#s-compare").onclick = compareModes;
  $("#s-q").onkeydown = (e) => { if (e.key === "Enter") doSearch(); };
  doSearch();
}

function hitsTable(r) {
  const askedFor = r.prefilter_cves[0]
    || ($("#s-q").value.match(/CVE-\d{4}-\d{4,}/i) || [""])[0].toUpperCase();
  return `<div class="card scroll-x">
    <div class="chart-note" style="margin-bottom:10px">
      ${esc(r.mode)} · ${esc(r.backend)} ·
      prefilter ${r.prefilter_cves.length ? esc(r.prefilter_cves.join(", ")) : "off"} ·
      ${r.total_ms} ms ${Object.entries(r.timings)
        .map(([k, v]) => `<span style="color:var(--ink-muted)">${esc(k)} ${v}</span>`).join(" · ")}
    </div>
    <table><thead><tr><th class="num">RRF</th><th class="num">lex</th>
      <th class="num">dense</th><th>CVE</th><th>Chunk</th></tr></thead><tbody>
    ${r.hits.map((h) => {
      const wrong = askedFor && !h.cve_ids.includes(askedFor);
      return `<tr>
        <td class="num mono">${h.rrf_score.toFixed(5)}</td>
        <td class="num">${h.lexical_rank ?? "—"}</td>
        <td class="num">${h.dense_rank ?? "—"}</td>
        <td class="mono" ${wrong ? 'style="color:var(--critical)"' : ""}>
          ${esc(h.cve_ids.join(", "))}${wrong ? " ✕" : ""}</td>
        <td style="font-size:12.5px;color:var(--ink-2)">${esc(h.content.slice(0, 150))}…</td>
      </tr>`;
    }).join("")}
    </tbody></table>
    ${askedFor && r.hits.some((h) => !h.cve_ids.includes(askedFor))
      ? `<p class="sub" style="margin:12px 0 0;color:var(--critical)">Rows marked ✕ are a
          <b>different CVE</b> than the one asked for. A planner handed that context writes
          a confident, well-cited ticket about the wrong software.</p>` : ""}
  </div>`;
}

async function doSearch() {
  const out = $("#s-out");
  const q = $("#s-q").value.trim();
  if (!q) { out.innerHTML = `<div class="empty">Enter a query.</div>`; return; }
  out.innerHTML = `<div class="loading">Searching…</div>`;
  try {
    out.innerHTML = hitsTable(await api("/search", { q, k: 6, ...searchState }));
  } catch (e) {
    out.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  }
}

async function compareModes() {
  const out = $("#s-out");
  const q = $("#s-q").value.trim();
  if (!q) return;
  out.innerHTML = `<div class="loading">Running all three modes…</div>`;
  const combos = [
    ["dense only, no prefilter", { mode: "dense", prefilter: false }],
    ["lexical only", { mode: "lexical", prefilter: false }],
    ["hybrid, no prefilter", { mode: "hybrid", prefilter: false }],
    ["hybrid + prefilter", { mode: "hybrid", prefilter: true }],
  ];
  try {
    const results = await Promise.all(combos.map(([, p]) =>
      api("/search", { q, k: 3, backend: searchState.backend, ...p })));
    const asked = (q.match(/CVE-\d{4}-\d{4,}/i) || [""])[0].toUpperCase();
    out.innerHTML = `<div class="card">
      <div class="chart-title">Same query, four retrieval strategies</div>
      <div class="chart-note">“On target” counts hits whose CVE matches the one asked for.</div>
      <table style="margin-top:12px"><thead><tr><th>Strategy</th><th>Top hit</th>
        <th class="num">On target</th><th class="num">ms</th></tr></thead><tbody>
      ${results.map((r, i) => {
        const top = r.hits[0]?.cve_ids.join(", ") || "—";
        const ok = asked ? r.hits.filter((h) => h.cve_ids.includes(asked)).length : null;
        const bad = asked && top !== asked;
        return `<tr><td>${esc(combos[i][0])}</td>
          <td class="mono" ${bad ? 'style="color:var(--critical)"' : ""}>${esc(top)}
            ${bad ? "✕" : ""}</td>
          <td class="num">${ok == null ? "—" : `${ok}/${r.hits.length}`}</td>
          <td class="num">${r.total_ms}</td></tr>`;
      }).join("")}
      </tbody></table></div>`;
  } catch (e) {
    out.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  }
}

/* ----------------------------------------------------------------- teams -- */

async function renderTeams() {
  const el = $("#view-teams");
  el.innerHTML = `<h1>Teams</h1>
    <p class="sub">What each owner is on the hook for. Tickets are addressed to a team,
      not a host, because the upgrade is performed once per team per package.</p>
    <div class="loading">Loading…</div>`;
  try {
    const teams = await api("/teams");
    el.innerHTML = `<h1>Teams</h1>
      <p class="sub">What each owner is on the hook for. Tickets are addressed to a team,
        not a host, because the upgrade is performed once per team per package.</p>
      <div class="card">
        <div class="chart-title">Critical findings by team</div>
        <div class="chart-note">Sorted by critical count — where to look first.</div>
        ${hbars(teams, {
          value: (t) => t.critical, label: (t) => t.owner_team,
          color: () => "var(--critical)", note: "Critical findings by team",
        })}
      </div>
      <div class="card scroll-x" style="margin-top:10px">
        <table><thead><tr><th>Team</th><th>Contact</th><th class="num">Open</th>
          <th class="num">Hosts</th><th class="num">Critical</th><th class="num">High</th>
          <th class="num">Overdue</th><th>Next due</th></tr></thead><tbody>
        ${teams.map((t) => `<tr class="clickable" data-team="${esc(t.owner_team)}">
          <td><b>${esc(t.owner_team)}</b></td>
          <td class="mono" style="font-size:12px">${esc(t.owner_email)}</td>
          <td class="num">${fmt(t.open_findings)}</td>
          <td class="num">${fmt(t.assets)}</td>
          <td class="num" style="color:var(--critical)"><b>${fmt(t.critical)}</b></td>
          <td class="num">${fmt(t.high)}</td>
          <td class="num">${fmt(t.overdue)}</td>
          <td class="num">${esc(t.next_due ?? "—")}</td>
        </tr>`).join("")}
        </tbody></table></div>`;
    el.querySelectorAll("tr[data-team]").forEach((tr) => {
      tr.onclick = () => {
        triageState.team = tr.dataset.team;
        triageState.band = "";
        show("triage");
        setTimeout(() => { const s = $("#f-team"); if (s) s.value = tr.dataset.team; }, 50);
      };
    });
  } catch (e) {
    el.innerHTML = `<h1>Teams</h1><p class="err">${esc(e.message)}</p>`;
  }
}

/* ----------------------------------------------------------------- guide -- */

function renderGuide() {
  const el = $("#view-guide");
  if (el.dataset.done) return;
  el.dataset.done = "1";
  el.innerHTML = `
    <h1>Guide</h1>
    <p class="sub">What this system does, and how to verify each claim yourself.</p>
    <div class="banner">
      <div><b>Interactive tutorial</b>
        <p>Walks the real data and stops at the evidence for each stage.</p></div>
      <button class="btn primary" id="guide-tour">Start tutorial</button>
    </div>

    <h2>The problem</h2>
    <p class="sub">A scanner over a real fleet produces tens of thousands of findings.
      The queue becomes unreadable, so it goes unread, and the two findings that matter
      sit beside forty thousand that don't. Three things have to happen:
      <b>prioritise</b>, <b>collapse</b>, <b>explain</b>.</p>

    <h2>The rule everything follows</h2>
    <p class="sub">Vulnerability management is an audit surface. A due date is a
      commitment someone is measured against. If a model invents a patch version, that
      is not a bug — it is a compliance defect an engineer will act on. So risk scores
      and due dates are computed by <b>deterministic policy</b> and are fully
      reproducible; the model writes prose, and a <b>non-LLM check</b> verifies every
      identifier in it. The model proposes; deterministic code disposes.</p>

    <h2>How to verify it</h2>
    <ol class="steps-list">
      <li><b>Priority isn't CVSS.</b> Go to <b>Triage queue</b>, sort by exploit
        probability. CVE-2021-45105 is CVSS 5.9 — a "medium" — with an EPSS of 0.99999.
        It correctly outranks many HIGHs.</li>
      <li><b>See the arithmetic.</b> Click any row. The drawer shows all four components,
        the SLA rule that set the date, and the raw factors JSON. No model produced any
        of those numbers.</li>
      <li><b>Watch findings collapse.</b> <b>Fix actions</b> turns the open findings into
        the upgrades a human performs — roughly a 60× reduction. One
        <code class="inline">apt-get install</code> closes many CVEs.</li>
      <li><b>Break retrieval on purpose.</b> On <b>Retrieval</b>, search
        <code class="inline">CVE-2021-44228</code> in <b>dense</b> mode with the prefilter
        off. It returns unrelated vim CVEs. Then press <b>Compare all modes</b> to see
        why hybrid retrieval plus a CVE prefilter is a correctness requirement here, not
        an optimisation.</li>
      <li><b>Check the grounding gate.</b> In <b>Fix actions</b>, click a row with a
        <span class="pill ok">grounded</span> plan. Every CVE id and version in it appears
        verbatim in retrieved context — verified by a regex, not requested in a prompt.</li>
    </ol>

    <h2>Known limits, stated plainly</h2>
    <p class="sub">The gate catches fabrication, not vagueness — "apply vendor updates"
      invents nothing and is useless, which is what the eval rubric measures separately
      (<code class="inline">sentinel eval run</code>). The fleet is synthetic but the
      vulnerabilities are real. Free-tier model terms generally permit training on
      submitted data, so real asset inventory belongs on a self-hosted or paid model.</p>

    <h2>Running the pipeline</h2>
    <pre class="block">sentinel fleet generate      # synthetic hosts + SBOMs
sentinel scan                # Trivy -> findings
sentinel enrich all          # KEV + EPSS (bulk), NVD (rate limited)
sentinel score               # deterministic risk + SLA
sentinel rag build           # chunk + embed the corpus
sentinel plan run --band critical
sentinel eval run            # plan quality rubric
sentinel tickets file --sink memory --execute
sentinel serve               # this dashboard</pre>`;
  $("#guide-tour").onclick = startTour;
}

/* -------------------------------------------------------------- tutorial -- */

const TOUR = [
  {
    view: "overview", target: ".tiles",
    title: "103,166 findings is not a work queue",
    body: "A scanner over 500 hosts produced this. Nobody triages it. Everything that " +
          "follows exists to turn it into work someone actually does.",
    evidence: async () => {
      const s = await api("/stats", { include_fix_actions: true });
      return `open findings : ${fmt(s.findings_open)}\nfix actions   : ${fmt(s.fix_actions)}` +
             `\nreduction     : ${(s.findings_open / s.fix_actions).toFixed(0)}x`;
    },
  },
  {
    view: "overview", target: ".grid-2",
    title: "Priority is not severity",
    body: "Bands come from four capped components: severity (40), real-world " +
          "exploitation (30), exposure (15), asset value (15). Exploitation weighs " +
          "almost as much as severity on purpose — a CVSS 9.8 nobody has weaponised is " +
          "a worse use of an afternoon than a CVSS 7.2 in CISA KEV.",
    evidence: async () => {
      const b = await api("/stats/bands");
      return b.map((r) => `${r.band.padEnd(9)} ${String(fmt(r.findings)).padStart(7)}` +
        `  ${r.kev ? r.kev + " KEV" : ""}`).join("\n");
    },
  },
  {
    view: "triage", target: "#triage-table",
    title: "A 'medium' that outranks a 'high'",
    body: "NVD calls CVE-2021-45105 a MEDIUM at CVSS 5.9. Its EPSS is 0.99999 — " +
          "near-certain exploitation — so it scores above a CVSS 8.1 that nobody has " +
          "weaponised. Severity alone would bury it. Click any row after the tour to " +
          "see the full arithmetic behind a score.",
    before: async () => {
      triageState.sort = "epss"; triageState.band = ""; triageState.kev_only = false;
      const s = $("#f-sort"); if (s) s.value = "epss";
      await loadTriage();
    },
    // Fetch the two specific CVEs the claim is about, rather than the EPSS
    // top-3: several CVEs tie at 1.000 and the tie-break is risk score, so the
    // generic query showed CVSS-10 rows and contradicted the text above.
    evidence: async () => {
      const [medium, high] = await Promise.all([
        api("/findings", { cve_id: "CVE-2021-45105", sort: "risk", limit: 1 }),
        api("/findings", { cve_id: "CVE-2026-28387", sort: "risk", limit: 1 }),
      ]);
      const line = (r, verdict) => r.length
        ? `${r[0].cve_id}  CVSS ${String(r[0].cvss_v31_score).padEnd(4)} ` +
          `(${verdict})  EPSS ${r[0].epss_score.toFixed(5)}  -> score ${r[0].risk_score}`
        : null;
      return [line(medium, "NVD: MEDIUM"), line(high, "NVD: HIGH  ")]
        .filter(Boolean).join("\n") || "(those CVEs are not in this fleet)";
    },
  },
  {
    view: "actions", target: "#actions-table",
    title: "The unit of work is the upgrade",
    body: "One `apt-get install curl=…` closes 15 CVEs on a host. Findings group by " +
          "(team, package, os_family, band). Note the target version is the highest " +
          "required across the package — so the critical and the low ticket name the " +
          "same version with different dates, and doing the urgent one closes the rest.",
    evidence: async () => {
      const a = await api("/fix-actions", { band: "critical", limit: 3 });
      return a.map((r) => `${r.package_name.slice(0, 32).padEnd(32)} -> ` +
        `${r.fixed_version || "no fix"}  (${r.cve_ids.length} CVEs, ${r.asset_count} hosts)`).join("\n");
    },
  },
  {
    view: "search", target: "#s-out",
    title: "Pure vector search gets this wrong",
    body: "Searching the literal string CVE-2021-44228 with dense retrieval returns " +
          "unrelated vim CVEs — the Log4j family's descriptions sit at 0.79–0.84 cosine " +
          "similarity to each other. Embeddings are weakest at exact identifiers, and " +
          "this domain is made almost entirely of exact identifiers.",
    before: async () => {
      $("#s-q").value = "CVE-2021-44228";
      searchState.mode = "dense"; searchState.prefilter = false;
      $("#s-pre").checked = false;
      $("#s-mode").querySelectorAll("button").forEach((x) =>
        x.setAttribute("aria-pressed", x.dataset.mode === "dense"));
      await doSearch();
    },
    evidence: async () => {
      const r = await api("/search", { q: "CVE-2021-44228", mode: "dense",
                                       prefilter: false, k: 3 });
      return r.hits.map((h) => `${h.cve_ids.join(",").padEnd(16)} ${h.content.slice(0, 44)}…`)
        .join("\n");
    },
  },
  {
    view: "search", target: "#s-out",
    title: "Lexical + dense + a prefilter, fused on ranks",
    body: "Three mechanisms failing in different directions: lexical nails exact " +
          "identifiers, dense handles paraphrase, and a CVE prefilter makes a wrong-CVE " +
          "result structurally impossible. Fused with Reciprocal Rank Fusion on ranks — " +
          "not scores, because ts_rank is unbounded and cosine is 0–1, so adding them " +
          "is meaningless.",
    before: async () => {
      searchState.mode = "hybrid"; searchState.prefilter = true;
      $("#s-pre").checked = true;
      $("#s-mode").querySelectorAll("button").forEach((x) =>
        x.setAttribute("aria-pressed", x.dataset.mode === "hybrid"));
      await compareModes();
    },
    evidence: async () => "Compare all modes is running above — note which rows are ✕.",
  },
  {
    view: "actions", target: "#actions-table",
    title: "The grounding gate is a regex, not a prompt",
    body: "“Only use the provided context” is a request. Verifying that every CVE id and " +
          "version string appears verbatim in a retrieved chunk is a guarantee. It caught " +
          "a real one on the first live call: the model wrote CVE-2021-4428, a digit " +
          "dropped. Plans that fail are stored, flagged, and never attached to a ticket. " +
          "Click a row with a 'grounded' plan to read one.",
    before: async () => { actionState.band = "critical"; await loadActions(); },
    evidence: async () => {
      const s = await api("/stats");
      return `plans           : ${fmt(s.plans)}\npassed grounding: ${fmt(s.plans_grounded)}` +
             (s.plans ? `\nrate            : ${((s.plans_grounded / s.plans) * 100).toFixed(0)}%` : "");
    },
  },
  {
    view: "guide", target: ".steps-list",
    title: "Your turn",
    body: "The Guide lists each claim and how to check it yourself. The three things " +
          "worth remembering: the model proposes and deterministic code disposes; " +
          "hybrid retrieval is a correctness requirement here, not an optimisation; " +
          "and the plan cache is the architecture — 103,166 findings become 108 model calls.",
    evidence: async () => null,
  },
];

let tourIndex = 0;

function startTour() { tourIndex = 0; renderTourStep(); }
function endTour() { clearFocus(); $("#tour-root").innerHTML = ""; }

function clearFocus() {
  document.querySelectorAll(".tut-focus").forEach((n) => n.classList.remove("tut-focus"));
}

async function renderTourStep() {
  const step = TOUR[tourIndex];
  clearFocus();
  if (!step) return endTour();

  const root = $("#tour-root");
  root.innerHTML = `
    <div class="tut-card" role="dialog" aria-modal="false" aria-label="Tutorial">
      <div class="step">Step ${tourIndex + 1} of ${TOUR.length}</div>
      <h4>${esc(step.title)}</h4><p>${esc(step.body)}</p>
      <div class="evidence" id="tut-ev">loading evidence…</div>
      <div class="tut-actions">
        <button class="btn" id="tut-skip">Skip tour</button><span class="spacer"></span>
        <button class="btn" id="tut-back" ${tourIndex === 0 ? "disabled" : ""}>Back</button>
        <button class="btn primary" id="tut-next">
          ${tourIndex === TOUR.length - 1 ? "Finish" : "Next"}</button>
      </div></div>`;

  $("#tut-skip").onclick = () => { clearFocus(); endTour(); };
  $("#tut-back").onclick = () => { tourIndex--; renderTourStep(); };
  $("#tut-next").onclick = () => { tourIndex++; renderTourStep(); };

  show(step.view, { silent: true });
  if (step.before) { try { await step.before(); } catch { /* evidence still loads */ } }

  // The view re-renders asynchronously, so look the element up after it settles.
  setTimeout(() => {
    const el = document.querySelector(step.target);
    if (el) {
      clearFocus();
      el.classList.add("tut-focus");
      el.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  }, 260);

  const ev = $("#tut-ev");
  try {
    const text = await step.evidence();
    if (text) ev.textContent = text; else ev.remove();
  } catch (e) { ev.textContent = `(could not load evidence: ${e.message})`; }
}

/* ------------------------------------------------------------- navigation -- */

const RENDER = {
  overview: renderOverview, triage: renderTriage, actions: renderActions,
  search: renderSearch, teams: renderTeams, guide: renderGuide,
};

function show(view, opts = {}) {
  Object.keys(RENDER).forEach((v) => {
    $(`#view-${v}`).hidden = v !== view;
  });
  document.querySelectorAll("nav.side button[data-view]").forEach((b) => {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  if (!opts.silent) location.hash = view;
  RENDER[view]();
}

document.querySelectorAll("nav.side button[data-view]").forEach((b) => {
  b.onclick = () => show(b.dataset.view);
});
$("#start-tour").onclick = startTour;
$("#theme-toggle").onclick = () => {
  const dark = document.documentElement.getAttribute("data-theme") === "dark";
  document.documentElement.setAttribute("data-theme", dark ? "light" : "dark");
  try { localStorage.setItem("sentinel-theme", dark ? "light" : "dark"); } catch { /* private mode */ }
};
try {
  const saved = localStorage.getItem("sentinel-theme");
  if (saved) document.documentElement.setAttribute("data-theme", saved);
} catch { /* private mode: fall back to prefers-color-scheme */ }

show(location.hash.slice(1) in RENDER ? location.hash.slice(1) : "overview");

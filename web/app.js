/* SOC//AGENT console — drives the LangGraph run over SSE and renders every view. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const SVGNS = "http://www.w3.org/2000/svg";
const svgEl = (tag, attrs = {}) => { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const S = {
  meta: null, fault: "", dataset: "synthetic", runId: null, result: null, running: false, bench: null,
  queue: [], draining: false, lastNode: "__start__", visits: {}, path: [], traceCount: 0, seq: 0,
  cpAttempts: { 1: 0, 2: 0 }, detailId: null, responseId: null, incFilter: "all", incSearch: "",
  chat: [], finished: false,
};

const AGENT_COLOR = {
  "Planner": "#7aa2f7", "Research": "#7dcfff", "Executor": "#a9b1d6", "Critic": "#e0af68",
  "Severity router": "#bb9af7", "Software Development": "#73daca", "Business Automation": "#9ece6a",
  "Analyst (human)": "#f7768e",
};
const LEVEL_COLOR = { critical: "#f7768e", high: "#ff9e64", medium: "#e0af68", low: "#9ece6a" };
const STAGE_COLOR = {
  reconnaissance: "#565f89", delivery: "#bb9af7", credential_access: "#ff9e64", initial_access: "#e0af68",
  execution: "#f7768e", persistence: "#c0caf5", lateral_movement: "#bb9af7", command_and_control: "#7dcfff",
  exfiltration: "#7aa2f7", impact: "#f7768e", context: "#414868",
};
const PHASE_COLOR = { identify: "#565f89", preserve_evidence: "#bb9af7", contain: "#f7768e", eradicate: "#ff9e64",
  recover: "#9ece6a", lessons_learned: "#7aa2f7" };
const REP_COLOR = { malicious: "#f7768e", suspicious: "#e0af68", benign: "#9ece6a", unknown: "#565f89" };
const ROUTE_LABEL = { escalate: "Escalated", analyst_queue: "Analyst queue", auto_close: "Auto-closed" };
const PACE = { packet: 380, line: 6, cap: 900 };
const FAULT_DESC = {
  "": "Agents behave correctly.",
  all: "Research skips a lookup, Executor drops evidence, the LLM invents an IP, the rule is too broad: the Critic rejects each once, then the retries pass.",
  persistent: "The Executor repeats the same mistake, so 2 retries are exhausted and the incident goes to a human.",
};

/* ================================================================ ambient */

function toast(msg, cls = "") {
  const t = document.createElement("div");
  t.className = `toast ${cls}`; t.innerHTML = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 4600);
}

function setStatus(text, cls) {
  document.body.classList.toggle("running", cls === "running" || cls === "waiting");
  const pill = $("#sys-status");
  pill.className = `status-pill ${cls || ""}`;
  $(".txt", pill).textContent = text;
}

function countUp(el, target, decimals = 0, suffix = "") {
  const t0 = performance.now(), dur = reduceMotion ? 1 : 1200;
  const final = () => (el.textContent = Number(target).toFixed(decimals) + suffix);
  (function step(t) {
    const k = Math.max(0, Math.min(1, (t - t0) / dur)), e = 1 - Math.pow(1 - k, 3);
    el.textContent = (target * e).toFixed(decimals) + suffix;
    if (k < 1) requestAnimationFrame(step);
  })(t0);
  setTimeout(final, dur + 80); // rAF can be throttled in background tabs; always land on the real value
}

/* ================================================================ controls */

function segment(id, onChange) {
  $$(`#${id} button`).forEach((b) => b.addEventListener("click", () => {
    $$(`#${id} button`).forEach((x) => x.classList.remove("on"));
    b.classList.add("on"); onChange(b.dataset.v);
  }));
}

function initControls() {
  segment("seg-fault", (v) => { S.fault = v; $("#fault-desc").textContent = FAULT_DESC[v]; });
  $("#opt-model").addEventListener("change", (e) => ($("#hs-llm").textContent = e.target.value.replace(":latest", "")));
  $("#opt-dataset").addEventListener("change", (e) => {
    if (e.target.value === "__upload__") { $("#upload-file").click(); e.target.value = S.dataset; return; }
    S.dataset = e.target.value; describeDataset();
  });
  $("#upload-file").addEventListener("change", uploadDataset);
  $("#run-btn").addEventListener("click", startRun);
  $("#arch-btn").addEventListener("click", () => openModal(
    `<div class="panel-head"><span>// ARCHITECTURE</span><button class="ghost-btn" data-close>✕ Close</button></div>
     <img src="/docs-assets/architecture.png" alt="Architecture diagram" style="width:100%;border-radius:8px">`, "arch"));
  $$("#tabs button").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
}

function describeDataset() {
  const d = S.meta.datasets.find((x) => x.key === S.dataset);
  $("#dataset-desc").textContent = d ? `${d.alerts} alerts${d.eval ? " · ground truth available" : " · no ground truth"}` : "";
  countUp($("#hs-alerts"), d ? d.alerts : 0);
}

function fillDatasets() {
  $("#opt-dataset").innerHTML = S.meta.datasets.map((d) => `<option value="${esc(d.key)}" ${d.key === S.dataset ? "selected" : ""}>${esc(d.label)}</option>`).join("")
    + '<option value="__upload__">Upload JSON (alerts or Windows/Sysmon events)…</option>';
  describeDataset();
}

async function uploadDataset(e) {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  try {
    const records = JSON.parse(await file.text());
    const r = await fetch("/api/datasets", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: file.name, records }) });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || r.statusText);
    S.meta = await fetch("/api/meta").then((x) => x.json());
    S.dataset = data.key;
    fillDatasets();
    toast(`Loaded <b>${esc(file.name)}</b>: ${data.alerts} alerts (${esc(data.format)} format)`, "green");
  } catch (err) { toast(`<b style="color:var(--red)">UPLOAD FAILED</b> ${esc(err.message)}`, "red"); }
}

async function loadMeta() {
  S.meta = await fetch("/api/meta").then((r) => r.json());
  fillDatasets();
  const models = S.meta.ollama.models || [];
  const sel = $("#opt-model");
  sel.innerHTML = models.map((m) => `<option>${esc(m)}</option>`).join("") || "<option>no models found</option>";
  sel.disabled = !models.length;
  $("#run-btn").disabled = !models.length;
  if (models.length) {
    $("#hs-llm").textContent = models[0].replace(":latest", "");
    $("#mode-desc").textContent = "Plans investigations and writes prose; scoring, routing and pass/fail stay deterministic Python.";
  } else {
    $("#hs-llm").textContent = "Offline";
    $("#mode-desc").innerHTML = '<span style="color:var(--red)">Ollama is not running.</span> Start it and run <code>ollama pull llama3.2</code>, then reload.';
    toast('<b style="color:var(--red)">OLLAMA NOT RUNNING</b> — start Ollama, then reload the page', "red");
  }
}

/* ================================================================ views */

const RENDER = {};
function showView(name) {
  $$("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  if (RENDER[name]) RENDER[name]();
  if (name !== "console") {
    const el = $(`#view-${name}`);
    window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 96, behavior: reduceMotion ? "auto" : "smooth" });
  }
}

function openModal(html, cls = "") {
  const card = $("#modal-card");
  card.className = `modal-card ${cls}`; card.innerHTML = html;
  $("#modal").classList.remove("hidden");
  $$("[data-close]", card).forEach((b) => b.addEventListener("click", closeModal));
}
function closeModal() { $("#modal").classList.add("hidden"); }
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal" && !$("#modal-card").dataset.lock) closeModal(); });

/* ================================================================ pipeline graph */

const NODES = {
  __start__: { x: 48, y: 190, shape: "circle", idx: "IN", name: "ALERTS" },
  planner: { x: 165, y: 190, idx: "01", name: "PLANNER" },
  research: { x: 310, y: 190, idx: "02", name: "RESEARCH" },
  executor: { x: 455, y: 190, idx: "03", name: "EXECUTOR" },
  critic_cp1: { x: 600, y: 190, shape: "diamond", idx: "04 · CP1", name: "CRITIC" },
  router: { x: 740, y: 190, shape: "diamond", idx: "ROUTER", name: "SEVERITY" },
  devagent: { x: 880, y: 95, idx: "05", name: "SOFTWARE DEV" },
  critic_cp2: { x: 1025, y: 95, shape: "diamond", idx: "04 · CP2", name: "CRITIC" },
  approval: { x: 1170, y: 95, shape: "hex", idx: "HITL", name: "ANALYST" },
  automation: { x: 1025, y: 265, idx: "06", name: "AUTOMATION" },
  __end__: { x: 1210, y: 265, shape: "circle", idx: "OUT", name: "CONSOLE" },
};
const EDGES = [
  ["__start__", "planner", "M78,190 L106,190", ""],
  ["planner", "research", "M224,190 L251,190", ""],
  ["research", "executor", "M369,190 L396,190", ""],
  ["executor", "critic_cp1", "M514,190 L558,190", ""],
  ["critic_cp1", "executor", "M600,156 C600,108 455,108 455,165", "EVIDENCE", true],
  ["critic_cp1", "research", "M600,156 C600,40 310,40 310,165", "LOOKUPS", true],
  ["critic_cp1", "router", "M642,190 L698,190", "PASS"],
  ["router", "devagent", "M740,156 C740,105 780,95 821,95", "≥70"],
  ["router", "automation", "M740,224 C740,268 880,265 966,265", "<70 only"],
  ["devagent", "critic_cp2", "M939,95 L983,95", ""],
  ["critic_cp2", "devagent", "M1025,61 C1025,12 880,12 880,70", "FAIL", true],
  ["critic_cp2", "approval", "M1067,95 L1118,95", "PASS"],
  ["approval", "automation", "M1170,121 C1170,195 1085,205 1050,240", ""],
  ["automation", "__end__", "M1084,265 L1180,265", ""],
];
const EDGE = {};
const NODE_EL = {};

function buildPipeline() {
  const svg = $("#pipeline");
  svg.innerHTML = "";
  const defs = svgEl("defs");
  defs.innerHTML = `<marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="rgba(125,140,163,.6)"/></marker>`;
  svg.appendChild(defs);
  const eg = svgEl("g"), lg = svgEl("g"), ng = svgEl("g");
  svg.append(eg, lg, ng);
  for (const [a, b, d, label, retry] of EDGES) {
    const p = svgEl("path", { d, class: `edge${retry ? " retry" : ""}`, "marker-end": "url(#arr)" });
    eg.appendChild(p);
    const L = p.getTotalLength(), mid = p.getPointAtLength(L / 2);
    const t = svgEl("text", { x: mid.x, y: mid.y - (retry ? 6 : 7), class: `edge-label${retry ? " retry" : ""}` });
    t.textContent = label;
    lg.appendChild(t);
    EDGE[`${a}>${b}`] = { path: p, label: t, retry: !!retry, base: label, count: 0 };
  }
  for (const [id, n] of Object.entries(NODES)) {
    const g = svgEl("g", { class: "node", "data-node": id });
    let shape;
    if (n.shape === "circle") shape = svgEl("circle", { cx: n.x, cy: n.y, r: 30, class: "shape" });
    else if (n.shape === "diamond") shape = svgEl("polygon", { points: `${n.x},${n.y - 34} ${n.x + 42},${n.y} ${n.x},${n.y + 34} ${n.x - 42},${n.y}`, class: "shape" });
    else if (n.shape === "hex") shape = svgEl("polygon", { points: `${n.x - 52},${n.y} ${n.x - 38},${n.y - 26} ${n.x + 38},${n.y - 26} ${n.x + 52},${n.y} ${n.x + 38},${n.y + 26} ${n.x - 38},${n.y + 26}`, class: "shape" });
    else shape = svgEl("rect", { x: n.x - 59, y: n.y - 25, width: 118, height: 50, rx: 9, class: "shape" });
    g.appendChild(shape);
    const small = n.shape === "circle" || n.shape === "diamond";
    const idx = svgEl("text", { x: n.x, y: n.y - 5, class: "n-idx" }); idx.textContent = n.idx;
    const name = svgEl("text", { x: n.x, y: n.y + 11, class: "n-name", "font-size": small ? 10.5 : 12 }); name.textContent = n.name;
    const cnt = svgEl("text", { x: n.x + (n.shape === "diamond" ? 30 : 50), y: n.y - (n.shape === "diamond" ? 28 : 30), class: "n-count" });
    g.append(idx, name, cnt);
    ng.appendChild(g);
    NODE_EL[id] = { g, cnt };
  }
}

function setNode(id, cls) {
  const n = NODE_EL[id];
  if (!n) return;
  n.g.classList.remove("done", "active", "reject", "waiting", "flagged");
  if (cls) n.g.classList.add(cls);
}

function stamp(id, text, color) {
  const n = NODES[id], t = svgEl("text", { x: n.x, y: n.y - 46, class: "stamp" });
  if (color) t.style.fill = color;
  t.textContent = text;
  $("#pipeline").appendChild(t);
  setTimeout(() => t.remove(), 1500);
}

function animatePacket(edge, dur) {
  return new Promise((resolve) => {
    if (!dur || !edge) return resolve();
    const p = edge.path, L = p.getTotalLength();
    const dot = svgEl("circle", { r: 5, class: `packet${edge.retry ? " red" : ""}` });
    $("#pipeline").appendChild(dot);
    const t0 = performance.now();
    let finished = false;
    const finish = () => { if (!finished) { finished = true; dot.remove(); resolve(); } };
    setTimeout(finish, dur + 120);   // rAF can be paused in hidden/throttled tabs: never block the run on it
    (function step(t) {
      if (finished) return;
      const k = Math.max(0, Math.min(1, (t - t0) / dur)), e = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
      const pt = p.getPointAtLength(e * L);
      dot.setAttribute("cx", pt.x); dot.setAttribute("cy", pt.y);
      if (k < 1) requestAnimationFrame(step); else finish();
    })(t0);
  });
}

async function traverse(from, to) {
  const edge = EDGE[`${from}>${to}`];
  if (!edge) return;
  edge.path.classList.add("lit");
  edge.count += 1;
  if (edge.retry) { edge.label.textContent = `${edge.base} ×${edge.count}`; edge.label.classList.add("hot"); }
  await animatePacket(edge, PACE.packet);
}

function renderPath() {
  $("#path-line").innerHTML = S.path.length ? "PATH › " + S.path.map(([node, st]) => {
    const label = S.meta.nodes[node] || node;
    if (st.startsWith("retry")) return `<span class="p fail">${esc(label)} ✗ REJECTED${st === "retry_research" ? " → RESEARCH" : ""}</span>`;
    if (st === "flagged") return `<span class="p flag">${esc(label)} ✗ RETRIES EXHAUSTED → HUMAN</span>`;
    if (node.startsWith("critic")) return `<span class="p pass">${esc(label)} ✓</span>`;
    return `<span class="p">${esc(label)}</span>`;
  }).join(" → ") : "";
}

/* ================================================================ terminal */

function termLine(html, cls = "") {
  const term = $("#term");
  const d = document.createElement("div");
  d.className = `term-line ${cls}`; d.innerHTML = html;
  term.appendChild(d);
  term.scrollTop = term.scrollHeight;
}

function formatEntry(e) {
  const color = AGENT_COLOR[e.agent] || "#9fb0c6";
  const cls = { pass: "pass", fail: "fail", fault: "fault" }[e.status] || "";
  const mark = { pass: "✔ ", fail: "✘ ", fault: "⚠ " }[e.status] || "";
  return [`<span class="t">${esc(e.timestamp)}</span> <span class="a" style="color:${color}">${esc(e.agent.toUpperCase())}</span>`
    + `${mark}${esc(e.action)}${e.tool ? ` <span class="tool">[${esc(e.tool)}]</span>` : ""}`
    + `${e.inputs ? ` ${esc(e.inputs)}` : ""}${e.outputs ? ` <span class="out">→ ${esc(e.outputs)}</span>` : ""}`, cls];
}

async function streamTrace(entries) {
  const delay = Math.min(PACE.line, PACE.cap / Math.max(1, entries.length));
  let budget = 0;
  for (const e of entries) {
    termLine(...formatEntry(e));
    budget += delay;
    if (budget >= 16) { await sleep(budget); budget = 0; }
  }
  S.traceCount += entries.length;
  $("#trace-count").textContent = `${S.traceCount} events`;
}

/* ================================================================ run lifecycle */

function resetConsole() {
  $$(".pill").forEach((p) => p.classList.remove("live", "done-ag", "rejected"));
  buildPipeline();
  Object.assign(S, { lastNode: "__start__", visits: {}, path: [], traceCount: 0, seq: 0, result: null,
    cpAttempts: { 1: 0, 2: 0 }, finished: false, queue: [], chat: [], detailId: null, responseId: null });
  setNode("__start__", "done");
  $("#term").innerHTML = "";
  $("#trace-count").textContent = "0 events";
  $("#path-line").innerHTML = "";
  $("#critic-loop").innerHTML = "";
  $("#critic-state").textContent = "watching…";
  $$("#kpis b").forEach((b) => (b.textContent = "0"));
  $$("#tabs button").forEach((b) => { if (!["console", "benchmark", "memory"].includes(b.dataset.view)) b.disabled = true; });
}

async function startRun() {
  if (S.running) return;
  S.running = true;
  $("#run-btn").disabled = true;
  $(".run-txt").textContent = "Agents running";
  showView("console");
  resetConsole();
  setStatus("Agents running", "running");
  termLine(`$ soc-agent run --dataset=${S.dataset} --fault=${S.fault || "none"} --hitl=${$("#opt-approval").checked} --memory=${$("#opt-memory").checked} --llm=ollama:${$("#opt-model").value}`, "dim");
  const body = { dataset: S.dataset, fault: S.fault || null, approval: $("#opt-approval").checked,
    memory: $("#opt-memory").checked, model: $("#opt-model").value };
  try {
    if ($("#opt-feed").checked) await playFeed(S.dataset);
    const r = await fetch("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(await r.text());
    S.runId = (await r.json()).run_id;
    listen(0);
  } catch (err) { runFailed(err.message); }
}

function listen(since) {
  const es = new EventSource(`/api/runs/${S.runId}/events?since=${since}`);
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    S.seq = ev.seq;
    if (["interrupt", "done", "error"].includes(ev.type)) es.close();
    S.queue.push(ev);
    drain();
  };
  es.onerror = () => { es.close(); if (!S.finished && S.running && !$("#modal-card").dataset.lock) runFailed("Event stream disconnected"); };
}

async function drain() {
  if (S.draining) return;
  S.draining = true;
  while (S.queue.length) {
    const ev = S.queue.shift();
    if (ev.type === "node") await handleNode(ev);
    else if (ev.type === "interrupt") await handleInterrupt(ev.payload);
    else if (ev.type === "done") await handleDone();
    else if (ev.type === "error") runFailed(ev.message);
  }
  S.draining = false;
}

async function handleNode(ev) {
  const from = S.lastNode, to = ev.node;
  agentLive(to, ev.label);
  const prev = NODE_EL[from]?.g;
  if (prev && prev.classList.contains("active")) setNode(from, "done");
  await traverse(from, to);
  S.visits[to] = (S.visits[to] || 0) + 1;
  setNode(to, "active");
  if (S.visits[to] > 1) NODE_EL[to].cnt.textContent = `×${S.visits[to]}`;
  $("#active-node").textContent = `▶ ${ev.label}`;
  termLine(`── ${esc(ev.label.toUpperCase())} ${"─".repeat(60)}`, "node-hdr");
  await streamTrace(ev.trace);
  S.path.push([to, ev.status]);
  renderPath();

  for (const p of ev.prose || []) liveProseCard(p);
  if (to.startsWith("critic")) {
    const cp = to === "critic_cp1" ? 1 : 2;
    S.cpAttempts[cp] += 1;
    if (ev.status.startsWith("retry")) {
      setNode(to, "reject"); stamp(to, "REJECTED");
      agentRejected(); Tunnel.flash("#ff4a3d");
      const back = ev.status === "retry_research" ? "Research" : cp === 1 ? "Executor" : "Software Development";
      toast(`<b style="color:var(--red)">CRITIC ${cp} REJECTED</b> — sending work back to ${back} (retry ${ev.retries[`cp${cp}`]}/${S.meta.thresholds.max_retries})`, "red");
      liveVerdictCard(cp, ev.verdicts, "fail");
    } else if (ev.status === "flagged") {
      setNode(to, "flagged"); stamp(to, "HUMAN REVIEW", "var(--amber)");
      toast(`<b style="color:var(--amber)">RETRIES EXHAUSTED</b> — incident flagged for human review`, "amber");
      liveVerdictCard(cp, ev.verdicts, "flag");
    } else {
      setNode(to, "done");
      if (S.cpAttempts[cp] > 1) { liveVerdictCard(cp, [], "pass"); toast(`<b style="color:var(--green)">CRITIC ${cp} PASSED</b> on attempt ${S.cpAttempts[cp]}`, "green"); }
    }
  }
  S.lastNode = to;
}

function liveProseCard(p) {
  const box = $("#critic-loop");
  const fixed = p.passed ? `passed after ${p.attempts - 1} rewrite(s)` : p.replaced ? "replaced by the factual template" : "shipped unchecked";
  box.insertAdjacentHTML("beforeend", `<div class="vcard ${p.passed ? "pass" : "fail"}"><h4>✎ FACT-CHECK · ${esc(p.kind.replace(/_/g, " "))} · ${esc(p.subject)}</h4>
    <ul>${p.rejections.map((r) => `<li>Rejected: ${esc(r[0])}</li>`).join("")}<li>${esc(fixed)}</li></ul></div>`);
  box.scrollTop = box.scrollHeight;
}

function liveVerdictCard(cp, verdicts, kind) {
  const box = $("#critic-loop");
  const attempt = S.cpAttempts[cp];
  const title = kind === "pass" ? `✔ CHECKPOINT ${cp} PASSED · attempt ${attempt}`
    : kind === "flag" ? `⚠ CHECKPOINT ${cp} · retries exhausted · attempt ${attempt}` : `✘ CHECKPOINT ${cp} REJECTED · attempt ${attempt}`;
  const reasons = kind === "pass" ? ["Graph looped back and the agent redid the work using the Critic's reasons."]
    : verdicts.flatMap((v) => v.reasons.map((r) => `${v.incident_id}: ${r}`));
  box.insertAdjacentHTML("beforeend", `<div class="vcard ${kind}"><h4>${title}</h4><ul>${reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>`);
  box.scrollTop = box.scrollHeight;
  $("#critic-state").textContent = kind === "pass" ? "loop closed" : "loop active";
}

async function handleInterrupt(payload) {
  const from = S.lastNode;
  if (NODE_EL[from]?.g.classList.contains("active")) setNode(from, "done");
  await traverse(from, "approval");
  setNode("approval", "waiting");
  S.lastNode = "approval";
  $("#active-node").textContent = "⏸ waiting for analyst";
  setStatus("Waiting for analyst", "waiting");
  agentLive("approval", "Analyst approval");
  $("#visual-caption").innerHTML = "Paused: <b>waiting for the analyst</b>";
  termLine(`── GRAPH PAUSED (LangGraph interrupt) · analyst approval required ${"─".repeat(30)}`, "node-hdr");
  openApproval(payload.incidents);
}

function openApproval(items) {
  const decisions = {};
  const rows = items.map((it) => {
    const def = it.needs_human_review ? "rejected" : "approved";
    const opt = (v, label) => `<button data-v="${v}" class="${def === v ? "on" : ""}">${label}</button>`;
    decisions[it.incident_id] = { decision: def, by: "SOC analyst (web console)", comment: "" };
    return `<div class="approve-item" data-id="${esc(it.incident_id)}">
      <div>
        <div><b style="font-family:var(--font-display)">${esc(it.incident_id)}</b> ${levelBadge(it.label, it.severity)} ${esc(it.headline)}</div>
        <div class="muted" style="font-size:11.5px;margin-top:4px">${it.needs_human_review ? '<span style="color:var(--amber)">⚠ Critic could not verify this incident (retries exhausted)</span> · ' : ""}
          ${it.critic_passed ? '<span style="color:var(--green)">✔ Critic checkpoint 2 passed</span>' : '<span style="color:var(--red)">✘ Critic checkpoint 2 failed</span>'}</div>
        <div style="margin-top:8px;font-size:11px;color:var(--muted);letter-spacing:.12em">PROPOSED CONTAINMENT (SIMULATED)</div>
        <ul>${it.containment.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>
      </div>
      <div class="decide">
        <div class="seg">${opt("approved", "Approve")}${opt("rejected", "Hold")}${opt("false_positive", "False +")}</div>
        <small class="muted" style="font-size:10.5px">Approve and False + are remembered for the next run.</small>
        <input type="text" placeholder="comment (optional)">
      </div></div>`;
  }).join("");
  openModal(`<div class="scan"></div><h3>⏸ ANALYST APPROVAL REQUIRED</h3>
    <p class="muted" style="margin:0 0 6px">The LangGraph run is paused at an interrupt. No containment is authorised until you decide.</p>
    ${rows}
    <div style="display:flex;justify-content:flex-end;margin-top:14px"><button class="btn solid" id="approve-go">Submit decisions &amp; resume graph ▶</button></div>`);
  const card = $("#modal-card");
  card.dataset.lock = "1";
  $$(".approve-item", card).forEach((row) => {
    const id = row.dataset.id;
    $$(".seg button", row).forEach((b) => b.addEventListener("click", () => {
      $$(".seg button", row).forEach((x) => x.classList.remove("on")); b.classList.add("on");
      decisions[id].decision = b.dataset.v;
    }));
    $("input", row).addEventListener("input", (e) => (decisions[id].comment = e.target.value));
  });
  $("#approve-go").addEventListener("click", async () => {
    $("#approve-go").disabled = true;
    const r = await fetch(`/api/runs/${S.runId}/approve`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decisions }) });
    delete card.dataset.lock;
    closeModal();
    if (!r.ok) return runFailed(await r.text());
    const held = Object.values(decisions).filter((d) => d.decision !== "approved").length;
    toast(`Analyst decisions submitted · ${held} containment held or false positive · graph resuming`, held ? "amber" : "green");
    setStatus("Agents running", "running");
    setNode("approval", "done");
    listen((await r.json()).since);
  });
}

async function handleDone() {
  const from = S.lastNode;
  if (NODE_EL[from]?.g.classList.contains("active")) setNode(from, "done");
  await traverse(from, "__end__");
  setNode("__end__", "done");
  $("#active-node").textContent = "✔ run complete";
  S.finished = true;
  const r = await fetch(`/api/runs/${S.runId}/result`);
  S.result = await r.json();
  S.running = false;
  $("#run-btn").disabled = false;
  $(".run-txt").textContent = "Run again";
  setStatus("Run complete", "done");
  agentsSettle();
  Tunnel.flash("#9fe0b4");
  $("#visual-caption").innerHTML = `<b>Run complete</b>: ${S.result.incidents.length} incidents`;
  $$("#tabs button").forEach((b) => (b.disabled = b.dataset.view === "eval" && !S.result.evaluation));
  fillKpis();
  renderCriticLoop();
  termLine(`$ run complete · ${S.result.incidents.length} incidents · ${S.traceCount} trace events`, "pass");
  toast(`<b style="color:var(--green)">TRIAGE COMPLETE</b> · ${S.result.incidents.filter((i) => i.route === "escalate").length} escalated · ${S.result.prose_checks.filter((p) => p.rejections.length).length} LLM text(s) rewritten after fact-check`, "green");
}

function runFailed(msg) {
  S.running = false; S.finished = true;
  $("#run-btn").disabled = false; $(".run-txt").textContent = "Run triage";
  setStatus("Run failed", "error");
  agentsSettle(true);
  $("#visual-caption").textContent = "Run stopped";
  termLine(`✘ ${esc(msg)}`, "fail");
  toast(`<b style="color:var(--red)">RUN FAILED</b> ${esc(msg)}`, "red");
}

function fillKpis() {
  const r = S.result, inc = r.incidents;
  const vals = { alerts: r.alerts.length, incidents: inc.length, escalate: inc.filter((i) => i.route === "escalate").length,
    queue: inc.filter((i) => i.route === "analyst_queue").length, closed: inc.filter((i) => i.route === "auto_close").length,
    retries: r.retries.cp1 + r.retries.cp2, rewrites: r.prose_checks.reduce((n, p) => n + p.rejections.length, 0) };
  $$("#kpis b").forEach((b) => countUp(b, vals[b.dataset.k], +(b.dataset.decimals || 0), b.dataset.suffix || ""));
}

function renderCriticLoop() {
  const groups = {};
  for (const v of S.result.verdicts) (groups[`${v.checkpoint}|${v.incident_id}`] ||= []).push(v);
  const loops = Object.entries(groups).filter(([, vs]) => vs.some((v) => !v.passed));
  const box = $("#critic-loop");
  const prose = S.result.prose_checks.filter((p) => p.rejections.length);
  const proseHtml = prose.map((p) => `<div class="vcard ${p.passed ? "pass" : "fail"}"><h4>✎ FACT-CHECK · ${esc(p.kind.replace(/_/g, " "))} · ${esc(p.subject)} · ${p.attempts} attempt(s)</h4>
    <ul>${p.rejections.map((r) => `<li>Rejected: ${esc(r.join("; "))}</li>`).join("")}<li>${p.passed ? "Rewrite passed" : "Replaced by the factual template"}</li></ul></div>`).join("");
  if (!loops.length && !prose.length) {
    box.innerHTML = `<div class="vcard pass"><h4>✔ ALL WORK APPROVED FIRST TIME</h4><ul><li>The Critic checked ${Object.keys(groups).length} verdicts and sent nothing back.</li><li>Turn on fault injection to see the feedback loop.</li></ul></div>`;
    $("#critic-state").textContent = "no rejections";
    return;
  }
  box.innerHTML = loops.map(([key, vs]) => {
    const [cp, id] = key.split("|");
    const exhausted = !vs[vs.length - 1].passed;
    const cards = vs.map((v) => `<div class="vcard ${v.passed ? "pass" : "fail"}"><h4>${v.passed ? "✔ PASSED" : "✘ REJECTED"} · CP${cp} · ${esc(v.target)} #${v.attempt}</h4>
      <ul>${v.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>`).join("");
    const flag = exhausted ? `<div class="vcard flag"><h4>⚠ RETRIES EXHAUSTED · ${esc(id)}</h4><ul><li>Max ${S.meta.thresholds.max_retries} retries reached</li><li>Flagged for human review; can never auto-close</li></ul></div>` : "";
    return `<div class="muted" style="font-size:11px;letter-spacing:.12em">${esc(id)} · CHECKPOINT ${cp}</div><div class="loop-row">${cards}${flag}</div>`;
  }).join("") + proseHtml;
  $("#critic-state").textContent = `${loops.length} feedback loop(s) · ${prose.length} fact-check rewrite(s)`;
}

/* ================================================================ live feed */

function playFeed(dataset) {
  return new Promise((resolve) => {
    const panel = $("#feed-panel");
    panel.classList.remove("hidden");
    $("#feed-ticker").innerHTML = "";
    $("#feed-cands").innerHTML = "";
    setStatus("Live feed", "running");
    termLine("── LIVE FEED · alerts arriving in time order; candidates form as the Planner groups them ──", "node-hdr");
    let seen = 0;
    const es = new EventSource(`/api/feed?dataset=${encodeURIComponent(dataset)}&seconds=16`);
    es.onmessage = (m) => {
      const ev = JSON.parse(m.data);
      if (ev.type === "end") {
        es.close();
        $("#feed-state").textContent = `${ev.total} alerts received · handing over to the agents`;
        setStatus("Agents running", "running");
        return resolve();
      }
      seen += ev.alerts.length;
      $("#feed-state").textContent = `${seen}/${ev.total} alerts · ${ev.candidates.length} candidates`;
      const tick = $("#feed-ticker");
      for (const a of ev.alerts) {
        tick.insertAdjacentHTML("afterbegin", `<div class="term-line"><span class="t">${esc(a.ts.slice(11))}</span> <span class="a" style="color:${a.raw_severity === "low" ? "var(--muted)" : "var(--amber)"}">${esc(a.host)}</span>${esc(a.rule_name)} <span class="out">${esc(a.user)}</span></div>`);
      }
      while (tick.children.length > 14) tick.lastChild.remove();
      $("#feed-cands").innerHTML = ev.candidates.slice().sort((a, b) => b.stages.length - a.stages.length || b.alerts - a.alerts).slice(0, 18)
        .map((c) => `<div class="fcand ${c.stages.length ? "hot" : ""}"><b>${esc(c.host)}</b><span>${c.alerts} alert${c.alerts > 1 ? "s" : ""} · ${esc(c.first.slice(11, 16))}</span>
          ${c.stages.length ? `<em>${esc(c.stages.join(" → "))}</em>` : ""}</div>`).join("");
    };
    es.onerror = () => { es.close(); resolve(); };
  });
}

/* ================================================================ helpers for views */

const levelBadge = (label, score) => `<span class="badge lv-${esc(label)}">${esc(label)}${score != null ? ` · ${score}` : ""}</span>`;
const routeChip = (route) => `<span class="chip route-${esc(route)}">${esc(ROUTE_LABEL[route] || route)}</span>`;
const byId = () => Object.fromEntries(S.result.incidents.map((i) => [i.id, i]));
const alertsById = () => Object.fromEntries(S.result.alerts.map((a) => [a.id, a]));
const placeholder = (title, text) => `<div class="panel placeholder"><b>${esc(title)}</b>${esc(text)}</div>`;
const fmtTime = (ts) => ts.replace("T", " ").slice(5, 16);
const isExternal = (ip) => ip && !/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

function md(src) {
  const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/_(.+?)_/g, "<i>$1</i>").replace(/`(.+?)`/g, "<code>$1</code>");
  const out = [];
  const lines = src.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("|")) {
      const rows = [];
      while (i < lines.length && lines[i].startsWith("|")) rows.push(lines[i++].trim().slice(1, -1).split("|").map((c) => c.trim()));
      i--;
      const body = rows.filter((r) => !r.every((c) => /^:?-+:?$/.test(c)));
      out.push(`<table><thead><tr>${body[0].map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>${body.slice(1).map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
    } else if (/^#{1,6} /.test(line)) {
      const n = Math.max(4, line.indexOf(" "));
      out.push(`<h${Math.min(n, 5)}>${inline(line.replace(/^#+ /, ""))}</h${Math.min(n, 5)}>`);
    } else if (/^(\s*)(- |\d+\. )/.test(line)) {
      const items = [];
      const ordered = /^\s*\d+\. /.test(line);
      while (i < lines.length && /^(\s*)(- |\d+\. )/.test(lines[i])) items.push(lines[i++].replace(/^\s*(- \[ \] |- |\d+\. )/, ""));
      i--;
      out.push(`<${ordered ? "ol" : "ul"}>${items.map((x) => `<li>${inline(x)}</li>`).join("")}</${ordered ? "ol" : "ul"}>`);
    } else if (line.trim()) out.push(`<p>${inline(line)}</p>`);
  }
  return out.join("");
}

function yamlHtml(src) {
  return src.split("\n").map((l) => {
    const m = l.match(/^(\s*-?\s*)([\w|.]+)(:)(.*)$/);
    if (!m) return `<span class="s">${esc(l)}</span>`;
    const val = m[4].trim();
    const v = /^(true|false|\d+)$/.test(val) ? `<span class="b">${esc(m[4])}</span>` : `<span class="s">${esc(m[4])}</span>`;
    return `${esc(m[1])}<span class="k">${esc(m[2])}</span>${m[3]}${v}`;
  }).join("\n");
}

function animateBars(root) {
  requestAnimationFrame(() => requestAnimationFrame(() => $$("[data-w]", root).forEach((el) => (el.style.width = el.dataset.w))));
}

/* ================================================================ incidents */

RENDER.incidents = function () {
  const v = $("#view-incidents");
  if (!S.result) return (v.innerHTML = placeholder("NO RUN YET", "Run triage from the console first."));
  v.innerHTML = `<h2 class="section-title">INCIDENTS</h2><p class="section-sub">Candidate incidents built by the Planner and correlated by the Executor. Click a row for detail.</p>
    <div class="panel"><div class="filters">
      ${["all", "escalate", "analyst_queue", "auto_close"].map((f) => `<button class="fbtn ${S.incFilter === f ? "on" : ""}" data-f="${f}">${f === "all" ? "All" : ROUTE_LABEL[f]}</button>`).join("")}
      <input type="text" id="inc-search" placeholder="search host, user, stage, technique…" value="${esc(S.incSearch)}">
    </div><div class="scroll" style="max-height:540px"><table class="tbl" id="inc-table"></table></div></div>
    <div class="panel"><div class="panel-head"><span>// SEVERITY OVER THE DAY</span><span class="muted">bubble size = correlated alerts</span></div><div id="sev-chart"></div></div>`;
  $$(".fbtn", v).forEach((b) => b.addEventListener("click", () => { S.incFilter = b.dataset.f; RENDER.incidents(); }));
  $("#inc-search").addEventListener("input", (e) => { S.incSearch = e.target.value; fillIncidentTable(); });
  fillIncidentTable();
  $("#sev-chart").innerHTML = severityChart();
  $$("#sev-chart .dot").forEach((d) => d.addEventListener("click", () => openDetail(d.dataset.id)));
};

function fillIncidentTable() {
  const q = S.incSearch.toLowerCase();
  const rows = S.result.incidents.filter((i) => (S.incFilter === "all" || i.route === S.incFilter)
    && (!q || [i.id, i.host, i.users.join(" "), i.stages.join(" "), (i.techniques || []).map((t) => t.id).join(" ")].join(" ").toLowerCase().includes(q)));
  $("#inc-table").innerHTML = `<thead><tr><th>Incident</th><th>Level</th><th>Severity</th><th>Route</th><th>Host</th><th>Users</th><th>Kill chain</th><th>ATT&amp;CK</th><th>Alerts</th><th>Intel</th><th></th></tr></thead><tbody>
    ${rows.map((i, n) => `<tr class="click appear" data-id="${esc(i.id)}" style="animation-delay:${Math.min(n, 25) * 18}ms">
      <td><b>${esc(i.id)}</b>${i.alert_ids.some((a) => a.startsWith("LIVE")) ? ' <span class="chip">LIVE</span>' : ""}</td>
      <td>${levelBadge(i.label)}</td>
      <td><div class="sev"><div class="bar"><i data-w="${i.severity}%" style="background:${LEVEL_COLOR[i.label]}"></i></div><b>${i.severity}</b></div></td>
      <td>${routeChip(i.route)}</td><td>${esc(i.host)}</td><td>${esc(i.users.join(", "))}</td>
      <td style="font-size:11px">${esc(i.stages.join(" → ") || "—")}</td>
      <td>${(i.techniques || []).map((t) => `<span class="chip ttp">${esc(t.id)}</span>`).join("")}</td>
      <td>${i.alert_ids.length}</td><td style="color:${REP_COLOR[i.intel_verdict]}">${esc(i.intel_verdict)}</td>
      <td>${i.needs_human_review ? '<span title="needs human review" style="color:var(--amber)">⚠</span>' : ""}</td></tr>`).join("")}</tbody>`;
  $$("#inc-table tr.click").forEach((tr) => tr.addEventListener("click", () => openDetail(tr.dataset.id)));
  animateBars($("#inc-table"));
}

function severityChart() {
  const inc = S.result.incidents, W = 1200, H = 300, m = { l: 44, r: 20, t: 16, b: 34 };
  const times = inc.map((i) => +new Date(i.start));
  const x0 = Math.min(...times) - 1800e3, x1 = Math.max(...times) + 1800e3;
  const x = (t) => m.l + ((t - x0) / (x1 - x0)) * (W - m.l - m.r), y = (s) => H - m.b - (s / 100) * (H - m.t - m.b);
  let g = `<svg class="chart" viewBox="0 0 ${W} ${H}">`;
  g += `<line class="axis" x1="${m.l}" y1="${H - m.b}" x2="${W - m.r}" y2="${H - m.b}"/>`;
  for (let h = Math.ceil(x0 / 3600e3) * 3600e3; h <= x1; h += 2 * 3600e3)
    g += `<text class="tick" x="${x(h)}" y="${H - 12}" text-anchor="middle">${String(new Date(h).getHours()).padStart(2, "0")}:00</text>`;
  for (const s of [0, 50, 100]) g += `<text class="tick" x="${m.l - 8}" y="${y(s) + 3}" text-anchor="end">${s}</text>`;
  for (const [s, label] of [[S.meta.thresholds.low, `${S.meta.thresholds.low} · analyst queue`], [S.meta.thresholds.high, `${S.meta.thresholds.high} · playbook + rule`]])
    g += `<line class="thr" x1="${m.l}" x2="${W - m.r}" y1="${y(s)}" y2="${y(s)}"/><text class="thr-label" x="${m.l + 6}" y="${y(s) - 5}">${label}</text>`;
  inc.slice().reverse().forEach((i, n) => {
    const r = 5 + Math.sqrt(i.alert_ids.length) * 2.6, c = LEVEL_COLOR[i.label];
    g += `<circle class="dot" data-id="${esc(i.id)}" cx="${x(+new Date(i.start))}" cy="${y(i.severity)}" r="${r}" fill="${c}" fill-opacity=".55" stroke="${c}" stroke-width="1.5" style="animation-delay:${n * 15}ms"><title>${esc(i.id)} · ${esc(i.host)} · ${i.severity}</title></circle>`;
  });
  return g + "</svg>";
}

/* ================================================================ detail */

function openDetail(id) { S.detailId = id; showView("detail"); }

RENDER.detail = function () {
  const v = $("#view-detail");
  if (!S.result) return (v.innerHTML = placeholder("NO RUN YET", "Run triage first."));
  const all = byId(), A = alertsById(), E = S.result.enriched;
  const inc = all[S.detailId] || S.result.incidents[0];
  S.detailId = inc.id;
  const verdicts = S.result.verdicts.filter((x) => x.incident_id === inc.id);
  const b = inc.score_breakdown;
  v.innerHTML = `<div class="detail-head"><h2>${esc(inc.id)}</h2>${levelBadge(inc.label, inc.severity)} ${routeChip(inc.route)}
      ${inc.needs_human_review ? '<span class="chip" style="color:var(--amber);border-color:var(--amber)">⚠ needs human review</span>' : ""}
      <select id="detail-pick">${S.result.incidents.map((i) => `<option value="${esc(i.id)}" ${i.id === inc.id ? "selected" : ""}>${esc(i.id)} · ${esc(i.hosts.join(" + "))} · ${i.severity} · ${esc(ROUTE_LABEL[i.route])}</option>`).join("")}</select></div>
    ${inc.hosts.length > 1 ? `<div class="note" style="border-color:var(--violet)">Cross-host incident: ${esc(inc.hosts.join(" → "))} (linked by the Executor because the same account moved between them)</div>` : ""}
    <p style="color:#c3cfdf;margin:6px 0 8px">${esc(inc.summary)}</p>
    <div>${(inc.techniques || []).map((t) => `<span class="chip ttp" title="${esc(t.tactic)}">${esc(t.id)} ${esc(t.name)}</span>`).join("")}</div>
    ${inc.close_note ? `<div class="note">${esc(inc.close_note)}</div>` : ""}
    ${inc.checklist ? `<div class="note amber"><b>Analyst checklist</b><ul>${inc.checklist.map((c) => `<li>${esc(c)}</li>`).join("")}</ul></div>` : ""}
    <div class="row wide-left" style="margin-top:14px">
      <div class="panel"><div class="panel-head"><span>// TIMELINE OF CORRELATED ALERTS</span><span class="muted">${inc.alert_ids.length} alerts · ${fmtTime(inc.start)} → ${fmtTime(inc.end)}</span></div>
        ${timelineChart(inc, A)}
        <div class="scroll" style="max-height:300px;margin-top:10px"><table class="tbl"><thead><tr><th>ID</th><th>Time</th><th>Rule</th><th>Stage</th><th>User</th><th>Indicator</th><th>Message</th></tr></thead><tbody>
        ${inc.alert_ids.map((id) => { const a = A[id], st = S.result.stage_of[id] || "context";
          const ioc = a.domain || (isExternal(a.src_ip) ? a.src_ip : "") || (isExternal(a.dst_ip) ? a.dst_ip : "") || (a.hash ? a.hash.slice(0, 12) + "…" : "");
          return `<tr><td>${esc(id)}</td><td>${esc(fmtTime(a.ts))}</td><td>${esc(a.rule_name)}</td><td style="color:${STAGE_COLOR[st]}">${esc(st)}</td><td>${esc(a.user)}</td><td>${esc(ioc)}</td><td class="muted">${esc(a.message)}</td></tr>`; }).join("")}
        </tbody></table></div></div>
      <div class="panel"><div class="panel-head"><span>// SEVERITY RUBRIC</span><span class="total" style="font:900 26px var(--font-display);color:${LEVEL_COLOR[inc.label]}">${b.total}</span></div>
        <div class="breakdown">
          ${[["Kill-chain stages", b.stage_points, 45, `${inc.stages.length} × 15`], ["Asset criticality", b.asset_points, 25, inc.asset_criticality],
             ["Threat intel", b.intel_points, 20, inc.intel_verdict], ["Behaviour", b.behaviour_points, 10, inc.behaviour]].map(([l, p, max, why]) =>
            `<div class="item"><div class="lbl"><span>${l} <span class="muted">· ${esc(why)}</span></span><b>${p > 0 ? "+" : ""}${p}</b></div>
             <div class="track"><div class="fill ${p < 0 ? "neg" : ""}" data-w="${Math.abs(p) / max * 100}%"></div></div></div>`).join("")}
        </div>
        <div class="panel-head" style="margin-top:16px"><span>// CRITIC VERDICTS</span></div>
        ${verdicts.map((x) => `<div class="vcard ${x.passed ? "pass" : "fail"}" style="margin-bottom:8px"><h4>${x.passed ? "✔" : "✘"} CP${x.checkpoint} · ${esc(x.target)} #${x.attempt}${x.checkpoint === 1 ? ` · critic ${x.critic_score} vs executor ${x.agent_score}` : ""}</h4>
          <ul>${x.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>`).join("") || '<p class="muted">Low-severity incident: verified silently.</p>'}
        <div class="panel-head" style="margin-top:16px"><span>// CLAIMS + CITED EVIDENCE</span></div>
        <ul class="claims" style="padding-left:18px;margin:0">${inc.claims.map((c) => `<li>${esc(c.text)}<br><code class="ids">${esc(c.alert_ids.join(", ") || "NO EVIDENCE")}</code></li>`).join("")}</ul>
      </div>
    </div>
    <div class="row two">
      <div class="panel"><div class="panel-head"><span>// RESEARCH AGENT · INVESTIGATION</span><span class="muted">${inc.candidates.length} candidate(s)</span></div>
        ${inc.candidates.map((cid) => { const p = E.plans[cid]; if (!p) return "";
          return `<p style="margin:6px 0 4px"><b>${esc(cid)}</b> <span class="chip">${p.planner === "llm" ? "planned by LLM" : "standard checklist"}</span></p>
            ${p.rationale ? `<p class="muted" style="margin:0 0 6px;font-size:12px">“${esc(p.rationale)}”</p>` : ""}
            <div>${p.calls.map(([tool, arg]) => `<span class="chip">${esc(tool)}(${esc(arg.length > 22 ? arg.slice(0, 20) + "…" : arg)})</span>`).join("")}</div>
            ${p.rejected.length ? `<p style="color:var(--red);font-size:11.5px;margin:6px 0 0">Rejected invalid calls: ${esc(p.rejected.join(", "))}</p>` : ""}`; }).join("")}
        <div class="panel-head" style="margin-top:16px"><span>// ANALYST FEEDBACK</span></div>
        <p class="muted" style="font-size:12px;margin:0 0 8px">Teach the system: the lesson is stored in analyst memory and applied on the next run.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn" data-fb="false_positive">Mark false positive</button><button class="btn danger" data-fb="confirmed">Confirm malicious</button></div>
        <div id="fb-out" class="muted" style="font-size:12px;margin-top:8px"></div>
      </div>
      <div class="panel"><div class="panel-head"><span>// ENRICHMENT RESULTS</span></div>
        ${inc.hosts.map((h) => `<dl class="kv" style="margin-bottom:8px">${Object.entries(E.hosts[h] || { host: h, status: "not looked up" }).map(([k, val]) => `<dt>${esc(k)}</dt><dd>${esc(val)}</dd>`).join("")}</dl>`).join("")}
        ${inc.users.map((u) => E.users[u] ? `<p style="margin:12px 0 4px"><b>${esc(u)}</b> <span class="muted">baseline</span></p><dl class="kv"><dt>hours</dt><dd>${esc(E.users[u].work_hours.join("–"))}h</dd><dt>usual hosts</dt><dd>${esc(E.users[u].usual_hosts.join(", "))}</dd>${E.users[u].learned && E.users[u].learned.length ? `<dt>learned</dt><dd style="color:var(--green)">${esc(E.users[u].learned.join(", "))}</dd>` : ""}</dl>` : "").join("")}
        <p style="margin:12px 0 4px"><b>Indicators</b></p>
        <table class="tbl"><tbody>${[...new Set(inc.alert_ids.flatMap((id) => Object.keys(E.alerts[id].intel)))].map((ioc) => { const r = E.intel[ioc];
          return `<tr><td style="word-break:break-all">${esc(ioc.length > 40 ? ioc.slice(0, 16) + "…" : ioc)}</td><td style="color:${REP_COLOR[r.reputation]}">${esc(r.reputation)}</td><td class="muted">${esc(r.source === "analyst memory" ? "🧠 " : "")}${esc(r.note)}</td></tr>`; }).join("")}</tbody></table>
        ${E.hunts && Object.keys(E.hunts).some((k) => inc.alert_ids.some((id) => Object.keys(E.alerts[id].intel).includes(k))) ? `<p style="margin:12px 0 4px"><b>Hunts</b></p>${Object.entries(E.hunts).filter(([k]) => inc.alert_ids.some((id) => Object.keys(E.alerts[id].intel).includes(k))).map(([k, h]) => `<div class="muted" style="font-size:12px">${esc(k.length > 30 ? k.slice(0, 16) + "…" : k)}: ${h.alerts} alert(s) on ${esc(h.hosts.join(", "))}</div>`).join("")}` : ""}
      </div>
    </div>`;
  $$("[data-fb]", v).forEach((b) => b.addEventListener("click", async () => {
    const r = await fetch(`/api/runs/${S.runId}/feedback`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: inc.id, verdict: b.dataset.fb }) });
    const data = await r.json();
    if (!r.ok) return toast(`<b style="color:var(--red)">FEEDBACK FAILED</b> ${esc(data.detail)}`, "red");
    const l = data.learned, parts = [...l.allow.map((x) => `allow-listed ${x}`), ...l.block.map((x) => `block-listed ${x}`), ...l.baselines];
    $("#fb-out").innerHTML = parts.length ? "Learned: " + esc(parts.join("; ")) : "Nothing new to learn from this incident.";
    toast(`🧠 Analyst memory updated for <b>${esc(inc.id)}</b> · applies on the next run`, "green");
  }));
  $("#detail-pick").addEventListener("change", (e) => { S.detailId = e.target.value; RENDER.detail(); });
  animateBars(v);
};

function timelineChart(inc, A) {
  const alerts = inc.alert_ids.map((id) => A[id]);
  const rules = [...new Set(alerts.map((a) => a.rule_name))];
  const W = 900, rowH = 40, m = { l: 190, r: 24, t: 14, b: 30 }, H = m.t + m.b + rules.length * rowH;
  const ts = alerts.map((a) => +new Date(a.ts));
  let t0 = Math.min(...ts), t1 = Math.max(...ts);
  if (t1 - t0 < 120e3) { t0 -= 60e3; t1 += 60e3; }
  const x = (t) => m.l + ((t - t0) / (t1 - t0)) * (W - m.l - m.r);
  let g = `<svg class="chart" viewBox="0 0 ${W} ${H}">`;
  rules.forEach((r, k) => {
    const yy = m.t + k * rowH + rowH / 2;
    g += `<line class="axis" x1="${m.l}" x2="${W - m.r}" y1="${yy}" y2="${yy}" stroke-dasharray="2 4"/><text class="tick" x="${m.l - 10}" y="${yy + 4}" text-anchor="end" style="font-size:11px">${esc(r)}</text>`;
  });
  for (let k = 0; k <= 4; k++) { const t = t0 + (t1 - t0) * k / 4; const d = new Date(t);
    g += `<text class="tick" x="${x(t)}" y="${H - 8}" text-anchor="middle">${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}</text>`; }
  alerts.forEach((a, n) => {
    const st = S.result.stage_of[a.id] || "context", c = STAGE_COLOR[st];
    g += `<circle class="dot" cx="${x(+new Date(a.ts))}" cy="${m.t + rules.indexOf(a.rule_name) * rowH + rowH / 2}" r="7" fill="${c}" fill-opacity=".8" stroke="#fff" stroke-opacity=".5" style="animation-delay:${n * 40}ms"><title>${esc(a.id)} · ${esc(a.ts)} · ${esc(st)}\n${esc(a.message)}</title></circle>`;
  });
  return g + "</svg>";
}

/* ================================================================ ATT&CK */

RENDER.attack = function () {
  const v = $("#view-attack");
  if (!S.result) return (v.innerHTML = placeholder("NO RUN YET", "Run triage first."));
  const at = S.result.attack;
  v.innerHTML = `<h2 class="section-title">MITRE ATT&amp;CK COVERAGE</h2>
    <p class="section-sub">Techniques observed in queued or escalated incidents. Glowing = observed · 🛡 = detection rule passed the Critic.</p>
    <div class="panel"><div class="attack-grid">${at.tactics.map((tac, ci) => `<div><div class="tactic-h">${esc(tac)}</div>
      ${at.techniques.filter((t) => t.tactic === tac).map((t, k) => `<div class="ttp-cell ${t.incidents.length ? "hit" : ""}" style="animation-delay:${(ci * 2 + k) * 60}ms">
        <b>${esc(t.id)} ${t.covered ? "🛡" : ""}</b>${esc(t.name)}${t.incidents.length ? `<div class="incs">${t.incidents.map((i) => `<a href="#" data-id="${esc(i)}" style="color:#ffd2da">${esc(i)}</a>`).join(", ")}</div>` : ""}</div>`).join("")}</div>`).join("")}
    </div></div>`;
  $$("a[data-id]", v).forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); openDetail(a.dataset.id); }));
};

/* ================================================================ response (playbook + rule) */

RENDER.response = function () {
  const v = $("#view-response");
  if (!S.result) return (v.innerHTML = placeholder("NO RUN YET", "Run triage first."));
  const esc8 = S.result.incidents.filter((i) => i.route === "escalate");
  if (!esc8.length) return (v.innerHTML = placeholder("NOTHING ESCALATED", "No incident reached severity 70, so no playbook or rule was needed."));
  const inc = esc8.find((i) => i.id === S.responseId) || esc8[0];
  S.responseId = inc.id;
  const bundle = S.result.detection_rule[inc.id];
  const final = S.result.verdicts.filter((x) => x.checkpoint === 2 && x.incident_id === inc.id).pop();
  const t = final.rule_tests, dec = S.result.approvals[inc.id];
  const hold = dec && dec.decision !== "approved";
  const sig = bundle.sigma || { sigma: "", splunk: "", elastic: [], errors: [] };
  v.innerHTML = `<h2 class="section-title">RESPONSE</h2><p class="section-sub">Software Development agent output for severity ≥ 70, validated by Critic checkpoint 2.</p>
    <div class="filters">${esc8.map((i) => `<button class="fbtn ${i.id === inc.id ? "on" : ""}" data-id="${esc(i.id)}">${esc(i.id)} · ${esc(i.hosts.join(" + "))} · ${i.severity}</button>`).join("")}</div>
    <div class="panel"><div class="detail-head"><h2 style="font-size:19px">${esc(inc.headline)}</h2>${levelBadge(inc.label, inc.severity)}</div>
      ${dec ? `<div class="note ${hold ? "red" : ""}">🧑‍⚖️ Containment <b>${esc(dec.decision.replace("_", " "))}</b> by ${esc(dec.by)}${dec.comment ? ` — <i>${esc(dec.comment)}</i>` : ""}</div>` : ""}
      <div class="tests">${[["Fires on replayed attack", t.fires_on_attack_replay], ["Fires on this incident", t.fires_on_incident],
        ["Silent on benign logs", t.silent_on_benign], ["Critic checkpoint 2", final.passed]].map(([l, ok]) =>
        `<div class="test ${ok ? "ok" : "bad"}">${l}<b>${ok ? "PASS" : "FAIL"}</b></div>`).join("")}</div>
    </div>
    <div class="row two">
      <div class="panel"><div class="panel-head"><span>// INCIDENT-RESPONSE PLAYBOOK</span><span class="muted">evidence preserved before containment</span></div>
        <div class="stepper">${S.result.playbook[inc.id].map((s, n) => `<div class="step ${hold && s.phase === "contain" ? "hold" : ""}" style="--pc:${PHASE_COLOR[s.phase]};animation-delay:${n * 70}ms">
          <div class="ph">${esc(s.order)} · ${esc(s.phase.replace("_", " "))}${hold && s.phase === "contain" ? '<span class="hold-tag">ON HOLD</span>' : ""}</div>
          <div>${esc(s.action)}</div><div class="own">${esc(s.owner)}</div></div>`).join("")}</div></div>
      <div class="panel"><div class="panel-head"><span>// DETECTION RULE · ${esc(bundle.rule.id)}</span><span class="muted">attempt ${bundle.attempt}</span></div>
        <pre class="code">${yamlHtml(bundle.yaml)}</pre>
        <details><summary>Generated unit test (pytest)</summary><pre class="code">${esc(bundle.unit_test)}</pre></details>
      </div>
    </div>
    <div class="panel"><div class="panel-head"><span>// SIGMA EXPORT (pySigma)</span><a class="btn" href="/api/runs/${S.runId}/export/sigma?incident=${encodeURIComponent(inc.id)}">⬇ rule.sigma.yml</a></div>
      <div class="filters" id="sig-tabs"><button class="fbtn on" data-s="sigma">Sigma YAML</button><button class="fbtn" data-s="splunk">Splunk SPL</button><button class="fbtn" data-s="elastic">Elastic (Lucene)</button></div>
      <pre class="code" id="sig-out"></pre>
      ${sig.errors.length ? `<p style="color:var(--amber);font-size:12px">${esc(sig.errors.join("; "))}</p>` : ""}
      <p class="muted" style="font-size:11.5px">Base rules use Windows Security / Sysmon fields; the sequence is a Sigma correlation rule (temporal_ordered). Splunk's backend converts it as unordered "temporal"; Elastic gets one query per step.</p>
    </div>`;
  const showSig = (k) => { $("#sig-out").innerHTML = k === "sigma" ? yamlHtml(sig.sigma) : esc(k === "splunk" ? sig.splunk : sig.elastic.map((q, n) => `# step ${n + 1}\n${q}`).join("\n\n")); };
  $$("#sig-tabs button").forEach((b) => b.addEventListener("click", () => { $$("#sig-tabs button").forEach((x) => x.classList.toggle("on", x === b)); showSig(b.dataset.s); }));
  showSig("sigma");
  $$(".fbtn[data-id]", v).forEach((b) => b.addEventListener("click", () => { S.responseId = b.dataset.id; RENDER.response(); }));
};

/* ================================================================ reports */

RENDER.reports = function () {
  const v = $("#view-reports");
  if (!S.result) return (v.innerHTML = placeholder("NO RUN YET", "Run triage first."));
  const tickets = Object.values(S.result.tickets), open = tickets.filter((k) => k.status === "Open");
  const base = `/api/runs/${S.runId}/export`;
  v.innerHTML = `<h2 class="section-title">TICKETS &amp; REPORTS</h2><p class="section-sub">Business Automation agent output · all integrations are mocks.</p>
    <div class="filters"><a class="btn solid" href="${base}/pdf">⬇ Report + handover PDF</a><a class="btn" href="${base}/tickets">⬇ tickets.json</a></div>
    <div class="panel"><div class="panel-head"><span>// OPEN TICKETS · ${open.length}</span><span class="muted">${tickets.length - open.length} created as closed</span></div>
      <div class="scroll"><table class="tbl"><thead><tr><th>Ticket</th><th>Pri</th><th>Title</th><th>Queue</th><th>Assignee</th><th>SLA</th><th>Due</th><th>Containment</th></tr></thead><tbody>
      ${open.map((k) => `<tr><td><b>${esc(k.ticket_id)}</b></td><td><span class="badge lv-${{ P1: "critical", P2: "high", P3: "medium" }[k.priority] || "low"}">${esc(k.priority)}</span></td>
        <td>${esc(k.title)}${k.needs_human_review ? ' <span style="color:var(--amber)">⚠</span>' : ""}</td><td>${esc(k.queue)}</td><td>${esc(k.assignee)}</td>
        <td>${esc(k.sla_minutes)}m</td><td>${esc(k.sla_due)}</td><td class="muted">${esc(k.containment || "—")}</td></tr>`).join("")}</tbody></table></div></div>
    <div class="panel"><div class="panel-head"><span>// NOTIFICATIONS (MOCK)</span></div>
      ${S.result.notifications.map((n) => `<div class="term-line"><span class="t">${esc(n.sent_at)}</span> <span class="a" style="color:${n.channel === "slack" ? "#bb9af7" : "#7aa2f7"}">${esc(n.channel.toUpperCase())}</span>${esc(n.to)} <span class="out">→ ${esc(n.message)}</span></div>`).join("")}</div>
    <div class="row two"><div class="panel"><div class="panel-head"><span>// INCIDENT REPORT</span></div><div class="md md-box">${md(S.result.report.summary_md)}</div></div>
      <div class="panel"><div class="panel-head"><span>// SHIFT HANDOVER</span></div><div class="md md-box">${md(S.result.report.handover_md)}</div></div></div>
    <div class="panel"><details><summary>Auto-close justification notes (${tickets.length - open.length})</summary>
      ${S.result.incidents.filter((i) => i.route === "auto_close").map((i) => `<p class="muted" style="font-size:12px;margin:4px 0">${esc(i.close_note)}</p>`).join("")}</details></div>`;
};

/* ================================================================ evaluation */

RENDER.eval = function () {
  const v = $("#view-eval");
  if (!S.result) return (v.innerHTML = placeholder("NO RUN YET", "Run triage first."));
  const r = S.result.evaluation;
  if (!r) return (v.innerHTML = placeholder("NO GROUND TRUTH", "This dataset has no labels. Use the synthetic dataset, or the Benchmark tab."));
  const tile = (label, value, cls) => `<div class="kpi ${cls}"><span>${label}</span><b>${value}</b></div>`;
  v.innerHTML = `<h2 class="section-title">EVALUATION</h2><p class="section-sub">This run against the ground truth (read only here, after the run — the agents never see it).</p>
    <div class="kpis" style="grid-template-columns:repeat(4,1fr)">
      ${tile("Attack chains correct", `${r.attacks_correlated}/${r.attacks_total}`, "green")}
      ${tile("Alert precision", r.alerts.precision.toFixed(3), "cyan")}
      ${tile("Alert recall", r.alerts.recall.toFixed(3), "cyan")}
      ${tile("Alert F1", r.alerts.f1.toFixed(3), "cyan")}
      ${tile("Benign alerts escalated", `${r.benign_wrongly_escalated}/${r.benign_total}`, r.benign_wrongly_escalated ? "red" : "green")}
      ${tile("Critic retries", r.critic_retries, "magenta")}
      ${tile("LLM rewrites (fact-check)", r.prose_rewrites, "magenta")}
      ${tile("Rule tests passed", `${r.rule_tests_passed}/${r.rule_tests_total}`, "green")}</div>
    <div class="panel"><div class="panel-head"><span>// ATTACK CHAINS VS GROUND TRUTH</span></div><div class="scroll"><table class="tbl"><thead><tr><th>Chain</th><th>Name</th><th>Incident</th><th>Hosts</th><th>Score</th><th>Expected</th><th>Actual</th><th>Alerts</th><th></th></tr></thead><tbody>
      ${r.chains.map((c) => `<tr><td><b>${esc(c.chain)}</b></td><td>${esc(c.name)}</td><td><a href="#" data-id="${esc(c.incident)}">${esc(c.incident)}</a></td><td>${esc(c.hosts.join(", "))}</td><td>${c.severity}</td><td>${esc(c.expected_band)}</td><td>${esc(c.actual_band)}</td><td>${esc(c.alerts_found)}</td><td>${c.correct ? '<span style="color:var(--green)">✔ correct</span>' : '<span style="color:var(--red)">✘ miss</span>'}</td></tr>`).join("")}</tbody></table></div></div>
    <p class="muted" style="font-size:12px">Alert metrics: an attack alert is a true positive when it lands in an incident scored ≥ 40. For many datasets and the Critic ablation, open the Benchmark tab.</p>`;
  $$("a[data-id]", v).forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); openDetail(a.dataset.id); }));
};

/* ================================================================ benchmark */

RENDER.benchmark = function () {
  const v = $("#view-benchmark");
  v.innerHTML = `<h2 class="section-title">BENCHMARK</h2>
    <p class="section-sub">Many generated datasets (different seeds and noise levels), plus a fault campaign: every fault is run with the Critic enforcing and with the Critic disabled. Uses the deterministic mock model so results are reproducible.</p>
    <div class="panel"><div class="filters">
      <label class="muted" style="font-size:12px">Seeds <input type="text" id="b-seeds" value="1,2,3,4,5" style="width:120px;margin:0 0 0 6px"></label>
      <label class="muted" style="font-size:12px">Alerts per dataset <input type="text" id="b-sizes" value="150,300,600" style="width:130px;margin:0 0 0 6px"></label>
      <label class="muted" style="font-size:12px">Faults per type <input type="text" id="b-per" value="6" style="width:50px;margin:0 0 0 6px"></label>
      <button class="btn solid" id="b-run">Run benchmark</button></div>
      <div id="b-progress" class="muted" style="font-size:12px"></div>
      <div class="sev" style="margin-top:8px"><div class="bar"><i id="b-bar" style="background:var(--accent)"></i></div></div></div>
    <div id="b-out">${S.bench ? "" : '<p class="muted">No benchmark run yet.</p>'}</div>`;
  if (S.bench) drawBench(S.bench);
  $("#b-run").addEventListener("click", async () => {
    const nums = (id) => $(id).value.split(",").map((x) => parseInt(x, 10)).filter((x) => !isNaN(x));
    $("#b-run").disabled = true;
    const r = await fetch("/api/benchmark", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ seeds: nums("#b-seeds"), sizes: nums("#b-sizes"), per_type: nums("#b-per")[0] || 6 }) }).then((x) => x.json());
    for (;;) {
      await sleep(500);
      const j = await fetch(`/api/benchmark/${r.job_id}`).then((x) => x.json());
      if (!$("#b-progress")) return;
      $("#b-progress").textContent = `${j.phase}: ${j.step} (${j.done}/${j.total})`;
      $("#b-bar").style.width = j.total ? `${(j.done / j.total) * 100}%` : "0";
      if (j.status === "done") { S.bench = j.result; drawBench(j.result); break; }
      if (j.status === "error") { $("#b-progress").textContent = "Failed: " + j.step; break; }
    }
    $("#b-run").disabled = false;
  });
};

function drawBench(res) {
  const b = res.benchmark, a = res.ablation;
  const pm = (x) => `${x[0].toFixed(3)} <span class="muted">± ${x[1].toFixed(3)}</span>`;
  const misses = b.rows.filter((r) => r.chains_ok < r.chains_total);
  $("#b-out").innerHTML = `<div class="panel"><div class="panel-head"><span>// DETECTION ACROSS DATASETS</span><span class="muted">finished ${esc(res.finished)}</span></div>
      <table class="tbl"><thead><tr><th>Alerts per dataset</th><th>Runs</th><th>Precision</th><th>Recall</th><th>F1</th><th>Chains detected</th><th>Benign incidents escalated</th></tr></thead><tbody>
      ${b.summary.map((s) => `<tr><td>${s.size}</td><td>${s.runs}</td><td>${pm(s.precision)}</td><td>${pm(s.recall)}</td><td>${pm(s.f1)}</td><td>${esc(s.chains_detected)}</td><td>${s.benign_incidents_escalated}</td></tr>`).join("")}</tbody></table>
      ${misses.length ? `<p class="muted" style="font-size:12px">Chain misses: ${misses.map((r) => `seed ${r.seed} (${r.alerts} alerts): ${esc(r.chains)}`).join(" · ")} — usually an attack on a low-criticality host scoring below its expected band.</p>` : ""}
      <details><summary>All ${b.rows.length} runs</summary><table class="tbl"><thead><tr><th>Seed</th><th>Alerts</th><th>TP</th><th>FP</th><th>FN</th><th>P</th><th>R</th><th>F1</th><th>Chains</th><th>s</th></tr></thead><tbody>
        ${b.rows.map((r) => `<tr><td>${r.seed}</td><td>${r.alerts}</td><td>${r.tp}</td><td>${r.fp}</td><td>${r.fn}</td><td>${r.precision}</td><td>${r.recall}</td><td>${r.f1}</td><td>${esc(r.chains)}</td><td>${r.seconds}</td></tr>`).join("")}</tbody></table></details></div>
    <div class="panel"><div class="panel-head"><span>// CRITIC ABLATION · ${a.total.injected} INJECTED FAULTS</span></div>
      <table class="tbl"><thead><tr><th>Fault</th><th>Agent</th><th>Injected</th><th>Caught by Critic</th><th>Corrected in output</th><th>Shipped with Critic off</th></tr></thead><tbody>
      ${a.table.map((r) => `<tr><td>${esc(r.fault.replace(/_/g, " "))}</td><td>${esc(r.agent)}</td><td>${r.injected}</td>
        <td><div class="sev"><div class="bar"><i data-w="${(r.caught / r.injected) * 100}%" style="background:var(--green)"></i></div><b>${r.caught}</b></div></td>
        <td><div class="sev"><div class="bar"><i data-w="${(r.corrected / r.injected) * 100}%" style="background:var(--green)"></i></div><b>${r.corrected}</b></div></td>
        <td><div class="sev"><div class="bar"><i data-w="${(r.shipped_without_critic / r.injected) * 100}%" style="background:var(--red)"></i></div><b>${r.shipped_without_critic}</b></div></td></tr>`).join("")}
      <tr><td><b>Total</b></td><td></td><td><b>${a.total.injected}</b></td><td><b>${a.total.caught}</b></td><td><b>${a.total.corrected}</b></td><td><b>${a.total.shipped_without_critic}</b></td></tr></tbody></table>
      <p class="muted" style="font-size:12px">Caught = the Critic rejected work in that run. Corrected = the defect is absent from the final output. Shipped = with the Critic disabled, the defect reached the final output.</p></div>`;
  animateBars($("#b-out"));
}

/* ================================================================ memory */

RENDER.memory = async function () {
  const v = $("#view-memory");
  const m = await fetch("/api/memory").then((r) => r.json());
  const row = (kind, key, note) => `<tr><td style="word-break:break-all">${esc(key)}</td><td class="muted">${esc(note)}</td><td><button class="btn" data-forget="${esc(kind)}|${esc(key)}">Forget</button></td></tr>`;
  v.innerHTML = `<h2 class="section-title">ANALYST MEMORY</h2>
    <p class="section-sub">What analysts taught the system (false positives, confirmed incidents). The Research agent applies it on every run with "Use analyst memory" on.</p>
    <div class="row two">
      <div class="panel"><div class="panel-head"><span>// ALLOW-LIST (FALSE POSITIVES)</span><span class="muted">${Object.keys(m.allow).length}</span></div>
        <table class="tbl"><tbody>${Object.entries(m.allow).map(([k, x]) => row("allow", k, x.note)).join("") || '<tr><td class="muted">empty</td></tr>'}</tbody></table></div>
      <div class="panel"><div class="panel-head"><span>// BLOCK-LIST (CONFIRMED)</span><span class="muted">${Object.keys(m.block).length}</span></div>
        <table class="tbl"><tbody>${Object.entries(m.block).map(([k, x]) => row("block", k, x.note)).join("") || '<tr><td class="muted">empty</td></tr>'}</tbody></table></div></div>
    <div class="panel"><div class="panel-head"><span>// LEARNED USER BASELINES</span></div>
      <table class="tbl"><tbody>${Object.entries(m.baselines).map(([u, b]) => row("baselines", u, `extra hosts: ${b.extra_hosts.join(", ") || "—"} · extra hours: ${b.extra_hours.map((h) => String(h).padStart(2, "0") + ":00").join(", ") || "—"}`)).join("") || '<tr><td class="muted">empty</td></tr>'}</tbody></table></div>
    <div class="panel"><div class="panel-head"><span>// LOG</span><button class="btn danger" id="mem-clear">Clear all memory</button></div>
      ${m.log.slice().reverse().map((l) => `<div class="term-line"><span class="t">${esc(l.at)}</span> <span class="a">${esc(l.verdict.replace("_", " "))}</span>${esc(l.incident)} by ${esc(l.by)}</div>`).join("") || '<p class="muted">No feedback yet. Mark an incident false positive or confirmed in Detail or in the approval step.</p>'}</div>`;
  $$("[data-forget]", v).forEach((b) => b.addEventListener("click", async () => {
    const [kind, key] = b.dataset.forget.split("|");
    await fetch(`/api/memory/${encodeURIComponent(kind)}/${encodeURIComponent(key)}`, { method: "DELETE" });
    RENDER.memory();
  }));
  $("#mem-clear").addEventListener("click", async () => { await fetch("/api/memory", { method: "DELETE" }); RENDER.memory(); });
};

/* ================================================================ ask */

RENDER.ask = function () {
  const v = $("#view-ask");
  if (!S.result) return (v.innerHTML = placeholder("NO RUN YET", "Run triage first."));
  const top = S.result.incidents[0];
  const sugg = [`Why is ${top.id} rated ${top.label}?`, "What did the Critic reject?", `What should we do about ${top.id}?`,
    "How did the Research agent investigate?", "Did the fact-check catch anything?", "What has analyst memory learned?"];
  v.innerHTML = `<h2 class="section-title">ASK THE RUN</h2>
    <p class="section-sub">Retrieval is deterministic: your question is matched to incidents and topics, and only facts from this run are passed to the model
      (<b style="color:var(--cyan)">Ollama · ${esc(S.result.config.ollama_model)}</b>), which writes the answer. The Critic fact-checks every answer before you see it.</p>
    <div class="panel chat"><div class="suggest">${sugg.map((q) => `<button>${esc(q)}</button>`).join("")}</div>
      <div class="chat-log" id="chat-log"></div>
      <form class="chat-input" id="chat-form"><input type="text" id="chat-q" placeholder="ask about incidents, scores, the Critic, playbooks, tickets…" autocomplete="off"><button class="btn solid">Send ▶</button></form></div>`;
  const log = $("#chat-log");
  const draw = () => {
    log.innerHTML = S.chat.length ? S.chat.map(renderMsg).join("") : '<p class="muted center" style="margin:auto">Ask about an incident (INC-…), a host, user, IP or domain, the Critic, scores, playbooks, rules, tickets, ATT&amp;CK, research plans or analyst memory.</p>';
    log.scrollTop = log.scrollHeight;
  };
  const send = async (q) => {
    if (!q.trim()) return;
    S.chat.push({ role: "user", text: q }, { role: "bot", pending: true });
    draw();
    try {
      const r = await fetch(`/api/runs/${S.runId}/ask`, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q }) });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || r.statusText);
      S.chat[S.chat.length - 1] = { role: "bot", ...data };
    } catch (err) { S.chat[S.chat.length - 1] = { role: "bot", answer: `Request failed: ${err.message}`, facts: [], incidents: [], alerts: [], backend: "error" }; }
    draw();
  };
  $$(".suggest button", v).forEach((b) => b.addEventListener("click", () => send(b.textContent)));
  $("#chat-form").addEventListener("submit", (e) => { e.preventDefault(); const q = $("#chat-q").value; $("#chat-q").value = ""; send(q); });
  draw();
};

function renderMsg(m) {
  if (m.role === "user") return `<div class="msg user">${esc(m.text)}</div>`;
  if (m.pending) return `<div class="msg bot"><div class="typing"><span></span><span></span><span></span></div></div>`;
  const refs = [...m.incidents, ...m.alerts.slice(0, 8)];
  return `<div class="msg bot"><div class="md">${md(m.answer)}</div>
    <div class="meta">grounded in: ${esc(refs.join(", ") || "run overview")}${m.alerts.length > 8 ? "…" : ""} · answered by ${esc(m.backend)}${m.fact_check ? ` · fact-check: ${m.fact_check.passed ? (m.fact_check.attempts > 1 ? `passed after ${m.fact_check.attempts - 1} rewrite(s)` : "passed") : "replaced by facts"}` : ""}</div>
    <details><summary>${m.facts.length} facts retrieved from the run</summary><ul style="font-size:11.5px;color:var(--muted);padding-left:16px">${m.facts.map((f) => `<li>${esc(f)}</li>`).join("")}</ul></details></div>`;
}

/* ================================================================ hero: agent pills */

const PILL_FOR = { planner: "planner", research: "research", executor: "executor", critic_cp1: "critic", critic_cp2: "critic",
  devagent: "devagent", approval: "approval", automation: "automation" };

function agentLive(node, label) {
  const name = PILL_FOR[node];
  $$(".pill.live").forEach((p) => { p.classList.remove("live"); p.classList.add("done-ag"); });
  if (name) {
    const pill = $(`.pill[data-agent="${name}"]`);
    pill.classList.remove("done-ag", "rejected");
    pill.classList.add("live");
  }
  $("#visual-caption").innerHTML = `<b>${esc(label.replace(/^\d\s+/, ""))}</b> is working`;
}

function agentRejected() {
  const pill = $('.pill[data-agent="critic"]');
  pill.classList.add("rejected");
  setTimeout(() => pill.classList.remove("rejected"), 1600);
}

function agentsSettle(failed = false) {
  $$(".pill.live").forEach((p) => { p.classList.remove("live"); p.classList.add(failed ? "rejected" : "done-ag"); });
}

/* ================================================================ hero: wire tunnel */

// A perspective tunnel of dotted rings. It drifts slowly at rest, speeds up while agents work,
// and briefly takes a colour when something happens (red: Critic rejection, mint: run complete).
const Tunnel = (() => {
  const canvas = $("#tunnel");
  const ctx = canvas.getContext("2d");
  const RINGS = 22, SPOKES = 40;
  let w = 0, h = 0, dpr = 1, phase = 0, twist = 0, speed = 0.05, last = performance.now();
  let flashColor = null, flashUntil = 0;

  function resize() {
    dpr = Math.min(2, window.devicePixelRatio || 1);
    w = canvas.clientWidth; h = canvas.clientHeight;
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  }

  function rgba(hex, a) {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`;
  }

  function draw() {
    if (!w || !h) return;
    ctx.clearRect(0, 0, w, h);
    const cx = w / 2, cy = h / 2, base = Math.max(w, h) * 0.075;
    const now = performance.now();
    const tint = flashColor && now < flashUntil ? flashColor : "#ece7df";
    const glow = flashColor && now < flashUntil ? 1 : 0;
    const rings = [];
    for (let i = 0; i < RINGS; i++) {
      const z = ((i + phase) % RINGS) / RINGS * 1.15 + 0.06;       // 0.06 (near) .. 1.21 (far)
      const r = base / z;
      const alpha = Math.max(0, Math.min(1, (1.25 - z) * 0.85)) * (0.35 + 0.65 * glow * (1 - z));
      const pts = [];
      for (let k = 0; k < SPOKES; k++) {
        const a = (k / SPOKES) * Math.PI * 2 + twist * (1.2 - z);
        pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r * 0.92]);
      }
      rings.push({ z, alpha, pts });
    }
    rings.sort((a, b) => b.z - a.z);
    ctx.lineWidth = 0.6;
    for (let k = 0; k < SPOKES; k++) {                                // spokes
      ctx.beginPath();
      rings.forEach((ring, n) => { const [x, y] = ring.pts[k]; n ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      ctx.strokeStyle = rgba(tint, 0.08 + glow * 0.08);
      ctx.stroke();
    }
    for (const ring of rings) {                                       // rings + dots
      ctx.beginPath();
      ring.pts.forEach(([x, y], n) => (n ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
      ctx.closePath();
      ctx.strokeStyle = rgba(tint, ring.alpha * 0.22);
      ctx.stroke();
      ctx.fillStyle = rgba(tint, ring.alpha * 0.9);
      const size = Math.max(0.6, 2.1 - ring.z * 1.4);
      for (const [x, y] of ring.pts) ctx.fillRect(x - size / 2, y - size / 2, size, size);
    }
  }

  function frame(t) {
    const dt = Math.min(0.1, (t - last) / 1000);
    last = t;
    const target = document.body.classList.contains("running") ? 1.6 : 0.12;
    speed += (target - speed) * Math.min(1, dt * 2.5);
    phase = (phase + speed * dt * 2) % RINGS;
    twist += dt * (0.04 + speed * 0.05);
    draw();
    requestAnimationFrame(frame);
  }

  new ResizeObserver(resize).observe(canvas);
  if (!reduceMotion) requestAnimationFrame(frame);
  return {
    flash(color) { flashColor = color; flashUntil = performance.now() + 900; if (reduceMotion) { draw(); setTimeout(draw, 950); } },
  };
})();

/* ================================================================ chrome */

// Panel headings arrive as "// UPPER CASE · WORDS" from the renderers; show them in sentence case.
const KEEP = { "ATT&CK": "ATT&CK", "MITRE": "MITRE", "LLM": "LLM", "IR": "IR", "CP1": "CP1", "CP2": "CP2", "SPL": "SPL",
  "PYSIGMA": "pySigma", "SIGMA": "Sigma", "SPLUNK": "Splunk", "ELASTIC": "Elastic", "LUCENE": "Lucene",
  "CRITIC": "Critic", "RESEARCH": "Research", "EXECUTOR": "Executor", "PLANNER": "Planner", "INC": "INC" };

function sentenceCase(text) {
  const words = text.replace(/^\/\/\s*/, "").replace(/\s+·\s+/g, ", ").split(/(\s+)/).map((tok) => {
    const core = tok.replace(/[(),:]/g, "");
    if (KEEP[core]) return tok.replace(core, KEEP[core]);
    if (/[a-z]/.test(core) && /[A-Z]/.test(core)) return tok;                    // already mixed case, e.g. pySigma
    if (/^[A-Z]+-\d+/.test(core) || /\d/.test(core) && /[A-Z]-/.test(core)) return tok;   // IDs like INC-002, SOC-RULE-...
    return tok.toLowerCase();
  }).join("");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function tidyHeads(root = document) {
  $$(".panel-head > span:first-child", root).forEach((el) => {
    if (el.dataset.tidy || !el.textContent.startsWith("//")) return;
    el.dataset.tidy = "1";
    el.textContent = sentenceCase(el.textContent);
  });
}

new MutationObserver(() => setTimeout(tidyHeads, 0)).observe($("main"), { childList: true, subtree: true });
tidyHeads();

window.addEventListener("scroll", () => $("#nav").classList.toggle("scrolled", window.scrollY > 24), { passive: true });

/* ================================================================ boot */

(async function boot() {
  initControls();
  buildPipeline();
  try { await loadMeta(); } catch { toast("Backend not reachable — start it with <b>python server.py</b>", "red"); }
})();

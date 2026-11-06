"use strict";
// All API data is rendered with textContent only (never innerHTML) so attack
// payloads in the dataset can never execute in the page.

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
};
const pretty = (s) => String(s || "").replace(/_/g, " ");
const NAMES = { rag_injection: "RAG injection", multi_turn_manipulation: "Multi-turn manipulation", output_validation: "Output validation" };
const cap = (s) => { if (NAMES[s]) return NAMES[s]; s = pretty(s); return s.charAt(0).toUpperCase() + s.slice(1); };
const pct = (m) => (m && m.percent !== null && m.percent !== undefined ? m.percent.toFixed(0) + "%" : "n/a");

const OUTCOME = {
  attack_success: ["Attack succeeded", "bad"],
  safe_completion: ["Blocked, task done", "good"],
  safe_incomplete: ["Blocked, task not done", "good"],
  not_applicable: ["Not applicable", "neutral"],
  error: ["Error", "neutral"],
};
const METRICS = [
  ["attack_success_rate", "Attacks that succeeded"],
  ["sensitive_information_exposure_rate", "Secret leaked"],
  ["unauthorized_tool_call_rate", "Out-of-policy tool call made"],
  ["blocked_call_rate", "A defense blocked a call"],
  ["task_completion_rate", "Normal task still done"],
];

let CASES = [];
let selected = "A-02";

async function api(path, body) {
  const opts = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
  let res;
  try { res = await fetch(path, opts); } catch (e) { throw new Error("Network error. Check your connection and try again."); }
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) {
    const detail = data && data.details ? data.details.map((d) => d.field + ": " + d.message).join("; ") : "";
    throw new Error((data && data.error ? data.error : "Request failed (" + res.status + ")") + (detail ? ". " + detail : ""));
  }
  return data;
}

function showError(msg) { const n = $("error"); n.textContent = msg || ""; n.hidden = !msg; }
const defenses = () => [...document.querySelectorAll("#defense-list input:checked")].map((i) => i.value);
const provisioning = () => document.querySelector("input[name=prov]:checked").value;

/* ---------- case list ---------- */
function renderCaseList() {
  const q = $("case-filter").value.trim().toLowerCase();
  const list = $("case-list");
  list.textContent = "";
  let shown = 0;
  let lastCat = null;
  CASES.forEach((c) => {
    const hay = (c.id + " " + c.title + " " + c.category).toLowerCase();
    if (q && !hay.includes(q)) return;
    if (c.category !== lastCat) { list.appendChild(el("div", "case-group", cap(c.category))); lastCat = c.category; }
    const b = el("button", "case-opt");
    b.type = "button";
    b.setAttribute("role", "option");
    b.setAttribute("aria-selected", String(c.id === selected));
    b.dataset.id = c.id;
    b.appendChild(el("span", "cid", c.id));
    b.appendChild(el("span", "ctitle", c.title));
    b.addEventListener("click", () => { selected = c.id; renderCaseList(); });
    b.addEventListener("dblclick", runOne);
    list.appendChild(b);
    shown++;
  });
  $("case-count").textContent = shown + " of " + CASES.length;
}

async function init() {
  try {
    const [cases, defs] = await Promise.all([api("/api/cases"), api("/api/defenses")]);
    CASES = cases.cases;
    renderCaseList();
    const box = $("defense-list");
    defs.defenses.forEach((d) => {
      const lab = el("label", "check");
      const inp = el("input");
      inp.type = "checkbox";
      inp.value = d.name;
      inp.checked = d.name === "sanitization" || d.name === "authorization";
      lab.appendChild(inp);
      const txt = el("span");
      txt.appendChild(el("span", "check-name", cap(d.name)));
      txt.appendChild(el("span", "check-desc", d.description));
      lab.appendChild(txt);
      box.appendChild(lab);
    });
  } catch (e) {
    showError("Could not load the test data. " + e.message);
  }
}

/* ---------- single run ---------- */
function renderCase(c) {
  $("ci-id").textContent = c.id;
  $("ci-cat").textContent = cap(c.category);
  const sev = $("ci-sev");
  sev.textContent = c.severity;
  sev.className = "sev sev-" + c.severity;
  $("ci-title").textContent = c.title;
  $("ci-policy").textContent = c.trusted_instruction;
  $("ci-chan").textContent = cap(c.injection_channel);
  $("ci-safe").textContent = c.expected_safe_behavior;
  $("ci-payload").textContent = c.attack_prompt;
}

function renderRun(node, title, r) {
  node.textContent = "";
  const [label, tone] = OUTCOME[r.outcome] || [cap(r.outcome), "neutral"];
  const head = el("div", "run-head");
  head.appendChild(el("h3", null, title));
  head.appendChild(el("span", "verdict " + tone, label));
  node.appendChild(head);

  const kv = el("dl", "kv");
  const row = (k, v, bad) => { kv.appendChild(el("dt", null, k)); kv.appendChild(el("dd", bad ? "bad" : null, v)); };
  const secrets = r.signals.exposed_secrets || [];
  const out = r.signals.external_recipients || [];
  row("Defenses on", r.defenses.length ? r.defenses.map(cap).join(", ") : "None");
  row("Secret leaked", secrets.length ? secrets.join(", ") : "No", secrets.length > 0);
  row("Sent outside", out.length ? out.join(", ") : "Nothing", out.length > 0);
  row("Injection reached model", r.signals.injection_reached_model ? "Yes" : "No");
  if (r.signals.defense_interventions && r.signals.defense_interventions.length) row("Defenses that acted", r.signals.defense_interventions.map(cap).join(", "));
  row("Normal task done", r.task_completed ? "Yes" : "No");
  node.appendChild(kv);

  node.appendChild(el("p", "label", "What happened"));
  const trace = el("div", "trace");
  const calls = r.tool_calls.slice();
  r.messages.forEach((m) => {
    const untrusted = m.trust === "untrusted";
    const step = el("div", "step" + (untrusted ? " untrusted" : ""));
    const who = el("div", "who");
    who.appendChild(el("b", null, m.role === "tool" ? "Tool result · " + (m.name || "") : cap(m.role)));
    if (untrusted) who.appendChild(el("span", "tag u", "untrusted"));
    step.appendChild(who);
    if (m.content) step.appendChild(el("div", "body", m.content));
    (m.tool_calls || []).forEach((tc) => {
      const call = calls.shift();
      const s = el("div", "body", "→ " + tc.name + " " + JSON.stringify(tc.arguments));
      step.appendChild(s);
      if (call) {
        if (call.blocked_by) { step.classList.add("blocked"); step.appendChild(el("div", "note good", "Blocked by " + pretty(call.blocked_by) + ". Never ran.")); }
        else if (call.violations && call.violations.length) {
          step.classList.add("bad");
          call.violations.forEach((v) => step.appendChild(el("div", "note bad", "Broke policy: " + v.detail)));
        }
      }
    });
    trace.appendChild(step);
  });
  node.appendChild(trace);
}

function setTab(which) {
  const base = which === "base";
  $("tab-base").setAttribute("aria-selected", String(base));
  $("tab-def").setAttribute("aria-selected", String(!base));
  $("run-baseline").dataset.hidden = String(!base);
  $("run-defended").dataset.hidden = String(base);
}

function pill(id, r) {
  const n = $(id);
  const [label, tone] = OUTCOME[r.outcome] || ["", "neutral"];
  n.textContent = tone === "bad" ? "leaked" : tone === "good" ? "blocked" : "";
  n.className = "pill " + tone;
}

async function runOne() {
  const btn = $("run-btn");
  showError("");
  btn.disabled = true;
  btn.textContent = "Running";
  try {
    const d = await api("/api/run", { case_id: selected, defenses: defenses(), tool_provisioning: provisioning() });
    renderCase(d.case);
    renderRun($("run-baseline"), "Without defenses", d.baseline);
    renderRun($("run-defended"), "With defenses", d.defended);
    pill("tb-base", d.baseline);
    pill("tb-def", d.defended);
    setTab("base");
    $("empty").hidden = true;
    $("bench").hidden = true;
    $("single").hidden = false;
    if (window.matchMedia("(max-width: 1000px)").matches) $("single").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    showError(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run attack";
  }
}

/* ---------- benchmark ---------- */
function cell(m) {
  const td = el("td");
  if (!m) { td.textContent = "n/a"; return td; }
  td.appendChild(el("span", "num", m.numerator + " / " + m.denominator));
  td.appendChild(el("span", "ci", pct(m) + ", 95% CI " + (m.ci95_low * 100).toFixed(0) + " to " + (m.ci95_high * 100).toFixed(0) + "%"));
  return td;
}

async function runBench() {
  const btn = $("bench-btn");
  showError("");
  btn.disabled = true;
  btn.textContent = "Running";
  try {
    const d = await api("/api/benchmark", { defenses: defenses(), tool_provisioning: provisioning() });
    const on = d.defended.defenses;
    $("bench-title").textContent = on.length ? "Without vs with " + on.map(pretty).join(", ") : "No defenses selected";
    const sum = $("bench-summary");
    sum.textContent = "";
    const a = d.baseline.overall.attack_success_rate, b = d.defended.overall.attack_success_rate, t = d.defended.overall.task_completion_rate;
    [["bad", a.numerator + " of " + a.denominator, "attacks got through without defenses"],
     [b.numerator ? "bad" : "good", b.numerator + " of " + b.denominator, "got through with these defenses"],
     [t.numerator === t.denominator ? "good" : "bad", t.numerator + " of " + t.denominator, "normal tasks still done"]].forEach(([cls, big, small]) => {
      const box = el("div", cls); box.appendChild(el("b", null, big)); box.appendChild(el("span", null, small)); sum.appendChild(box);
    });
    const body = $("bench-body");
    body.textContent = "";
    METRICS.forEach(([k, label]) => {
      const tr = el("tr");
      tr.appendChild(el("td", null, label));
      tr.appendChild(cell(d.baseline.overall[k]));
      tr.appendChild(cell(d.defended.overall[k]));
      body.appendChild(tr);
    });
    const cats = $("bench-cats");
    cats.textContent = "";
    const lg = el("div", "legend");
    lg.appendChild(el("span", "lb", "Without"));
    lg.appendChild(el("span", "ld", "With"));
    cats.appendChild(lg);
    Object.keys(d.baseline.by_category).forEach((c) => {
      const r = el("div", "cat");
      r.appendChild(el("span", null, cap(c)));
      const bars = el("div", "cat-bars");
      [["base", d.baseline.by_category[c]], ["def", d.defended.by_category[c]]].forEach(([cls, m]) => {
        const line = el("div", "cat-line");
        const t = el("div", "track " + cls);
        const f = el("i");
        f.style.width = (m && m.percent ? m.percent : 0) + "%";
        t.appendChild(f);
        line.appendChild(t);
        line.appendChild(el("span", "cat-val", m ? m.numerator + " / " + m.denominator : "n/a"));
        bars.appendChild(line);
      });
      r.appendChild(bars);
      cats.appendChild(r);
    });
    $("bench-meta").textContent = d.cases + " attacks, each run twice on " + d.model + " with " + (d.tool_provisioning === "full" ? "all tools" : "task tools only") + ". " + d.elapsed_ms + " ms.";
    $("empty").hidden = true;
    $("single").hidden = true;
    $("bench").hidden = false;
  } catch (e) {
    showError(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run all 30";
  }
}

$("case-filter").addEventListener("input", renderCaseList);
$("run-btn").addEventListener("click", runOne);
$("bench-btn").addEventListener("click", runBench);
$("tab-base").addEventListener("click", () => setTab("base"));
$("tab-def").addEventListener("click", () => setTab("def"));
init();

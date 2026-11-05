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
const pct = (m) => (m && m.percent !== null && m.percent !== undefined ? m.percent.toFixed(1) + "%" : "n/a");

const OUTCOME = {
  attack_success: ["Attack succeeded", "bad"],
  safe_completion: ["Attack blocked, task done", "good"],
  safe_incomplete: ["Attack blocked, task not done", "good"],
  not_applicable: ["Not applicable", "neutral"],
  error: ["Error", "neutral"],
};
const METRIC_LABELS = {
  attack_success_rate: "Attacks that succeeded",
  safe_completion_rate: "Blocked and task done",
  unauthorized_tool_call_rate: "Runs with an out-of-policy tool call",
  sensitive_information_exposure_rate: "Secret leaked",
  task_completion_rate: "Normal task still done",
  blocked_call_rate: "Runs where a defense blocked a call",
};

async function api(path, body) {
  const opts = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    throw new Error("Network error. Check your connection and try again.");
  }
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON */ }
  if (!res.ok) {
    const detail = data && data.details ? data.details.map((d) => d.field + ": " + d.message).join("; ") : "";
    throw new Error((data && data.error ? data.error : "Request failed (" + res.status + ")") + (detail ? " - " + detail : ""));
  }
  return data;
}

function showError(id, msg) { const n = $(id); n.textContent = msg; n.hidden = !msg; }
function selectedDefenses() { return [...document.querySelectorAll("#defense-list input:checked")].map((i) => i.value); }

async function init() {
  try {
    const [cases, defenses] = await Promise.all([api("/api/cases"), api("/api/defenses")]);
    const sel = $("case-select");
    sel.textContent = "";
    const groups = {};
    cases.cases.forEach((c) => {
      if (!groups[c.category]) {
        groups[c.category] = el("optgroup");
        groups[c.category].label = pretty(c.category);
        sel.appendChild(groups[c.category]);
      }
      const o = el("option", null, c.id + "  " + c.title);
      o.value = c.id;
      groups[c.category].appendChild(o);
    });
    const start = cases.cases.find((c) => c.id === "A-02");
    if (start) sel.value = start.id;

    const list = $("defense-list");
    defenses.defenses.forEach((d) => {
      const lab = el("label", "chip");
      lab.title = d.description;
      const box = el("input");
      box.type = "checkbox";
      box.value = d.name;
      box.checked = d.name === "authorization" || d.name === "sanitization";
      lab.appendChild(box);
      lab.appendChild(document.createTextNode(pretty(d.name)));
      list.appendChild(lab);
    });
  } catch (e) {
    showError("run-error", "Could not load the demo data: " + e.message);
  }
}

function renderCase(c) {
  $("ci-id").textContent = c.id;
  $("ci-cat").textContent = pretty(c.category);
  const sev = $("ci-sev");
  sev.textContent = "severity: " + c.severity;
  sev.className = "tag sev-" + c.severity;
  $("ci-chan").textContent = "enters via: " + pretty(c.injection_channel);
  $("ci-title").textContent = c.title;
  $("ci-policy").textContent = c.trusted_instruction;
  $("ci-payload").textContent = c.attack_prompt;
  $("ci-safe").textContent = c.expected_safe_behavior;
  $("case-info").hidden = false;
}

function renderRun(node, title, r) {
  node.textContent = "";
  node.appendChild(el("h4", null, title));
  const [label, tone] = OUTCOME[r.outcome] || [pretty(r.outcome), "neutral"];
  node.appendChild(el("span", "verdict " + tone, label));

  const facts = el("ul", "facts");
  const fact = (k, v) => { const li = el("li"); li.appendChild(el("b", null, k + ": ")); li.appendChild(document.createTextNode(v)); facts.appendChild(li); };
  fact("Defenses", r.defenses.length ? r.defenses.map(pretty).join(", ") : "none");
  fact("Secrets exposed", r.signals.exposed_secrets && r.signals.exposed_secrets.length ? r.signals.exposed_secrets.join(", ") : "none");
  fact("Sent outside the company", r.signals.external_recipients && r.signals.external_recipients.length ? r.signals.external_recipients.join(", ") : "nothing");
  fact("Injection reached the model", r.signals.injection_reached_model ? "yes" : "no");
  if (r.signals.defense_interventions && r.signals.defense_interventions.length) fact("Defenses that acted", r.signals.defense_interventions.map(pretty).join(", "));
  fact("Normal task done", r.task_completed ? "yes" : "no");
  node.appendChild(facts);

  node.appendChild(el("p", "label", "Agent trace"));
  const trace = el("div", "trace");
  r.messages.forEach((m) => {
    const box = el("div", "msg" + (m.trust === "untrusted" ? " untrusted" : ""));
    const who = el("div", "who");
    who.appendChild(el("span", null, m.role === "tool" ? "tool result: " + (m.name || "") : m.role));
    who.appendChild(el("span", null, "[" + m.trust + "]"));
    box.appendChild(who);
    if (m.content) box.appendChild(el("div", "body", m.content));
    (m.tool_calls || []).forEach((tc) => box.appendChild(el("div", "body", "calls " + tc.name + " " + JSON.stringify(tc.arguments))));
    trace.appendChild(box);
  });
  node.appendChild(trace);

  if (r.tool_calls.length) {
    node.appendChild(el("p", "label", "Tool calls vs policy"));
    const calls = el("div", "trace");
    r.tool_calls.forEach((c) => {
      const cls = c.blocked_by ? "call blocked" : c.violations.length ? "call violation" : "call";
      const box = el("div", cls, c.tool + " " + JSON.stringify(c.arguments));
      c.violations.forEach((v) => box.appendChild(el("span", "why", "policy violation: " + v.detail)));
      if (c.blocked_by) box.appendChild(el("span", "blk", "blocked by " + pretty(c.blocked_by) + ", never executed"));
      else if (c.violations.length) box.appendChild(el("span", "why", "executed anyway"));
      calls.appendChild(box);
    });
    node.appendChild(calls);
  }
}

async function runOne() {
  const btn = $("run-btn");
  showError("run-error", "");
  btn.disabled = true;
  btn.textContent = "Running...";
  try {
    const data = await api("/api/run", {
      case_id: $("case-select").value,
      defenses: selectedDefenses(),
      tool_provisioning: $("provisioning").value,
    });
    renderCase(data.case);
    renderRun($("run-baseline"), "No defenses", data.baseline);
    renderRun($("run-defended"), data.defended.defenses.length ? "With selected defenses" : "With selected defenses (none chosen)", data.defended);
    $("results").hidden = false;
    $("case-info").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    showError("run-error", e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run attack";
  }
}

function metricCell(m) {
  const td = el("td");
  if (!m) { td.textContent = "n/a"; return td; }
  td.appendChild(document.createTextNode(pct(m) + " (" + m.numerator + "/" + m.denominator + ")"));
  td.appendChild(el("span", "ci", "95% CI " + (m.ci95_low * 100).toFixed(1) + " to " + (m.ci95_high * 100).toFixed(1)));
  return td;
}

async function runBench() {
  const btn = $("bench-btn");
  showError("bench-error", "");
  btn.disabled = true;
  btn.textContent = "Running...";
  try {
    const d = await api("/api/benchmark", { defenses: selectedDefenses(), tool_provisioning: $("provisioning").value });
    $("bench-def-h").textContent = d.defended.defenses.length ? "Defended: " + d.defended.defenses.map(pretty).join(", ") : "Defended (no defenses chosen)";
    const body = $("bench-body");
    body.textContent = "";
    Object.keys(METRIC_LABELS).forEach((k) => {
      const tr = el("tr");
      tr.appendChild(el("td", null, METRIC_LABELS[k]));
      tr.appendChild(metricCell(d.baseline.overall[k]));
      tr.appendChild(metricCell(d.defended.overall[k]));
      body.appendChild(tr);
    });
    const cats = $("bench-cats");
    cats.textContent = "";
    const legend = el("div", "legend");
    legend.appendChild(el("span", "lb", "No defenses"));
    legend.appendChild(el("span", "ld", "Defended"));
    cats.appendChild(legend);
    Object.keys(d.baseline.by_category).forEach((cat) => {
      const row = el("div", "bar-row");
      row.appendChild(el("div", null, pretty(cat)));
      const pair = el("div", "bar-pair");
      [["base", d.baseline.by_category[cat]], ["def", d.defended.by_category[cat]]].forEach(([cls, m]) => {
        const line = el("div");
        line.style.display = "grid";
        line.style.gridTemplateColumns = "1fr 110px";
        line.style.gap = "8px";
        line.style.alignItems = "center";
        const bar = el("div", "bar " + cls);
        const fill = el("i");
        fill.style.width = (m && m.percent ? m.percent : 0) + "%";
        bar.appendChild(fill);
        line.appendChild(bar);
        line.appendChild(el("span", "bar-val", m ? pct(m) + " (" + m.numerator + "/" + m.denominator + ")" : "n/a"));
        pair.appendChild(line);
      });
      row.appendChild(pair);
      cats.appendChild(row);
    });
    $("bench-meta").textContent = d.cases + " attacks, run twice each. Test agent: " + d.model + ". Tool access: " + d.tool_provisioning + ". Took " + d.elapsed_ms + " ms.";
    $("bench").hidden = false;
  } catch (e) {
    showError("bench-error", e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run all 30 attacks";
  }
}

$("run-btn").addEventListener("click", runOne);
$("bench-btn").addEventListener("click", runBench);
init();

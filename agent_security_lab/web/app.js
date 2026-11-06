"use strict";
// Preferences are optional: the console must work with browser storage disabled.
(() => {
  const key = "research-lab-theme";
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const button = document.querySelector("#theme-toggle");
  let preference = null;
  try {
    preference = localStorage.getItem(key);
  } catch {}
  if (!["light", "dark"].includes(preference)) preference = null;
  function apply() {
    const dark = preference ? preference === "dark" : media.matches;
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    button.setAttribute("aria-pressed", String(dark));
  }
  button.addEventListener("click", () => {
    preference =
      document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    try {
      localStorage.setItem(key, preference);
    } catch {}
    apply();
  });
  media.addEventListener("change", apply);
  window.addEventListener("storage", (event) => {
    if (event.key !== key && event.key !== null) return;
    preference = ["light", "dark"].includes(event.newValue)
      ? event.newValue
      : null;
    apply();
  });
  apply();
})();
const $ = (selector) => document.querySelector(selector);
const state = {
  token: "",
  corpus: [],
  history: [],
  experiment: null,
  job: null,
};
function node(tag, cls = "", text = "") {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  n.textContent = text;
  return n;
}
function notice(message, error = false) {
  const n = $("#notice");
  n.hidden = false;
  n.className = error ? "error" : "";
  n.textContent = message;
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Lab-Token": state.token,
      ...(options.headers || {}),
    },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}
function view(name) {
  const names = {
    overview: "Results",
    corpus: "Scenarios",
    traces: "Traces",
    runs: "History",
    method: "Notes",
  };
  if (!names[name]) return;
  document.querySelectorAll(".view").forEach((v) => {
    v.hidden = v.id !== `view-${name}`;
  });
  document.querySelectorAll(".nav-item").forEach((n) => {
    n.classList.toggle("active", n.dataset.view === name);
    if (n.dataset.view === name) n.setAttribute("aria-current", "page");
    else n.removeAttribute("aria-current");
  });
  $("#crumb").textContent = names[name];
}
document
  .querySelectorAll("[data-view]")
  .forEach((b) => b.addEventListener("click", () => view(b.dataset.view)));
function selectedCases() {
  return [...document.querySelectorAll("input[name=case]:checked")].map(
    (c) => c.value,
  );
}
function planned() {
  const modes = document.querySelectorAll("input[name=mode]:checked").length;
  $("#planned-count").textContent =
    selectedCases().length * modes * Number($("#trials").value);
}
function selectCases(predicate) {
  document.querySelectorAll("input[name=case]").forEach((c) => {
    c.checked = predicate(state.corpus.find((s) => s.name === c.value));
  });
  planned();
}
function buildCorpus() {
  $("#stat-cases").replaceChildren(
    document.createTextNode(String(state.corpus.length).padStart(2, "0")),
    node("small", "", "cases"),
  );
  $("#corpus-count").textContent = state.corpus.length;
  const options = $("#case-options");
  options.replaceChildren();
  state.corpus.forEach((c) => {
    const label = node("label", "case-option");
    const check = document.createElement("input");
    check.type = "checkbox";
    check.name = "case";
    check.value = c.name;
    check.checked = c.split === "development";
    check.addEventListener("change", planned);
    label.append(
      check,
      node("span", "", c.name),
      node("small", "", c.split === "holdout" ? "HOLDOUT" : "DEV"),
    );
    options.append(label);
  });
  renderCorpus();
  planned();
}
function renderCorpus() {
  const q = $("#corpus-search").value.toLowerCase();
  const target = $("#corpus-cards");
  target.replaceChildren();
  state.corpus
    .filter((c) =>
      `${c.name} ${c.description} ${c.family}`.toLowerCase().includes(q),
    )
    .forEach((c) => {
      const card = node("div", "corpus-card");
      card.append(
        node("h3", "", c.name),
        node("span", "pill subtle", c.split.toUpperCase()),
        node("span", "pill subtle", c.family),
        node("p", "", c.description),
      );
      const details = node("details");
      details.append(
        node("summary", "", "Inspect untrusted input"),
        node("pre", "", c.email),
      );
      card.append(details);
      target.append(card);
    });
  if (!target.children.length)
    target.append(node("p", "muted", "No matching scenarios."));
}
function percent(value) {
  return value === null || value === undefined
    ? "—"
    : `${Math.round(value * 100)}%`;
}
function outcome(run) {
  if (run.status !== "completed") return ["neutral", run.status];
  if (run.metrics.unauthorized_effects) return ["bad", "Unauthorized effect"];
  if (run.metrics.blocked_calls) return ["good", "Policy blocked"];
  if (run.metrics.legitimate_task_completed) return ["good", "Task completed"];
  return ["neutral", "Task unfinished"];
}
function renderExperiment(experiment) {
  state.experiment = experiment;
  const replay = experiment.kind === "policy_replay";
  $("#experiment-kind").textContent = replay ? "Policy replay" : "Live model";
  $("#experiment-kind").className = replay ? "pill" : "pill live";
  $("#experiment-note").textContent = experiment.notes;
  $("#run-provenance").textContent =
    `${(experiment.provenance.git_commit || "unknown").slice(0, 7)}${experiment.provenance.git_dirty ? " (dirty)" : ""} · ${experiment.runs.length} runs · ${new Date(experiment.created_at).toLocaleString()}`;
  $("#download").disabled = false;
  $("#download-markdown").disabled = false;
  const comparison = $("#comparison");
  const table = node("table", "comparison-table");
  table.setAttribute("aria-label", "Agent mode comparison");
  const head = node("thead"),
    headings = node("tr"),
    body = node("tbody");
  [
    "Mode",
    replay ? "Replay effects" : "Attack success",
    "Benign completion",
    "Completion under attack",
    "Excluded",
  ].forEach((label) => {
    const th = node("th", "", label);
    th.scope = "col";
    headings.append(th);
  });
  head.append(headings);
  experiment.summary.forEach((s) => {
    const row = node("tr"),
      mode = node("td", "", s.label);
    mode.append(
      node("small", "", `${s.unexposed} unexposed · ${s.errors} errors`),
    );
    const effects = node(
      "td",
      "numeric",
      s.attack_valid_exposed
        ? `${s.attack_effects}/${s.attack_valid_exposed}`
        : "—",
    );
    effects.append(node("small", "", "exposed, completed only"));
    const benign = node("td", "numeric", percent(s.benign_completion_rate));
    benign.append(node("small", "", `${s.benign_valid} valid controls`));
    row.append(
      mode,
      effects,
      benign,
      node("td", "numeric", percent(s.completion_under_attack)),
      node("td", "numeric", s.excluded),
    );
    body.append(row);
  });
  table.append(head, body);
  comparison.replaceChildren(table);
  const rows = $("#result-rows");
  const traceSelect = $("#trace-select");
  rows.replaceChildren();
  traceSelect.replaceChildren();
  experiment.runs.forEach((run, index) => {
    const row = node("tr");
    const name = node("td");
    name.append(
      node("span", "case-name", run.scenario),
      node("span", "case-family", `${run.split} / trial ${run.trial}`),
    );
    const mode = node(
      "td",
      "muted",
      run.mode === "guarded" ? "Policy" : "Prompt only",
    );
    const exposed = node(
      "td",
      "muted",
      run.family === "benign"
        ? "Control"
        : run.metrics.attack_exposed
          ? "Observed"
          : "Not observed",
    );
    const result = node("td");
    const [kind, label] = outcome(run);
    result.append(node("span", `outcome ${kind}`, `● ${label}`));
    const action = node("td");
    const button = node("button", "text-button", "↗");
    button.setAttribute("aria-label", `Inspect ${run.scenario} ${run.mode}`);
    button.addEventListener("click", () => {
      traceSelect.value = index;
      renderTrace(index);
      view("traces");
    });
    action.append(button);
    row.append(name, mode, exposed, result, action);
    rows.append(row);
    const option = node(
      "option",
      "",
      `${run.scenario} · ${run.mode} · #${run.trial}`,
    );
    option.value = index;
    traceSelect.append(option);
  });
  if (!experiment.runs.length) {
    const tr = node("tr");
    const td = node("td", "muted", "Cancelled before any runs completed.");
    td.colSpan = 5;
    tr.append(td);
    rows.append(tr);
  }
  renderTrace(0);
}
function renderTrace(index) {
  const target = $("#trace-content");
  target.replaceChildren();
  const run = state.experiment?.runs[Number(index)];
  if (!run) {
    target.append(node("p", "muted", "No trace available."));
    return;
  }
  const meta = node("div", "trace-meta");
  [
    run.agent,
    run.status,
    `seed ${run.seed}`,
    `exposure: ${run.metrics.input_observed ? "observed" : "not observed"}`,
  ].forEach((t) => meta.append(node("span", "pill subtle", t)));
  target.append(meta);
  run.events.forEach((event) => {
    const item = node("div", `trace-event ${event.decision}`);
    const heading = node("div", "event-heading");
    heading.append(
      node(
        "strong",
        "",
        `${String(event.step).padStart(2, "0")} / ${event.tool}`,
      ),
      node("small", "", event.decision.toUpperCase()),
    );
    item.append(heading);
    const details = node("details");
    details.open = event.decision === "blocked";
    details.append(
      node("summary", "", event.result.error || "Arguments & result"),
      node(
        "pre",
        "",
        JSON.stringify(
          { arguments: event.arguments, result: event.result },
          null,
          2,
        ),
      ),
    );
    item.append(details);
    target.append(item);
  });
  if (!run.events.length)
    target.append(node("p", "muted", "No tool calls were executed."));
  const evidence = node("details");
  evidence.append(
    node("summary", "", "Reproducibility record"),
    node(
      "pre",
      "",
      JSON.stringify(
        {
          fixture_sha256: run.fixture_sha256,
          source: state.experiment.provenance,
          settings: run.settings,
          model_manifest: state.experiment.model_manifest || null,
          metrics: run.metrics,
        },
        null,
        2,
      ),
    ),
  );
  target.append(evidence);
  if (run.trajectory) {
    const transcript = node("details");
    transcript.append(
      node("summary", "", "Full model trajectory"),
      node("pre", "", JSON.stringify(run.trajectory, null, 2)),
    );
    target.append(transcript);
  }
  if (run.final_message) {
    const final = node("details");
    final.append(
      node("summary", "", "Final model message"),
      node("pre", "", run.final_message),
    );
    target.append(final);
  }
}
async function refreshHistory(selectLatest = false) {
  state.history = await api("/api/experiments");
  $("#stat-live").replaceChildren(
    document.createTextNode(
      String(
        state.history
          .filter((e) => e.kind === "live_model")
          .reduce((n, e) => n + e.summary.reduce((a, s) => a + s.runs, 0), 0),
      ),
    ),
    node("small", "", "recorded"),
  );
  const target = $("#history");
  target.replaceChildren();
  state.history.forEach((e) => {
    const button = node("button", "history-row");
    button.append(
      node(
        "strong",
        "",
        `${e.kind === "policy_replay" ? "Policy replay" : e.config.model} · ${e.summary.reduce((n, s) => n + s.runs, 0)} runs`,
      ),
      node(
        "span",
        "",
        `${new Date(e.created_at).toLocaleString()} / ${e.id.slice(0, 12)} / ${e.status}`,
      ),
    );
    button.addEventListener("click", async () => {
      try {
        renderExperiment(await api(`/api/experiments/${e.id}`));
        view("overview");
      } catch (error) {
        notice(error.message, true);
      }
    });
    target.append(button);
  });
  if (!state.history.length)
    target.append(
      node(
        "p",
        "muted",
        "No recorded experiments. Start with the policy demo.",
      ),
    );
  if (selectLatest && state.history.length)
    renderExperiment(await api(`/api/experiments/${state.history[0].id}`));
}
function busy(value) {
  $("#submit-run").disabled = value;
  $("#quick-run").disabled = value;
  $("#empty-run")?.toggleAttribute("disabled", value);
  $("#cancel-run").hidden = !value;
  $("#job-progress").hidden = !value;
}
async function launch(config) {
  if (state.job) return;
  state.job = "pending";
  busy(true);
  try {
    const job = await api("/api/experiments", {
      method: "POST",
      body: JSON.stringify(config),
    });
    state.job = job.job_id;
    notice("Experiment running. No real email or payment will be sent.");
    poll();
  } catch (error) {
    state.job = null;
    busy(false);
    notice(error.message, true);
  }
}
async function poll() {
  try {
    const job = await api(`/api/jobs/${state.job}`);
    $("#progress").max = job.total || 1;
    $("#progress").value = job.completed || 0;
    $("#progress-text").textContent =
      `${job.completed}/${job.total} runs · ${job.status}`;
    if (job.status === "completed") {
      busy(false);
      renderExperiment(await api(`/api/experiments/${job.experiment_id}`));
      await refreshHistory();
      notice(
        state.experiment.status === "cancelled"
          ? "Experiment cancelled. Completed runs have been preserved."
          : "Experiment complete. Inspect the outcomes and trace evidence below.",
      );
      view("overview");
      state.job = null;
      return;
    }
    if (job.status === "error") throw new Error(job.error);
    setTimeout(poll, 700);
  } catch (error) {
    busy(false);
    state.job = null;
    notice(error.message, true);
  }
}
function quickRun() {
  launch({
    agent: "scripted",
    scenarios: state.corpus
      .filter((c) => c.split === "development")
      .map((c) => c.name),
    modes: ["unsafe", "guarded"],
    trials: 1,
    seed: 42,
  });
}
$("#quick-run").addEventListener("click", quickRun);
$("#empty-run").addEventListener("click", quickRun);
$("#run-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const agent = $("input[name=agent]:checked").value;
  launch({
    agent,
    model: agent === "ollama" ? $("#model").value : null,
    scenarios: selectedCases(),
    modes: [...document.querySelectorAll("input[name=mode]:checked")].map(
      (m) => m.value,
    ),
    trials: Number($("#trials").value),
    seed: Number($("#seed").value),
  });
});
document.querySelectorAll("input[name=agent]").forEach((radio) =>
  radio.addEventListener("change", () => {
    const live = $("input[name=agent]:checked").value === "ollama";
    $("#model-options").hidden = !live;
    $("#trials").disabled = !live;
    if (!live) $("#trials").value = 1;
    $("#trial-help").textContent = live
      ? "Repeated trials vary the seed. Both modes use the same per-trial seed; each run has a fresh canary."
      : "One replay per case. Repeating a scripted plan is not an independent trial.";
    planned();
  }),
);
$("#select-dev").addEventListener("click", () =>
  selectCases((c) => c.split === "development"),
);
$("#select-holdout").addEventListener("click", () =>
  selectCases((c) => c.split === "holdout"),
);
$("#select-all").addEventListener("click", () => selectCases(() => true));
document
  .querySelectorAll("input[name=mode],#trials,#seed")
  .forEach((n) => n.addEventListener("change", planned));
$("#corpus-search").addEventListener("input", renderCorpus);
$("#trace-select").addEventListener("change", (e) =>
  renderTrace(e.target.value),
);
$("#refresh").addEventListener("click", () =>
  refreshHistory().catch((e) => notice(e.message, true)),
);
$("#cancel-run").addEventListener("click", async () => {
  if (!state.job) return;
  try {
    await api(`/api/jobs/${state.job}/cancel`, { method: "POST", body: "{}" });
    notice(
      "Cancellation requested. The current local model request may take up to its timeout to finish.",
    );
  } catch (error) {
    notice(error.message, true);
  }
});
$("#download").addEventListener("click", () => {
  if (!state.experiment) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(state.experiment, null, 2)], {
      type: "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `experiment-${state.experiment.id}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("#download-markdown").addEventListener("click", async () => {
  if (!state.experiment) return;
  try {
    const response = await fetch(`/api/experiments/${state.experiment.id}/report.md`);
    if (!response.ok) throw new Error("Could not export the saved report.");
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = `experiment-${state.experiment.id}.md`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { notice(error.message, true); }
});
(async () => {
  try {
    state.token = (await api("/api/session")).token;
    state.corpus = await api("/api/corpus");
    buildCorpus();
    await refreshHistory(true);
    const models = await api("/api/models");
    $("#model-status").textContent = models.available
      ? `${models.models.length} installed local model(s)`
      : "Ollama not connected";
    const select = $("#model");
    select.replaceChildren();
    if (models.models.length)
      models.models.forEach((m) => {
        const option = node("option", "", m.name);
        option.value = m.name;
        select.append(option);
      });
    else {
      select.append(node("option", "", "No local model available"));
      select.firstChild.value = "";
      $("#model-help").textContent =
        models.message ||
        "Install a local tool-capable model before running live experiments.";
    }
  } catch (error) {
    notice(`Could not initialize workspace: ${error.message}`, true);
  }
})();

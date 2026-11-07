"use strict";
const $ = (selector) => document.querySelector(selector);
const state = {
  labs: [],
  provider: null,
  token: "",
  lab: null,
  busy: false,
  drafts: {},
  result: null,
};
const bytes = (value) => new TextEncoder().encode(value).length;
function element(tag, text, className = "") {
  const node = document.createElement(tag);
  node.textContent = text;
  node.className = className;
  return node;
}
function notify(text) {
  $("#notice").textContent = text;
  $("#notice").hidden = !text;
}
function setTheme(dark) {
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  $("#theme-toggle").setAttribute("aria-pressed", String(dark));
}
try {
  setTheme(
    (localStorage.getItem("research-lab-theme") ||
      (matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light")) === "dark",
  );
} catch {
  setTheme(matchMedia("(prefers-color-scheme: dark)").matches);
}
$("#theme-toggle").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme !== "dark";
  setTheme(dark);
  try {
    localStorage.setItem("research-lab-theme", dark ? "dark" : "light");
  } catch {}
});
async function api(path, body) {
  const response = await fetch(
    path,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Lab-Token": state.token,
          },
          body: JSON.stringify(body),
        },
  );
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed.");
  return data;
}
function updateForm() {
  $("#result").classList.toggle("is-running", state.busy);
  const size = bytes($("#payload").value);
  $("#payload-count").textContent = `${size.toLocaleString()} / 8,000 bytes`;
  $("#submit-attack").disabled =
    state.busy ||
    !state.provider?.ready ||
    !$("#consent").checked ||
    !$("#payload").value.trim() ||
    size > 8000;
  $("#submit-attack").textContent = state.busy
    ? "Agent is running…"
    : "Test attack";
  $("#payload").disabled = state.busy;
  $("#reset").disabled = state.busy;
  $("#consent").disabled = state.busy;
}
function emptyResult() {
  $("#result").replaceChildren(
    element("h2", "Agent response"),
    element(
      "p",
      "Your result and the agent's tool calls will appear here after an attempt.",
      "muted",
    ),
  );
}
function route() {
  const id = location.hash.startsWith("#/labs/")
    ? location.hash.slice(7)
    : null;
  const lab = state.labs.find((item) => item.id === id);
  if (state.lab) state.drafts[state.lab.id] = $("#payload").value;
  state.lab = lab || null;
  $("#catalog").hidden = !!lab;
  $("#workspace").hidden = !lab;
  notify(id && !lab ? "That lab was not found. Choose a lab below." : "");
  document.title = lab
    ? `${lab.title} — AI Agent Security Lab`
    : "Labs — AI Agent Security Lab";
  if (!lab) return;
  for (const [selector, field] of [
    ["#lab-title", "title"],
    ["#lab-description", "description"],
    ["#objective", "objective"],
    ["#context", "context"],
    ["#surface", "surface"],
    ["#hint", "hint"],
  ])
    $(selector).textContent = lab[field];
  $("#lab-category").textContent = `${lab.number} / ${lab.category}`;
  $("#tool-reference").replaceChildren(
    ...(lab.tools || []).map(({ function: tool }) => {
      const item = element("div", "", "tool-reference-item");
      const args = Object.entries(tool.parameters.properties)
        .map(([name, value]) => `${name}: ${value.type}`)
        .join(", ");
      item.append(
        element("code", `${tool.name}(${args})`),
        element("p", tool.description, "muted small"),
      );
      return item;
    }),
  );
  $("#payload").value = state.drafts[lab.id] || "";
  $("#consent").checked = false;
  $("#consent-row").hidden = !state.provider.ready;
  $("#provider-status").replaceChildren(
    element("span", state.provider.message),
  );
  emptyResult();
  if (state.busy)
    $("#result").append(element("p", "An attempt is still running.", "muted"));
  updateForm();
  $("#lab-title").focus({ preventScroll: true });
  window.scrollTo(0, 0);
}
function renderCatalog() {
  $("#labs").replaceChildren(
    ...state.labs.map((lab) => {
      const link = element("a", "", "lab-card");
      link.href = `#/labs/${lab.id}`;
      link.setAttribute("aria-label", `Start ${lab.title}`);
      const text = element("div", "");
      text.append(
        element("h2", lab.title),
        element("p", lab.description),
        element("span", `${lab.category} · ${lab.level}`, "lab-meta"),
      );
      const start = element("span", "Start lab", "start");
      const arrow = element("span", "→", "start-arrow");
      arrow.setAttribute("aria-hidden", "true");
      start.append(arrow);
      link.append(element("span", lab.number, "lab-number"), text, start);
      return link;
    }),
  );
}
function showResult(attempt) {
  const titles = {
    objective_reached: "Objective reached",
    objective_not_reached: "Objective not reached",
    effect_observed_incomplete: "Effect observed · incomplete run",
    inconclusive: "Attempt inconclusive",
  };
  const report = attempt.report,
    panel = $("#result");
  panel.replaceChildren(
    element("h2", "Attempt result"),
    element(
      "p",
      titles[attempt.verdict] || "Unknown result",
      `verdict ${attempt.verdict === "objective_reached" ? "success" : ""}`,
    ),
    element("p", attempt.feedback),
  );
  panel.append(
    element(
      "p",
      `${report.agent} · ${report.status} · ${report.events.length} tool calls`,
      "muted small",
    ),
  );
  if (report.final_message)
    panel.append(
      element("h2", "Agent response"),
      element("pre", report.final_message),
    );
  const trace = element("div", "", "trace");
  trace.append(element("h2", "What the agent did"));
  if (!report.events.length)
    trace.append(element("p", "No tool calls were executed.", "muted"));
  report.events.forEach((event) => {
    const details = element("details", "");
    details.append(
      element(
        "summary",
        `${event.step}. ${event.tool} — ${event.decision}${report.phases ? ` · phase ${event.phase}` : ""}`,
      ),
      element(
        "pre",
        JSON.stringify(
          { arguments: event.arguments, result: event.result },
          null,
          2,
        ),
      ),
    );
    trace.append(details);
  });
  panel.append(trace);
  const download = element("button", "Download this attempt", "quiet download");
  download.type = "button";
  download.addEventListener("click", () => {
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(attempt, null, 2)], {
        type: "application/json",
      }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `attempt-${attempt.id}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  panel.append(download, element("p", attempt.limits, "muted small"));
}
$("#payload").addEventListener("input", () => {
  if (state.lab) state.drafts[state.lab.id] = $("#payload").value;
  updateForm();
});
$("#consent").addEventListener("change", updateForm);
$("#reset").addEventListener("click", () => {
  if (state.busy) return;
  $("#payload").value = "";
  state.drafts[state.lab.id] = "";
  $("#consent").checked = false;
  if (state.result?.lab === state.lab.id) state.result = null;
  notify("");
  emptyResult();
  updateForm();
});
$("#attack-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("#submit-attack").disabled || !state.lab) return;
  const submittedLab = state.lab.id,
    payload = $("#payload").value;
  state.busy = true;
  notify("");
  updateForm();
  $("#result").replaceChildren(
    element("h2", "Agent is running…"),
    element(
      "p",
      "The target is reading your payload and choosing its own tools. An attempt can take several minutes.",
      "muted",
    ),
  );
  try {
    const { job_id: jobId } = await api("/api/attempts", {
      lab: submittedLab,
      payload,
      allow_api_call: true,
    });
    let job;
    do {
      await new Promise((resolve) => setTimeout(resolve, 900));
      job = await api(`/api/jobs/${jobId}`);
    } while (["queued", "running"].includes(job.status));
    if (job.status !== "completed")
      throw new Error(job.error || "Attempt did not finish.");
    const attempt = await api(`/api/attempts/${job.attempt_id}`);
    state.result = attempt;
    if (state.lab?.id === submittedLab) showResult(attempt);
    else
      notify(
        `The ${state.labs.find((lab) => lab.id === submittedLab).title} attempt finished. Open that lab to inspect it.`,
      );
  } catch (error) {
    notify(error.message);
    if (state.lab?.id === submittedLab)
      $("#result").replaceChildren(
        element("h2", "Attempt did not finish"),
        element(
          "p",
          "No successful result is assumed. Check the connection and try again.",
          "muted",
        ),
      );
  } finally {
    state.busy = false;
    $("#consent").checked = false;
    updateForm();
  }
});
window.addEventListener("hashchange", () => {
  route();
  if (state.result && state.lab && state.result.lab === state.lab.id)
    showResult(state.result);
});
(async () => {
  try {
    const [session, data] = await Promise.all([
      api("/api/session"),
      api("/api/labs"),
    ]);
    state.token = session.token;
    state.labs = data.labs;
    state.provider = data.provider;
    renderCatalog();
    route();
  } catch (error) {
    notify(`Could not load labs: ${error.message}`);
  }
})();

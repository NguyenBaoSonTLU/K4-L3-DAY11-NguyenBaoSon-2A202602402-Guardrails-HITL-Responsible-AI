(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const sessionKey = "vinbank-guardrail-session";
  let sessionId = localStorage.getItem(sessionKey);
  if (!sessionId || !/^[A-Za-z0-9_-]{8,80}$/.test(sessionId)) {
    sessionId = crypto.randomUUID ? crypto.randomUUID() : `local_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    localStorage.setItem(sessionKey, sessionId);
  }
  let redactedCount = Number(sessionStorage.getItem("vinbank-redacted-count") || 0);
  let toastTimer;

  async function request(path, options = {}) {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    let data;
    try { data = await response.json(); } catch { data = {}; }
    if (!response.ok) {
      const detail = typeof data.detail === "string" ? data.detail : "Request failed. Please try again.";
      throw new Error(detail);
    }
    return data;
  }

  function toast(message) {
    const node = $("#toast");
    node.textContent = message;
    node.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { node.hidden = true; }, 5000);
  }

  function setPage(page) {
    $$(".page").forEach((section) => {
      const active = section.id === `page-${page}`;
      section.classList.toggle("active", active);
      section.hidden = !active;
    });
    $$(".nav-item").forEach((button) => {
      const active = button.dataset.page === page;
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
    $("#page-breadcrumb").textContent = page === "lab" ? "Safety lab" : page === "evidence" ? "Evidence" : "Playground";
    if (page === "evidence") loadEvidence();
  }

  function appendMessage(role, text, { blocked = false, error = false } = {}) {
    const row = document.createElement("div");
    row.className = `message ${role}${blocked ? " blocked" : ""}${error ? " error" : ""}`;
    const avatar = document.createElement("div");
    avatar.className = "message-avatar";
    avatar.textContent = role === "user" ? "YOU" : "VB";
    const content = document.createElement("div");
    content.className = "message-content";
    const label = document.createElement("div");
    label.className = "message-label";
    label.textContent = role === "user" ? "You" : blocked ? "VinBank Blue · blocked" : error ? "VinBank Blue · unavailable" : "VinBank Blue";
    const bubble = document.createElement("div");
    bubble.className = "message-bubble";
    bubble.textContent = text;
    content.append(label, bubble);
    row.append(avatar, content);
    const log = $("#chat-log");
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }

  function updateMetrics(data) {
    $("#metric-requests").textContent = data.total_requests ?? 0;
    $("#metric-blocked").textContent = data.blocked_requests ?? 0;
    $("#metric-redacted").textContent = redactedCount;
  }

  function updateTrace(data) {
    const steps = $$("#trace-list .trace-step");
    (data.trace || []).forEach((step, index) => {
      const row = steps[index];
      if (!row) return;
      row.className = `trace-step ${step.status}`;
      row.querySelector("small").textContent = step.detail;
      row.querySelector(".step-state").textContent = step.status;
    });
    const summary = $("#trace-summary");
    summary.classList.toggle("blocked", Boolean(data.blocked));
    summary.querySelector(".summary-icon").textContent = data.blocked ? "⛨" : "✓";
    summary.querySelector("strong").textContent = data.blocked ? "Request stopped" : data.redacted ? "Reply cleaned" : "Reply delivered";
    summary.querySelector("p").textContent = data.blocked
      ? `Decision made by ${data.layer || "a security layer"}.`
      : data.redacted ? "Sensitive text was removed before delivery." : "All required checks completed.";
  }

  async function loadHealth() {
    try {
      const data = await request("/api/health");
      $("#model-name").textContent = data.model;
      const status = $("#connection-status");
      status.classList.toggle("offline", !data.key_configured);
      status.innerHTML = "";
      const dot = document.createElement("span");
      dot.className = "status-dot";
      status.append(dot, document.createTextNode(data.key_configured ? "Model key configured" : "Model key needed"));
    } catch {
      $("#model-name").textContent = "Model status unavailable";
      const status = $("#connection-status");
      status.classList.add("offline");
      status.textContent = "Server unavailable";
    }
  }

  async function loadSession() {
    try { updateMetrics(await request(`/api/session/${sessionId}`)); }
    catch { /* Local counters start at zero until a request succeeds. */ }
  }

  $("#chat-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = $("#chat-input");
    const message = input.value.trim();
    if (!message) return;
    appendMessage("user", message);
    input.value = "";
    const button = $("#chat-send");
    button.disabled = true;
    button.textContent = "Sending…";
    try {
      const data = await request("/api/chat", {
        method: "POST",
        body: JSON.stringify({ session_id: sessionId, message }),
      });
      appendMessage("assistant", data.reply || "No response returned.", { blocked: data.blocked });
      if (data.redacted) {
        redactedCount += 1;
        sessionStorage.setItem("vinbank-redacted-count", String(redactedCount));
      }
      updateMetrics(data.metrics || {});
      updateTrace(data);
    } catch (error) {
      appendMessage("assistant", error.message, { error: true });
      toast(error.message);
      await loadSession();
    } finally {
      button.disabled = false;
      button.innerHTML = "Send <span>➜</span>";
      input.focus();
    }
  });

  $("#chat-input").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      $("#chat-form").requestSubmit();
    }
  });

  $$(".sample-chip").forEach((button) => button.addEventListener("click", () => {
    $("#chat-input").value = button.dataset.prompt;
    $("#chat-input").focus();
  }));
  $$(".nav-item").forEach((button) => button.addEventListener("click", () => setPage(button.dataset.page)));

  function setResult(selector, title, details, good) {
    const node = $(selector);
    node.className = `lab-result ${good ? "good" : "bad"}`;
    node.textContent = "";
    const heading = document.createElement("strong");
    heading.textContent = title;
    node.append(heading, document.createTextNode(details));
  }

  $("#input-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await request("/api/lab/input", {
        method: "POST", body: JSON.stringify({ text: $("#input-text").value }),
      });
      setResult("#input-result", data.decision === "ALLOW" ? "Allowed" : "Blocked",
        `${data.reason}. Injection: ${data.injection} · Topic: ${data.topic}.`, data.decision === "ALLOW");
    } catch (error) { toast(error.message); }
  });

  $("#output-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await request("/api/lab/output", {
        method: "POST", body: JSON.stringify({ text: $("#output-text").value }),
      });
      setResult("#output-result", data.safe ? "Safe response" : "Sensitive content found",
        `${data.issues.length ? data.issues.join(" · ") + "\n" : ""}Preview: ${data.redacted}`, data.safe);
    } catch (error) { toast(error.message); }
  });

  $("#action-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await request("/api/lab/action", {
        method: "POST",
        body: JSON.stringify({
          action: $("#action-type").value,
          destination: $("#action-destination").value,
          payload: $("#action-payload").value,
          approval_id: $("#approval-id").value || null,
          reviewer_id: $("#reviewer-id").value || null,
        }),
      });
      setResult("#action-result", data.allowed ? "Permitted by policy" : "Action denied",
        `${data.reason}${data.requires_human ? " · Human approval required." : ""}`, data.allowed);
    } catch (error) { toast(error.message); }
  });

  async function loadEvidence() {
    try {
      const data = await request("/api/evidence");
      $("#evidence-empty").hidden = data.defense_available || data.attack_available;
      $("#e-safe").textContent = data.defense_available ? `${data.safe_passed}/${data.safe_total}` : "—";
      $("#e-attacks").textContent = data.defense_available ? `${data.attacks_blocked}/${data.attacks_total}` : "—";
      $("#e-rate").textContent = data.defense_available ? data.rate_blocked : "—";
      $("#e-red").textContent = data.attack_available ? `${data.red_leaks}/${data.red_total}` : "—";
      $("#defense-file-status").textContent = data.defense_available
        ? `${data.defense_valid ? "Schema valid." : "Schema validation failed."} ${data.safe_passed} safe prompts passed; ${data.attacks_blocked} attack prompts blocked.`
        : "Generate the CP3 result file to see Blue defense metrics.";
      $("#attack-file-status").textContent = data.attack_available
        ? `${data.red_leaks} Red leaks observed; ${data.advance_blocks} Red Advance blocks recorded.`
        : "Generate the CP4 attack file to see Red team metrics.";
      [["#defense-file-badge", data.defense_available && data.defense_valid], ["#attack-file-badge", data.attack_available]].forEach(([selector, found]) => {
        const badge = $(selector);
        badge.textContent = found ? "Available" : selector === "#defense-file-badge" && data.defense_available ? "Invalid" : "Missing";
        badge.classList.toggle("found", found);
      });
    } catch (error) { toast(error.message); }
  }
  $("#refresh-evidence").addEventListener("click", loadEvidence);

  loadHealth();
  loadSession();
  loadEvidence();
})();

/**
 * CyberGPT — Frontend Application Logic
 * ------------------------------------------------------------------
 *  * Lucide icon initialization (lucide.createIcons())
 *  * 5-tab switching with strict isolation
 *    (.tab-view { display:none } / .tab-view.active { display:flex })
 *  * Double-click send protection (disable + re-enable in `finally`)
 *  * Explicit password audit — CLICK ONLY (no input/keyup listeners)
 *  * Collapsible hint toggles + scenario evaluation submission
 *  * Dynamic cheat-sheet renderer (3 tiers)
 *  * Shared scenario renderer for Phishing Lab + SOC Drills
 *  * Markdown rendering via marked.js
 */

"use strict";

/* ============================================================
   GLOBAL STATE
   ============================================================ */
const state = {
  activeTab: "chat",
  tier: "balanced",
  sessionId: "default",
  cheatTier: "beginner",
  // Per-lab scenario tab state
  labs: {
    phishing: {
      category: "All Labs",
      loaded: false,
      scenarios: [],
    },
    soc: {
      category: "All",
      loaded: false,
      scenarios: [],
    },
  },
  // Track per-scenario UI state: selected option index
  scenarioUI: {},
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

/* ============================================================
   LUCIDE ICONS
   ============================================================ */
function refreshIcons(root) {
  if (window.lucide && typeof window.lucide.createIcons === "function") {
    window.lucide.createIcons({ nodes: root ? [root] : undefined });
  }
}

/* ============================================================
   HELPERS
   ============================================================ */
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text == null ? "" : String(text);
  return div.innerHTML;
}

function renderMarkdown(text) {
  if (window.marked) {
    try {
      return marked.parse(text);
    } catch (e) {
      return escapeHtml(text);
    }
  }
  return escapeHtml(text).replace(/\n/g, "<br>");
}

/* ============================================================
   TAB SWITCHING (strict isolation)
   ============================================================ */
function initTabs() {
  $$(".nav-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.tab;
      state.activeTab = target;

      $$(".nav-tab").forEach((t) => {
        const active = t === tab;
        t.classList.toggle("active", active);
        t.setAttribute("aria-selected", active ? "true" : "false");
      });
      $$(".tab-view").forEach((view) => {
        view.classList.toggle("active", view.id === `tab-${target}`);
      });

      // Lazy-load the relevant scenario lab on first visit.
      if (target === "phishing") loadLab("phishing");
      if (target === "soc") loadLab("soc");
      if (target === "cheatsheets") loadCheatSheet(state.cheatTier);
    });
  });
}

/* ============================================================
   LLM TIER SWITCHER
   ============================================================ */
function initTierSwitcher() {
  $$(".tier-btn[data-tier]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.tier = btn.dataset.tier;
      $$(".tier-btn[data-tier]").forEach((b) =>
        b.classList.toggle("active", b === btn)
      );
      updateChatMeta();
    });
  });
}

function updateChatMeta() {
  const meta = $("#chat-meta");
  if (!meta) return;
  const labels = {
    flash: "⚡ Flash — 2-3 high-impact lines (~3-5s)",
    balanced: "🛡 Balanced — 4-7 lines: mechanics + detection",
    pro: "🧠 Pro — 13-20 lines: executive briefing",
  };
  meta.textContent = `Tier: ${labels[state.tier] || labels.balanced}`;
}

/* ============================================================
   CHAT — double-click-safe send + markdown rendering
   ============================================================ */
function appendMessage(role, content, metaInfo) {
  const log = $("#chat-log");
  const wrapper = document.createElement("div");
  wrapper.className = `chat-message ${role}`;

  const avatar = document.createElement("div");
  avatar.className = "msg-avatar";
  avatar.innerHTML =
    role === "user"
      ? '<i data-lucide="user" class="h-4 w-4"></i>'
      : '<i data-lucide="bot" class="h-4 w-4"></i>';

  const body = document.createElement("div");
  body.className = "msg-body";

  if (role === "assistant") {
    body.innerHTML = renderMarkdown(content);
    if (metaInfo) {
      const tag = document.createElement("span");
      tag.className = "msg-model-tag";
      tag.textContent = metaInfo;
      body.appendChild(tag);
    }
  } else {
    body.textContent = content;
  }

  wrapper.appendChild(avatar);
  wrapper.appendChild(body);
  log.appendChild(wrapper);
  log.scrollTop = log.scrollHeight;
  refreshIcons(wrapper);
}

function setSendButtonLoading(isLoading) {
  const btn = $("#chat-send");
  const text = btn.querySelector(".btn-text");
  const icon = btn.querySelector(".btn-icon");
  const spinner = btn.querySelector(".btn-spinner");
  btn.disabled = isLoading;
  if (isLoading) {
    text.textContent = "Analyzing";
    if (icon) icon.classList.add("hidden");
    if (spinner) spinner.classList.remove("hidden");
  } else {
    text.textContent = "Send";
    if (icon) icon.classList.remove("hidden");
    if (spinner) spinner.classList.add("hidden");
  }
}

async function sendChatMessage(event) {
  event.preventDefault();
  const input = $("#chat-input");
  const message = input.value.trim();
  if (!message) return;

  // Double-click / double-submit protection.
  const btn = $("#chat-send");
  if (btn.disabled) return;

  appendMessage("user", message);
  input.value = "";
  setSendButtonLoading(true);

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        tier: state.tier,
        session_id: state.sessionId,
      }),
    });
    const data = await res.json();

    if (data.success) {
      state.sessionId = data.session_id || state.sessionId;
      updateSessionChip();
      const meta = `Model: ${data.model_used} | ${(data.tier || "").toUpperCase()} | ${data.tokens_used} tokens | ${data.latency_ms}ms`;
      appendMessage("assistant", data.reply, meta);
    } else {
      appendMessage(
        "assistant",
        `⚠️ **LLM Unavailable**\n\n${escapeHtml(data.error || "Unknown error")}\n\nThe NVIDIA NIM failover chain was exhausted. Verify the account has live models provisioned (see console).`
      );
    }
  } catch (err) {
    appendMessage("assistant", `⚠️ **Network error:** ${escapeHtml(err.message)}`);
  } finally {
    // Always re-enable the send button — even on failure.
    setSendButtonLoading(false);
  }
}

function updateSessionChip() {
  // Session chip is shown in the chat meta line.
}

function initChat() {
  $("#chat-form").addEventListener("submit", sendChatMessage);
  updateChatMeta();

  // Quick action pills — insert query and send immediately.
  $$("#quick-pills .quick-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      const input = $("#chat-input");
      input.value = pill.dataset.query || "";
      $("#chat-form").requestSubmit();
    });
  });
}

/* ============================================================
   PASSWORD AUDIT — CLICK-ONLY (NO input/keyup listeners)
   This fixes the 429 rate-limit bug: analysis triggers ONLY on
   the explicit audit button click. Client-side Shannon entropy
   is computed instantly at click time; the backend is fetched
   thereafter. The live meter updates only on discrete
   'change'/'blur' events — never on 'input' or 'keyup'.
   ============================================================ */

// --- Client-side Shannon entropy (instant, no network) ---
function shannonEntropy(pwd) {
  if (!pwd) return 0;
  const freq = {};
  for (const ch of pwd) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / pwd.length;
    h -= p * Math.log2(p);
  }
  return h * pwd.length; // total bits
}

function charsetPool(pwd) {
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;
  return pool || 1;
}

function charsetEntropy(pwd) {
  return pwd.length * Math.log2(charsetPool(pwd));
}

function entropyStrengthLabel(bits) {
  if (bits < 28) return "Very Weak";
  if (bits < 40) return "Weak";
  if (bits < 55) return "Fair";
  if (bits < 75) return "Strong";
  return "Very Strong";
}

function entropyMeterPercent(bits) {
  return Math.min(100, Math.max(0, (bits / 100) * 100));
}

// NOTE: Intentionally NO 'input' or 'keyup' listeners on #password-field.
function updateLiveEntropyPreview() {
  const pwd = $("#password-field").value;
  const bits = shannonEntropy(pwd);
  const live = $("#entropy-live");
  const fill = $("#entropy-fill");
  if (live) live.textContent = `${bits.toFixed(2)} bits (${entropyStrengthLabel(bits)})`;
  if (fill) fill.style.width = `${entropyMeterPercent(bits)}%`;
}

function initPasswordAudit() {
  // Discrete, non-rate-limiting events for the instant client preview.
  $("#password-field").addEventListener("change", updateLiveEntropyPreview);
  $("#password-field").addEventListener("blur", updateLiveEntropyPreview);

  // Show/hide toggle (swap lucide icon).
  $("#toggle-pw-visibility").addEventListener("click", () => {
    const field = $("#password-field");
    const isPassword = field.type === "password";
    field.type = isPassword ? "text" : "password";
    const icon = $("#toggle-pw-visibility i[data-lucide]");
    if (icon) icon.setAttribute("data-lucide", isPassword ? "eye-off" : "eye");
    refreshIcons($("#toggle-pw-visibility"));
  });

  // EXPLICIT-CLICK-ONLY audit trigger.
  $("#audit-btn").addEventListener("click", runPasswordAudit);
}

async function runPasswordAudit() {
  const pwd = $("#password-field").value;
  const resultBlock = $("#password-result");

  if (!pwd) {
    resultBlock.innerHTML = `
      <div class="result-placeholder">
        <i data-lucide="alert-triangle" class="h-5 w-5 text-cyber"></i>
        <p>⚠️ Enter a password first, then click <strong>Audit</strong>.</p>
      </div>`;
    refreshIcons(resultBlock);
    return;
  }

  // 1) Instant client-side Shannon entropy (no network).
  const clientBits = shannonEntropy(pwd);

  // 2) Fetch backend analysis (explicit click — immune to keystroke 429s).
  resultBlock.innerHTML = `
    <div class="result-placeholder">
      <i data-lucide="loader" class="h-5 w-5 text-cyber animate-spin"></i>
      <p>⏳ Auditing password &amp; generating hardened alternative…</p>
    </div>`;
  refreshIcons(resultBlock);

  try {
    const res = await fetch("/api/password/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pwd }),
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || "Audit failed");
    renderPasswordResult(data.audit, data.guidance, clientBits);
  } catch (err) {
    resultBlock.innerHTML = `
      <div class="result-placeholder">
        <i data-lucide="alert-octagon" class="h-5 w-5 text-cyber"></i>
        <p>⚠️ <strong>Audit error:</strong> ${escapeHtml(err.message)}</p>
      </div>`;
    refreshIcons(resultBlock);
  }
}

function renderPasswordResult(audit, guidance, clientBits) {
  const originalClass = audit.original_score <= 1 ? "weak" : audit.original_score === 2 ? "" : "strong";
  const hardenedClass = audit.hardened_score >= 3 ? "strong" : "";

  const recs = (audit.recommendations || [])
    .map((r) => `<li>${escapeHtml(r)}</li>`)
    .join("");

  const patterns = audit.pattern_findings && audit.pattern_findings.length
    ? audit.pattern_findings.map((p) => `<li>${escapeHtml(p)}</li>`).join("")
    : "<li>No risky patterns detected</li>";

  const html = `
    <div class="entropy-compare">
      <div class="entropy-card ${originalClass}">
        <h4>ORIGINAL</h4>
        <div class="bits">${audit.original_entropy_bits.toFixed(2)}</div>
        <div class="strength">${audit.original_strength} · ${audit.original_password.length} chars</div>
      </div>
      <div class="entropy-arrow">➜</div>
      <div class="entropy-card ${hardenedClass}">
        <h4>HARDENED</h4>
        <div class="bits">${audit.hardened_entropy_bits.toFixed(2)}</div>
        <div class="strength">${audit.hardened_strength} · +${audit.entropy_gain_bits.toFixed(2)} bits</div>
      </div>
    </div>

    <div class="hardened-box">
      <span class="hardened-label">🔐 RECOMMENDED ENTERPRISE HARDENED PASSWORD</span>
      <div class="hardened-password" id="hardened-password">${escapeHtml(audit.hardened_password)}</div>
      <div class="hardened-actions">
        <button class="copy-btn" id="copy-hardened-btn">
          <i data-lucide="copy" class="h-3.5 w-3.5"></i><span>Copy Hardened Password</span>
        </button>
      </div>
    </div>

    <div class="audit-details">
      <div class="detail-row"><span>Client-side Shannon entropy (instant):</span><strong>${clientBits.toFixed(2)} bits</strong></div>
      <div class="detail-row"><span>Entropy gain:</span><strong class="good">+${audit.entropy_gain_bits.toFixed(2)} bits</strong></div>
      <div class="detail-row"><span>RockYou breach corpus:</span><strong class="${audit.in_rockyou ? "bad" : "good"}">${audit.in_rockyou ? "FOUND — rotate everywhere" : "Not found"}</strong></div>
      <div class="detail-row"><span>Offline crack (Argon2id m=64MB/t=3/p=4):</span><strong>${audit.crack_time_offline_argon2id}</strong></div>
      <div class="detail-row"><span>Offline crack (bcrypt cost 12):</span><strong>${audit.crack_time_offline_bcrypt}</strong></div>
      <div class="detail-row"><span>Pattern analysis:</span></div>
      <ul class="recommendation-list">${patterns}</ul>
    </div>

    <div class="audit-details">
      <div class="detail-row"><span>Hardening recommendations:</span></div>
      <ul class="recommendation-list">${recs}</ul>
    </div>

    <div class="hash-guidance">
      <h4>🛡 STORAGE HASHING GUIDANCE</h4>
      <p><strong>Argon2id:</strong> memory=${guidance.argon2id.memory_mib}MB, iterations=${guidance.argon2id.iterations}, parallelism=${guidance.argon2id.parallelism} — ${escapeHtml(guidance.argon2id.note)}</p>
      <p><strong>bcrypt:</strong> cost factor ${guidance.bcrypt.cost_factor} — ${escapeHtml(guidance.bcrypt.note)}</p>
    </div>
  `;

  const resultBlock = $("#password-result");
  resultBlock.innerHTML = html;
  refreshIcons(resultBlock);

  // Wire the 1-click copy button.
  $("#copy-hardened-btn").addEventListener("click", async () => {
    const hardened = audit.hardened_password;
    try {
      await navigator.clipboard.writeText(hardened);
      const btn = $("#copy-hardened-btn");
      const span = btn.querySelector("span");
      const original = span.textContent;
      span.textContent = "Copied!";
      setTimeout(() => (span.textContent = original), 1800);
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = hardened;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
  });
}

/* ============================================================
   SCENARIO REPOSITORY — shared renderer for Phishing Lab & SOC Drills
   ============================================================ */
const LAB_CONFIG = {
  phishing: {
    gridId: "phishing-grid",
    filtersId: "phishing-filters",
    countId: "phishing-count",
    categories: ["All Labs", "Phishing Triage"],
    defaultCategory: "All Labs",
    labParam: "phishing",
  },
  soc: {
    gridId: "soc-grid",
    filtersId: "soc-filters",
    countId: "soc-count",
    categories: ["All", "Endpoint Defense", "Active Directory", "Web AppSec", "Cloud Security"],
    defaultCategory: "All",
    labParam: "soc",
  },
};

function difficultyClass(diff) {
  const d = (diff || "").toLowerCase();
  if (d === "beginner") return "diff-beginner";
  if (d === "intermediate") return "diff-intermediate";
  if (d === "advanced") return "diff-advanced";
  return "";
}

function initLabFilters(lab) {
  const cfg = LAB_CONFIG[lab];
  const container = $(`#${cfg.filtersId}`);
  container.innerHTML = cfg.categories
    .map(
      (c) =>
        `<button class="filter-btn ${c === state.labs[lab].category ? "active" : ""}" data-lab="${lab}" data-category="${c}">${c}</button>`
    )
    .join("");

  $$(`#${cfg.filtersId} .filter-btn`).forEach((btn) => {
    btn.addEventListener("click", () => {
      state.labs[lab].category = btn.dataset.category;
      $$(`#${cfg.filtersId} .filter-btn`).forEach((b) =>
        b.classList.toggle("active", b === btn)
      );
      loadLab(lab);
    });
  });
}

async function loadLab(lab) {
  const cfg = LAB_CONFIG[lab];
  const grid = $(`#${cfg.gridId}`);
  const count = $(`#${cfg.countId}`);

  grid.innerHTML = `<div class="result-placeholder"><i data-lucide="loader" class="h-5 w-5 text-cyber"></i><p>⏳ Loading SOC labs…</p></div>`;
  refreshIcons(grid);

  try {
    const url = `/api/scenarios?lab=${cfg.labParam}&category=${encodeURIComponent(state.labs[lab].category)}`;
    const res = await fetch(url);
    const data = await res.json();
    if (!data.success) throw new Error("Failed to load scenarios");

    state.labs[lab].scenarios = data.scenarios;
    state.labs[lab].loaded = true;
    if (count) count.textContent = `${data.count} lab(s) · ${data.active_category}`;
    renderScenarios(lab, data.scenarios);
  } catch (err) {
    grid.innerHTML = `<div class="result-placeholder"><i data-lucide="alert-octagon" class="h-5 w-5 text-cyber"></i><p>⚠️ ${escapeHtml(err.message)}</p></div>`;
    refreshIcons(grid);
  }
}

function renderScenarios(lab, scenarios) {
  const cfg = LAB_CONFIG[lab];
  const grid = $(`#${cfg.gridId}`);

  if (!scenarios || !scenarios.length) {
    grid.innerHTML = `<div class="result-placeholder"><i data-lucide="inbox" class="h-5 w-5 text-cyber"></i><p>No labs in this category.</p></div>`;
    refreshIcons(grid);
    return;
  }

  grid.innerHTML = scenarios
    .map((sc) => {
      const options = sc.options
        .map(
          (opt, i) =>
            `<button class="scenario-option" data-scenario="${sc.id}" data-index="${i}">${escapeHtml(opt)}</button>`
        )
        .join("");

      const hints = (sc.hints || [])
        .map((h) => `<li>${escapeHtml(h)}</li>`)
        .join("");

      return `
      <article class="scenario-card" id="card-${sc.id}">
        <div class="scenario-top">
          <span class="scenario-id">${sc.id}</span>
          <span class="scenario-difficulty ${difficultyClass(sc.difficulty)}">${sc.difficulty}</span>
        </div>
        <div class="scenario-category">${escapeHtml(sc.category)}</div>
        <h3 class="scenario-title">${escapeHtml(sc.title)}</h3>
        <p class="scenario-desc">${escapeHtml(sc.description)}</p>
        <pre class="telemetry-block">${escapeHtml(sc.telemetry)}</pre>
        <p class="scenario-question">Q: ${escapeHtml(sc.question)}</p>
        <div class="scenario-options">${options}</div>
        <div class="scenario-actions">
          <button class="hint-btn" data-hint="${sc.id}">
            <i data-lucide="lightbulb" class="h-3.5 w-3.5"></i><span>Show Hint</span>
          </button>
          <button class="submit-btn" data-submit="${sc.id}">
            <i data-lucide="check" class="h-3.5 w-3.5"></i><span>Submit Answer</span>
          </button>
        </div>
        <div class="hint-block" id="hint-${sc.id}"><strong>💡 Hints:</strong><ol>${hints}</ol></div>
        <div class="evaluation-result" id="eval-${sc.id}"></div>
      </article>
    `;
    })
    .join("");

  refreshIcons(grid);
}

/* Event delegation for scenario interactions (both labs). */
function initScenarioDelegation() {
  ["phishing", "soc"].forEach((lab) => {
    const cfg = LAB_CONFIG[lab];
    const grid = $(`#${cfg.gridId}`);
    if (!grid) return;

    grid.addEventListener("click", (e) => {
      const optionBtn = e.target.closest(".scenario-option");
      if (optionBtn) {
        handleOptionSelect(optionBtn);
        return;
      }
      const hintBtn = e.target.closest(".hint-btn");
      if (hintBtn) {
        handleHintToggle(hintBtn);
        return;
      }
      const submitBtn = e.target.closest(".submit-btn");
      if (submitBtn) {
        handleSubmit(lab, submitBtn);
        return;
      }
    });
  });
}

function handleOptionSelect(btn) {
  const sid = btn.dataset.scenario;
  $$(`.scenario-option[data-scenario="${sid}"]`).forEach((b) =>
    b.classList.remove("selected")
  );
  btn.classList.add("selected");
  state.scenarioUI[sid] = { selected: parseInt(btn.dataset.index, 10) };
}

function handleHintToggle(btn) {
  const sid = btn.dataset.hint;
  const block = $(`#hint-${sid}`);
  if (!block) return;
  const isOpen = block.classList.toggle("open");
  const span = btn.querySelector("span");
  if (span) span.textContent = isOpen ? "Hide Hint" : "Show Hint";
}

async function handleSubmit(lab, btn) {
  const scenarioId = btn.dataset.submit;
  const ui = state.scenarioUI[scenarioId];
  const evalBox = $(`#eval-${scenarioId}`);
  if (!evalBox) return;

  if (!ui || ui.selected === undefined) {
    evalBox.className = "evaluation-result show incorrect";
    evalBox.innerHTML = `<span class="eval-badge">⚠ Select an answer option first.</span>`;
    return;
  }

  // Disable the submit button to prevent double-submission.
  btn.disabled = true;

  try {
    const res = await fetch(`/api/scenarios/${scenarioId}/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selected_index: ui.selected }),
    });
    const data = await res.json();
    const ev = data.evaluation;

    // Mark options.
    $$(`.scenario-option[data-scenario="${scenarioId}"]`).forEach((b) => {
      const idx = parseInt(b.dataset.index, 10);
      b.classList.remove("correct", "incorrect");
      if (idx === ev.correct_index) b.classList.add("correct");
      else if (idx === ev.selected_index && !ev.correct) b.classList.add("incorrect");
    });

    const iocs = (ev.iocs || []).map((i) => escapeHtml(i)).join(" · ");
    const mitre = (ev.mitre_tactics || []).map((m) => escapeHtml(m)).join(" · ");

    evalBox.className = `evaluation-result show ${ev.correct ? "correct" : "incorrect"}`;
    evalBox.innerHTML = `
      <span class="eval-badge">${ev.badge}</span>
      <span class="eval-explanation"><strong>Forensic breakdown (NIST/SANS PICERL):</strong> ${escapeHtml(ev.explanation)}</span>
      <span class="eval-iocs">IoCs: ${iocs}</span>
      <span class="eval-mitre">MITRE ATT&CK: ${mitre}</span>
    `;
  } catch (err) {
    evalBox.className = "evaluation-result show incorrect";
    evalBox.innerHTML = `<span class="eval-badge">⚠ Evaluation error: ${escapeHtml(err.message)}</span>`;
  } finally {
    btn.disabled = false;
  }
}

/* ============================================================
   CHEAT SHEETS — multi-tier reference matrix loader
   ============================================================ */
function initCheatTiers() {
  $$("#cheat-tiers .tier-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.cheatTier = btn.dataset.cheatTier;
      $$("#cheat-tiers .tier-btn").forEach((b) =>
        b.classList.toggle("active", b === btn)
      );
      loadCheatSheet(state.cheatTier);
    });
  });
}

async function loadCheatSheet(tier) {
  const container = $("#cheat-container");
  if (!container) return;
  container.innerHTML = `<div class="result-placeholder"><i data-lucide="loader" class="h-5 w-5 text-cyber"></i><p>⏳ Loading ${tier} reference matrix…</p></div>`;
  refreshIcons(container);

  try {
    const res = await fetch(`/api/cheatsheets/${tier}`);
    const data = await res.json();
    if (!data.success) throw new Error("Failed to load cheat sheet");
    renderCheatSheet(data.sheet);
  } catch (err) {
    container.innerHTML = `<div class="result-placeholder"><i data-lucide="alert-octagon" class="h-5 w-5 text-cyber"></i><p>⚠️ ${escapeHtml(err.message)}</p></div>`;
    refreshIcons(container);
  }
}

function renderCheatSheet(sheet) {
  const container = $("#cheat-container");
  container.innerHTML = sheet.matrices
    .map((matrix) => {
      const headers = matrix.headers
        .map((h) => `<th>${escapeHtml(h)}</th>`)
        .join("");
      const rows = matrix.rows
        .map(
          (row) =>
            `<tr>${row.map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`
        )
        .join("");
      return `
        <div class="cheat-matrix">
          <div class="cheat-matrix-header">${escapeHtml(matrix.title)}</div>
          <table class="cheat-table">
            <thead><tr>${headers}</tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
    })
    .join("");
}

/* ============================================================
   BOOTSTRAP
   ============================================================ */
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initTierSwitcher();
  initChat();
  initPasswordAudit();

  // Initialize both scenario labs (filters + delegation).
  ["phishing", "soc"].forEach((lab) => {
    state.labs[lab].category = LAB_CONFIG[lab].defaultCategory;
    initLabFilters(lab);
  });
  initScenarioDelegation();

  initCheatTiers();

  // Initialize Lucide icons across the static shell.
  refreshIcons();

  // Eagerly load the default (chat) view's needs; phishing/soc load
  // lazily on first tab visit via initTabs().
});

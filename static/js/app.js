/**
 * CyberGPT — Frontend Application Logic
 * ------------------------------------------------------------------
 * Obsidian workspace shell:
 *  * Lucide icon initialization (lucide.createIcons())
 *  * 5-module switching with strict isolation
 *    (.tab-view { display:none } / .tab-view.active { display:flex })
 *  * Sidebar: desktop collapse + mobile slide-out drawer
 *  * Pill composer: single instance moved between empty-state / dock
 *  * Double-click send protection (disable + restore in `finally`)
 *  * Explicit password audit — CLICK ONLY (no input/keyup listeners)
 *  * Collapsible hint toggles + scenario evaluation (NIST PICERL)
 *  * Dynamic cheat-sheet renderer (3 tiers)
 *  * Markdown via marked.js + syntax highlighting + 1-click Copy Code
 *  * Flush Session Memory -> POST /api/clear-history
 */

"use strict";

/* ============================================================
   GLOBAL STATE
   ============================================================ */
const state = {
  activeTab: "chat",
  tier: "balanced",
  sessionId: cryptoId(),
  cheatTier: "beginner",
  messageCount: 0,
  turnCount: 0,
  // Client-side transcript mirror (drives the "Recent Operations" list).
  messages: [],
  // Per-lab scenario tab state
  labs: {
    phishing: { category: "All Labs", loaded: false, scenarios: [] },
    soc: { category: "All", loaded: false, scenarios: [] },
  },
  // Track per-scenario UI state: selected option index
  scenarioUI: {},
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const MODULE_LABELS = {
  chat: "Chat Copilot",
  phishing: "Phishing Triage Lab",
  password: "Password Hardening Audit",
  soc: "SOC Incident Drills",
  cheatsheets: "Security Cheat Sheets",
};

function cryptoId() {
  if (window.crypto && window.crypto.randomUUID) {
    return window.crypto.randomUUID().slice(0, 8);
  }
  return Math.random().toString(36).slice(2, 10);
}

/* ============================================================
   LUCIDE ICONS
   ============================================================ */
function refreshIcons(root) {
  if (window.lucide && typeof window.lucide.createIcons === "function") {
    try {
      window.lucide.createIcons({ nodes: root ? [root] : undefined });
    } catch (e) {
      /* icon rendering is cosmetic — never block app flow */
    }
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

/* Keyword sets for the lightweight syntax highlighter. */
const HL_KEYWORDS = {
  bash: ["if", "then", "else", "elif", "fi", "for", "while", "do", "done", "case", "esac",
         "function", "return", "echo", "cd", "export", "source", "local", "exit", "set",
         "in", "select", "until", "shift", "true", "false"],
  sh: ["if", "then", "else", "elif", "fi", "for", "while", "do", "done", "case", "esac",
       "function", "return", "echo", "cd", "export", "source", "local", "exit", "set", "in"],
  shell: ["if", "then", "else", "fi", "for", "while", "do", "done", "echo", "export", "exit"],
  zsh: ["if", "then", "else", "fi", "for", "while", "do", "done", "echo", "export", "exit"],
  powershell: ["if", "else", "elseif", "foreach", "for", "while", "do", "function", "param",
               "return", "try", "catch", "finally", "throw", "switch", "in", "begin",
               "process", "end", "filter", "workflow", "parallel", "sequence",
               "Get", "Set", "New", "Invoke", "Write", "Test", "Where", "Select", "ForEach",
               "Out", "Copy", "Move", "Remove", "Add", "Start", "Stop", "Export", "Import",
               "ConvertTo", "ConvertFrom", "Measure", "Group", "Sort", "Format", "Tee",
               "Wait", "Unblock", "Resolve", "Join", "Split", "Compare", "Find", "Search",
               "Clear", "Restart", "Enable", "Disable", "Grant", "Revoke", "New-Object",
               "$true", "$false", "$null", "$_", "$env"],
  ps1: ["if", "else", "foreach", "function", "param", "return", "Get-", "Set-", "New-", "Invoke-"],
  python: ["def", "class", "return", "if", "elif", "else", "for", "while", "import", "from",
           "as", "try", "except", "finally", "with", "lambda", "yield", "raise", "pass",
           "break", "continue", "and", "or", "not", "in", "is", "None", "True", "False",
           "global", "assert", "del", "async", "await"],
  py: ["def", "class", "return", "if", "elif", "else", "for", "while", "import", "from",
       "try", "except", "with", "lambda", "None", "True", "False", "and", "or", "not", "in"],
  sql: ["SELECT", "FROM", "WHERE", "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE",
        "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "ON", "GROUP", "BY", "ORDER", "HAVING",
        "LIMIT", "OFFSET", "UNION", "ALL", "CREATE", "TABLE", "DROP", "ALTER", "AND", "OR",
        "NOT", "NULL", "AS", "DISTINCT", "COUNT", "SUM", "WAITFOR", "DELAY", "IF", "EXISTS"],
  javascript: ["const", "let", "var", "function", "return", "if", "else", "for", "while",
               "do", "switch", "case", "break", "continue", "new", "class", "extends",
               "import", "export", "from", "default", "async", "await", "try", "catch",
               "finally", "throw", "typeof", "instanceof", "in", "of", "this", "null",
               "true", "false", "undefined", "void", "yield"],
  js: ["const", "let", "var", "function", "return", "if", "else", "for", "while", "new",
       "class", "async", "await", "try", "catch", "throw", "typeof", "this", "null", "true", "false"],
  json: ["true", "false", "null"],
  yaml: ["true", "false", "null"],
  splunk: ["index", "search", "stats", "eval", "where", "table", "rename", "dedup", "fields", "by"],
  sigma: ["title", "detection", "condition", "selection", "logsource", "falsepositives", "level", "status"],
};

const HL_GENERIC = new Set([
  "if", "else", "elif", "for", "while", "return", "function", "class", "def", "import",
  "from", "export", "const", "let", "var", "new", "try", "catch", "finally", "throw",
  "switch", "case", "break", "continue", "and", "or", "not", "null", "true", "false",
  "async", "await", "with", "in", "is", "as", "this",
]);

/**
 * Minimal, dependency-free syntax highlighter.
 * Escapes every segment as it emits, so no unescaped HTML can survive.
 * Colour set is intentionally restrained:
 *   comment  -> italic gray      string -> emerald
 *   number   -> cyan           flag    -> cyan
 *   keyword  -> blue
 */
function highlightCode(rawCode, lang) {
  const language = String(lang || "").toLowerCase().replace(/^language-/, "").trim();
  const known = Object.prototype.hasOwnProperty.call(HL_KEYWORDS, language);
  const kwSet = new Set(known ? HL_KEYWORDS[language] : HL_GENERIC);
  const caseInsensitive = language === "sql" || language === "powershell" || language === "ps1";

  // comment | string | number | flag | identifier
  const master = new RegExp(
    [
      "(\\/\\/[^\\n]*|#[^\\n]*|--[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/)",
      "(\"(?:[^\"\\\\\\n]|\\\\.)*\"|'(?:[^'\\\\\\n]|\\\\.)*')",
      "\\b(\\d+(?:\\.\\d+)?)\\b",
      "(-[A-Za-z][\\w-]*)",
      "([A-Za-z_$][\\w$]*)",
    ].join("|"),
    "g"
  );

  const looksLikeComment = (text) => {
    if (text.startsWith("//") || text.startsWith("/*")) return true;
    if (text.startsWith("--")) return true;
    if (text.startsWith("#")) {
      // '#' only opens a comment at a token boundary (never inside $var# or C#).
      const gap = rawCode.slice(0, master.lastIndex - text.length);
      const prev = /\s*$/.test(gap.slice(-1)) ? gap.replace(/\s+$/, "").slice(-1) : gap.slice(-1);
      return prev === "" || !/[A-Za-z0-9_$.#-]/.test(prev);
    }
    return false;
  };

  let out = "";
  let last = 0;
  let match;

  while ((match = master.exec(rawCode)) !== null) {
    out += escapeHtml(rawCode.slice(last, match.index));
    const full = match[0];
    const [, comment, str, num, flag, ident] = match;

    if (comment && looksLikeComment(full)) {
      out += `<span class="tok-comment">${escapeHtml(full)}</span>`;
    } else if (comment) {
      out += escapeHtml(full);
    } else if (str) {
      out += `<span class="tok-str">${escapeHtml(full)}</span>`;
    } else if (num) {
      out += `<span class="tok-num">${escapeHtml(full)}</span>`;
    } else if (flag) {
      out += `<span class="tok-flag">${escapeHtml(full)}</span>`;
    } else if (ident) {
      const probes = caseInsensitive
        ? [ident.toLowerCase(), ident.toUpperCase(), ident]
        : [ident, ident.toLowerCase()];
      if (probes.some((p) => kwSet.has(p))) {
        out += `<span class="tok-kw">${escapeHtml(full)}</span>`;
      } else {
        out += escapeHtml(full);
      }
    } else {
      out += escapeHtml(full);
    }
    last = match.index + full.length;
  }
  out += escapeHtml(rawCode.slice(last));
  return out;
}

/* ============================================================
   MARKDOWN RENDERING (marked.js + custom code blocks)
   ============================================================ */
let codeBlockSeq = 0;

function plainMarked(text) {
  if (window.marked) {
    try {
      return marked.parse(text);
    } catch (e) {
      /* fall through to escaped rendering */
    }
  }
  return `<p>${escapeHtml(text).replace(/\n/g, "<br>")}</p>`;
}

/**
 * Render markdown, then post-process every <pre><code> fence into a
 * labelled, syntax-highlighted block with a 1-click "Copy Code" button.
 */
function renderMarkdown(text) {
  const html = plainMarked(text);
  const holder = document.createElement("div");
  holder.innerHTML = html;

  // Wrap bare tables so they scroll horizontally instead of overflowing.
  holder.querySelectorAll("table").forEach((table) => {
    if (table.parentElement && table.parentElement.classList.contains("table-wrap")) return;
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
  });

  holder.querySelectorAll("pre").forEach((pre) => {
    const code = pre.querySelector("code");
    if (!code) return;

    const raw = code.textContent || "";
    const cls = code.getAttribute("class") || "";
    const langMatch = cls.match(/language-([\w-]+)/);
    const lang = langMatch ? langMatch[1] : (pre.getAttribute("data-lang") || "text");

    const block = document.createElement("div");
    block.className = "code-block";

    const head = document.createElement("div");
    head.className = "code-head";
    head.innerHTML =
      `<span class="code-lang">${escapeHtml(lang)}</span>` +
      `<button type="button" class="code-copy" data-code-id="${++codeBlockSeq}">` +
        `<i data-lucide="copy" class="c-ico"></i><span class="code-copy-label">Copy</span>` +
      `</button>`;

    const preNew = document.createElement("pre");
    const codeNew = document.createElement("code");
    codeNew.innerHTML = highlightCode(raw, lang);
    preNew.appendChild(codeNew);

    block.appendChild(head);
    block.appendChild(preNew);
    pre.parentNode.replaceChild(block, pre);
  });

  return holder.innerHTML;
}

/**
 * Wire 1-click copy buttons on rendered code blocks (event delegation).
 * Uses a clipboard API with a document.execCommand fallback.
 */
function initCodeCopyDelegation(root) {
  const scope = root || document;
  scope.addEventListener("click", async (e) => {
    const btn = e.target.closest(".code-copy");
    if (!btn) return;

    const block = btn.closest(".code-block");
    const code = block && block.querySelector("pre code");
    if (!code) return;

    const payload = code.textContent || "";
    let ok = false;
    try {
      await navigator.clipboard.writeText(payload);
      ok = true;
    } catch (err) {
      try {
        const ta = document.createElement("textarea");
        ta.value = payload;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand("copy");
        document.body.removeChild(ta);
      } catch (e2) {
        ok = false;
      }
    }

    const label = btn.querySelector(".code-copy-label");
    if (ok && label) {
      btn.classList.add("copied");
      const prev = label.textContent;
      label.textContent = "Copied";
      const icon = btn.querySelector("[data-lucide], svg");
      if (icon) {
        const old = icon.getAttribute("data-lucide");
        icon.setAttribute("data-lucide", "check");
        refreshIcons(btn);
        setTimeout(() => {
          icon.setAttribute("data-lucide", old || "copy");
          refreshIcons(btn);
        }, 1600);
      }
      setTimeout(() => {
        btn.classList.remove("copied");
        label.textContent = prev;
      }, 1600);
    }
  });
}

/* ============================================================
   SIDEBAR — desktop collapse + mobile drawer
   ============================================================ */
function isMobile() {
  // Spec: slide-out drawer strictly BELOW 768px; 768px+ is a collapsible sidebar.
  return window.matchMedia("(max-width: 767.98px)").matches;
}

function initSidebar() {
  const shell = $(".app-shell");
  const toggle = $("#sidebar-toggle");
  const closeBtn = $("#sidebar-close");
  const scrim = $("#sidebar-scrim");

  if (!shell) return;

  // Desktop starts expanded; mobile starts closed.
  if (!isMobile()) shell.classList.add("sidebar-expanded");
  shell.classList.remove("sidebar-collapsed", "sidebar-open");

  const setToggleAffordance = () => {
    if (!toggle) return;
    const collapsed = shell.classList.contains("sidebar-collapsed");
    const open = shell.classList.contains("sidebar-open");
    toggle.setAttribute("aria-expanded", isMobile() ? String(open) : String(!collapsed));
  };

  if (toggle) {
    toggle.addEventListener("click", () => {
      if (isMobile()) {
        const open = shell.classList.toggle("sidebar-open");
        shell.classList.remove("sidebar-collapsed");
        setToggleAffordance();
        if (open) {
          const focusable = $("#new-chat-btn");
          if (focusable) focusable.focus();
        }
      } else {
        const collapsed = shell.classList.toggle("sidebar-collapsed");
        if (!collapsed) shell.classList.add("sidebar-expanded");
        setToggleAffordance();
      }
    });
  }

  const closeDrawer = () => {
    shell.classList.remove("sidebar-open");
    setToggleAffordance();
  };

  if (closeBtn) closeBtn.addEventListener("click", closeDrawer);
  if (scrim) scrim.addEventListener("click", closeDrawer);

  // Escape closes the mobile drawer.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && shell.classList.contains("sidebar-open")) closeDrawer();
  });

  // Crossing the breakpoint resets drawer state.
  window.addEventListener("resize", () => {
    if (!isMobile()) {
      shell.classList.remove("sidebar-open");
    } else {
      shell.classList.remove("sidebar-collapsed", "sidebar-expanded");
    }
    setToggleAffordance();
  });

  setToggleAffordance();
}

/* ============================================================
   MODULE SWITCHING (strict isolation)
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

      // Breadcrumb indicator
      const crumb = $("#crumb-current");
      if (crumb) crumb.textContent = MODULE_LABELS[target] || target;

      // Close the mobile drawer after navigating.
      const shell = $(".app-shell");
      if (shell && isMobile()) shell.classList.remove("sidebar-open");

      // Reset scroll position of the main region.
      const main = $("#app-main");
      if (main) main.scrollTop = 0;

      // Lazy-load the relevant module on first visit.
      if (target === "phishing") loadLab("phishing");
      if (target === "soc") loadLab("soc");
      if (target === "cheatsheets") loadCheatSheet(state.cheatTier);
      if (target === "chat") {
        const input = $("#chat-input");
        if (input && !isMobile()) input.focus();
      }
    });
  });
}

/* ============================================================
   LLM TIER SWITCHER
   ============================================================ */
function initTierSwitcher() {
  $$("#tier-switcher .tier-btn[data-tier]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.tier = btn.dataset.tier;
      $$("#tier-switcher .tier-btn[data-tier]").forEach((b) =>
        b.classList.toggle("active", b === btn)
      );
      updateChatMeta();
    });
  });
}

function updateChatMeta() {
  const meta = $("#chat-meta-text");
  const profile = $("#profile-tier");
  const labels = {
    flash: "Flash — 2-3 lines · rapid triage",
    balanced: "Balanced — 4-7 lines · mechanics + detection",
    pro: "Pro — 13-20 lines · architecture & IoCs",
  };
  const text = labels[state.tier] || labels.balanced;
  if (meta) meta.textContent = `${text} · NVIDIA NIM failover`;
  if (profile) profile.textContent = state.tier.charAt(0).toUpperCase() + state.tier.slice(1);
}

/* ============================================================
   MESSAGE COMPOSER
   The composer is a single <template> instance that MOVES between
   the empty-state slot and the sticky dock, so its listeners and
   its ID are never duplicated.
   ============================================================ */
function initComposer() {
  const tpl = $("#composer-template");
  if (!tpl) return;

  const node = tpl.content.firstElementChild.cloneNode(true);

  // Mount in the empty-state slot initially.
  const emptySlot = $("#empty-composer-slot");
  const dockSlot = $("#dock-slot");
  if (emptySlot) emptySlot.appendChild(node);

  const input = node.querySelector("#chat-input");
  const sendBtn = node.querySelector("#chat-send");
  const attachBtn = node.querySelector("#telemetry-btn");
  const fileInput = node.querySelector("#telemetry-file");
  const attachChip = node.querySelector("#composer-attachment");
  const attachName = node.querySelector("#composer-attachment-name");
  const attachClear = node.querySelector("#composer-attachment-clear");

  /* ---- Auto-expanding textarea (no layout shift on mobile) ---- */
  const autosize = () => {
    input.style.height = "auto";
    const max = 184;
    const next = Math.min(input.scrollHeight, max);
    input.style.height = `${next}px`;
    input.style.overflowY = input.scrollHeight > max ? "auto" : "hidden";
  };
  input.addEventListener("input", () => {
    autosize();
    sendBtn.disabled = input.value.trim().length === 0;
  });

  // Enter sends; Shift+Enter inserts a newline.
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      if (!sendBtn.disabled) sendBtn.requestSubmit();
    }
  });

  /* ---- Telemetry artifact attachment ---- */
  if (attachBtn && fileInput) {
    attachBtn.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
      const file = fileInput.files && fileInput.files[0];
      if (!file) return;
      if (file.size > 64 * 1024) {
        attachName.textContent = `${file.name} — too large (max 64 KB)`;
        if (attachChip) attachChip.hidden = false;
        fileInput.value = "";
        return;
      }
      state.attachment = { name: file.name, file };
      if (attachName) attachName.textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
      if (attachChip) attachChip.hidden = false;
    });
  }

  if (attachClear) {
    attachClear.addEventListener("click", () => {
      state.attachment = null;
      if (fileInput) fileInput.value = "";
      if (attachChip) attachChip.hidden = true;
      input.focus();
    });
  }

  /* ---- Send (double-click safe) ---- */
  node.addEventListener("submit", sendChatMessage);

  // Keep a handle so message sending can find the live composer.
  window.__composer = {
    node,
    input,
    sendBtn,
    focus: () => input.focus(),
  };

  autosize();
  updateSendState();
}

function updateSendState() {
  const c = window.__composer;
  if (!c) return;
  const nonEmpty = c.input.value.trim().length > 0;
  c.sendBtn.disabled = nonEmpty ? c.sendBtn.disabled : true;
  c.sendBtn.disabled = !nonEmpty;
}

/** Swap the composer between the empty-state slot and the dock. */
function placeComposer(hasMessages) {
  const c = window.__composer;
  if (!c) return;
  const emptySlot = $("#empty-composer-slot");
  const dockSlot = $("#dock-slot");
  const shell = $(".chat-shell");
  if (!emptySlot || !dockSlot) return;

  const target = hasMessages ? dockSlot : emptySlot;
  if (c.node.parentElement !== target) target.appendChild(c.node);

  if (shell) shell.classList.toggle("has-messages", hasMessages);
}

function setSendButtonLoading(isLoading) {
  const c = window.__composer;
  if (!c) return;
  const btn = c.sendBtn;
  const icon = btn.querySelector(".btn-icon");
  const spinner = btn.querySelector(".btn-spinner");
  btn.disabled = isLoading;
  if (isLoading) {
    btn.setAttribute("aria-busy", "true");
    if (icon) icon.classList.add("hidden");
    if (spinner) spinner.classList.remove("hidden");
  } else {
    btn.removeAttribute("aria-busy");
    if (icon) icon.classList.remove("hidden");
    if (spinner) spinner.classList.add("hidden");
    updateSendState();
  }
}

/* ============================================================
   CHAT — append messages + double-click-safe send
   ============================================================ */
function appendMessage(role, content, metaInfo) {
  const log = $("#chat-log");
  if (!log) return null;

  const wrapper = document.createElement("div");
  wrapper.className = `chat-message ${role}`;

  const avatar = document.createElement("div");
  avatar.className = "msg-avatar";
  avatar.innerHTML =
    role === "user"
      ? '<i data-lucide="user" class="h-3.5 w-3.5"></i>'
      : '<i data-lucide="bot" class="h-3.5 w-3.5"></i>';

  const col = document.createElement("div");
  col.className = "msg-col";

  const who = document.createElement("div");
  who.className = "msg-who";
  who.textContent = role === "user" ? "Analyst" : "CyberGPT";

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

  col.appendChild(who);
  col.appendChild(body);
  wrapper.appendChild(avatar);
  wrapper.appendChild(col);
  log.appendChild(wrapper);
  log.scrollTop = log.scrollHeight;
  refreshIcons(wrapper);
  return wrapper;
}

async function sendChatMessage(event) {
  event.preventDefault();
  const c = window.__composer;
  if (!c) return;

  const input = c.input;
  const message = input.value.trim();
  if (!message) return;

  // Double-click / double-submit protection.
  if (c.sendBtn.disabled) return;

  // Optional telemetry artifact is attached as a labelled, bounded block.
  let payload = message;
  if (state.attachment && state.attachment.file) {
    try {
      const text = await state.attachment.file.text();
      if (text.length <= 16 * 1024) {
        payload = `${message}\n\n[Telemetry artifact attached by analyst: ${state.attachment.name}]\n\`\`\`\n${text}\n\`\`\``;
      }
    } catch (e) {
      /* binary artifact — filename only */
      payload = `${message}\n\n[Telemetry artifact attached: ${state.attachment.name} (binary, not inlined)]`;
    }
  }

  appendMessage("user", message);
  rememberTurn(message);
  // First message: the empty-state hero retires and the composer
  // migrates into the sticky dock.
  if (state.messages.length === 1) placeComposer(true);

  input.value = "";
  state.attachment = null;
  const fileInput = c.node.querySelector("#telemetry-file");
  if (fileInput) fileInput.value = "";
  const chip = c.node.querySelector("#composer-attachment");
  if (chip) chip.hidden = true;

  autosizeComposer();
  setSendButtonLoading(true);

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: payload,
        tier: state.tier,
        session_id: state.sessionId,
      }),
    });
    const data = await res.json();

    if (data.success) {
      if (data.session_id) state.sessionId = data.session_id;
      updateSessionChip();
      const meta =
        `Model: ${data.model_used} · ${String(data.tier || "").toUpperCase()} · ` +
        `${data.tokens_used} tokens · ${data.latency_ms}ms`;
      appendMessage("assistant", data.reply, meta);
    } else {
      appendMessage(
        "assistant",
        `⚠️ **Inference service unavailable**\n\n${escapeHtml(data.error || "Unknown error")}\n\nThe NVIDIA NIM failover chain was exhausted. Verify the account has live models provisioned.`
      );
    }
  } catch (err) {
    appendMessage("assistant", `⚠️ **Network error:** ${escapeHtml(err.message)}`);
  } finally {
    // Always re-enable the send button — even on failure.
    setSendButtonLoading(false);
    if (!isMobile()) c.input.focus();
  }
}

function autosizeComposer() {
  const c = window.__composer;
  if (!c) return;
  const input = c.input;
  input.style.height = "auto";
  const max = 184;
  input.style.height = `${Math.min(input.scrollHeight, max)}px`;
  input.style.overflowY = input.scrollHeight > max ? "auto" : "hidden";
}

/* ============================================================
   RECENT OPERATIONS (sidebar history, client-side transcript)
   ============================================================ */
function rememberTurn(text) {
  const clean = String(text).replace(/\s+/g, " ").trim();
  if (!clean) return;
  state.messages.push({
    id: ++state.turnCount,
    preview: clean.length > 46 ? `${clean.slice(0, 46)}…` : clean,
    full: clean,
    at: new Date(),
  });
  if (state.messages.length > 40) state.messages.shift();
  renderRecentList();
}

function renderRecentList() {
  const list = $("#recent-list");
  const count = $("#recent-count");
  if (!list) return;

  if (count) count.textContent = String(state.messages.length);

  if (!state.messages.length) {
    list.innerHTML = `<li class="recent-empty">No operations recorded this session.</li>`;
    return;
  }

  list.innerHTML = state.messages
    .slice()
    .reverse()
    .map(
      (m) => `
      <li>
        <button class="recent-item" type="button" data-recent="${m.id}" title="${escapeHtml(m.full)}">
          <i data-lucide="message-square-dashed" class="r-ico"></i>
          <span class="r-text">${escapeHtml(m.preview)}</span>
          <span class="r-num">#${m.id}</span>
        </button>
      </li>`
    )
    .join("");
  refreshIcons(list);
}

function initRecentList() {
  renderRecentList();
  const list = $("#recent-list");
  if (!list) return;
  list.addEventListener("click", (e) => {
    const btn = e.target.closest(".recent-item");
    if (!btn) return;
    // Jump back to the chat module — the transcript is live above.
    const chatTab = $('.nav-tab[data-tab="chat"]');
    if (chatTab) chatTab.click();
    const log = $("#chat-log");
    if (log) log.scrollTop = log.scrollHeight;
  });
}

function updateSessionChip() {
  const chip = $("#session-chip");
  if (chip) chip.textContent = state.sessionId;
}

/* ============================================================
   FLUSH SESSION MEMORY -> POST /api/clear-history
   ============================================================ */
function initFlushButton() {
  const btn = $("#flush-btn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const span = btn.querySelector("span");
    const original = span ? span.textContent : "";
    if (span) span.textContent = "Flushing…";

    try {
      const res = await fetch("/api/clear-history", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: state.sessionId }),
      });
      const data = await res.json();

      // Rotate to a fresh session regardless of the response so the
      // next turn starts with empty server-side memory.
      state.sessionId = cryptoId();
      updateSessionChip();

      const log = $("#chat-log");
      if (log) log.innerHTML = "";
      state.messages = [];
      state.turnCount = 0;
      renderRecentList();
      placeComposer(false);

      appendMessage(
        "assistant",
        `Session memory flushed — ${data && data.messages_removed != null ? data.messages_removed : 0} message(s) purged from the server-side buffer.\n\nA fresh session ID has been issued. The workspace is clear.`
      );
    } catch (err) {
      appendMessage(
        "assistant",
        `⚠️ **Could not reach the session service:** ${escapeHtml(err.message)}\nThe transcript was still cleared locally.`
      );
    } finally {
      if (span) span.textContent = original;
      btn.disabled = false;
    }
  });
}

/* ============================================================
   NEW CHAT (Ctrl+K / +)
   ============================================================ */
function initNewChatButton() {
  const btn = $("#new-chat-btn");
  if (!btn) return;

  const startNewChat = () => {
    const chatTab = $('.nav-tab[data-tab="chat"]');
    if (chatTab && state.activeTab !== "chat") chatTab.click();
    const c = window.__composer;
    if (c) {
      c.input.value = "";
      autosizeComposer();
      updateSendState();
      c.input.focus();
    }
    const shell = $(".app-shell");
    if (shell && isMobile()) shell.classList.remove("sidebar-open");
  };

  btn.addEventListener("click", startNewChat);

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      startNewChat();
    }
    // '+' opens a new chat when not typing in a field.
    if (e.key === "+" && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) {
      e.preventDefault();
      startNewChat();
    }
  });
}

/* ============================================================
   QUICK STARTER CHIPS
   ============================================================ */
function initQuickPills() {
  const row = $("#quick-pills");
  if (!row) return;

  row.addEventListener("click", (e) => {
    const pill = e.target.closest(".quick-pill");
    if (!pill) return;

    const c = window.__composer;
    if (!c) return;

    if (state.messages.length) {
      // Continue an existing conversation directly.
      c.input.value = pill.dataset.query || "";
      autosizeComposer();
      updateSendState();
      c.node.requestSubmit();
      return;
    }

    c.input.value = pill.dataset.query || "";
    autosizeComposer();
    updateSendState();
    c.node.requestSubmit();
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

function entropyStrengthColor(bits, alpha) {
  if (bits < 40) return `rgba(244,63,94,${alpha})`;
  if (bits < 55) return `rgba(245,158,11,${alpha})`;
  if (bits < 75) return `rgba(56,189,248,${alpha})`;
  return `rgba(0,245,160,${alpha})`;
}

function entropyMeterPercent(bits) {
  return Math.min(100, Math.max(0, (bits / 100) * 100));
}

// NOTE: Intentionally NO 'input' or 'keyup' listeners on #password-field.
function updateLiveEntropyPreview() {
  const field = $("#password-field");
  if (!field) return;
  const pwd = field.value;
  const bits = shannonEntropy(pwd);
  const live = $("#entropy-live");
  const fill = $("#entropy-fill");
  if (live) live.textContent = `${bits.toFixed(2)} bits (${entropyStrengthLabel(bits)})`;
  if (fill) {
    fill.style.width = `${entropyMeterPercent(bits)}%`;
    fill.style.background = entropyStrengthColor(bits, 1);
  }
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
  const field = $("#password-field");
  const auditBtn = $("#audit-btn");
  const resultBlock = $("#password-result");
  const pwd = field ? field.value : "";

  if (!pwd) {
    resultBlock.innerHTML = `
      <div class="result-placeholder">
        <i data-lucide="alert-triangle" class="h-5 w-5" style="color:var(--warning)"></i>
        <p>Enter a candidate password first, then select <strong>Audit Password</strong>.</p>
      </div>`;
    refreshIcons(resultBlock);
    field.focus();
    return;
  }

  // 1) Instant client-side Shannon entropy (no network).
  const clientBits = shannonEntropy(pwd);

  // 2) Fetch backend analysis (explicit click — immune to keystroke 429s).
  const btnLabel = auditBtn.querySelector("span");
  const btnIcon = auditBtn.querySelector("[data-lucide]");
  const originalLabel = btnLabel ? btnLabel.textContent : "";
  auditBtn.disabled = true;
  if (btnIcon) {
    btnIcon.classList.add("hidden");
    btnIcon.insertAdjacentHTML(
      "afterend",
      '<span class="a-spinner" id="audit-spinner" aria-hidden="true"></span>'
    );
  }
  if (btnLabel) btnLabel.textContent = "Auditing…";

  resultBlock.innerHTML = `
    <div class="result-placeholder">
      <i data-lucide="loader-2" class="h-5 w-5" style="color:var(--cyan)"></i>
      <p>Computing entropy and generating a hardened enterprise variant…</p>
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
      <div class="result-placeholder is-error">
        <i data-lucide="alert-octagon" class="h-5 w-5"></i>
        <p><strong>Audit error:</strong> ${escapeHtml(err.message)}</p>
      </div>`;
    refreshIcons(resultBlock);
  } finally {
    const sp = $("#audit-spinner");
    if (sp) sp.remove();
    if (btnIcon) btnIcon.classList.remove("hidden");
    if (btnLabel) btnLabel.textContent = originalLabel;
    auditBtn.disabled = false;
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
    : "<li>No risky structural patterns detected</li>";

  const html = `
    <div class="entropy-compare">
      <div class="entropy-card ${originalClass}">
        <h4>ORIGINAL</h4>
        <div class="bits">${Number(audit.original_entropy_bits).toFixed(2)}</div>
        <div class="strength">${escapeHtml(audit.original_strength)} · ${audit.original_password.length} chars</div>
      </div>
      <div class="entropy-arrow" aria-hidden="true"><i data-lucide="arrow-right"></i></div>
      <div class="entropy-card ${hardenedClass}">
        <h4>HARDENED</h4>
        <div class="bits">${Number(audit.hardened_entropy_bits).toFixed(2)}</div>
        <div class="strength">${escapeHtml(audit.hardened_strength)} · +${Number(audit.entropy_gain_bits).toFixed(2)} bits</div>
      </div>
    </div>

    <div class="hardened-box">
      <span class="hardened-label"><i data-lucide="shield-check"></i>RECOMMENDED ENTERPRISE HARDENED PASSWORD</span>
      <div class="hardened-password" id="hardened-password">${escapeHtml(audit.hardened_password)}</div>
      <div class="hardened-actions">
        <button class="copy-btn" id="copy-hardened-btn">
          <i data-lucide="copy"></i><span>Copy</span>
        </button>
      </div>
    </div>

    <div class="audit-details">
      <span class="detail-title">Entropy Analysis</span>
      <div class="detail-row"><span>Client-side Shannon entropy (instant)</span><strong>${clientBits.toFixed(2)} bits</strong></div>
      <div class="detail-row"><span>Server-side effective entropy</span><strong>${Number(audit.original_entropy_bits).toFixed(2)} bits</strong></div>
      <div class="detail-row"><span>Entropy gain from hardening</span><strong class="good">+${Number(audit.entropy_gain_bits).toFixed(2)} bits</strong></div>
      <div class="detail-row"><span>RockYou breach corpus</span><strong class="${audit.in_rockyou ? "bad" : "good"}">${audit.in_rockyou ? "FOUND — rotate everywhere" : "Not found"}</strong></div>
      <div class="detail-row"><span>Offline crack · Argon2id (m=64MB t=3 p=4)</span><strong>${escapeHtml(audit.crack_time_offline_argon2id)}</strong></div>
      <div class="detail-row"><span>Offline crack · bcrypt (cost ${audit.bcrypt_cost})</span><strong>${escapeHtml(audit.crack_time_offline_bcrypt)}</strong></div>
    </div>

    <div class="audit-details">
      <span class="detail-title">Pattern Findings</span>
      <ul class="recommendation-list">${patterns}</ul>
    </div>

    <div class="audit-details">
      <span class="detail-title">Hardening Recommendations</span>
      <ul class="recommendation-list">${recs}</ul>
    </div>

    <div class="hash-guidance">
      <h4><i data-lucide="key-round"></i>STORAGE HASHING GUIDANCE</h4>
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
    const btn = $("#copy-hardened-btn");
    const span = btn.querySelector("span");
    let ok = false;
    try {
      await navigator.clipboard.writeText(hardened);
      ok = true;
    } catch (e) {
      try {
        const ta = document.createElement("textarea");
        ta.value = hardened;
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand("copy");
        document.body.removeChild(ta);
      } catch (e2) {
        ok = false;
      }
    }
    if (!span) return;
    const original = span.textContent;
    span.textContent = ok ? "Copied" : "Copy failed";
    setTimeout(() => (span.textContent = original), 1800);
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
        `<button class="filter-btn ${c === state.labs[lab].category ? "active" : ""}" data-lab="${lab}" data-category="${c}" type="button">${c}</button>`
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

  grid.innerHTML = `<div class="result-placeholder"><i data-lucide="loader-2" class="h-5 w-5" style="color:var(--cyan)"></i><p>Loading lab repository…</p></div>`;
  refreshIcons(grid);

  try {
    const url = `/api/scenarios?lab=${cfg.labParam}&category=${encodeURIComponent(state.labs[lab].category)}`;
    const res = await fetch(url);
    const data = await res.json();
    if (!data.success) throw new Error("Failed to load scenarios");

    state.labs[lab].scenarios = data.scenarios;
    state.labs[lab].loaded = true;
    if (count) count.textContent = `${data.count} lab${data.count === 1 ? "" : "s"} · ${data.active_category}`;
    renderScenarios(lab, data.scenarios);
  } catch (err) {
    if (count) count.textContent = "Unavailable";
    grid.innerHTML = `<div class="result-placeholder is-error"><i data-lucide="alert-octagon" class="h-5 w-5"></i><p>${escapeHtml(err.message)}</p></div>`;
    refreshIcons(grid);
  }
}

function renderScenarios(lab, scenarios) {
  const cfg = LAB_CONFIG[lab];
  const grid = $(`#${cfg.gridId}`);

  if (!scenarios || !scenarios.length) {
    grid.innerHTML = `<div class="result-placeholder"><i data-lucide="inbox" class="h-5 w-5" style="color:var(--faint)"></i><p>No labs in this category.</p></div>`;
    refreshIcons(grid);
    return;
  }

  grid.innerHTML = scenarios
    .map((sc) => {
      const options = sc.options
        .map(
          (opt, i) => `
            <button class="scenario-option" type="button" data-scenario="${sc.id}" data-index="${i}">
              <span class="opt-key">${String.fromCharCode(65 + i)}</span>
              <span class="opt-text">${escapeHtml(opt)}</span>
            </button>`
        )
        .join("");

      const hints = (sc.hints || [])
        .map((h) => `<li>${escapeHtml(h)}</li>`)
        .join("");

      return `
      <article class="scenario-card" id="card-${sc.id}">
        <div class="scenario-top">
          <span class="scenario-id">${escapeHtml(sc.id)}</span>
          <span class="scenario-difficulty ${difficultyClass(sc.difficulty)}">${escapeHtml(sc.difficulty)}</span>
        </div>
        <div class="scenario-category">${escapeHtml(sc.category)}</div>
        <h3 class="scenario-title">${escapeHtml(sc.title)}</h3>
        <p class="scenario-desc">${escapeHtml(sc.description)}</p>
        <pre class="telemetry-block">${escapeHtml(sc.telemetry)}</pre>
        <p class="scenario-question">${escapeHtml(sc.question)}</p>
        <div class="scenario-options">${options}</div>
        <div class="scenario-actions">
          <button class="hint-btn" type="button" data-hint="${sc.id}">
            <i data-lucide="lightbulb" class="h-ico"></i><span>Show Hint</span>
          </button>
          <button class="submit-btn" type="button" data-submit="${sc.id}">
            <i data-lucide="check" class="h-ico"></i><span>Submit Answer</span>
          </button>
        </div>
        <div class="hint-block" id="hint-${sc.id}">
          <span class="hint-title"><i data-lucide="lightbulb"></i>HINTS</span>
          <ol>${hints}</ol>
        </div>
        <div class="evaluation-result" id="eval-${sc.id}" aria-live="polite"></div>
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
    evalBox.innerHTML = `<span class="eval-badge"><i data-lucide="alert-triangle"></i>Select an answer option first.</span>`;
    refreshIcons(evalBox);
    return;
  }

  // Disable the submit button to prevent double-submission.
  btn.disabled = true;
  const btnSpan = btn.querySelector("span");
  const originalLabel = btnSpan ? btnSpan.textContent : "";
  if (btnSpan) btnSpan.textContent = "Evaluating…";

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
      b.disabled = true;
    });

    const iocs = (ev.iocs || []).length
      ? (ev.iocs || []).map((i) => `<span class="eval-chip">${escapeHtml(i)}</span>`).join("")
      : `<span class="eval-chip mitre">No IoCs recorded</span>`;
    const mitre = (ev.mitre_tactics || []).length
      ? (ev.mitre_tactics || []).map((m) => `<span class="eval-chip mitre">${escapeHtml(m)}</span>`).join("")
      : "";

    evalBox.className = `evaluation-result show ${ev.correct ? "correct" : "incorrect"}`;
    evalBox.innerHTML = `
      <span class="eval-badge"><i data-lucide="${ev.correct ? "check-circle-2" : "alert-triangle"}"></i>${escapeHtml(ev.badge)}</span>
      <span class="eval-explanation"><strong>Forensic breakdown (NIST SP 800-61r2 / SANS PICERL):</strong> ${escapeHtml(ev.explanation)}</span>
      <span class="detail-title">Indicators of Compromise</span>
      <span class="eval-chips">${iocs}</span>
      ${mitre ? `<span class="detail-title">MITRE ATT&amp;CK Tactics</span><span class="eval-chips">${mitre}</span>` : ""}
    `;
    refreshIcons(evalBox);
  } catch (err) {
    evalBox.className = "evaluation-result show incorrect";
    evalBox.innerHTML = `<span class="eval-badge"><i data-lucide="alert-octagon"></i>Evaluation error: ${escapeHtml(err.message)}</span>`;
    refreshIcons(evalBox);
  } finally {
    btn.disabled = false;
    if (btnSpan) btnSpan.textContent = originalLabel;
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
  container.innerHTML = `<div class="result-placeholder"><i data-lucide="loader-2" class="h-5 w-5" style="color:var(--cyan)"></i><p>Loading ${escapeHtml(tier)} reference matrix…</p></div>`;
  refreshIcons(container);

  try {
    const res = await fetch(`/api/cheatsheets/${tier}`);
    const data = await res.json();
    if (!data.success) throw new Error("Failed to load cheat sheet");
    renderCheatSheet(data.sheet);
  } catch (err) {
    container.innerHTML = `<div class="result-placeholder is-error"><i data-lucide="alert-octagon" class="h-5 w-5"></i><p>${escapeHtml(err.message)}</p></div>`;
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
          <div class="cheat-matrix-header"><i data-lucide="table-2"></i>${escapeHtml(matrix.title)}</div>
          <div class="cheat-table-scroll">
            <table class="cheat-table">
              <thead><tr>${headers}</tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      `;
    })
    .join("");
  refreshIcons(container);
}

/* ============================================================
   BOOTSTRAP
   ============================================================ */
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initTierSwitcher();
  initSidebar();
  initComposer();
  initQuickPills();
  initCodeCopyDelegation($("#chat-log"));
  initCodeCopyDelegation(document);
  initPasswordAudit();
  initFlushButton();
  initNewChatButton();
  initRecentList();
  updateSessionChip();
  updateChatMeta();
  placeComposer(false);

  // Initialize both scenario labs (filters + delegation).
  ["phishing", "soc"].forEach((lab) => {
    state.labs[lab].category = LAB_CONFIG[lab].defaultCategory;
    initLabFilters(lab);
  });
  initScenarioDelegation();

  initCheatTiers();
  loadCheatSheet(state.cheatTier);

  // Initialize Lucide icons across the static shell.
  refreshIcons();
});

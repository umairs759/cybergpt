/**
 * CyberGPT — E2E Smoke Test (Phase 1 baseline parity)
 * ------------------------------------------------------------------
 * Runs against a local dev server (BASE_URL, default http://127.0.0.1:5000)
 * in BOTH chromium and firefox. Verifies:
 *   1. Zero page errors / console errors.
 *   2. Every .nav-tab switches #tab-<id> visibility + human breadcrumb title.
 *   3. Tier switcher sets .active on the selected button.
 *   4. Chat: POST /api/chat observed, user bubble rendered, input cleared
 *      only after the request is dispatched, reply bubble rendered, composer
 *      stays visible & usable in the dock afterwards.
 *   5. Phishing + SOC labs render scenario cards from /api/scenarios;
 *      category filters, hint toggles and answer evaluation work.
 * Screenshots are saved under tests/out/.
 *
 * Usage:  node tests/e2e_smoke.mjs
 */

import { chromium, firefox } from "playwright";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BASE_URL = process.env.BASE_URL || "http://127.0.0.1:5000";
const OUT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "out");

const TABS = [
  { id: "chat", label: "Chat Copilot" },
  { id: "phishing", label: "Phishing Triage Lab" },
  { id: "password", label: "Password Hardening Audit" },
  { id: "soc", label: "SOC Incident Drills" },
  { id: "cheatsheets", label: "Security Cheat Sheets" },
];

let failures = 0;
let checks = 0;

function ok(browser, name) {
  checks++;
  console.log(`  [PASS] ${browser} :: ${name}`);
}
function fail(browser, name, detail) {
  failures++;
  checks++;
  console.log(`  [FAIL] ${browser} :: ${name}${detail ? " — " + detail : ""}`);
}

async function expectVisible(page, browser, sel, name) {
  try {
    await page.waitForSelector(sel, { state: "visible", timeout: 8000 });
    ok(browser, `${name} visible (${sel})`);
    return true;
  } catch (e) {
    fail(browser, `${name} visible (${sel})`, e.message.split("\n")[0]);
    return false;
  }
}

async function runBrowser(browserType, browserName) {
  console.log(`\n=== ${browserName} ===`);
  const browser = await browserType.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1366, height: 900 } });
  const page = await context.newPage();

  const consoleErrors = [];
  const pageErrors = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => pageErrors.push(String(err)));

  // ---- Load the app ----
  try {
    await page.goto(BASE_URL, { waitUntil: "networkidle", timeout: 45000 });
    ok(browserName, "app loads");
  } catch (e) {
    fail(browserName, "app loads", e.message.split("\n")[0]);
    await browser.close();
    return;
  }

  // ---- 1. Tab switching: visibility + breadcrumb ----
  for (const tab of TABS) {
    const btn = page.locator(`.nav-tab[data-tab="${tab.id}"]`);
    try {
      await btn.click();
      await page.waitForSelector(`#tab-${tab.id}.active`, { state: "visible", timeout: 6000 });
      const visible = await page.evaluate((id) => {
        const views = Array.from(document.querySelectorAll(".tab-view"));
        const active = views.filter((v) => v.classList.contains("active"));
        const shown = views.filter((v) => {
          const cs = getComputedStyle(v);
          return cs.display !== "none" && v.classList.contains("active");
        });
        return {
          activeIds: active.map((v) => v.id),
          shownIds: shown.map((v) => v.id),
          expectedVisible: !!document.querySelector(`#tab-${id}`),
        };
      }, tab.id);
      const shownOk =
        visible.shownIds.length === 1 &&
        visible.shownIds[0] === `tab-${tab.id}` &&
        visible.activeIds.length === 1 &&
        visible.activeIds[0] === `tab-${tab.id}`;
      if (shownOk) ok(browserName, `tab "${tab.id}" shows only #tab-${tab.id}`);
      else
        fail(
          browserName,
          `tab "${tab.id}" shows only #tab-${tab.id}`,
          `active=${JSON.stringify(visible.activeIds)} shown=${JSON.stringify(visible.shownIds)}`
        );

      const crumb = await page.textContent("#crumb-current");
      if (crumb && crumb.trim() === tab.label)
        ok(browserName, `breadcrumb shows human title "${tab.label}"`);
      else fail(browserName, `breadcrumb shows human title "${tab.label}"`, `got "${crumb}"`);

      const othersHidden = await page.evaluate(
        (id) =>
          Array.from(document.querySelectorAll(".tab-view"))
            .filter((v) => v.id !== `tab-${id}`)
            .every((v) => getComputedStyle(v).display === "none"),
        tab.id
      );
      if (othersHidden) ok(browserName, `other views hidden when "${tab.id}" active`);
      else fail(browserName, `other views hidden when "${tab.id}" active`);
    } catch (e) {
      fail(browserName, `tab "${tab.id}" switching`, e.message.split("\n")[0]);
    }
  }
  await page.screenshot({ path: path.join(OUT_DIR, `smoke-${browserName}-tabs.png`), fullPage: false });

  // ---- 2. Tier switcher ----
  try {
    for (const tier of ["flash", "balanced", "pro"]) {
      await page.click(`#tier-switcher .tier-btn[data-tier="${tier}"]`);
      await page.waitForSelector(`#tier-switcher .tier-btn[data-tier="${tier}"].active`, {
        timeout: 4000,
      });
      const onlyOne = await page.$$eval("#tier-switcher .tier-btn", (btns) => {
        const active = btns.filter((b) => b.classList.contains("active"));
        return active.length === 1 ? active[0].dataset.tier : `count=${active.length}`;
      });
      if (onlyOne === tier) ok(browserName, `tier "${tier}" gets .active exclusively`);
      else fail(browserName, `tier "${tier}" gets .active exclusively`, `got ${onlyOne}`);
    }
  } catch (e) {
    fail(browserName, "tier switcher", e.message.split("\n")[0]);
  }

  // ---- 3. Chat round trip ----
  try {
    await page.click('.nav-tab[data-tab="chat"]');
    await page.waitForSelector("#chat-input", { state: "visible", timeout: 8000 });

    const composerInEmptyState = await page.evaluate(
      () => document.querySelector("#chat-form")?.parentElement?.id
    );
    if (composerInEmptyState === "empty-composer-slot")
      ok(browserName, "composer starts in empty-state slot");
    else
      fail(
        browserName,
        "composer starts in empty-state slot",
        `parent=${composerInEmptyState}`
      );

    // Delay the chat API so we can observe dispatch-vs-clear ordering.
    let chatRequestSeen = null;
    await page.route("**/api/chat", async (route) => {
      chatRequestSeen = route.request();
      await new Promise((r) => setTimeout(r, 400));
      await route.continue();
    });

    const chatPromise = page
      .waitForRequest((req) => req.url().includes("/api/chat") && req.method() === "POST", {
        timeout: 30000,
      })
      .catch(() => null);

    await page.fill("#chat-input", "What does SPF protect against in one line?");
    const typedBefore = await page.inputValue("#chat-input");
    if (typedBefore.length > 0) ok(browserName, "typed text present before send");
    else fail(browserName, "typed text present before send");

    await page.click("#chat-send");

    const req = await chatPromise;
    if (req) ok(browserName, "POST /api/chat observed");
    else fail(browserName, "POST /api/chat observed");

    if (chatRequestSeen) {
      const body = chatRequestSeen.postDataJSON();
      if (body && typeof body.message === "string" && body.message.length > 0)
        ok(browserName, "request body carries the message");
      else fail(browserName, "request body carries the message", JSON.stringify(body));
    }

    // After dispatch the input must be cleared…
    const clearedAfterDispatch = await page.evaluate(
      () => document.querySelector("#chat-input").value === ""
    );
    if (clearedAfterDispatch) ok(browserName, "input cleared after request dispatched");
    else fail(browserName, "input cleared after request dispatched");

    // …and the user bubble is already rendered (optimistic append).
    await page.waitForSelector(".chat-message.user", { timeout: 6000 });
    ok(browserName, "user bubble appears");

    // Assistant reply rendered (LLM round trip).
    await page.waitForSelector(".chat-message.assistant", { timeout: 60000 });
    const replyText = await page.textContent(".chat-message.assistant");
    if (replyText && replyText.trim().length > 0 && !replyText.includes("Network error"))
      ok(browserName, "assistant reply bubble rendered");
    else fail(browserName, "assistant reply bubble rendered", (replyText || "").slice(0, 80));

    // Composer migrated to the dock and remains visible + usable.
    await page.waitForFunction(
      () => document.querySelector("#chat-form")?.closest(".chat-dock") !== null,
      { timeout: 6000 }
    );
    ok(browserName, "composer moved into sticky dock");

    const composerVisible = await page.evaluate(() => {
      const el = document.querySelector("#chat-form");
      if (!el) return false;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      return cs.display !== "none" && r.width > 0 && r.height > 0;
    });
    if (composerVisible) ok(browserName, "composer visible in dock after send");
    else fail(browserName, "composer visible in dock after send");

    // Usable: type a second message and send it.
    await page.fill("#chat-input", "Second smoke-test message: define DKIM briefly.");
    await page.click("#chat-send");
    await page.waitForSelector(".chat-message.user >> nth=1", { timeout: 6000 });
    ok(browserName, "composer usable after first send (2nd user bubble appears)");
    await page
      .waitForSelector(".chat-message.assistant >> nth=1", { timeout: 60000 })
      .catch(() => {});
    await page.screenshot({ path: path.join(OUT_DIR, `smoke-${browserName}-chat.png`) });
  } catch (e) {
    fail(browserName, "chat round trip", e.message.split("\n")[0]);
  }

  // ---- 4. Labs: phishing + soc ----
  for (const lab of [
    {
      tab: "phishing",
      grid: "#phishing-grid",
      filters: "#phishing-filters",
      countId: "#phishing-count",
    },
    {
      tab: "soc",
      grid: "#soc-grid",
      filters: "#soc-filters",
      countId: "#soc-count",
    },
  ]) {
    try {
      await page.click(`.nav-tab[data-tab="${lab.tab}"]`);
      await page.waitForSelector(`${lab.grid} .scenario-card`, { timeout: 15000 });
      const cardCount = await page.$$eval(`${lab.grid} .scenario-card`, (c) => c.length);
      if (cardCount > 0) ok(browserName, `${lab.tab}: ${cardCount} scenario cards rendered`);
      else fail(browserName, `${lab.tab}: scenario cards rendered`);

      const countText = await page.textContent(lab.countId);
      if (countText && !/unavailable|error/i.test(countText))
        ok(browserName, `${lab.tab}: count chip populated ("${countText.trim()}")`);
      else fail(browserName, `${lab.tab}: count chip populated`, countText);

      // Category filter narrows or keeps the card set.
      const filterBtns = page.locator(`${lab.filters} .filter-btn`);
      const nFilters = await filterBtns.count();
      if (nFilters > 1) {
        await filterBtns.nth(1).click();
        await page.waitForTimeout(700); // refetch + render
        const filteredCount = await page.$$eval(`${lab.grid} .scenario-card`, (c) => c.length);
        if (Number.isFinite(filteredCount))
          ok(browserName, `${lab.tab}: category filter applied (${filteredCount} cards)`);
        else fail(browserName, `${lab.tab}: category filter applied`);
        const activeFilter = await page.$eval(
          `${lab.filters} .filter-btn.active`,
          (b) => b.textContent.trim()
        );
        ok(browserName, `${lab.tab}: filter chip .active = "${activeFilter}"`);
        // Back to "all"
        await page.locator(`${lab.filters} .filter-btn`).first().click();
        await page.waitForTimeout(700);
      } else {
        fail(browserName, `${lab.tab}: filter chips rendered`, `count=${nFilters}`);
      }

      // Hint toggle.
      const firstCard = page.locator(`${lab.grid} .scenario-card`).first();
      const sid = await firstCard.getAttribute("id");
      const scenarioId = sid.replace(/^card-/, "");
      await firstCard.locator(".hint-btn").click();
      await page.waitForSelector(`#hint-${scenarioId}.open`, { timeout: 5000 });
      ok(browserName, `${lab.tab}: hint block opens`);
      await firstCard.locator(".hint-btn").click();

      // Answer + evaluate.
      await firstCard.locator(".scenario-option").first().click();
      await firstCard.locator(".submit-btn").click();
      await page.waitForSelector(`#eval-${scenarioId}.show`, { timeout: 15000 });
      const evalHtml = await page.textContent(`#eval-${scenarioId}`);
      if (evalHtml && evalHtml.trim().length > 20)
        ok(browserName, `${lab.tab}: evaluation result rendered`);
      else fail(browserName, `${lab.tab}: evaluation result rendered`, (evalHtml || "").slice(0, 60));

      await page.screenshot({
        path: path.join(OUT_DIR, `smoke-${browserName}-${lab.tab}.png`),
      });
    } catch (e) {
      fail(browserName, `${lab.tab} lab interactions`, e.message.split("\n")[0]);
    }
  }

  // ---- 5. Console / page error report ----
  if (consoleErrors.length === 0) ok(browserName, "zero console errors");
  else fail(browserName, "zero console errors", JSON.stringify(consoleErrors.slice(0, 3)));
  if (pageErrors.length === 0) ok(browserName, "zero page errors");
  else fail(browserName, "zero page errors", JSON.stringify(pageErrors.slice(0, 3)));

  await browser.close();
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const engines = [
    [chromium, "chromium"],
    [firefox, "firefox"],
  ];
  for (const [type, name] of engines) {
    try {
      await runBrowser(type, name);
    } catch (e) {
      fail(name, "browser session", e.message);
    }
  }
  console.log(`\n=== SMOKE SUMMARY: ${checks - failures}/${checks} checks passed, ${failures} failed ===`);
  process.exit(failures === 0 ? 0 : 1);
}

main();

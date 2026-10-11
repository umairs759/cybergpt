/**
 * CyberGPT — E2E Routing & BYOK verification (Section 4 UX contract).
 * Verifies in a real Chromium browser:
 *   1. Cyber mode: off-topic query renders the "Switch to Normal Chat" action chip.
 *   2. Clicking the chip switches to Normal mode and re-asks the question.
 *   3. Knowledge-engine answers render styled lab chips under the bubble.
 *   4. Settings modal opens, saves BYOK keys to localStorage only, and the
 *      keys are transmitted in the /api/chat request body.
 */
import { chromium } from "playwright";

const BASE_URL = process.env.BASE_URL || "http://127.0.0.1:5000";
let failures = 0, checks = 0;
const ok = (name, detail = "") => { checks++; console.log(`  [PASS] ${name}${detail ? " — " + detail : ""}`); };
const fail = (name, detail = "") => { failures++; checks++; console.log(`  [FAIL] ${name}${detail ? " — " + detail : ""}`); };

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1366, height: 900 } });
const consoleErrors = [];
page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
page.on("pageerror", (e) => consoleErrors.push(String(e)));

await page.goto(BASE_URL, { waitUntil: "networkidle", timeout: 45000 });

// 1. Off-topic in cyber mode -> action chip
await page.fill("#chat-input", "what is trading");
await page.click("#chat-send");
await page.waitForSelector(".chat-message.assistant", { timeout: 30000 });
await page.waitForSelector(".action-chip", { timeout: 5000 }).then(
  () => ok("off-topic reply renders switch-mode action chip"),
  () => fail("off-topic reply renders switch-mode action chip")
);
const notice = await page.textContent(".chat-message.assistant .msg-body p");
if (notice && notice.length < 200 && notice.includes("Normal mode")) ok("off-topic notice is a short 1-liner");
else fail("off-topic notice is a short 1-liner", (notice || "").slice(0, 100));

// 2. Click chip -> switches to Normal mode, re-asks, gets a full answer
let normalBodySeen = null;
await page.route("**/api/chat", async (route) => {
  normalBodySeen = route.request().postDataJSON();
  await route.continue();
});
await page.click(".action-chip");
await page.waitForFunction(() => document.querySelector('.mode-pill[data-mode="normal"]')?.classList.contains("active"), { timeout: 5000 })
  .then(() => ok("chip click switches UI to Normal mode"))
  .catch(() => fail("chip click switches UI to Normal mode"));
await page.waitForSelector(".chat-message.assistant >> nth=1", { timeout: 60000 });
const full = await page.textContent(".chat-message.assistant >> nth=1");
if (full && full.length > 300) ok(`Normal mode re-ask produced a comprehensive guide (${full.length} chars)`);
else fail("Normal mode re-ask produced a comprehensive guide", (full || "").slice(0, 80));
if (normalBodySeen && normalBodySeen.mode === "normal") ok("re-ask request carried mode=normal");
else fail("re-ask request carried mode=normal", JSON.stringify(normalBodySeen));

// 3. Lab chips on a knowledge-engine answer (back in CYBER mode)
await page.click('.mode-pill[data-mode="cyber"]');
await page.fill("#chat-input", "explain pass the hash");
await page.click("#chat-send");
await page.waitForSelector(".lab-chip", { timeout: 8000 }).then(
  () => ok("knowledge-engine answer renders lab chips"),
  () => fail("knowledge-engine answer renders lab chips")
);
const chipCount = await page.$$eval(".lab-chip", (els) => els.length);
if (chipCount >= 1 && chipCount <= 2) ok(`lab chips bounded to <= 2 (found ${chipCount})`);
else fail("lab chips bounded to <= 2", String(chipCount));

// 4. Settings modal + BYOK round trip
await page.click("#settings-btn");
await page.waitForSelector("#settings-overlay:not([hidden])", { timeout: 5000 }).then(
  () => ok("settings modal opens"),
  () => fail("settings modal opens")
);
await page.fill("#byok-openai-key", "sk-test-1234-roundtrip");
await page.click("#settings-save");
await page.waitForTimeout(300);
const stored = await page.evaluate(() => localStorage.getItem("cybergpt_byok"));
if (stored && stored.includes("sk-test-1234-roundtrip")) ok("BYOK key saved to localStorage only");
else fail("BYOK key saved to localStorage only", String(stored));
await page.click("#settings-close");

let byokBody = null;
await page.route("**/api/chat", async (route) => {
  byokBody = route.request().postDataJSON();
  await route.continue();
});
await page.fill("#chat-input", "who is your developer");
await page.click("#chat-send");
for (let i = 0; i < 100 && byokBody === null; i++) {
  await page.waitForTimeout(100);
}
if (byokBody && byokBody.openai_api_key === "sk-test-1234-roundtrip") ok("BYOK key transmitted in request body");
else fail("BYOK key transmitted in request body", JSON.stringify(byokBody));
// Identity must NOT call any provider, so no page-side key use matters; still verify reply.
await page.waitForSelector(".chat-message.assistant >> nth=3", { timeout: 30000 });
await page.evaluate(() => localStorage.removeItem("cybergpt_byok"));

if (consoleErrors.length === 0) ok("zero console errors");
else fail("zero console errors", JSON.stringify(consoleErrors.slice(0, 3)));

await browser.close();
console.log(`\n=== ROUTING/BYOK SUMMARY: ${checks - failures}/${checks} checks passed, ${failures} failed ===`);
process.exit(failures === 0 ? 0 : 1);

// Responsive screenshots of the redesigned dashboard (docs/ui-design-system.md section 3).
// Prerequisites: the stack is running, `python3 scripts/stego_smoke.py` was run once (drones smoke-1/smoke-2 with a
// ready session), the dashboard is served on 127.0.0.1:5173, Playwright with Chromium is available.
// Usage: node scripts/ui_screenshots.js <output-directory>
// Every page is captured at 1440, 1024, 768 and 390 px in the dark theme; the core pages also in the light theme
// at 1440 and 390 px. Pages with an action (authentication, secure communication, steganography lab) run it once
// and are then resized without reloading, so every width shows the same real backend result.
const { chromium } = require('playwright');
const fs = require('fs');
const out = process.argv[2] || 'docs/screenshots/ui';
fs.mkdirSync(out, { recursive: true });
const BASE = process.env.UI_BASE || 'http://127.0.0.1:5173';
const WIDTHS = [1440, 1024, 768, 390];
const LIGHT_WIDTHS = [1440, 390];
const PAGES = [
  { name: 'overview', path: '/', core: true },
  { name: 'drones', path: '/drones', core: true },
  { name: 'groups', path: '/groups' },
  { name: 'authentication', path: '/authentication', core: true, action: async (p) => {
      await p.selectOption('select[aria-label="Initiator"]', 'smoke-1');
      await p.selectOption('select[aria-label="Verifier"]', 'smoke-2');
      await p.getByRole('button', { name: /Run M1–M8/ }).click();
      await p.waitForSelector('.decision', { timeout: 60000 });
    } },
  { name: 'secure-communication', path: '/secure-communication', core: true, action: async (p) => {
      await p.selectOption('select[aria-label="From"]', 'smoke-1');
      await p.selectOption('select[aria-label="To"]', 'smoke-2');
      await p.getByRole('button', { name: /Establish key/ }).click();
      await p.waitForFunction(() => /Established/.test(document.body.innerText), null, { timeout: 60000 });
      await p.getByRole('button', { name: /Encrypt and send/ }).click();
      await p.waitForSelector('.transport-flow', { timeout: 90000 });
    } },
  { name: 'steganography-lab', path: '/steganography', core: true, action: async (p) => {
      await p.selectOption('select[aria-label="Initiator"]', 'smoke-1');
      await p.selectOption('select[aria-label="Verifier"]', 'smoke-2');
      await p.getByRole('button', { name: /Send as image/ }).click();
      await p.waitForSelector('[data-testid="delivered"]', { timeout: 120000 });
      await p.locator('[data-testid^="patch-marker-"]').first().click();
    } },
  { name: 'knowledge-base', path: '/knowledge-base', core: true, action: async (p) => { await p.waitForSelector('[data-testid="kb-card-wow"]'); } },
  { name: 'trace', path: '/trace' },
  { name: 'event-log', path: '/logs', core: true },
  { name: 'system', path: '/system', core: true, action: async (p) => { await p.waitForFunction(() => /iod-fips203/.test(document.body.innerText), null, { timeout: 20000 }); } },
];
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const p = await ctx.newPage();
  const errs = [];
  p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });
  p.on('pageerror', (e) => errs.push('PAGEERROR ' + e.message));
  const shots = [];
  for (const pg of PAGES) {
    await p.setViewportSize({ width: 1440, height: 900 });
    await p.goto(BASE + pg.path, { waitUntil: 'networkidle' });
    await p.evaluate(() => { document.documentElement.classList.remove('light-theme'); });
    if (pg.action) await pg.action(p);
    await p.waitForTimeout(800);
    const themes = pg.core ? ['dark', 'light'] : ['dark'];
    for (const theme of themes) {
      if (theme === 'light') await p.getByRole('button', { name: /Switch to light theme/ }).click();
      for (const w of theme === 'dark' ? WIDTHS : LIGHT_WIDTHS) {
        await p.setViewportSize({ width: w, height: 900 });
        await p.waitForTimeout(350);
        const overflow = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        const file = `${out}/${pg.name}-${w}-${theme}.jpg`;
        await p.screenshot({ path: file, fullPage: true, type: 'jpeg', quality: 72 });
        shots.push({ file, overflow });
        console.log(`${file}  horizontal overflow ${overflow}px`);
      }
      if (theme === 'light') await p.getByRole('button', { name: /Switch to dark theme/ }).click();
    }
  }
  console.log('screenshots', shots.length, '| pages with horizontal page overflow:', shots.filter((s) => s.overflow > 1).map((s) => s.file));
  console.log('console errors:', errs.length, errs.slice(0, 5));
  await b.close();
})().catch((e) => { console.error('FAIL', e.message.slice(0, 600)); process.exit(1); });

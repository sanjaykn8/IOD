// Manual, reproducible browser check of the patch-wise Stego Lab, the Knowledge Base / Retrieval Monitor
// and the Algorithm Learning tab (not part of the automated suites: web-ui has no browser test runner).
// Prerequisites: the stack is running (scripts/*/run_demo.*), `python3 scripts/stego_smoke.py` was run once
// (it creates drones smoke-1/smoke-2 with a ready session), the dashboard is served on 127.0.0.1:5173, and
// Playwright with Chromium is installed (`npm i -D playwright && npx playwright install chromium`).
// Usage: node scripts/ui_check.js <output-directory-for-screenshots>
const { chromium } = require('playwright');
const out = process.argv[2];
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1500, height: 1000 }, deviceScaleFactor: 1 });
  const p = await ctx.newPage();
  const errs = [];
  p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
  p.on('pageerror', e => errs.push('PAGEERROR ' + e.message));
  await p.goto('http://127.0.0.1:5173/steganography', { waitUntil: 'networkidle' });
  await p.selectOption('select[aria-label="Drone D1"]', 'smoke-1');
  await p.selectOption('select[aria-label="Drone D2"]', 'smoke-2');
  await p.fill('textarea[aria-label="Message payload"]', 'UI check: patch-wise transport, both directions verified. ' + 'x'.repeat(260));
  // plan preview
  await p.getByRole('button', { name: /Preview plan/ }).click();
  await p.waitForSelector('[data-testid^="patch-row-"]', { timeout: 60000 });
  console.log('preview rows', await p.locator('[data-testid^="patch-row-"]').count(), 'markers', await p.locator('[data-testid^="patch-marker-"]').count());
  // send
  await p.getByRole('button', { name: /Send as image/ }).click();
  await p.waitForSelector('[data-testid="delivered"]', { timeout: 90000 });
  console.log('delivered:', (await p.locator('[data-testid="delivered"] pre').innerText()).slice(0, 60));
  console.log('stages ok', await p.locator('[data-testid="stage-ok"]').count(), 'failed', await p.locator('[data-testid="stage-failed"]').count(), 'none', await p.locator('[data-testid="stage-none"]').count());
  const rows = await p.locator('[data-testid^="patch-row-"]').count();
  console.log('patch rows', rows, 'kb cands', await p.locator('[data-testid^="kb-cand-"]').count());
  // click another marker
  const markers = p.locator('[data-testid^="patch-marker-"]');
  await markers.nth(Math.min(2, (await markers.count()) - 1)).click();
  console.log('inspector chip:', (await p.locator('[data-testid="patch-inspector"] .stego-chips').first().innerText()).replace(/\n/g, ' | ').slice(0, 160));
  const body = (await p.locator('main').innerText()).toLowerCase();
  for (const w of ['priority class', 'rag', 'manual override (controlled', 'explanation (simulated']) console.log('contains "' + w + '":', body.includes(w));
  await p.screenshot({ path: out + '/lab.png', fullPage: true });
  // events
  await p.locator('[data-testid="event-row"]').first().click();
  console.log('event detail rows', await p.locator('[data-testid="event-detail"] tbody tr').count());
  // D2->D1
  await p.selectOption('select[aria-label="Direction"]', 'D2_D1');
  await p.getByRole('button', { name: /Send as image/ }).click();
  await p.waitForFunction(() => { const e = document.querySelector('[data-testid="delivered"] span'); return e && /D1/.test(e.textContent || ''); }, null, { timeout: 90000 });
  console.log('D2->D1 delivered header:', await p.locator('[data-testid="delivered"] span').innerText());
  // KB page
  await p.goto('http://127.0.0.1:5173/knowledge-base', { waitUntil: 'networkidle' });
  await p.waitForSelector('[data-testid="kb-card-wow"]');
  await p.locator('[data-testid="kb-card-hugo"]').click();
  console.log('kb entry:', (await p.locator('[data-testid="kb-entry-detail"]').innerText()).slice(0, 220).replace(/\n/g, ' | '));
  await p.selectOption('select[aria-label="Event"]', { index: 1 });
  console.log('monitor rows', await p.locator('[data-testid="monitor-row"]').count());
  await p.getByRole('button', { name: /Run retrieval/ }).click();
  await p.waitForSelector('[data-testid^="patch-row-"]', { timeout: 60000 });
  await p.screenshot({ path: out + '/kb.png', fullPage: true });
  console.log('nav:', (await p.locator('nav.side-nav').innerText()).replace(/\n/g, ' | '));
  // old route gone
  const r = await p.goto('http://127.0.0.1:5173/rag');
  console.log('/rag status', r.status());
  // learning
  await p.goto('http://127.0.0.1:5173/steganography?view=learn', { waitUntil: 'networkidle' });
  await p.getByRole('tab', { name: /Compare all ten/ }).click();
  await p.getByRole('button', { name: /Compare all ten/ }).click();
  await p.waitForSelector('[data-testid="learn-patch-section"]', { timeout: 120000 });
  console.log('learn rows', await p.locator('[data-testid^="learn-cmp-"]').count(), 'survey', await p.locator('[data-testid^="learn-survey-"]').count());
  await p.screenshot({ path: out + '/learn.png', fullPage: true });
  console.log('console errors:', errs.length, errs.slice(0, 5));
  await b.close();
})().catch(e => { console.error('FAIL', e.message.slice(0, 600)); process.exit(1); });

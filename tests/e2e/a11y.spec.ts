import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. The teaching flows are already gated on browser
 * behaviour; this gates the same shipped bundle on accessibility. Scans the
 * full page with every <details> expanded, in the configured dark theme.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function openAllDetails(page: Page): Promise<void> {
	await page.evaluate(() => {
		for (const details of document.querySelectorAll('details')) {
			details.open = true;
		}
	});
}

async function scan(page: Page): Promise<void> {
	const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
	const summary = results.violations.map((v) => ({
		id: v.id,
		impact: v.impact,
		help: v.help,
		nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
	}));
	expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
	await page.goto('./');
	await openAllDetails(page);
	await scan(page);
});


// The sequence diagram, exchange-hash binding lab, and the "what actually
// catches a MITM" lab only render after a handshake runs — scan them too, in
// the configured dark theme.
async function connectAndExercise(page: Page): Promise<void> {
	await page.goto('./');
	await page.click('#start-btn');
	await page.click('.mode-pill[data-mode="accept-new"]');
	await page.click('#connect-btn');
	await expect(page.locator('.seq-diagram').first()).toBeVisible();
	// Mutate a hash-lab tile so the FAIL verdict styling is on screen.
	await page.locator('.hlab-swap').first().click();
	await expect(page.locator('.hlab-verdict--fail')).toBeVisible();
	// Run the MITM lab at the pin level so the "rejected" (good) warning styling
	// is on screen alongside the fingerprint comparison block.
	await page.locator('.auth-lab > summary').click();
	await page.check('#auth-level-pin');
	await page.click('#auth-run');
	await expect(page.locator('.auth-lab-out .ssh-warning')).toBeVisible();
}

test('no WCAG A/AA violations in post-connect exhibits (dark)', async ({ page }) => {
	await connectAndExercise(page);
	await openAllDetails(page);
	await scan(page);
});

test('sequence labels retain contrast during their staggered entrance', async ({ page }) => {
  await connectAndExercise(page);
  await openAllDetails(page);
  // Sample each actual shipped animation during its entrance, rather than
  // waiting for the low-contrast fade to finish or disabling motion in the gate.
  await page.evaluate(() => {
    for (const row of document.querySelectorAll('.seq-row')) {
      for (const animation of row.getAnimations()) {
        animation.pause();
        animation.currentTime = Number(animation.effect!.getTiming().delay) + 40;
      }
    }
  });
  await expect(page.locator('.seq-msg--left').first()).toBeVisible();
  await scan(page);

  // A genuine contrast regression must still fail the same axe rule.
  await page.locator('.seq-msg--left').first().evaluate(el => { el.style.color = '#444444'; });
  const negative = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(negative.violations.some(v => v.id === 'color-contrast' &&
    v.nodes.some(n => n.target.includes('.seq-msg--left')))).toBe(true);
});



for (const width of [1280, 380]) {
  test(`restricted changed-key continuation remains accessible at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('./');
    await page.click('#start-btn');
    await page.click('.mode-pill[data-mode="accept-new"]');
    await page.click('#connect-btn');
    await expect(page.locator('.pin-fp')).toBeVisible();
    await page.click('#restart-btn');
    await expect(page.locator('#restart-btn')).toBeEnabled();
    await page.click('.mode-pill[data-mode="no"]');
    await page.click('#connect-btn');
    await expect(page.locator('#connect-result .handshake-decision')).toHaveText('HOST KEY CHANGED — restricted continuation');
    await expect(page.locator('#connect-result .ssh-warning')).toContainText('not a successful login');
    await scan(page);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

for (const width of [320, 380, 1280]) {
  test(`ordinary and recovery handshakes reflow with complete fingerprints at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('./');
    await page.click('#start-btn');
    await page.click('.mode-pill[data-mode="accept-new"]');
    await page.click('#connect-btn');
    const decision = page.locator('#connect-result .handshake-decision');
    const details = page.locator('#connect-result .seq-note-detail').last();
    const checkReflow = async () => {
      const geometry = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, viewport: innerWidth }));
      expect(geometry.document).toBeLessThanOrEqual(geometry.viewport + 1);
      await scan(page);
    };
    await expect(decision).toContainText('TOFU');
    const oldPin = (await page.locator('.pin-fp').first().innerText()).trim();
    await expect(details).toContainText(oldPin);
    await checkReflow();
    await page.click('#restart-btn');
    await expect(page.locator('#restart-btn')).toBeEnabled();
    await page.click('#connect-btn');
    await expect(decision).toHaveText('HOST KEY CHANGED — rejected');
    await expect(page.locator('.pin-fp').first()).toHaveText(oldPin);
    await expect(details).toContainText(oldPin);
    await checkReflow();
    await page.click('#forget-btn');
    await expect(page.locator('.pin-fp')).toHaveCount(0);
    await page.click('#connect-btn');
    await expect(decision).toContainText('TOFU');
    const newPin = (await page.locator('.pin-fp').first().innerText()).trim();
    expect(newPin).not.toBe(oldPin);
    await expect(details).toContainText(newPin);
    await checkReflow();
  });
}

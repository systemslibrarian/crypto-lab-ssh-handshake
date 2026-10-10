import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. The teaching flows are already gated on browser
 * behaviour; this gates the same shipped bundle on accessibility. Scans the
 * full page with every <details> expanded, in both the dark (default) and
 * light themes.
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
// both themes.
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

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

test('no WCAG A/AA violations in light theme', async ({ page }) => {
	await page.goto('./');
	await page.locator('#cl-theme-toggle').click();
	await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
	await openAllDetails(page);
	await scan(page);
});

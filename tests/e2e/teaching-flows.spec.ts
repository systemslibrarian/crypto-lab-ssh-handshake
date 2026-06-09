import { test, expect, type Page } from '@playwright/test';

// Browser-level coverage for the teaching paths users actually walk. These
// validate the visible behaviour, not just the engine — regressions in the
// teaching surface matter as much as regressions in the cryptographic core.

async function startServer(page: Page): Promise<void> {
	await page.goto('./');
	await page.click('#start-btn');
	await expect(page.locator('.host-card-name')).toBeVisible();
}

test.describe('first-contact prompt (ask mode)', () => {
	test('accept (yes) pins the fingerprint and lands a TOFU decision', async ({ page }) => {
		await startServer(page);
		await page.click('#connect-btn');
		await expect(page.locator('#pending-accept')).toBeVisible();
		const fp = await page.locator('.ssh-warning--pending code').first().textContent();
		expect(fp).toMatch(/^SHA256:/);
		await page.click('#pending-accept');
		await expect(page.locator('.handshake-decision')).toContainText('TOFU');
		await expect(page.locator('.pin-fp')).toContainText('SHA256:');
	});

	test('reject (no) leaves known_hosts empty', async ({ page }) => {
		await startServer(page);
		await page.click('#connect-btn');
		await page.click('#pending-reject');
		await expect(page.locator('.handshake-decision')).toContainText('Unknown');
		await expect(page.locator('.pin-fp')).toHaveCount(0);
	});

	test('verify out of band pins after confirmation', async ({ page }) => {
		await startServer(page);
		await page.click('#connect-btn');
		await page.click('#pending-verify');
		await expect(page.locator('.handshake-decision')).toContainText('TOFU');
	});
});

test.describe('StrictHostKeyChecking modes', () => {
	test('yes refuses unknown hosts without prompting', async ({ page }) => {
		await startServer(page);
		await page.click('.mode-pill[data-mode="yes"]');
		await page.click('#connect-btn');
		await expect(page.locator('.handshake-decision')).toContainText('Unknown');
		await expect(page.locator('#pending-accept')).toHaveCount(0);
	});

	test('accept-new silently pins on first contact', async ({ page }) => {
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		await expect(page.locator('.handshake-decision')).toContainText('TOFU');
		await expect(page.locator('#pending-accept')).toHaveCount(0);
	});
});

test.describe('SSHFP', () => {
	test('with DNSSEC: Verify-via-SSHFP appears and accepts', async ({ page }) => {
		await startServer(page);
		// publish with DNSSEC (default checkbox state)
		await page.click('#sshfp-publish');
		await expect(page.locator('text=DNSSEC ✓ trustworthy channel')).toBeVisible();
		await page.click('#connect-btn');
		await expect(page.locator('#pending-sshfp')).toContainText('DNSSEC ✓');
		await page.click('#pending-sshfp');
		await expect(page.locator('.handshake-decision')).toContainText('TOFU');
	});

	test('without DNSSEC: Verify-via-SSHFP shows the risk wording', async ({ page }) => {
		await startServer(page);
		await page.uncheck('#sshfp-dnssec');
		await page.click('#sshfp-publish');
		await expect(page.locator('text=unsigned — DNS-spoofable')).toBeVisible();
		await page.click('#connect-btn');
		await expect(page.locator('#pending-sshfp')).toContainText('no DNSSEC — risky');
	});
});

test.describe('recovery flows', () => {
	test('ssh-keygen -R clears the pin and the next connect is first contact again', async ({ page }) => {
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		await expect(page.locator('.pin-fp')).toBeVisible();
		await page.click('#forget-btn');
		await expect(page.locator('.pin-fp')).toHaveCount(0);
		// Switch back to ask so the next connect surfaces the pending prompt.
		await page.click('.mode-pill[data-mode="ask"]');
		await page.click('#connect-btn');
		await expect(page.locator('#pending-accept')).toBeVisible();
	});

	test('Reset everything wipes server, pins, SSHFP, CA', async ({ page }) => {
		await startServer(page);
		await page.click('#sshfp-publish');
		await page.click('#ca-start');
		await page.click('#ca-trust');
		await page.click('#ca-sign');
		await page.click('#reset-all-btn');
		await expect(page.locator('.host-card-name')).toHaveCount(0);
		await expect(page.locator('text=No server running yet')).toBeVisible();
	});
});

test.describe('deep links', () => {
	test('?scenario=mitm-after auto-pins, then runs the MITM-after scenario', async ({ page }) => {
		await page.goto('./?scenario=mitm-after');
		await expect(page.locator('#scenario-output .handshake-decision')).toContainText('HOST KEY CHANGED', { timeout: 10_000 });
	});

	test('?scenario=tamper triggers the tampered-signature scenario', async ({ page }) => {
		await page.goto('./?scenario=tamper');
		await expect(page.locator('#scenario-output .handshake-summary')).toContainText('REJECTED', { timeout: 10_000 });
	});
});

test.describe('transcript + summary copy', () => {
	test('transcript inspector exposes copy-as-JSON', async ({ page, context }) => {
		await context.grantPermissions(['clipboard-read', 'clipboard-write']);
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		await page.click('.transcript-inspector > summary');
		const copyBtn = page.locator('.transcript-inspector .transcript-copy');
		await copyBtn.click();
		await expect(page.locator('.transcript-inspector .transcript-copy-msg')).toContainText('Copied');
	});

	test('share link button puts a ?scenario=... URL on the clipboard', async ({ page, context }) => {
		await context.grantPermissions(['clipboard-read', 'clipboard-write']);
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		await page.click('#scn-mitm-after');
		const shareBtn = page.locator('#scenario-output .share-scenario').first();
		await shareBtn.click();
		const text = await page.evaluate(() => navigator.clipboard.readText());
		expect(text).toContain('?scenario=mitm-after');
	});

	test('scenario summary copy puts Markdown on the clipboard', async ({ page, context }) => {
		await context.grantPermissions(['clipboard-read', 'clipboard-write']);
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		await page.click('#scn-mitm-after');
		const summaryBtn = page.locator('#scenario-output .transcript-copy').first();
		await summaryBtn.click();
		await expect(page.locator('#scenario-output .transcript-copy-msg').first()).toContainText('Copied');
		// Verify the actual clipboard content is a Markdown header
		const text = await page.evaluate(() => navigator.clipboard.readText());
		expect(text.startsWith('#')).toBeTruthy();
	});
});

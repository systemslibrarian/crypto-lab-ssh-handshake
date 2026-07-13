import { test, expect, type Page } from '@playwright/test';

// Browser-level coverage for the teaching paths users actually walk. These
// validate the visible behaviour, not just the engine — regressions in the
// teaching surface matter as much as regressions in the cryptographic core.

async function startServer(page: Page): Promise<void> {
	await page.goto('./');
	await page.click('#start-btn');
	await expect(page.locator('.host-card-name')).toBeVisible();
}

// The "Advanced trust bootstrap" disclosure (SSHFP + @cert-authority) is gated
// behind progressive disclosure: it unlocks only after the learner does one
// TOFU connect AND runs the MITM-after-pinning scenario. This mirrors the
// intended teaching order — plain TOFU first, second-order trust after. Tests
// that exercise SSHFP/CA must walk that path to reach the controls.
async function unlockAdvancedTrust(page: Page): Promise<void> {
	await page.click('.mode-pill[data-mode="accept-new"]');
	await page.click('#connect-btn');
	await expect(page.locator('.pin-fp')).toBeVisible();
	await page.click('#scn-mitm-after');
	await expect(page.locator('#scenario-output .handshake-decision')).toContainText('HOST KEY CHANGED');
	const advanced = page.locator('#advanced-trust');
	await expect(advanced).not.toHaveClass(/is-locked/);
	await advanced.locator('summary').click();
	await expect(advanced).toHaveAttribute('open', '');
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
		await unlockAdvancedTrust(page);
		// publish with DNSSEC (default checkbox state)
		await page.click('#sshfp-publish');
		await expect(page.locator('text=DNSSEC ✓ trustworthy channel')).toBeVisible();
		// Return to a first-contact state so the SSHFP-verify prompt can fire.
		await page.click('#forget-btn');
		await page.click('.mode-pill[data-mode="ask"]');
		await page.click('#connect-btn');
		await expect(page.locator('#pending-sshfp')).toContainText('DNSSEC ✓');
		await page.click('#pending-sshfp');
		await expect(page.locator('#connect-result .handshake-decision')).toContainText('TOFU');
	});

	test('without DNSSEC: Verify-via-SSHFP shows the risk wording', async ({ page }) => {
		await startServer(page);
		await unlockAdvancedTrust(page);
		await page.uncheck('#sshfp-dnssec');
		await page.click('#sshfp-publish');
		await expect(page.locator('text=unsigned — DNS-spoofable')).toBeVisible();
		await page.click('#forget-btn');
		await page.click('.mode-pill[data-mode="ask"]');
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
		await unlockAdvancedTrust(page);
		await page.click('#sshfp-publish');
		await page.click('#ca-start');
		await page.click('#ca-trust');
		await page.click('#ca-sign');
		await page.click('#reset-all-btn');
		await expect(page.locator('.host-card-name')).toHaveCount(0);
		await expect(page.locator('text=No server running yet')).toBeVisible();
	});
});

test.describe('sequence diagram', () => {
	test('a connect renders the two-party message flow with arrows', async ({ page }) => {
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		const seq = page.locator('#connect-result .seq-diagram');
		await expect(seq).toBeVisible();
		await expect(seq.locator('.seq-heads')).toContainText('client');
		await expect(seq.locator('.seq-heads')).toContainText('server');
		// The wire messages: client offers eph (→) and server hello (←).
		await expect(seq.locator('.seq-arrow-right')).toBeVisible();
		await expect(seq.locator('.seq-arrow-left')).toBeVisible();
	});

	test('a MITM-after connect marks the known_hosts arrow FAIL', async ({ page }) => {
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		await page.click('#scn-mitm-after');
		const seq = page.locator('#scenario-output .seq-diagram');
		await expect(seq.locator('.seq-fail')).toHaveCount(1);
	});
});

test.describe('exchange-hash binding lab', () => {
	test('swapping a tile changes H and flips the signature to FAIL', async ({ page }) => {
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		const lab = page.locator('.hash-lab');
		await expect(lab).toBeVisible();
		// Genuine handshake: signature verifies.
		await expect(lab.locator('.hlab-verdict')).toContainText('SIGNATURE OK');
		const before = await lab.locator('.hlab-h-value').textContent();
		// Swap the host public key (a MITM substituting its own identity).
		await lab.locator('.hlab-swap').first().click();
		await expect(lab.locator('.hlab-verdict--fail')).toContainText('SIGNATURE FAIL');
		const after = await lab.locator('.hlab-h-value').textContent();
		expect(after).not.toBe(before);
		// Restore returns to the OK state.
		await lab.locator('.hlab-reset').click();
		await expect(lab.locator('.hlab-verdict')).toContainText('SIGNATURE OK');
	});
});

test.describe('forward secrecy vs authentication toggle', () => {
	test('auth OFF lets a MITM connect; auth ON catches it', async ({ page }) => {
		await startServer(page);
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		const lab = page.locator('.auth-lab');
		await expect(lab).toBeVisible();
		await lab.locator('> summary').click();
		// Auth OFF: KEX still agrees, MITM connects silently.
		await lab.locator('#auth-verify').uncheck();
		await lab.locator('#auth-run').click();
		await expect(lab.locator('.auth-lab-out')).toContainText('connected silently');
		// Auth ON: same MITM rejected.
		await lab.locator('#auth-verify').check();
		await lab.locator('#auth-run').click();
		await expect(lab.locator('.auth-lab-out')).toContainText('MITM rejected');
	});
});

test.describe('progressive disclosure', () => {
	test('advanced trust bootstrap is locked until TOFU + MITM-after are done', async ({ page }) => {
		await startServer(page);
		const advanced = page.locator('#advanced-trust');
		await expect(advanced).toHaveClass(/is-locked/);
		// Clicking the locked summary must not expand it (SSHFP stays hidden).
		await advanced.locator('summary').click();
		await expect(advanced).not.toHaveAttribute('open', '');
		await expect(page.locator('#sshfp-publish')).toBeHidden();
		// Complete the two milestones.
		await page.click('.mode-pill[data-mode="accept-new"]');
		await page.click('#connect-btn');
		await page.click('#scn-mitm-after');
		await expect(advanced).not.toHaveClass(/is-locked/);
		await advanced.locator('summary').click();
		await expect(page.locator('#sshfp-publish')).toBeVisible();
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

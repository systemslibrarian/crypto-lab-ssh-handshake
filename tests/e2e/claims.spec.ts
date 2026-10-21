import { expect, test, type Page } from '@playwright/test';

function xorHex(...hexValues: string[]): string {
	const bytes = hexValues.map((hex) => Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16)));
	const out = new Uint8Array(bytes[0]?.length ?? 0);
	for (let i = 0; i < out.length; i++) {
		for (const value of bytes) out[i] ^= value[i]!;
	}
	return Array.from(out, (byte) => byte.toString(2).padStart(8, '0')).join('');
}

async function openPacketLayer(page: Page): Promise<void> {
	await page.goto('./');
	await expect(page.locator('#packet-layer-heading')).toHaveText('After the handshake: the packet layer');
}

async function captureApw(page: Page): Promise<void> {
	await page.click('#apw-capture');
	await expect(page.locator('#apw-status')).toHaveText('Target captured.');
	await expect(page.locator('#apw-inject')).toBeEnabled();
}

async function assertDisplayedXor(page: Page, expectedBits: number): Promise<void> {
	const prime = (await page.locator('#apw-prime').getAttribute('data-bytes'))!;
	const last = (await page.locator('#apw-last').getAttribute('data-bytes'))!;
	const predecessor = (await page.locator('#apw-cprev').getAttribute('data-bytes'))!;
	const displayed = (await page.locator('#apw-recovered').getAttribute('data-recovered-bits'))!;
	const computed = xorHex(prime, last, predecessor).slice(0, expectedBits);
	expect(displayed).toBe(computed);
	await expect(page.locator('#apw-true-bits')).toHaveText(computed);
}

test('[mutation:apw-ideal] idealised receiver verdict follows real CBC XOR', async ({ page }) => {
	await openPacketLayer(page);
	await captureApw(page);
	await page.selectOption('#apw-receiver', 'ideal');
	await page.click('#apw-inject');
	await expect(page.locator('#apw-verdict')).toHaveText('⚠ ALARM — PLAINTEXT LEAKED (32 bits)');
	await assertDisplayedXor(page, 32);
	const prime = (await page.locator('#apw-prime').getAttribute('data-bytes'))!;
	const length = Number.parseInt(prime.slice(0, 8), 16);
	await expect(page.locator('#apw-reaction')).toContainText(`ℓ = ${length.toLocaleString()}`);
	await expect(page.locator('#apw-reaction')).toContainText('bytes counted');
});

test('[mutation:apw-openssh] pre-5.2 verdict follows the range oracle', async ({ page }) => {
	await openPacketLayer(page);
	await captureApw(page);
	await page.selectOption('#apw-receiver', 'openssh');
	await page.selectOption('#apw-depth', '14');
	await page.click('#apw-inject');
	await expect(page.locator('#apw-verdict')).toHaveText('⚠ ALARM — PLAINTEXT LEAKED (14 bits)');
	await expect(page.locator('.reaction-log strong')).toHaveText('FIN');
	await assertDisplayedXor(page, 14);
});

test('pre-5.2 aligned wait recovers the displayed 32-bit prefix', async ({ page }) => {
	await openPacketLayer(page);
	await captureApw(page);
	await page.selectOption('#apw-receiver', 'openssh');
	await page.selectOption('#apw-depth', '32');
	await page.click('#apw-inject');
	await expect(page.locator('#apw-verdict')).toHaveText('⚠ ALARM — PLAINTEXT LEAKED (32 bits)');
	await expect(page.locator('.reaction-log strong')).toHaveText('WAIT → MAC_ERROR');
	expect(await page.locator('.reaction-log strong').getAttribute('data-reaction-final')).toBe('MAC_ERROR');
	await assertDisplayedXor(page, 32);
});

test('[mutation:apw-ctr] AES-CTR defence is tied to an unrelated computed prefix', async ({ page }) => {
	await openPacketLayer(page);
	await captureApw(page);
	await page.selectOption('#apw-fix', 'ctr');
	await page.click('#apw-run-fix');
	await expect(page.locator('#apw-ctr-verdict')).toHaveText('✓ DEFENCE HELD — AES-CTR USED AN UNRELATED KEYSTREAM BLOCK');
	const proof = page.locator('#apw-ctr-proof');
	expect(await proof.getAttribute('data-unrelated')).toBe('true');
	expect(await proof.getAttribute('data-candidate')).not.toBe(await proof.getAttribute('data-target'));
});

test('[mutation:apw-chacha] ChaCha defence is tied to the real Poly1305 rejection', async ({ page }) => {
	await openPacketLayer(page);
	await captureApw(page);
	await page.selectOption('#apw-fix', 'chacha');
	await page.click('#apw-run-fix');
	await expect(page.locator('#apw-chacha-verdict')).toHaveText('✓ DEFENCE HELD — POLY1305 REJECTED BEFORE PAYLOAD DECRYPTION');
	expect(await page.locator('#apw-chacha-proof').getAttribute('data-rejected')).toBe('true');
});

test('measured rates equal displayed hits divided by attempts', async ({ page }) => {
	test.slow();
	await openPacketLayer(page);
	await page.selectOption('#apw-attempts', '1048576');
	await page.click('#apw-run-rate');
	const result = page.locator('#apw-rate-result');
	await expect(result).toBeVisible();
	const total = Number(await result.getAttribute('data-attempts'));
	const hits14 = Number(await result.getAttribute('data-hits-14'));
	const hits32 = Number(await result.getAttribute('data-hits-32'));
	const displayedRates = await result.locator('[data-rate]').evaluateAll((nodes) =>
		nodes.map((node) => Number((node as HTMLElement).dataset.rate)),
	);
	expect(displayedRates[0]).toBe(hits14 / total);
	expect(displayedRates[1]).toBe(hits32 / total);
});

async function waitForTerrapin(page: Page): Promise<void> {
	await expect(page.locator('#terrapin-demo')).toBeVisible();
	await expect(page.locator('#terrapin-signature')).toHaveText('VERIFIED');
}

test('[mutation:strict-kex] safe default rejects IGNORE at the computed strict-kex rule', async ({ page }) => {
	await openPacketLayer(page);
	await waitForTerrapin(page);
	await expect(page.locator('#strict-state')).toContainText('STRICT KEX ACTIVE');
	await expect(page.locator('#strict-strip-proof')).toContainText('host signature FAILS');
	await page.click('#terrapin-inject');
	await expect(page.locator('#strict-verdict')).toHaveText('✓ DEFENCE HELD — STRICT KEX REJECTED SSH_MSG_IGNORE');
	await expect(page.locator('[data-counter="client-receive"]')).toHaveText('2');
});

test('[mutation:terrapin] delivered sequence matches C.Rcv and authenticated truncation is proved', async ({ page }) => {
	await openPacketLayer(page);
	await waitForTerrapin(page);
	const originalH = await page.locator('#terrapin-hash').innerText();
	await page.uncheck('#strict-client');
	await page.uncheck('#strict-server');
	await expect(page.locator('#strict-state')).toContainText('BROKEN MODE');
	await page.click('#terrapin-inject');
	await expect(page.locator('#terrapin-h-unchanged')).toHaveText('UNCHANGED');
	expect(await page.locator('#terrapin-hash').innerText()).toBe(originalH);
	await page.click('#terrapin-delete');

	// Parse all four live counters at the instant the next packet is about to
	// be verified. C.Rcv is the nonce/sequence the receiver will use.
	const counterValues = await page.locator('[data-counter]').evaluateAll((nodes) =>
		Object.fromEntries(nodes.map((node) => [(node as HTMLElement).dataset.counter!, Number(node.textContent)])),
	);
	expect(counterValues).toEqual({
		'client-send': 3,
		'client-receive': 4,
		'server-send': 5,
		'server-receive': 3,
	});
	await page.click('#terrapin-deliver');
	await expect(page.locator('#terrapin-verdict')).toHaveText('⚠ ALARM — PACKET DELETED, MAC VALID');
	const fixture = page.locator('#terrapin-negative-fixture');
	expect(Number(await fixture.getAttribute('data-client-receive-used'))).toBe(counterValues['client-receive']);
	expect(await fixture.getAttribute('data-client-receive-used')).toBe(await fixture.getAttribute('data-delivered-sequence'));
	await expect(fixture.locator('strong')).toHaveText('AUTHENTICATED — AND TRUNCATED');
	await expect(fixture).toContainText('A valid MAC on every delivered packet does not mean no packet was deleted.');
	await expect(fixture.locator('[data-proof="signature"]')).toContainText('VERIFIED');
	await expect(fixture.locator('[data-proof="tags"]')).toContainText('VERIFIED');
	await expect(fixture.locator('[data-proof="ext-info"]')).toContainText('NEVER ARRIVED');
	await expect(page.locator('#ext-sig')).toHaveText('MISSING');
	await expect(page.locator('#ext-ping')).toHaveText('MISSING');
});

test('delete without IGNORE, late IGNORE, and one-sided strict kex fail safely', async ({ page }) => {
	await openPacketLayer(page);
	await waitForTerrapin(page);
	await page.uncheck('#strict-server');
	await expect(page.locator('#strict-state')).toContainText('one-sided support is not negotiation');
	await page.click('#terrapin-delete');
	await page.click('#terrapin-deliver');
	await expect(page.locator('#terrapin-result')).toContainText('sequence-number mismatch');
	await page.click('#terrapin-reset');
	await page.click('#terrapin-late');
	await expect(page.locator('#terrapin-result')).toContainText('IGNORE after NEWKEYS would need a valid encrypted packet and tag');
});

test('retirement and no-op guards remove the overclaim and keep safe defaults inert', async ({ page }) => {
	await openPacketLayer(page);
	const body = await page.locator('body').innerText();
	expect(body).not.toContain('H commits the entire handshake transcript');
	expect(body).not.toContain('why one signature covers everything');
	const kickers = await page.locator('.section-kicker').allTextContents();
	expect(kickers).toEqual([
		'Section · 1',
		'Section · 2',
		'Section · 3',
		'Section · 4',
		'Section · 5',
		'Section · 6',
		'Section · 7',
	]);
	await captureApw(page);
	await page.click('#apw-inject');
	await expect(page.locator('#apw-reaction')).toContainText('No broken receiver selected');
	await expect(page.locator('#apw-verdict')).toHaveCount(0);
	await page.selectOption('#apw-target', 'tag');
	await captureApw(page);
	await page.selectOption('#apw-receiver', 'ideal');
	await page.click('#apw-inject');
	await expect(page.locator('#apw-reaction')).toContainText('the tag is not CBC ciphertext');
});


// copy.test.ts — a copy-fidelity gate for the three claims this lab makes
// ABOUT OpenSSH and the SSHFP registries, rather than about its own model.
//
// Each one shipped wrong once, and each one is checkable against a source:
//
//   1. The first-contact prompt. OpenSSH asks "(yes/no/[fingerprint])" —
//      sshconnect.c builds exactly that string, and confirm() accepts the
//      fingerprint itself in place of "yes". Two page strings said
//      "(yes/no/[verify])" and "(yes/no)" while data.ts had it right, so the
//      expected text is DERIVED from data.ts and the page is held to it.
//   2. StrictHostKeyChecking=no. ssh_config(5): with "no" or "off" ssh adds NEW
//      host keys and lets connections to hosts with CHANGED keys proceed
//      "subject to some restrictions" — it does not replace the stored key, and
//      it prints the REMOTE HOST IDENTIFICATION HAS CHANGED banner while doing
//      it. The mode help said the pin could be silently overwritten; the rest of
//      the lab correctly says the old pin is retained.
//   3. The SSHFP numbers. RFC 4255 registers algorithms 1 (RSA) and 2 (DSS) and
//      fingerprint type 1 (SHA-1). Algorithm 3 (ECDSA) and fingerprint type 2
//      (SHA-256) are RFC 6594's; algorithm 4 (Ed25519) is RFC 7479's.

import { describe, expect, it } from 'vitest';
import { explainMode } from './policy.ts';
// Read as text (Vite's ?raw), so the gate inspects the shipped copy itself
// rather than a second transcription of it kept in this file.
import ui from './ui.ts?raw';
import data from './data.ts?raw';

/** OpenSSH's prompt, taken from the lab's own reference copy rather than retyped. */
const PROMPT = (() => {
	const match = data.match(/Are you sure you want to continue connecting \([^)]*\)\?/);
	if (!match) throw new Error('data.ts no longer quotes the first-contact prompt');
	return match[0];
})();

describe('the first-contact prompt is quoted as OpenSSH prints it', () => {
	it('data.ts holds the real prompt', () => {
		expect(PROMPT).toBe('Are you sure you want to continue connecting (yes/no/[fingerprint])?');
	});

	it('every page copy of the prompt matches it', () => {
		const quotes = [...ui.matchAll(/Are you sure you want to continue connecting \([^)]*\)\?/g)].map(m => m[0]);
		expect(quotes.length).toBeGreaterThan(0);
		for (const quote of quotes) expect(quote).toBe(PROMPT);
	});

	it('neither of the two wrong spellings is anywhere in the source', () => {
		for (const source of [ui, data]) {
			expect(source).not.toContain('(yes/no/[verify])');
			expect(source).not.toMatch(/continue connecting \(yes\/no\)\?/);
		}
	});
});

describe('StrictHostKeyChecking=no does not overwrite the pin', () => {
	const help = explainMode('no');

	it('says the old pin is retained', () => {
		expect(help).toMatch(/old pin is retained/i);
	});

	it('does not claim the pin is silently overwritten', () => {
		expect(help).not.toMatch(/silently overwritten/i);
		expect(help).not.toMatch(/overwritten\b(?!, )/i);
	});

	it('still names the mode dangerous, because it is', () => {
		expect(help).toMatch(/Dangerous/);
	});
});

describe('SSHFP numbers are credited to the RFC that registered them', () => {
	it('algorithm 3 and fingerprint type 2 are RFC 6594', () => {
		const hint = ui.match(/SSHFP RDATA:[^<]*(?:<[^>]*>[^<]*)*?(?=<\/p>)/)?.[0] ?? '';
		expect(hint).toContain('RFC 6594');
		expect(hint).toMatch(/[Aa]lgorithm 3 = ECDSA and fp-type 2 = SHA-256 come from RFC 6594/);
		expect(hint).toMatch(/algorithm 4 = Ed25519 from RFC 7479/);
		// The old cite put 3 and 2 on RFC 4255 + RFC 7479.
		expect(ui).not.toContain('(RFC 4255 + RFC 7479.)');
	});

	it('the reference list names RFC 6594', () => {
		expect(data).toContain('https://www.rfc-editor.org/rfc/rfc6594');
	});
});

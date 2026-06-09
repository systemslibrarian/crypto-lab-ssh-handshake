// sshfp.test.ts — the toy SSHFP registry behaves like the real spec at a
// behavioural level, including the honest DNS-spoof-without-DNSSEC failure
// mode.

import { afterEach, describe, expect, it } from 'vitest';
import {
	clearSshfp,
	lookupSshfp,
	poisonSshfp,
	publishSshfp,
	removeSshfp,
	verifySshfp,
} from './sshfp.ts';

const HOST = 'server.example.com';
const FP_REAL = 'SHA256:realrealrealrealrealrealrealrealrealreal+x';
const FP_FAKE = 'SHA256:attackerattackerattackerattackerattacker+y';

describe('sshfp', () => {
	afterEach(() => clearSshfp());

	it('no record → verifier reports no-record', () => {
		expect(verifySshfp(HOST, FP_REAL).kind).toBe('no-record');
	});

	it('published + match + dnssec → match (safe)', () => {
		publishSshfp(HOST, FP_REAL, true);
		const v = verifySshfp(HOST, FP_REAL);
		expect(v.kind).toBe('match');
	});

	it('published + match without dnssec → match-unsigned (warn)', () => {
		publishSshfp(HOST, FP_REAL, false);
		expect(verifySshfp(HOST, FP_REAL).kind).toBe('match-unsigned');
	});

	it('published + mismatch → mismatch', () => {
		publishSshfp(HOST, FP_REAL, true);
		expect(verifySshfp(HOST, FP_FAKE).kind).toBe('mismatch');
	});

	it('poison (DNS spoof, no DNSSEC) → match-unsigned for the attacker fingerprint', () => {
		poisonSshfp(HOST, FP_FAKE);
		const v = verifySshfp(HOST, FP_FAKE);
		expect(v.kind).toBe('match-unsigned');
	});

	it('lookup + remove', () => {
		publishSshfp(HOST, FP_REAL);
		expect(lookupSshfp(HOST)?.fingerprint).toBe(FP_REAL);
		expect(removeSshfp(HOST)).toBe(true);
		expect(lookupSshfp(HOST)).toBeUndefined();
	});
});

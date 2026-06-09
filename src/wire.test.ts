// wire.test.ts — SSH wire-format serialization round-trips and produces a
// fingerprint string in OpenSSH's exact format ("SHA256:" + base64 of
// SHA-256 over the canonical pubkey blob).

import { describe, expect, it } from 'vitest';
import { sshFingerprint, sshPublicKeyBase64, sshPublicKeyBlob, sshfpRecord } from './wire.ts';

// JWK for a fixed Ed25519 public key (the test vector x = 32 zero bytes).
const zeroEd25519: JsonWebKey = {
	kty: 'OKP',
	crv: 'Ed25519',
	x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', // base64url of 32 zero bytes (no padding)
};

describe('wire', () => {
	it('builds a 51-byte ssh-ed25519 blob (4+11 + 4+32)', () => {
		const blob = sshPublicKeyBlob(zeroEd25519, 'Ed25519');
		expect(blob.length).toBe(4 + 'ssh-ed25519'.length + 4 + 32);
	});

	it('encodes the length prefix in big-endian', () => {
		const blob = sshPublicKeyBlob(zeroEd25519, 'Ed25519');
		// First 4 bytes = length of "ssh-ed25519" (11) in big-endian.
		expect(blob[0]).toBe(0);
		expect(blob[1]).toBe(0);
		expect(blob[2]).toBe(0);
		expect(blob[3]).toBe(11);
	});

	it('produces a SHA256: fingerprint in the OpenSSH format', async () => {
		const blob = sshPublicKeyBlob(zeroEd25519, 'Ed25519');
		const fp = await sshFingerprint(blob);
		expect(fp).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
		expect(fp.endsWith('=')).toBe(false); // trailing padding stripped
	});

	it('round-trips: base64 of the blob is what known_hosts shows in field 3', () => {
		const blob = sshPublicKeyBlob(zeroEd25519, 'Ed25519');
		const b64 = sshPublicKeyBase64(blob);
		// First 4 bytes of the decoded base64 are the big-endian length of "ssh-ed25519"
		const bin = atob(b64);
		expect(bin.charCodeAt(3)).toBe(11);
	});

	it('SSHFP record reports algo 4 for ed25519 and fp-type 2 for SHA-256', async () => {
		const blob = sshPublicKeyBlob(zeroEd25519, 'Ed25519');
		const rec = await sshfpRecord('server.example.com', blob, 'ssh-ed25519');
		expect(rec.algo).toBe(4);
		expect(rec.fpType).toBe(2);
		expect(rec.rr).toMatch(/^server\.example\.com\. \d+ IN SSHFP 4 2 [0-9a-f]+$/);
		expect(rec.hashHex.length).toBe(64);
	});

	it('different ed25519 keys produce different fingerprints', async () => {
		const a = await sshFingerprint(sshPublicKeyBlob(zeroEd25519, 'Ed25519'));
		const other: JsonWebKey = { ...zeroEd25519, x: 'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
		const b = await sshFingerprint(sshPublicKeyBlob(other, 'Ed25519'));
		expect(a).not.toBe(b);
	});

	it('ECDSA P-256 blob includes the uncompressed-point prefix 0x04 and is correctly framed', () => {
		const ec: JsonWebKey = {
			kty: 'EC',
			crv: 'P-256',
			x: 'A'.repeat(43), // 43 base64 chars ≈ 32 bytes
			y: 'B'.repeat(43),
		};
		const blob = sshPublicKeyBlob(ec, 'ECDSA P-256');
		// Layout: 4 + 19 + 4 + 8 + 4 + 65 = 104
		expect(blob.length).toBe(4 + 'ecdsa-sha2-nistp256'.length + 4 + 'nistp256'.length + 4 + 65);
		// The 0x04 prefix sits right after the third length field.
		const pointOffset = 4 + 19 + 4 + 8 + 4;
		expect(blob[pointOffset]).toBe(0x04);
	});
});

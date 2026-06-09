// ca.test.ts — host certificate sign/verify, principal binding, expiry,
// host-key binding, and rejection by a different CA.

import { describe, expect, it } from 'vitest';
import { SshServer } from './engine.ts';
import { HostCA, verifyCert } from './ca.ts';

const HOST = 'server.example.com';

describe('HostCA + verifyCert', () => {
	it('issues a cert that verifies under its own CA', async () => {
		const ca = await HostCA.create('Acme CA');
		const server = await SshServer.create(HOST);
		const cert = await ca.sign(HOST, server.publicIdentity().hostPubJwk);
		const verdict = await verifyCert(cert, ca.publicIdentity().pubJwk, HOST, server.publicIdentity().hostPubJwk);
		expect(verdict.valid).toBe(true);
	});

	it('rejects a cert verified under a different CA', async () => {
		const goodCA = await HostCA.create('Acme CA');
		const otherCA = await HostCA.create('Rogue CA');
		const server = await SshServer.create(HOST);
		const cert = await goodCA.sign(HOST, server.publicIdentity().hostPubJwk);
		const verdict = await verifyCert(cert, otherCA.publicIdentity().pubJwk, HOST, server.publicIdentity().hostPubJwk);
		expect(verdict.valid).toBe(false);
	});

	it('rejects a cert whose principal does not match the connection name', async () => {
		const ca = await HostCA.create('Acme CA');
		const server = await SshServer.create('other.example.com');
		const cert = await ca.sign('other.example.com', server.publicIdentity().hostPubJwk);
		const verdict = await verifyCert(cert, ca.publicIdentity().pubJwk, HOST, server.publicIdentity().hostPubJwk);
		expect(verdict.valid).toBe(false);
		expect(verdict.reason).toMatch(/principal/);
	});

	it('rejects a cert that does not bind the presented host pubkey', async () => {
		const ca = await HostCA.create('Acme CA');
		const certified = await SshServer.create(HOST);
		const other = await SshServer.create(HOST);
		// Cert signed for `certified`, but the connection presents `other`.
		const cert = await ca.sign(HOST, certified.publicIdentity().hostPubJwk);
		const verdict = await verifyCert(cert, ca.publicIdentity().pubJwk, HOST, other.publicIdentity().hostPubJwk);
		expect(verdict.valid).toBe(false);
	});

	it('rejects an expired cert', async () => {
		const ca = await HostCA.create('Acme CA');
		const server = await SshServer.create(HOST);
		const cert = await ca.sign(HOST, server.publicIdentity().hostPubJwk);
		const expired = { ...cert, validUntil: new Date(Date.now() - 1000).toISOString() };
		const verdict = await verifyCert(expired, ca.publicIdentity().pubJwk, HOST, server.publicIdentity().hostPubJwk);
		expect(verdict.valid).toBe(false);
		expect(verdict.reason).toMatch(/expired/);
	});

	it('issues a cert with OpenSSH-shaped fields: serial, nonce, key_id, principals', async () => {
		const ca = await HostCA.create('Acme CA');
		const server = await SshServer.create(HOST);
		const cert = await ca.sign(HOST, server.publicIdentity().hostPubJwk);
		expect(cert.nonce.length).toBeGreaterThan(40); // base64 of 32 bytes
		expect(cert.serial).toMatch(/^\d+$/);
		expect(cert.certType).toBe('host');
		expect(cert.validPrincipals).toContain(HOST);
		expect(cert.keyId).toContain(HOST);
		expect(cert.criticalOptions).toEqual({});
		expect(cert.extensions).toEqual({});
		expect(cert.reserved).toBe('');
	});

	it('rejects a cert whose valid_principals omits the connection name', async () => {
		const ca = await HostCA.create('Acme CA');
		const server = await SshServer.create(HOST);
		const cert = await ca.sign(HOST, server.publicIdentity().hostPubJwk, {
			validPrincipals: ['someone-else.example.com'],
		});
		const verdict = await verifyCert(cert, ca.publicIdentity().pubJwk, HOST, server.publicIdentity().hostPubJwk);
		expect(verdict.valid).toBe(false);
		expect(verdict.reason).toMatch(/valid_principals/);
	});

	it('the same CA can sign a rotated host key so reconnect avoids the TOFU prompt', async () => {
		const ca = await HostCA.create('Acme CA');
		const oldServer = await SshServer.create(HOST);
		const newServer = await SshServer.create(HOST);
		const newCert = await ca.sign(HOST, newServer.publicIdentity().hostPubJwk);
		const verdict = await verifyCert(newCert, ca.publicIdentity().pubJwk, HOST, newServer.publicIdentity().hostPubJwk);
		expect(verdict.valid).toBe(true);
		// And the old server's cert should not verify under a cert issued for the new key.
		const stillVerdict = await verifyCert(newCert, ca.publicIdentity().pubJwk, HOST, oldServer.publicIdentity().hostPubJwk);
		expect(stillVerdict.valid).toBe(false);
	});
});

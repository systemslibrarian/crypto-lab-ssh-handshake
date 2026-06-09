// engine.test.ts — automated coverage of the SSH transport-handshake model.
// Mirrors the six headline scenarios from the demo: first-use TOFU, reconnect,
// MITM after pinning, MITM on first contact, tampered host signature, and
// legitimate host-key rotation (server reinstall).

import { describe, expect, it } from 'vitest';
import {
	SshClient,
	SshServer,
	makeMitm,
	algoNames,
	type ServerHello,
} from './engine.ts';
import { sshFingerprint, sshPublicKeyBlob } from './wire.ts';

const HOST = 'server.example.com';

describe('SSH handshake engine', () => {
	it('reports algorithm names without throwing', () => {
		const { kex, sig } = algoNames();
		expect(typeof kex).toBe('string');
		expect(typeof sig).toBe('string');
	});

	it('first connect: TOFU pins the host key and the handshake succeeds', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		const result = await client.connect(HOST, server);
		expect(result.connected).toBe(true);
		expect(result.signatureValid).toBe(true);
		expect(result.sharedAgrees).toBe(true);
		expect(result.hostKeyDecision).toBe('tofu-pinned');
		expect(client.knownHosts.get(HOST)).toBe(server.publicIdentity().fingerprint);
	});

	it('reconnect: pinned fingerprint matches and the handshake succeeds', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		await client.connect(HOST, server);
		const result = await client.connect(HOST, server);
		expect(result.connected).toBe(true);
		expect(result.hostKeyDecision).toBe('matches-known');
	});

	it('MITM after pinning: changed host key is detected and the connection is refused', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		await client.connect(HOST, server);
		const attacker = await makeMitm(HOST);
		const result = await client.connect(HOST, attacker);
		expect(result.connected).toBe(false);
		expect(result.hostKeyDecision).toBe('CHANGED-REJECTED');
		// Pin must not be silently updated to the attacker's fingerprint.
		expect(client.knownHosts.get(HOST)).toBe(server.publicIdentity().fingerprint);
	});

	it('MITM on first contact (fresh client): TOFU cannot detect the swap', async () => {
		// The honest TOFU limitation: a fresh client pins whatever responds.
		const attacker = await makeMitm(HOST);
		const client = new SshClient();
		const result = await client.connect(HOST, attacker);
		expect(result.connected).toBe(true);
		expect(result.hostKeyDecision).toBe('tofu-pinned');
		expect(client.knownHosts.get(HOST)).toBe(attacker.identity.fingerprint);
	});

	it('tampered host signature: signature verification fails and the connection is refused', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		await client.connect(HOST, server); // pin
		const tampered = {
			respond: async (clientEphPubJwk: JsonWebKey): Promise<ServerHello> => {
				const hello = await server.respond(clientEphPubJwk);
				const bin = atob(hello.hostSignatureB64);
				const bytes = new Uint8Array(bin.length);
				for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
				bytes[0] ^= 0xff;
				let s = '';
				for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
				return { ...hello, hostSignatureB64: btoa(s) };
			},
		};
		const result = await client.connect(HOST, tampered);
		expect(result.connected).toBe(false);
		expect(result.signatureValid).toBe(false);
	});

	it('legitimate rotation (server reinstall) trips the SAME warning as MITM', async () => {
		// The honest dual-use lesson: TOFU cannot distinguish reinstall from attack.
		const oldServer = await SshServer.create(HOST);
		const client = new SshClient();
		await client.connect(HOST, oldServer); // pin

		const newServer = await SshServer.create(HOST); // same name, new key
		const result = await client.connect(HOST, newServer);
		expect(result.connected).toBe(false);
		expect(result.hostKeyDecision).toBe('CHANGED-REJECTED');

		// Recovery: drop the stale pin and reconnect (ssh-keygen -R)
		client.knownHosts.delete(HOST);
		const recovered = await client.connect(HOST, newServer);
		expect(recovered.connected).toBe(true);
		expect(recovered.hostKeyDecision).toBe('tofu-pinned');
		expect(client.knownHosts.get(HOST)).toBe(newServer.publicIdentity().fingerprint);
	});

	it('shared secret check: each side derives the same ECDH bits', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		const result = await client.connect(HOST, server);
		expect(result.sharedAgrees).toBe(true);
		expect(result.steps.find((s) => s.label === 'Shared secret')?.ok).toBe(true);
	});

	it('exchange-hash binding: signature is over a fresh hash every connection', async () => {
		// Two connections must produce different exchange hashes (different
		// ephemerals each time), even with the same long-term host key.
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		const hashes: string[] = [];
		const tap = {
			respond: async (jwk: JsonWebKey): Promise<ServerHello> => {
				const hello = await server.respond(jwk);
				hashes.push(hello.exchangeHash);
				return hello;
			},
		};
		await client.connect(HOST, tap);
		await client.connect(HOST, tap);
		expect(hashes.length).toBe(2);
		expect(hashes[0]).not.toBe(hashes[1]);
	});

	it('mitm helper produces a different host key than the real server', async () => {
		const server = await SshServer.create(HOST);
		const attacker = await makeMitm(HOST);
		expect(attacker.identity.fingerprint).not.toBe(server.publicIdentity().fingerprint);
	});

	it('engine fingerprint matches ssh-keygen -lf format (SHA-256 over the canonical wire blob)', async () => {
		const server = await SshServer.create(HOST);
		const id = server.publicIdentity();
		const blob = sshPublicKeyBlob(id.hostPubJwk, algoNames().sig);
		const wireFp = await sshFingerprint(blob);
		expect(id.fingerprint).toBe(wireFp);
		expect(id.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
	});
});

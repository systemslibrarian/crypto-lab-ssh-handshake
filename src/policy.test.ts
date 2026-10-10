// policy.test.ts — coverage of the StrictHostKeyChecking policy wrapper.

import { describe, expect, it } from 'vitest';
import { SshClient, SshServer, makeMitm, algoNames } from './engine.ts';
import { clearKnownHosts, connectWithPolicy, findPin, removePin } from './policy.ts';

const HOST = 'server.example.com';

describe('connectWithPolicy', () => {
	it('mode=yes refuses an unknown host without prompting', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		const r = await connectWithPolicy(client, HOST, server, 'yes');
		expect(r.connected).toBe(false);
		expect(r.result.hostKeyDecision).toBe('unknown');
		expect(client.knownHosts.has(HOST)).toBe(false);
	});

	it('mode=ask holds first contact and lets the caller accept', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		const r = await connectWithPolicy(client, HOST, server, 'ask');
		expect(r.connected).toBe(false);
		expect(r.pendingFirstContact).toBeDefined();
		expect(r.pendingFirstContact!.presentedFingerprint).toBe(server.publicIdentity().fingerprint);
		expect(client.knownHosts.has(HOST)).toBe(false); // not pinned yet
		r.pendingFirstContact!.accept();
		expect(client.knownHosts.get(HOST)?.get(algoNames().sig)).toBe(server.publicIdentity().fingerprint);
	});

	it('mode=ask lets the caller reject and leaves known_hosts empty', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		const r = await connectWithPolicy(client, HOST, server, 'ask');
		r.pendingFirstContact!.reject();
		expect(client.knownHosts.has(HOST)).toBe(false);
	});

	it('mode=accept-new keeps the engine default — auto-pin on first contact', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		const r = await connectWithPolicy(client, HOST, server, 'accept-new');
		expect(r.connected).toBe(true);
		expect(client.knownHosts.get(HOST)?.get(algoNames().sig)).toBe(server.publicIdentity().fingerprint);
	});

	it('mode=accept-new still rejects a changed host key', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		await connectWithPolicy(client, HOST, server, 'accept-new');
		const attacker = await makeMitm(HOST);
		const r = await connectWithPolicy(client, HOST, attacker, 'accept-new');
		expect(r.connected).toBe(false);
		expect(r.result.hostKeyDecision).toBe('CHANGED-REJECTED');
	});

	it('mode=no continues with restrictions without replacing the known host pin', async () => {
		const oldServer = await SshServer.create(HOST);
		const client = new SshClient();
		await connectWithPolicy(client, HOST, oldServer, 'accept-new');
		const newServer = await SshServer.create(HOST);
		const r = await connectWithPolicy(client, HOST, newServer, 'no');
		expect(r.connected).toBe(true);
		expect(client.knownHosts.get(HOST)?.get(algoNames().sig)).toBe(oldServer.publicIdentity().fingerprint);
        expect(r.result.hostKeyDecision).toBe('CHANGED-ALLOWED-RESTRICTED');
        expect(r.result.restrictedCapabilities).toEqual([
          'password authentication', 'keyboard-interactive authentication',
          'agent forwarding', 'X11 forwarding', 'port forwarding',
          'tunnel forwarding', 'UpdateHostkeys',
        ]);
        expect(r.result.summary).toMatch(/restricted.*pin retained/i);
        expect(r.result.steps.at(-1)?.ok).toBe(false);
        // The new key has not become trusted in any later strict-mode attempt.
        const again = await connectWithPolicy(client, HOST, newServer, 'no');
        expect(again.result.hostKeyDecision).toBe('CHANGED-ALLOWED-RESTRICTED');
        const strict = await connectWithPolicy(client, HOST, newServer, 'accept-new');
        expect(strict.connected).toBe(false);
        expect(strict.result.hostKeyDecision).toBe('CHANGED-REJECTED');
        const original = await connectWithPolicy(client, HOST, oldServer, 'yes');
        expect(original.connected).toBe(true);
        expect(original.result.hostKeyDecision).toBe('matches-known');
	});

	it('findPin / removePin mirror ssh-keygen -F / -R', async () => {
		const server = await SshServer.create(HOST);
		const client = new SshClient();
		await connectWithPolicy(client, HOST, server, 'accept-new');
		expect(findPin(client, HOST)).toBe(server.publicIdentity().fingerprint);
		expect(removePin(client, HOST)).toBe(true);
		expect(findPin(client, HOST)).toBeUndefined();
		expect(removePin(client, HOST)).toBe(false);
	});

	it('clearKnownHosts wipes every pin', async () => {
		const server = await SshServer.create(HOST);
		const other = await SshServer.create('other.example.com');
		const client = new SshClient();
		await connectWithPolicy(client, HOST, server, 'accept-new');
		await connectWithPolicy(client, 'other.example.com', other, 'accept-new');
		expect(client.knownHosts.size).toBe(2);
		clearKnownHosts(client);
		expect(client.knownHosts.size).toBe(0);
	});
});


describe('restricted continuation failure controls', () => {
  it('mode=no first contact still pins a valid key without changed-key restrictions', async () => {
    const server = await SshServer.create(HOST);
    const client = new SshClient();
    const r = await connectWithPolicy(client, HOST, server, 'no');
    expect(r.connected).toBe(true);
    expect(r.result.hostKeyDecision).toBe('tofu-pinned');
    expect(r.result.restrictedCapabilities).toBeUndefined();
    expect(findPin(client, HOST)).toBe(server.publicIdentity().fingerprint);
  });

  it('mode=no cannot turn failed KEX into a successful changed-host handshake', async () => {
    const oldServer = await SshServer.create(HOST);
    const client = new SshClient();
    await connectWithPolicy(client, HOST, oldServer, 'accept-new');
    const replacement = await SshServer.create(HOST);
    const responder = { respond: async (jwk: JsonWebKey) => {
      const hello = await replacement.respond(jwk);
      return { ...hello, sharedSecretHex: 'invalid-secret' };
    } };
    const r = await connectWithPolicy(client, HOST, responder, 'no');
    expect(r.result.signatureValid).toBe(true);
    expect(r.result.sharedAgrees).toBe(false);
    expect(r.connected).toBe(false);
    expect(r.result.connected).toBe(false);
    expect(r.result.restrictedCapabilities).toBeUndefined();
    expect(findPin(client, HOST)).toBe(oldServer.publicIdentity().fingerprint);
  });

  it('changed-host invalid signatures remain rejected and preserve the pin', async () => {
    const oldServer = await SshServer.create(HOST);
    const client = new SshClient();
    await connectWithPolicy(client, HOST, oldServer, 'accept-new');
    const replacement = await SshServer.create(HOST);
    const responder = { respond: async (jwk: JsonWebKey) => ({
      ...await replacement.respond(jwk), hostSignatureB64: 'AA==',
    }) };
    const r = await connectWithPolicy(client, HOST, responder, 'no');
    expect(r.result.signatureValid).toBe(false);
    expect(r.connected).toBe(false);
    expect(r.result.restrictedCapabilities).toBeUndefined();
    expect(findPin(client, HOST)).toBe(oldServer.publicIdentity().fingerprint);
  });

  it.each(['yes', 'ask', 'accept-new', 'no'] as const)('first-contact failed signature is never pinned or offered for acceptance in %s mode', async mode => {
    const server = await SshServer.create(HOST);
    const client = new SshClient();
    const responder = { respond: async (jwk: JsonWebKey) => ({
      ...await server.respond(jwk), hostSignatureB64: 'AA==',
    }) };
    const r = await connectWithPolicy(client, HOST, responder, mode);
    expect(r.connected).toBe(false);
    expect(r.pendingFirstContact).toBeUndefined();
    expect(findPin(client, HOST)).toBeUndefined();
    expect(r.result.hostKeyDecision).toBe('unknown');
  });
});


it.each(['yes', 'ask', 'accept-new', 'no'] as const)('first-contact failed KEX is never pinned or offered for acceptance in %s mode', async mode => {
  const server = await SshServer.create(HOST);
  const client = new SshClient();
  const responder = { respond: async (jwk: JsonWebKey) => ({
    ...await server.respond(jwk), sharedSecretHex: 'invalid-secret',
  }) };
  const r = await connectWithPolicy(client, HOST, responder, mode);
  expect(r.result.signatureValid).toBe(true);
  expect(r.result.sharedAgrees).toBe(false);
  expect(r.connected).toBe(false);
  expect(r.pendingFirstContact).toBeUndefined();
  expect(findPin(client, HOST)).toBeUndefined();
  expect(r.result.hostKeyDecision).toBe('unknown');
});

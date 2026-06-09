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

	it('mode=no silently accepts a changed host key (dangerous, OpenSSH parity)', async () => {
		const oldServer = await SshServer.create(HOST);
		const client = new SshClient();
		await connectWithPolicy(client, HOST, oldServer, 'accept-new');
		const newServer = await SshServer.create(HOST);
		const r = await connectWithPolicy(client, HOST, newServer, 'no');
		expect(r.connected).toBe(true);
		expect(client.knownHosts.get(HOST)?.get(algoNames().sig)).toBe(newServer.publicIdentity().fingerprint);
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

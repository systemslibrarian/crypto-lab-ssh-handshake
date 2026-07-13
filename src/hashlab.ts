// hashlab.ts — the interactive "exchange-hash binding" exhibit.
//
// The load-bearing intuition of SSH host authentication is: the server signs
// ONE hash H that commits to the host name, both ephemeral public keys, the
// host's long-term public key, and the shared secret. "Any substitution
// changes H, so the signature over the old H no longer verifies." That claim
// is the whole reason a single host signature authenticates the entire
// handshake — and until now it was pure prose.
//
// This exhibit renders H's five inputs as tiles feeding an H = SHA256(...) box,
// then lets the learner swap ONE tile (simulating a MITM substituting a field)
// and watch — using the REAL primitives from engine.ts — H change and the REAL
// host signature verification flip from OK to FAIL in the same frame. Nothing
// here is faked: recomputeExchangeHash and verifyHostSignature are the same
// SHA-256 + Web Crypto verify the handshake itself runs.

import type { Transcript } from './transcript.ts';
import {
	recomputeExchangeHash,
	verifyHostSignature,
	makeMitm,
	SshServer,
	algoNames,
	type ExchangeHashInputs,
} from './engine.ts';
import { shortBytes } from './transcript.ts';

// The mutable fields. "shared secret" is derived, not a wire field the attacker
// can freely set, but swapping it models a KEX substitution and is instructive.
type TileKey = 'hostName' | 'hostPubJwk' | 'clientEphJwk' | 'serverEphJwk' | 'sharedSecretB64';

interface TileMeta {
	key: TileKey;
	title: string;
	blurb: string;
}

const TILES: TileMeta[] = [
	{ key: 'hostName', title: 'host name', blurb: 'the name you typed — server.example.com' },
	{ key: 'clientEphJwk', title: 'client ephemeral pub', blurb: "your one-time KEX public key" },
	{ key: 'serverEphJwk', title: 'server ephemeral pub', blurb: "the server's one-time KEX public key" },
	{ key: 'hostPubJwk', title: 'host public key', blurb: "the server's long-term identity key" },
	{ key: 'sharedSecretB64', title: 'shared secret', blurb: 'the ECDH secret both sides derived' },
];

// The genuine, unmodified inputs captured from the last real handshake.
function baseInputs(t: Transcript): ExchangeHashInputs | null {
	if (!t.hostPubJwk || !t.clientEphemeralPubJwk || !t.serverEphemeralPubJwk || !t.sharedSecretB64) {
		return null;
	}
	return {
		hostName: t.hostName,
		hostPubJwk: t.hostPubJwk,
		clientEphJwk: t.clientEphemeralPubJwk,
		serverEphJwk: t.serverEphemeralPubJwk,
		sharedSecretB64: t.sharedSecretB64,
	};
}

// Produce a plausible "attacker-substituted" value for a given tile, so the
// swap is realistic (a real other key / name / secret, not garbage). These are
// generated with the same real key-gen the engine uses.
async function forgedValue(key: TileKey, base: ExchangeHashInputs): Promise<Partial<ExchangeHashInputs>> {
	switch (key) {
		case 'hostName':
			return { hostName: 'evil.attacker.example' };
		case 'hostPubJwk': {
			// A different long-term host key (a MITM presenting its own identity).
			const other = await SshServer.create(base.hostName);
			return { hostPubJwk: other.publicIdentity().hostPubJwk };
		}
		case 'clientEphJwk':
		case 'serverEphJwk': {
			// A different ephemeral key of the same shape.
			const other = await makeMitm(base.hostName);
			const hello = await other.respond(base.clientEphJwk);
			return key === 'clientEphJwk'
				? { clientEphJwk: hello.serverEphPubJwk }
				: { serverEphJwk: hello.serverEphPubJwk };
		}
		case 'sharedSecretB64': {
			// Flip a byte of the shared secret (models a KEX-substitution mismatch).
			const bin = atob(base.sharedSecretB64);
			const bytes = new Uint8Array(bin.length);
			for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
			if (bytes.length) bytes[0] ^= 0xff;
			let s = '';
			for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
			return { sharedSecretB64: btoa(s) };
		}
	}
}

function tileValuePreview(key: TileKey, inp: ExchangeHashInputs): string {
	switch (key) {
		case 'hostName':
			return inp.hostName;
		case 'hostPubJwk':
			return shortBytes(inp.hostPubJwk.x ?? '', 14, 8);
		case 'clientEphJwk':
			return shortBytes(inp.clientEphJwk.x ?? '', 14, 8);
		case 'serverEphJwk':
			return shortBytes(inp.serverEphJwk.x ?? '', 14, 8);
		case 'sharedSecretB64':
			return shortBytes(inp.sharedSecretB64, 14, 8);
	}
}

interface LabState {
	base: ExchangeHashInputs;
	current: ExchangeHashInputs;
	mutated: TileKey | null;
	genuineH: string;
	signatureB64: string;
}

// Render the full exhibit into `container`, capturing the current transcript.
export function mountHashLab(container: HTMLElement, transcript: Transcript | null): void {
	if (!transcript) {
		container.replaceChildren();
		return;
	}
	const base = baseInputs(transcript);
	if (!base || !transcript.hostSignatureB64 || !transcript.exchangeHash) {
		container.replaceChildren();
		return;
	}

	const state: LabState = {
		base,
		current: { ...base },
		mutated: null,
		genuineH: transcript.exchangeHash,
		signatureB64: transcript.hostSignatureB64,
	};

	container.replaceChildren();
	container.innerHTML = shell();
	const tilesWrap = container.querySelector<HTMLElement>('.hlab-tiles')!;
	const hOut = container.querySelector<HTMLElement>('.hlab-h-value')!;
	const verdictOut = container.querySelector<HTMLElement>('.hlab-verdict')!;
	const resetBtn = container.querySelector<HTMLButtonElement>('.hlab-reset')!;

	async function recompute(): Promise<void> {
		const H = await recomputeExchangeHash(state.current);
		const changed = H !== state.genuineH;
		// The signature was made over the GENUINE H. Verify it against the H we
		// just recomputed from (possibly mutated) inputs — this is exactly what
		// the client does, and it fails the moment any bound field differs.
		const sigOk = await verifyHostSignature(state.current.hostPubJwk, H, state.signatureB64);

		hOut.textContent = H;
		hOut.classList.toggle('hlab-h-value--changed', changed);

		if (!state.mutated) {
			verdictOut.className = 'hlab-verdict hlab-verdict--ok';
			verdictOut.innerHTML = `<span class="hlab-verdict-badge">SIGNATURE OK</span> H matches the value the host signed. The host proved it owns the key — authentication succeeds.`;
		} else if (sigOk) {
			// Should not happen for a genuine substitution, but be honest if it does.
			verdictOut.className = 'hlab-verdict hlab-verdict--ok';
			verdictOut.innerHTML = `<span class="hlab-verdict-badge">SIGNATURE OK</span> Unexpectedly still valid.`;
		} else {
			verdictOut.className = 'hlab-verdict hlab-verdict--fail';
			verdictOut.innerHTML = `<span class="hlab-verdict-badge">SIGNATURE FAIL</span> You swapped <strong>${labelFor(state.mutated)}</strong>, so H changed. The host's signature was over the ORIGINAL H — it no longer verifies. <strong>This is why one host signature authenticates the whole handshake:</strong> a MITM can't substitute any bound field without breaking it.`;
		}
		paintTiles();
	}

	function paintTiles(): void {
		tilesWrap.innerHTML = TILES.map((t) => {
			const mutated = state.mutated === t.key;
			const cls = mutated ? 'hlab-tile hlab-tile--mutated' : 'hlab-tile';
			const val = tileValuePreview(t.key, state.current);
			const action = mutated
				? `<span class="hlab-tile-tag">swapped by attacker</span>`
				: `<button type="button" class="hlab-swap" data-key="${t.key}" ${state.mutated ? 'disabled' : ''}>Swap this field</button>`;
			return `
				<div class="${cls}">
					<p class="hlab-tile-title">${t.title}</p>
					<p class="hlab-tile-blurb">${t.blurb}</p>
					<code class="hlab-tile-val">${val}</code>
					${action}
				</div>`;
		}).join('');
		tilesWrap.querySelectorAll<HTMLButtonElement>('.hlab-swap').forEach((btn) => {
			btn.addEventListener('click', () => {
				void (async () => {
					const key = btn.dataset.key as TileKey;
					const forged = await forgedValue(key, state.base);
					state.current = { ...state.base, ...forged };
					state.mutated = key;
					await recompute();
				})();
			});
		});
	}

	resetBtn.addEventListener('click', () => {
		state.current = { ...state.base };
		state.mutated = null;
		void recompute();
	});

	paintTiles();
	void recompute();
}

function labelFor(key: TileKey): string {
	return TILES.find((t) => t.key === key)?.title ?? key;
}

function shell(): string {
	const { sig } = algoNames();
	return `
		<details class="hash-lab" open>
			<summary>Exchange-hash binding — why one signature covers everything</summary>
			<p class="hlab-intro">The server signs a single hash <code>H</code>. These five fields feed into it. Swap any one — as a man-in-the-middle would — and watch <code>H</code> change and the real ${sig} signature stop verifying, in the same frame.</p>
			<div class="hlab-flow">
				<div class="hlab-tiles" role="group" aria-label="Exchange hash inputs"></div>
				<div class="hlab-arrow" aria-hidden="true">▼ feeds into ▼</div>
				<div class="hlab-h">
					<p class="hlab-h-label">H = SHA256( host name ∥ host pubkey ∥ client eph ∥ server eph ∥ shared secret )</p>
					<code class="hlab-h-value" aria-label="Computed exchange hash H"></code>
				</div>
				<p class="hlab-verdict hlab-verdict--ok" role="status" aria-live="polite"></p>
			</div>
			<div class="hlab-actions">
				<button type="button" class="tab-button hlab-reset">Restore the genuine handshake</button>
			</div>
			<p class="hlab-foot">Real SHA-256 over the canonical wire encoding, then a real Web Crypto signature verify — the identical check the client runs in step "Host signature" above. Nothing here is simulated.</p>
		</details>`;
}

// ui.ts — SSH Handshake & known_hosts demo UI.
//
// Mounts a single `mountApp(root)` that renders the whole demo. State (the
// running server, the client with its known_hosts pin map, and the latest
// connect result) lives in a closure and is mutated by event handlers.

import {
	SshServer,
	SshClient,
	makeMitm,
	algoNames,
	type ConnectResult,
	type ServerHello,
	type HostPublic,
} from './engine.ts';
import {
	clearKnownHosts,
	connectWithPolicy,
	explainMode,
	findPin,
	knownHostsLine,
	removePin,
	sshKeygenF,
	sshKeyType,
	type StrictMode,
	type PolicyConnectResult,
} from './policy.ts';
import { shortBytes, tapResponder, type Transcript } from './transcript.ts';
import {
	clearSshfp,
	lookupSshfp,
	poisonSshfp,
	publishSshfp,
	verifySshfp,
} from './sshfp.ts';
import { HostCA, verifyCert, caAlgo, type HostCert } from './ca.ts';
import { sshKeyTypeFromSigAlgo, sshfpRecord, sshPublicKeyBlob } from './wire.ts';
import {
	CITATIONS,
	HANDSHAKE_CONCEPTS,
	OPENSSH_CROSSWALK,
	REAL_WORLD,
	SCOPE,
	THREE_TRUST_MODELS,
	TOFU_LESSONS,
} from './data.ts';

function el<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	className?: string,
	html?: string,
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (html !== undefined) node.innerHTML = html;
	return node;
}

const HOST_NAME = 'server.example.com';

interface AppState {
	server: SshServer | null;
	client: SshClient;
	mode: StrictMode;
	ca: HostCA | null;
	caTrusted: boolean;             // @cert-authority pin
	currentCert: HostCert | null;   // cert signing this server's pubkey
	lastResult: ConnectResult | null;
	lastResultLabel: string;
	lastTranscript: Transcript | null;
	pending: PolicyConnectResult['pendingFirstContact'] | null;
	pendingLabel: string;
	rerenderSetup: () => void;
	rerenderConnect: () => void;
	rerenderScenarios: () => void;
	logScenario: (msg: string) => void;
}

async function ensureServer(state: AppState): Promise<SshServer> {
	if (!state.server) {
		state.server = await SshServer.create(HOST_NAME);
	}
	return state.server;
}

// ---------- 1. Hero ----------------------------------------------------------

function renderHero(): HTMLElement {
	const hero = el('section', 'hero-panel');
	const { kex, sig } = algoNames();
	hero.innerHTML = `
		<button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light mode">🌙</button>
		<div class="hero-copy">
			<p class="eyebrow">Trust · SSH / TOFU</p>
			<h1>SSH Handshake &amp; known_hosts</h1>
			<p class="hero-text">
				SSH has no CA and no web of trust. The first time you connect to a server, your
				client sees its long-term host key, asks <em>are you sure?</em>, and — if you say
				yes — pins the fingerprint forever. Every connection after that compares the
				presented key to the pin and refuses if it changed. That single check, called
				<strong>Trust On First Use</strong>, is how SSH gets server authentication without
				a central authority. The handshake underneath uses real ephemeral ECDH for forward
				secrecy and a host signature to prove key ownership — and this demo runs both with
				the Web Crypto API in your browser.
			</p>
			<details class="why-details">
				<summary>Why does SSH ask "are you sure?" the first time?</summary>
				<p>
					Because it cannot know. There is no trusted third party telling the client what
					the real host key is supposed to be. The prompt is SSH being honest about that:
					the very first connection is a leap of faith. Once you say yes, the key is
					pinned into <code>~/.ssh/known_hosts</code> and any future swap will be loudly
					rejected — but the first answer has to come from you, ideally after verifying
					the fingerprint somewhere outside the SSH session itself.
				</p>
			</details>
		</div>
		<div class="hero-metric-card">
			<p class="hero-metric-label">At a glance</p>
			<p class="hero-metric-value">Real ${kex} + ${sig} · forward-secret handshake · trust on first use</p>
			<p class="hero-metric-note">Every step in this demo is a real cryptographic operation: ephemeral key agreement, exchange-hash binding, host signature, fingerprint compare. TOFU is a policy on top of that real crypto, not a substitute for it.</p>
		</div>
	`;
	return hero;
}

// ---------- 2. Start the server ---------------------------------------------

function renderSetupSection(state: AppState): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'setup';
	section.setAttribute('aria-labelledby', 'setup-heading');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 1</p>
				<h2 id="setup-heading">Start the server</h2>
				<p class="panel-copy">A real sshd is a long-running process that holds a host key for years. In this demo, click <strong>Start SSH server</strong> to generate one in your browser. The fingerprint you see is the same kind of <code>SHA256:</code> identity that <code>ssh-keyscan</code> would print.</p>
			</div>
		</div>
		<div class="ssh-actions">
			<button id="start-btn" class="tab-button" type="button">Start SSH server</button>
			<button id="restart-btn" class="tab-button" type="button" hidden>Restart with a new host key</button>
			<span id="start-status" class="ssh-status"></span>
		</div>
		<div id="host-display" class="ssh-host-display"></div>
		<div id="sshfp-display" class="ssh-host-display"></div>
		<div id="ca-display" class="ssh-host-display"></div>
	`;

	const startBtn = section.querySelector<HTMLButtonElement>('#start-btn')!;
	const restartBtn = section.querySelector<HTMLButtonElement>('#restart-btn')!;
	const status = section.querySelector<HTMLElement>('#start-status')!;
	const host = section.querySelector<HTMLElement>('#host-display')!;
	const sshfpDisplay = section.querySelector<HTMLElement>('#sshfp-display')!;
	const caDisplay = section.querySelector<HTMLElement>('#ca-display')!;

	function refresh(): void {
		if (!state.server) {
			host.innerHTML = `<p class="panel-copy ssh-empty">No server running yet. The handshake needs a host key — generate one to continue.</p>`;
			sshfpDisplay.innerHTML = '';
			caDisplay.innerHTML = '';
			startBtn.hidden = false;
			restartBtn.hidden = true;
			return;
		}
		const id = state.server.publicIdentity();
		host.innerHTML = `
			<div class="host-card">
				<p class="host-card-label">Host identity</p>
				<p class="host-card-name">${id.name}</p>
				<p class="host-card-fp" aria-label="Host key fingerprint"><span class="fp-tag">${algoNames().sig}</span><code>${id.fingerprint}</code></p>
				<p class="panel-copy">This is the server's long-term identity. Every legitimate connection to <code>${id.name}</code> should present exactly this fingerprint.</p>
			</div>
		`;
		sshfpDisplay.innerHTML = renderSshfpCard(state);
		const publishBtn = sshfpDisplay.querySelector<HTMLButtonElement>('#sshfp-publish');
		const sshfpRemoveBtn = sshfpDisplay.querySelector<HTMLButtonElement>('#sshfp-remove');
		publishBtn?.addEventListener('click', () => {
			if (!state.server) return;
			const dnssec = (sshfpDisplay.querySelector<HTMLInputElement>('#sshfp-dnssec'))?.checked ?? true;
			publishSshfp(HOST_NAME, state.server.publicIdentity().fingerprint, dnssec);
			state.rerenderSetup();
			state.rerenderConnect();
		});
		sshfpRemoveBtn?.addEventListener('click', () => {
			clearSshfp();
			state.rerenderSetup();
			state.rerenderConnect();
		});

		caDisplay.innerHTML = renderCaCard(state);
		caDisplay.querySelector<HTMLButtonElement>('#ca-start')?.addEventListener('click', () => {
			void (async () => {
				state.ca = await HostCA.create('Acme Internal CA');
				state.caTrusted = false;
				state.currentCert = null;
				state.rerenderSetup();
				state.rerenderConnect();
			})();
		});
		caDisplay.querySelector<HTMLButtonElement>('#ca-trust')?.addEventListener('click', () => {
			state.caTrusted = !state.caTrusted;
			state.rerenderSetup();
			state.rerenderConnect();
		});
		caDisplay.querySelector<HTMLButtonElement>('#ca-sign')?.addEventListener('click', () => {
			void (async () => {
				if (!state.ca || !state.server) return;
				state.currentCert = await state.ca.sign(HOST_NAME, state.server.publicIdentity().hostPubJwk);
				state.rerenderSetup();
				state.rerenderConnect();
			})();
		});
		caDisplay.querySelector<HTMLButtonElement>('#ca-clear')?.addEventListener('click', () => {
			state.ca = null;
			state.caTrusted = false;
			state.currentCert = null;
			state.rerenderSetup();
			state.rerenderConnect();
		});
		startBtn.hidden = true;
		restartBtn.hidden = false;
	}

	state.rerenderSetup = refresh;
	refresh();

	async function start(message: string): Promise<void> {
		startBtn.disabled = true;
		restartBtn.disabled = true;
		startBtn.setAttribute('aria-busy', 'true');
		status.textContent = 'Generating host key…';
		try {
			state.server = await SshServer.create(HOST_NAME);
			status.textContent = message;
			state.rerenderSetup();
			state.rerenderConnect();
			state.rerenderScenarios();
		} catch (err) {
			status.textContent = `Failed: ${(err as Error).message}`;
		} finally {
			startBtn.disabled = false;
			restartBtn.disabled = false;
			startBtn.removeAttribute('aria-busy');
		}
	}

	startBtn.addEventListener('click', () => {
		void start(`Host key generated using ${algoNames().sig}.`);
	});
	restartBtn.addEventListener('click', () => {
		void start('New host key generated. Reconnect to see the pinned key warning.');
	});

	return section;
}

// ---------- 3. Connect (handshake) ------------------------------------------

function renderConnectSection(state: AppState): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'connect';
	section.setAttribute('aria-labelledby', 'connect-heading');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 2</p>
				<h2 id="connect-heading">Connect</h2>
				<p class="panel-copy">Run the handshake. The client makes an ephemeral key, the server replies with its ephemeral key plus a signature over the exchange hash, and the client verifies the signature and applies the <code>known_hosts</code> policy.</p>
			</div>
		</div>
		<fieldset class="ssh-mode" aria-describedby="mode-help">
			<legend class="ssh-mode-legend">StrictHostKeyChecking</legend>
			<div id="mode-controls" role="radiogroup" aria-label="StrictHostKeyChecking mode" class="ssh-mode-row"></div>
			<p id="mode-help" class="ssh-mode-help"></p>
		</fieldset>
		<div class="ssh-actions">
			<button id="connect-btn" class="tab-button" type="button">ssh ${HOST_NAME}</button>
			<button id="forget-btn" class="tab-button" type="button">ssh-keygen -R ${HOST_NAME}</button>
			<button id="reset-btn" class="tab-button" type="button">Reset known_hosts only</button>
			<button id="reset-all-btn" class="tab-button" type="button">Reset everything</button>
			<span id="connect-status" class="ssh-status" aria-live="polite"></span>
		</div>
		<div id="connect-pending" class="ssh-output" aria-live="polite"></div>
		<div id="connect-result" class="ssh-output" aria-live="polite"></div>
		<div id="connect-pins" class="ssh-pins-wrap"></div>
	`;

	const connectBtn = section.querySelector<HTMLButtonElement>('#connect-btn')!;
	const forgetBtn = section.querySelector<HTMLButtonElement>('#forget-btn')!;
	const resetBtn = section.querySelector<HTMLButtonElement>('#reset-btn')!;
	const resetAllBtn = section.querySelector<HTMLButtonElement>('#reset-all-btn')!;
	const status = section.querySelector<HTMLElement>('#connect-status')!;
	const modeControls = section.querySelector<HTMLElement>('#mode-controls')!;
	const modeHelp = section.querySelector<HTMLElement>('#mode-help')!;
	const pendingBox = section.querySelector<HTMLElement>('#connect-pending')!;
	const resultBox = section.querySelector<HTMLElement>('#connect-result')!;
	const pinsBox = section.querySelector<HTMLElement>('#connect-pins')!;

	function renderModeControls(): void {
		const modes: { value: StrictMode; label: string }[] = [
			{ value: 'yes', label: 'yes' },
			{ value: 'ask', label: 'ask' },
			{ value: 'accept-new', label: 'accept-new' },
			{ value: 'no', label: 'no' },
		];
		modeControls.innerHTML = modes
			.map((m) => {
				const active = state.mode === m.value;
				return `<button type="button" role="radio" aria-checked="${active}" tabindex="${active ? '0' : '-1'}" class="mode-pill ${active ? 'is-active' : ''}" data-mode="${m.value}">${m.label}</button>`;
			})
			.join('');
		modeHelp.textContent = explainMode(state.mode);
	}

	modeControls.addEventListener('click', (e) => {
		const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('.mode-pill');
		if (!btn) return;
		state.mode = btn.dataset.mode as StrictMode;
		state.pending = null;
		state.pendingLabel = '';
		renderModeControls();
		refresh();
	});

	modeControls.addEventListener('keydown', (e) => {
		if (!(e.target as HTMLElement).classList.contains('mode-pill')) return;
		const pills = Array.from(modeControls.querySelectorAll<HTMLButtonElement>('.mode-pill'));
		const idx = pills.indexOf(e.target as HTMLButtonElement);
		let next = -1;
		switch (e.key) {
			case 'ArrowRight':
			case 'ArrowDown':
				next = (idx + 1) % pills.length;
				break;
			case 'ArrowLeft':
			case 'ArrowUp':
				next = (idx - 1 + pills.length) % pills.length;
				break;
			case 'Home':
				next = 0;
				break;
			case 'End':
				next = pills.length - 1;
				break;
			default:
				return;
		}
		e.preventDefault();
		const target = pills[next]!;
		state.mode = target.dataset.mode as StrictMode;
		state.pending = null;
		state.pendingLabel = '';
		renderModeControls();
		refresh();
		target.focus();
	});

	function refresh(): void {
		if (!state.server) {
			resultBox.innerHTML = `<p class="panel-copy ssh-empty">Start the server first, then run the handshake.</p>`;
			pendingBox.innerHTML = '';
			pinsBox.replaceChildren(renderKnownHosts(state));
			connectBtn.disabled = true;
			forgetBtn.disabled = true;
			return;
		}
		connectBtn.disabled = false;
		const pinned = findPin(state.client, HOST_NAME);
		forgetBtn.disabled = !pinned;
		connectBtn.textContent = pinned ? `ssh ${HOST_NAME} (reconnect)` : `ssh ${HOST_NAME}`;

		if (state.pending) {
			pendingBox.innerHTML = renderPendingPrompt(state.pending, state.pendingLabel);
			wirePendingButtons();
		} else {
			pendingBox.innerHTML = '';
		}

		if (state.lastResult) {
			resultBox.innerHTML = renderConnectResult(state.lastResult, state.lastResultLabel)
				+ renderTranscript(state.lastTranscript, state.lastResult);
		} else if (!state.pending) {
			const hint = pinned
				? `<p class="panel-copy ssh-empty">Click <strong>ssh ${HOST_NAME} (reconnect)</strong> — the pinned fingerprint should match.</p>`
				: `<p class="panel-copy ssh-empty">Click <strong>ssh ${HOST_NAME}</strong> to run the first connection. ${state.mode === 'ask' ? 'Mode <code>ask</code> will prompt you on first contact.' : ''}</p>`;
			resultBox.innerHTML = hint;
		} else {
			resultBox.innerHTML = '';
		}
		pinsBox.replaceChildren(renderKnownHosts(state));
	}

	function wirePendingButtons(): void {
		const acceptBtn = pendingBox.querySelector<HTMLButtonElement>('#pending-accept');
		const rejectBtn = pendingBox.querySelector<HTMLButtonElement>('#pending-reject');
		const verifyBtn = pendingBox.querySelector<HTMLButtonElement>('#pending-verify');
		const sshfpBtn = pendingBox.querySelector<HTMLButtonElement>('#pending-sshfp');
		acceptBtn?.addEventListener('click', () => {
			state.pending?.accept();
			completePending(true, 'Fingerprint accepted — host pinned in known_hosts.');
		});
		rejectBtn?.addEventListener('click', () => {
			state.pending?.reject();
			completePending(false, 'Fingerprint rejected — connection refused. known_hosts unchanged.');
		});
		verifyBtn?.addEventListener('click', () => {
			state.pending?.accept();
			completePending(true, 'Fingerprint matches the out-of-band reference — host pinned. (Safe TOFU bootstrap.)');
		});
		sshfpBtn?.addEventListener('click', () => {
			const fp = state.pending?.presentedFingerprint;
			if (!fp) return;
			const verdict = verifySshfp(HOST_NAME, fp);
			if (verdict.kind === 'match') {
				state.pending?.accept();
				completePending(true, 'SSHFP+DNSSEC match — host pinned via VerifyHostKeyDNS. Real bootstrap of trust.');
			} else if (verdict.kind === 'match-unsigned') {
				state.pending?.accept();
				completePending(true, 'SSHFP matched but without DNSSEC — pinned anyway. WARNING: a DNS-spoofing attacker could have produced this record.');
			} else {
				state.pending?.reject();
				completePending(false, 'SSHFP verdict was not a clean match — refusing the connection.');
			}
		});
	}

	function completePending(accepted: boolean, message: string): void {
		// Promote the held result into the lastResult slot with the new decision baked in.
		if (state.lastTranscript && state.lastResult) {
			const decision = accepted ? 'tofu-pinned' : 'unknown';
			state.lastResult = {
				...state.lastResult,
				hostKeyDecision: decision,
				connected: accepted && state.lastResult.signatureValid && state.lastResult.sharedAgrees,
				summary: accepted
					? 'Connected (first use) — host key pinned by explicit user decision.'
					: 'REJECTED — user declined the fingerprint on first contact.',
				steps: [
					...state.lastResult.steps.slice(0, -1),
					{
						label: accepted ? 'known_hosts (user accepted)' : 'known_hosts (user rejected)',
						detail: accepted
							? `User accepted ${findPin(state.client, HOST_NAME)} for "${HOST_NAME}".`
							: `User rejected the presented fingerprint for "${HOST_NAME}".`,
						ok: accepted,
					},
				],
			};
		}
		state.pending = null;
		state.pendingLabel = '';
		status.textContent = message;
		refresh();
		state.rerenderScenarios();
	}

	state.rerenderConnect = refresh;
	renderModeControls();
	refresh();

	connectBtn.addEventListener('click', () => {
		void (async () => {
			if (!state.server) return;
			connectBtn.disabled = true;
			status.textContent = 'Running handshake…';
			try {
				const pinnedBefore = state.client.knownHosts.has(HOST_NAME);
				const tap = tapResponder(HOST_NAME, state.server, algoNames());

				// CA path takes priority over TOFU: if the host presents a cert AND
				// the client trusts the issuing CA, the cert verification IS the
				// trust decision — known_hosts is bypassed entirely.
				if (state.currentCert && state.caTrusted && state.ca && state.server) {
					// Run the engine handshake to get sig/sharedSecret confirmation,
					// but DON'T use the engine's TOFU decision — we'll override.
					// Use a fresh sub-client so the engine's pin logic doesn't fire.
					const subClient = new SshClient();
					const engineResult = await subClient.connect(HOST_NAME, tap);
					const verdict = await verifyCert(
						state.currentCert,
						state.ca.publicIdentity().pubJwk,
						HOST_NAME,
						state.server.publicIdentity().hostPubJwk,
					);
					state.lastResult = {
						...engineResult,
						hostKeyDecision: verdict.valid ? 'matches-known' : 'CHANGED-REJECTED',
						connected: verdict.valid && engineResult.signatureValid && engineResult.sharedAgrees,
						summary: verdict.valid
							? `Connected via @cert-authority. ${verdict.reason}`
							: `REJECTED — cert verification failed: ${verdict.reason}`,
						steps: [
							...engineResult.steps.slice(0, -1),
							{
								label: verdict.valid ? '@cert-authority' : '@cert-authority (rejected)',
								detail: verdict.reason,
								ok: verdict.valid,
							},
						],
					};
					state.lastTranscript = tap.transcript;
					state.lastResultLabel = `Cert-authority (mode=${state.mode})`;
					state.pending = null;
					state.pendingLabel = '';
					status.textContent = state.lastResult.connected
						? 'Connected via @cert-authority. TOFU was not consulted.'
						: state.lastResult.summary;
					state.rerenderConnect();
					state.rerenderScenarios();
					return;
				}

				const policyResult = await connectWithPolicy(state.client, HOST_NAME, tap, state.mode);
				state.lastResult = policyResult.result;
				state.lastTranscript = tap.transcript;
				state.lastResultLabel = pinnedBefore ? `Reconnect (mode=${state.mode})` : `First contact (mode=${state.mode})`;
				if (policyResult.pendingFirstContact) {
					state.pending = policyResult.pendingFirstContact;
					state.pendingLabel = 'First contact';
					status.textContent = 'Awaiting explicit accept/reject decision.';
				} else {
					state.pending = null;
					state.pendingLabel = '';
					status.textContent = policyResult.connected ? 'Connection established.' : policyResult.result.summary;
				}
				state.rerenderConnect();
				state.rerenderScenarios();
			} catch (err) {
				status.textContent = `Failed: ${(err as Error).message}`;
			} finally {
				connectBtn.disabled = false;
			}
		})();
	});

	forgetBtn.addEventListener('click', () => {
		if (!findPin(state.client, HOST_NAME)) return;
		removePin(state.client, HOST_NAME);
		state.lastResult = null;
		state.lastTranscript = null;
		state.pending = null;
		state.pendingLabel = '';
		status.textContent = `ssh-keygen -R: removed pin for ${HOST_NAME}. Next connect will be first contact again.`;
		state.rerenderConnect();
		state.rerenderScenarios();
	});

	resetBtn.addEventListener('click', () => {
		clearKnownHosts(state.client);
		state.lastResult = null;
		state.lastTranscript = null;
		state.pending = null;
		state.pendingLabel = '';
		status.textContent = 'known_hosts cleared. The next connection will be first contact again.';
		state.rerenderConnect();
		state.rerenderScenarios();
	});

	resetAllBtn.addEventListener('click', () => {
		state.client = new SshClient();
		state.server = null;
		state.ca = null;
		state.caTrusted = false;
		state.currentCert = null;
		clearSshfp();
		state.lastResult = null;
		state.lastTranscript = null;
		state.pending = null;
		state.pendingLabel = '';
		state.mode = 'ask';
		status.textContent = 'Reset complete. Server stopped, CA forgotten, SSHFP cleared, known_hosts emptied.';
		state.rerenderSetup();
		state.rerenderConnect();
		state.rerenderScenarios();
	});

	return section;
}

function renderPendingPrompt(pending: NonNullable<PolicyConnectResult['pendingFirstContact']>, label: string): string {
	const fp = pending.presentedFingerprint;
	const sshfp = lookupSshfp(HOST_NAME);
	let sshfpAction = '';
	let sshfpHint = '';
	if (sshfp) {
		const verdict = verifySshfp(HOST_NAME, fp);
		if (verdict.kind === 'match') {
			sshfpAction = `<button id="pending-sshfp" class="tab-button" type="button" title="VerifyHostKeyDNS=yes — DNSSEC-signed SSHFP record agrees with the presented fingerprint">Verify via SSHFP (DNSSEC ✓) — accept automatically</button>`;
			sshfpHint = `<p class="ssh-warning-body">A DNSSEC-signed SSHFP record for ${HOST_NAME} is on file and matches the presented fingerprint — safe to accept on first contact.</p>`;
		} else if (verdict.kind === 'match-unsigned') {
			sshfpAction = `<button id="pending-sshfp" class="tab-button" type="button" title="Matches an SSHFP record served without DNSSEC — the record itself is forgeable">Verify via SSHFP (no DNSSEC — risky) — accept</button>`;
			sshfpHint = `<p class="ssh-warning-body">An SSHFP record matches, but it was served WITHOUT DNSSEC. A DNS-spoofing attacker can serve their own fingerprint here. Not a real verification.</p>`;
		} else if (verdict.kind === 'mismatch') {
			sshfpHint = `<p class="ssh-warning-body"><strong>SSHFP MISMATCH:</strong> DNS publishes <code>${verdict.record.fingerprint}</code> for ${HOST_NAME}, but the server presented <code>${verdict.presented}</code>. Either the server rotated keys without updating DNS, or this is an attack. Reject.</p>`;
		}
	}
	return `
		<div class="ssh-warning ssh-warning--pending" role="alert">
			<p class="ssh-warning-title">${label}: The authenticity of host "${HOST_NAME}" can't be established.</p>
			<p class="ssh-warning-body">
				Host key fingerprint is <code>${fp}</code>.<br>
				Are you sure you want to continue connecting (yes/no/[verify])?
				This is what OpenSSH prints — TOFU at this moment is a leap of faith.
			</p>
			${sshfpHint}
			<div class="pending-actions">
				<button id="pending-accept" class="tab-button" type="button">Accept (yes) — pin and connect</button>
				<button id="pending-reject" class="tab-button" type="button">Reject (no) — refuse the connection</button>
				<button id="pending-verify" class="tab-button" type="button" title="Simulates: the fingerprint matches what your operator told you out of band">Verify out of band ✓ — fingerprint matches my reference</button>
				${sshfpAction}
			</div>
		</div>
	`;
}

function renderCertFields(c: HostCert): string {
	const opts = Object.keys(c.criticalOptions).length === 0 ? '(none)' : JSON.stringify(c.criticalOptions);
	const exts = Object.keys(c.extensions).length === 0 ? '(none)' : JSON.stringify(c.extensions);
	return `
		<details class="known-hosts-file" open>
			<summary>ssh-keygen -L -f host_key-cert.pub</summary>
			<dl class="sshfp-grid cert-grid">
				<dt>type</dt><dd><code>ssh-${caAlgo() === 'Ed25519' ? 'ed25519' : 'ecdsa-sha2-nistp256'}-cert-v01@openssh.com host certificate</code></dd>
				<dt>signing CA</dt><dd><code>${c.issuer} (${c.issuerFingerprint})</code></dd>
				<dt>key ID</dt><dd><code>"${c.keyId}"</code></dd>
				<dt>serial</dt><dd><code>${c.serial}</code></dd>
				<dt>nonce</dt><dd><code>${shortBytes(c.nonce, 16, 8)}</code></dd>
				<dt>principals</dt><dd><code>${c.validPrincipals.join(', ')}</code></dd>
				<dt>valid after</dt><dd><code>${c.validAfter}</code></dd>
				<dt>valid before</dt><dd><code>${c.validBefore}</code></dd>
				<dt>critical options</dt><dd><code>${opts}</code></dd>
				<dt>extensions</dt><dd><code>${exts}</code></dd>
				<dt>signature</dt><dd><code>${shortBytes(c.signature, 24, 12)}</code></dd>
			</dl>
			<p class="kh-hint">Same field set as <code>ssh-keygen -L</code> prints for a real OpenSSH host certificate. The on-disk format is an SSH-wire-format blob; this demo encodes the same fields in JSON for readability.</p>
		</details>
	`;
}

function renderCaCard(state: AppState): string {
	if (!state.ca) {
		return `
			<div class="host-card sshfp-card">
				<p class="host-card-label">OpenSSH @cert-authority (not configured)</p>
				<p class="panel-copy">Start a host CA to demonstrate the certificate-based trust path. The CA signs the host's pubkey, the client trusts the CA via <code>@cert-authority</code>, and TOFU is skipped entirely. This is how organizations run SSH fleets without exhausting their users on host-key warnings.</p>
				<div class="pending-actions">
					<button id="ca-start" class="tab-button" type="button">Start a host CA</button>
				</div>
			</div>
		`;
	}
	const id = state.ca.publicIdentity();
	const certInfo = state.currentCert
		? renderCertFields(state.currentCert)
		: '<p class="panel-copy ssh-empty">No certificate signed yet.</p>';
	return `
		<div class="host-card sshfp-card">
			<p class="host-card-label">OpenSSH @cert-authority CA</p>
			<p class="host-card-name">${id.name}</p>
			<p class="host-card-fp"><span class="fp-tag">${caAlgo()}</span><code>${id.fingerprint}</code></p>
			<p class="panel-copy">CA trust state: ${state.caTrusted ? '<strong>trusted (@cert-authority pinned)</strong>' : '<strong>not yet trusted</strong>'}.</p>
			<h4 class="ssh-section-h ca-cert-h">Host certificate</h4>
			${certInfo}
			<div class="pending-actions">
				<button id="ca-trust" class="tab-button" type="button">${state.caTrusted ? 'Untrust CA' : 'Trust CA (@cert-authority)'}</button>
				<button id="ca-sign" class="tab-button" type="button">Sign host pubkey with CA</button>
				<button id="ca-clear" class="tab-button" type="button">Forget CA</button>
			</div>
		</div>
	`;
}

function renderSshfpCard(state: AppState): string {
	const rec = lookupSshfp(HOST_NAME);
	let rrLine = '(record not yet published)';
	if (rec && state.server) {
		// Best-effort RR rendering — uses the current host's actual blob.
		const id = state.server.publicIdentity();
		try {
			const sig = algoNames().sig;
			const blob = sshPublicKeyBlob(id.hostPubJwk, sig);
			const keyType = sshKeyTypeFromSigAlgo(sig);
			// sshfpRecord is async; we render synchronously here, so embed an
			// async stub that the page will replace via a data attribute.
			rrLine = `<span data-sshfp-rr data-keytype="${keyType}"></span>`;
			void sshfpRecord(HOST_NAME, blob, keyType).then((r) => {
				const span = document.querySelector(`[data-sshfp-rr][data-keytype="${keyType}"]`);
				if (span) span.textContent = r.rr;
			});
		} catch {
			rrLine = '(RR rendering unavailable for this algorithm)';
		}
	}
	const body = rec
		? `
			<p class="host-card-label">SSHFP DNS record (published)</p>
			<dl class="sshfp-grid">
				<dt>name</dt><dd><code>${rec.hostName}</code></dd>
				<dt>fingerprint</dt><dd><code>${rec.fingerprint}</code></dd>
				<dt>signed</dt><dd>${rec.dnssecSigned ? '<code>DNSSEC ✓ trustworthy channel</code>' : '<code class="warn">unsigned — DNS-spoofable</code>'}</dd>
				<dt>dig output</dt><dd><pre class="kh-file"><code>${rrLine}</code></pre></dd>
			</dl>
			<p class="kh-hint">SSHFP RDATA: <code>&lt;algorithm&gt; &lt;fp-type&gt; &lt;hex-fingerprint&gt;</code>. Algorithm 4 = Ed25519, 3 = ECDSA. fp-type 2 = SHA-256. (RFC 4255 + RFC 7479.)</p>
			<div class="pending-actions">
				<button id="sshfp-remove" class="tab-button" type="button">Remove SSHFP record</button>
			</div>
		`
		: `
			<p class="host-card-label">SSHFP DNS record (not published)</p>
			<p class="panel-copy">Publish the host fingerprint as an SSHFP DNS record (RFC 4255) so that clients with <code>VerifyHostKeyDNS=yes</code> can skip the first-contact prompt. With DNSSEC, this is a real bootstrap of trust. Without DNSSEC, it is the same gamble as TOFU.</p>
			<div class="pending-actions sshfp-publish-row">
				<label class="sshfp-dnssec-label">
					<input type="checkbox" id="sshfp-dnssec" checked />
					<span>publish with DNSSEC</span>
				</label>
				<button id="sshfp-publish" class="tab-button" type="button">Publish SSHFP record</button>
			</div>
		`;
	return `<div class="host-card sshfp-card">${body}</div>`;
}

function renderTranscript(transcript: Transcript | null, result: ConnectResult | null): string {
	if (!transcript || !result) return '';
	const fpFromHost = transcript.hostPubJwk
		? (transcript.hostPubJwk.x ?? '') + (transcript.hostPubJwk.y ?? '')
		: '(none)';
	const jwkPreview = (jwk: JsonWebKey | null): string => {
		if (!jwk) return '(none)';
		const x = jwk.x ?? '';
		const y = jwk.y ?? '';
		const kty = jwk.kty ?? '?';
		const crv = jwk.crv ?? '?';
		return `${kty}/${crv}  x=${shortBytes(x)}${y ? `  y=${shortBytes(y)}` : ''}`;
	};
	const highlight = transcriptHighlight(result);
	const rowClass = (key: keyof Transcript): string =>
		highlight.has(key) ? 'transcript-row transcript-row--changed' : 'transcript-row';

	const json = JSON.stringify(transcript, null, 2);

	return `
		<details class="transcript-inspector">
			<summary>Transcript inspector — the bytes that flowed</summary>
			<div class="transcript-grid">
				<div class="${rowClass('hostName')}"><span class="t-label">host name</span><code>${transcript.hostName}</code></div>
				<div class="${rowClass('algoKex')}"><span class="t-label">KEX algorithm</span><code>${transcript.algoKex}</code></div>
				<div class="${rowClass('algoSig')}"><span class="t-label">SIG algorithm</span><code>${transcript.algoSig}</code></div>
				<div class="${rowClass('clientEphemeralPubJwk')}"><span class="t-label">client ephemeral pubkey</span><code>${jwkPreview(transcript.clientEphemeralPubJwk)}</code></div>
				<div class="${rowClass('serverEphemeralPubJwk')}"><span class="t-label">server ephemeral pubkey</span><code>${jwkPreview(transcript.serverEphemeralPubJwk)}</code></div>
				<div class="${rowClass('hostPubJwk')}"><span class="t-label">host pubkey (long-term)</span><code>${jwkPreview(transcript.hostPubJwk)}  → ${shortBytes(fpFromHost)}</code></div>
				<div class="${rowClass('exchangeHash')}"><span class="t-label" title="Teaching surrogate — see Scope section">exchange hash H *</span><code>${transcript.exchangeHash ?? '(none)'}</code></div>
				<div class="${rowClass('hostSignatureB64')}"><span class="t-label">host signature over H</span><code>${shortBytes(transcript.hostSignatureB64, 28, 16)}</code></div>
				<div class="transcript-row"><span class="t-label">shared secret (display)</span><code>${shortBytes(transcript.sharedSecretB64, 22, 10)}</code></div>
				<div class="transcript-row"><span class="t-label">decision</span><code>${result.hostKeyDecision}</code></div>
			</div>
			<p class="transcript-footnote">* "Exchange hash H" here is a teaching surrogate. Real RFC 4253 / RFC 8731 H also commits the SSH version strings and KEX_INIT payloads that this demo does not model. See Scope &amp; provenance for the full list.</p>
			<div class="transcript-actions">
				<button class="tab-button transcript-copy" type="button" data-json='${encodeForAttr(json)}'>Copy transcript as JSON</button>
				<span class="transcript-copy-msg" aria-live="polite"></span>
			</div>
		</details>
	`;
}

function encodeForAttr(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/'/g, '&#39;').replace(/</g, '&lt;');
}

// Which transcript fields are "the smoking gun" for the failure?
function transcriptHighlight(result: ConnectResult): Set<keyof Transcript> {
	const set = new Set<keyof Transcript>();
	if (!result.signatureValid) set.add('hostSignatureB64');
	if (result.hostKeyDecision === 'CHANGED-REJECTED') set.add('hostPubJwk');
	return set;
}

function renderConnectResult(result: ConnectResult, label: string): string {
	const stepLis = result.steps
		.map((step) => {
			const cls = step.ok ? 'scenario-status--valid' : 'scenario-status--invalid';
			const badge = step.ok ? 'OK' : 'FAIL';
			return `
				<li class="handshake-step">
					<div class="handshake-step-head">
						<span class="handshake-step-label">${step.label}</span>
						<span class="handshake-step-badge ${cls}">${badge}</span>
					</div>
					<p class="handshake-step-detail">${step.detail}</p>
				</li>
			`;
		})
		.join('');

	const decisionClass = decisionAccent(result.hostKeyDecision);
	const decisionText = decisionLabel(result.hostKeyDecision);
	const banner = decisionBanner(result);

	return `
		<div class="handshake-card">
			<div class="handshake-card-head">
				<p class="hero-metric-label">${label}</p>
				<span class="handshake-decision ${decisionClass}">${decisionText}</span>
			</div>
			<ol class="handshake-step-list">${stepLis}</ol>
			${banner}
			<p class="handshake-summary">${result.summary}</p>
		</div>
	`;
}

function renderKnownHosts(state: AppState): HTMLElement {
	const wrap = el('div', 'known-hosts-pins');
	if (state.client.knownHosts.size === 0) {
		wrap.innerHTML = `
			<p class="hero-metric-label">known_hosts</p>
			<p class="panel-copy ssh-empty">Empty. First connection will pin a fingerprint here.</p>
		`;
		return wrap;
	}
	const sig = algoNames().sig;
	const currentJwk = state.lastTranscript?.hostPubJwk ?? null;
	const rows = Array.from(state.client.knownHosts.entries())
		.map(([name, fp]) => `<li class="pin-row"><span class="pin-host">${name}</span><code class="pin-fp">${fp}</code></li>`)
		.join('');
	const file = Array.from(state.client.knownHosts.entries())
		.map(([name]) => {
			// Use the captured host pubkey if it matches this name; otherwise
			// fall back to a synthesized line showing the fingerprint.
			if (currentJwk && name === HOST_NAME) {
				return knownHostsLine(name, currentJwk, sig);
			}
			return `${name} ${sshKeyType(sig)} <pinned ${state.client.knownHosts.get(name)}>`;
		})
		.join('\n');
	const grepOutput = sshKeygenF(state.client, HOST_NAME, currentJwk, sig);
	return Object.assign(wrap, {
		innerHTML: `
			<p class="hero-metric-label">known_hosts (in memory)</p>
			<ul class="pin-list">${rows}</ul>
			<details class="known-hosts-file">
				<summary>~/.ssh/known_hosts (file format — exact)</summary>
				<pre class="kh-file"><code>${file}</code></pre>
				<p class="kh-hint">Third field is base64 of the canonical OpenSSH wire-format public key blob (RFC 4253 §6.6 / RFC 8709 §4), exactly what <code>ssh-keyscan</code> produces. Real files may also use HashKnownHosts (hashed hostnames starting with <code>|1|</code>).</p>
			</details>
			<details class="known-hosts-file">
				<summary>Multi-key host: what real OpenSSH writes (illustrative)</summary>
				<pre class="kh-file"><code>${escapeHtml(multiKeyIllustration(currentJwk, sig))}</code></pre>
				<p class="kh-hint">A typical sshd offers ed25519, ecdsa, AND rsa host keys at the same hostname — your known_hosts ends up with one line per algorithm. This demo's engine runs ONE algorithm at a time, so only the ${sshKeyType(sig)} line above is the result of an actual handshake; the others are placeholders showing the file shape.</p>
			</details>
			<details class="known-hosts-file">
				<summary>ssh-keygen -F ${HOST_NAME}</summary>
				<pre class="kh-file"><code>${escapeHtml(grepOutput)}</code></pre>
			</details>
		`,
	});
}

function multiKeyIllustration(currentJwk: JsonWebKey | null, currentSig: string): string {
	const ACTIVE = sshKeyType(currentSig);
	const activeLine = currentJwk
		? knownHostsLine(HOST_NAME, currentJwk, currentSig)
		: `${HOST_NAME} ${ACTIVE} <active key>`;
	const placeholderEd25519 = `${HOST_NAME} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILLUSTRATIVEonlyNOTrealKEYbytesAAAAAAAAAAAAA`;
	const placeholderEcdsa = `${HOST_NAME} ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBILLUSTRATIVEonlyNOTrealKEYbytesAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`;
	const placeholderRsa = `${HOST_NAME} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQILLUSTRATIVEonlyNOTrealKEYbytes...`;
	const lines: string[] = ['# real-sshd lines, one per host-key algorithm:'];
	if (ACTIVE === 'ssh-ed25519') {
		lines.push(activeLine + '    # ← active in this demo');
		lines.push(placeholderEcdsa + '    # illustrative only');
	} else {
		lines.push(placeholderEd25519 + '    # illustrative only');
		lines.push(activeLine + '    # ← active in this demo');
	}
	lines.push(placeholderRsa + '    # illustrative only (RSA not modelled by Web Crypto Ed25519/ECDSA fallback)');
	return lines.join('\n');
}

function escapeHtml(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function decisionAccent(d: ConnectResult['hostKeyDecision']): string {
	switch (d) {
		case 'tofu-pinned':
			return 'scenario-status--pending';
		case 'matches-known':
			return 'scenario-status--valid';
		case 'CHANGED-REJECTED':
		case 'unknown':
		default:
			return 'scenario-status--invalid';
	}
}

function decisionLabel(d: ConnectResult['hostKeyDecision']): string {
	switch (d) {
		case 'tofu-pinned':
			return 'TOFU · pinned on first contact';
		case 'matches-known':
			return 'Matches known_hosts';
		case 'CHANGED-REJECTED':
			return 'HOST KEY CHANGED — rejected';
		case 'unknown':
		default:
			return 'Unknown host';
	}
}

function decisionBanner(result: ConnectResult): string {
	if (result.hostKeyDecision === 'CHANGED-REJECTED') {
		return `
			<div class="ssh-warning ssh-warning--bad" role="alert">
				<p class="ssh-warning-title ssh-warning-deco" aria-hidden="true">@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@</p>
				<p class="ssh-warning-title">@&nbsp;&nbsp;&nbsp;&nbsp;WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!&nbsp;&nbsp;&nbsp;&nbsp;@</p>
				<p class="ssh-warning-title ssh-warning-deco" aria-hidden="true">@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@</p>
				<p class="ssh-warning-body">IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY! Someone could be eavesdropping on you right now (man-in-the-middle attack). The host key has changed since the last time you connected. Either the host was reinstalled, or this is the attack TOFU is designed to catch.</p>
			</div>
		`;
	}
	if (!result.signatureValid) {
		return `
			<div class="ssh-warning ssh-warning--bad">
				<p class="ssh-warning-title">Host signature verification failed</p>
				<p class="ssh-warning-body">The party on the other end could not prove possession of the host private key. Either the signature was tampered with in transit or the responder does not actually hold the key it claimed. Connection refused.</p>
			</div>
		`;
	}
	if (result.hostKeyDecision === 'tofu-pinned') {
		return `
			<div class="ssh-warning ssh-warning--pending">
				<p class="ssh-warning-title">The authenticity of host “${HOST_NAME}” can’t be established.</p>
				<p class="ssh-warning-body">No fingerprint is on file for this host. Real ssh would print the fingerprint and ask <em>Are you sure you want to continue connecting (yes/no)?</em> — this demo says yes for you. From here on, this fingerprint is the trusted identity for <code>${HOST_NAME}</code>. <strong>If you skipped out-of-band verification on first contact, this could be a MITM.</strong></p>
			</div>
		`;
	}
	return '';
}

// ---------- 4. Break it (MITM scenarios) ------------------------------------

function renderScenariosSection(state: AppState): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'scenarios';
	section.setAttribute('aria-labelledby', 'scenarios-heading');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 3</p>
				<h2 id="scenarios-heading">Break it (and recover)</h2>
				<p class="panel-copy">Five scenarios. The first three are attacks; the last two are legitimate operations that trip the SAME warning — which is the dual-use lesson at the heart of TOFU. Each opens its full transcript so you can see which field was the smoking gun.</p>
			</div>
		</div>
		<div id="scenario-buttons" class="ssh-scenario-buttons"></div>
		<div id="scenario-output" class="ssh-output ssh-scenario-output" aria-live="polite"></div>
		<div id="scenario-log" class="ssh-scenario-log" aria-live="polite"></div>
	`;

	const buttons = section.querySelector<HTMLElement>('#scenario-buttons')!;
	const output = section.querySelector<HTMLElement>('#scenario-output')!;
	const log = section.querySelector<HTMLElement>('#scenario-log')!;
	const logLines: string[] = [];

	state.logScenario = (msg: string) => {
		const stamp = new Date().toLocaleTimeString();
		logLines.unshift(`[${stamp}] ${msg}`);
		log.innerHTML = logLines.slice(0, 8).map((l) => `<p class="ssh-log-line">${l}</p>`).join('');
	};

	function refresh(): void {
		if (!state.server) {
			buttons.innerHTML = `<p class="panel-copy ssh-empty">Start the server first.</p>`;
			output.innerHTML = '';
			return;
		}
		const pinned = state.client.knownHosts.has(HOST_NAME);
		const caReady = !!state.ca && state.caTrusted && !!state.currentCert;
		buttons.innerHTML = `
			<button id="scn-mitm-after" class="tab-button" type="button" ${pinned ? '' : 'disabled'}>Attack · MITM after pinning ${pinned ? '' : '— connect once first'}</button>
			<button id="scn-mitm-first" class="tab-button" type="button">Attack · MITM on first contact (fresh client)</button>
			<button id="scn-tamper" class="tab-button" type="button">Attack · Tampered host signature</button>
			<button id="scn-dns-spoof" class="tab-button" type="button">Attack · DNS spoof of SSHFP without DNSSEC</button>
			<button id="scn-rogue-ca" class="tab-button" type="button" ${caReady ? '' : 'disabled'}>Attack · Rogue CA signs the attacker's host ${caReady ? '' : '— trust a CA and sign first'}</button>
			<button id="scn-rotate-planned" class="tab-button" type="button" ${pinned ? '' : 'disabled'}>Operations · Planned key rotation (maintenance)</button>
			<button id="scn-rotate-emergency" class="tab-button" type="button" ${pinned ? '' : 'disabled'}>Operations · Emergency rotation (compromise response)</button>
			<button id="scn-rotate-ca" class="tab-button" type="button" ${caReady ? '' : 'disabled'}>Operations · Rotate host under same CA (no warning) ${caReady ? '' : '— trust a CA and sign first'}</button>
		`;

		section.querySelector<HTMLButtonElement>('#scn-mitm-after')!.addEventListener('click', () => {
			void scenarioMitmAfter(state, output);
		});
		section.querySelector<HTMLButtonElement>('#scn-mitm-first')!.addEventListener('click', () => {
			void scenarioMitmFirst(state, output);
		});
		section.querySelector<HTMLButtonElement>('#scn-tamper')!.addEventListener('click', () => {
			void scenarioTamper(state, output);
		});
		section.querySelector<HTMLButtonElement>('#scn-dns-spoof')!.addEventListener('click', () => {
			void scenarioDnsSpoof(state, output);
		});
		section.querySelector<HTMLButtonElement>('#scn-rotate-planned')!.addEventListener('click', () => {
			void scenarioRotatePlanned(state, output);
		});
		section.querySelector<HTMLButtonElement>('#scn-rotate-emergency')!.addEventListener('click', () => {
			void scenarioRotateEmergency(state, output);
		});
		section.querySelector<HTMLButtonElement>('#scn-rogue-ca')!.addEventListener('click', () => {
			void scenarioRogueCa(state, output);
		});
		section.querySelector<HTMLButtonElement>('#scn-rotate-ca')!.addEventListener('click', () => {
			void scenarioRotateUnderCa(state, output);
		});
	}

	state.rerenderScenarios = refresh;
	refresh();

	return section;
}

async function scenarioMitmAfter(state: AppState, output: HTMLElement): Promise<void> {
	await ensureServer(state);
	if (!state.client.knownHosts.has(HOST_NAME)) {
		output.innerHTML = `<p class="panel-copy ssh-empty">Connect to the real server at least once first — there is nothing for TOFU to compare against yet.</p>`;
		return;
	}
	const attacker = await makeMitm(HOST_NAME);
	const tap = tapResponder(HOST_NAME, attacker, algoNames());
	const result = await state.client.connect(HOST_NAME, tap);
	output.innerHTML = renderScenarioResult(result, 'Attack · MITM after pinning', attacker.identity)
		+ renderTranscript(tap.transcript, result);
	state.logScenario(
		result.hostKeyDecision === 'CHANGED-REJECTED'
			? 'MITM after pinning: known_hosts caught the substituted host key. Connection refused. This is the protection working.'
			: `MITM after pinning gave an unexpected decision: ${result.hostKeyDecision}.`,
	);
	state.rerenderConnect();
}

async function scenarioMitmFirst(state: AppState, output: HTMLElement): Promise<void> {
	// Fresh client with no pins models the first-contact case.
	const freshClient = new SshClient();
	const attacker = await makeMitm(HOST_NAME);
	const tap = tapResponder(HOST_NAME, attacker, algoNames());
	const result = await freshClient.connect(HOST_NAME, tap);
	output.innerHTML = renderScenarioResult(result, 'Attack · MITM on first contact (fresh client)', attacker.identity)
		+ renderTranscript(tap.transcript, result);
	state.logScenario(
		result.connected
			? 'MITM on FIRST contact: the fresh client pinned the ATTACKER’s fingerprint. TOFU cannot detect this — only out-of-band fingerprint verification can.'
			: `MITM on first contact gave an unexpected decision: ${result.hostKeyDecision}.`,
	);
}

async function scenarioTamper(state: AppState, output: HTMLElement): Promise<void> {
	const server = await ensureServer(state);
	const tampered = {
		respond: async (clientEphPubJwk: JsonWebKey): Promise<ServerHello> => {
			const hello = await server.respond(clientEphPubJwk);
			// Corrupt the signature: flip a byte after decoding.
			const bin = atob(hello.hostSignatureB64);
			const bytes = new Uint8Array(bin.length);
			for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
			if (bytes.length > 0) bytes[0] = bytes[0] ^ 0xff;
			let s = '';
			for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
			return { ...hello, hostSignatureB64: btoa(s) };
		},
	};
	const tap = tapResponder(HOST_NAME, tampered, algoNames());
	const result = await state.client.connect(HOST_NAME, tap);
	output.innerHTML = renderScenarioResult(result, 'Attack · Tampered host signature', null)
		+ renderTranscript(tap.transcript, result);
	state.logScenario(
		!result.signatureValid
			? 'Tampered host signature: the client recomputed the exchange hash, the signature did not verify, connection refused. The host could not prove key ownership.'
			: 'Tampered host signature unexpectedly verified — engine bug.',
	);
}

async function scenarioDnsSpoof(state: AppState, output: HTMLElement): Promise<void> {
	// An attacker who controls DNS (no DNSSEC) publishes their OWN host
	// fingerprint at the host's name. A fresh client that "verifies via SSHFP"
	// matches the attacker's record and pins the attacker's key.
	const attacker = await makeMitm(HOST_NAME);
	poisonSshfp(HOST_NAME, attacker.identity.fingerprint);

	const freshClient = new SshClient();
	const tap = tapResponder(HOST_NAME, attacker, algoNames());
	const policyResult = await connectWithPolicy(freshClient, HOST_NAME, tap, 'ask');
	let summary: ConnectResult;
	let pinnedFp: string | undefined;
	if (policyResult.pendingFirstContact) {
		// Simulate the user clicking "Verify via SSHFP" and getting a match.
		const verdict = verifySshfp(HOST_NAME, policyResult.pendingFirstContact.presentedFingerprint);
		if (verdict.kind === 'match' || verdict.kind === 'match-unsigned') {
			policyResult.pendingFirstContact.accept();
			pinnedFp = freshClient.knownHosts.get(HOST_NAME);
			summary = {
				...policyResult.result,
				hostKeyDecision: 'tofu-pinned',
				connected: policyResult.result.signatureValid,
				summary: verdict.kind === 'match'
					? 'Connected — SSHFP matched (DNSSEC ✓). But this is a SPOOFED record.'
					: 'Connected — SSHFP matched without DNSSEC. The user accepted the attacker’s key thinking it was verified.',
			};
		} else {
			policyResult.pendingFirstContact.reject();
			summary = policyResult.result;
		}
	} else {
		summary = policyResult.result;
	}
	output.innerHTML = renderScenarioResult(summary, 'Attack · DNS spoof of SSHFP without DNSSEC', attacker.identity)
		+ `<div class="ssh-warning ssh-warning--bad" role="alert">
			<p class="ssh-warning-title">The lesson</p>
			<p class="ssh-warning-body">
				SSHFP without DNSSEC is not real verification. The attacker controlled the DNS path, so when the client looked up the "expected" fingerprint, it got back the attacker's. The client pinned <code>${pinnedFp ?? '(none)'}</code> — the attacker's key — and now believes that's the real host. <strong>If you use VerifyHostKeyDNS, you MUST also use DNSSEC end-to-end.</strong>
			</p>
		</div>`
		+ renderTranscript(tap.transcript, summary);
	state.logScenario(
		'DNS spoof: an unsigned SSHFP record served by an attacker passes the "out of band" check and the client pins the attacker. DNSSEC is the missing ingredient.',
	);
	// Clean up the poisoned record so the rest of the demo isn't broken.
	clearSshfp();
	state.rerenderSetup();
	state.rerenderConnect();
}

async function scenarioRotateUnderCa(state: AppState, output: HTMLElement): Promise<void> {
	if (!state.ca || !state.caTrusted) {
		output.innerHTML = `<p class="panel-copy ssh-empty">Start a CA and trust it (section 1) first.</p>`;
		return;
	}
	// Rotate the host key, re-sign with the SAME CA, then connect.
	state.server = await SshServer.create(HOST_NAME);
	state.currentCert = await state.ca.sign(HOST_NAME, state.server.publicIdentity().hostPubJwk);
	const tap = tapResponder(HOST_NAME, state.server, algoNames());
	const subClient = new SshClient();
	const engineResult = await subClient.connect(HOST_NAME, tap);
	const verdict = await verifyCert(
		state.currentCert,
		state.ca.publicIdentity().pubJwk,
		HOST_NAME,
		state.server.publicIdentity().hostPubJwk,
	);
	const result: ConnectResult = {
		...engineResult,
		hostKeyDecision: verdict.valid ? 'matches-known' : 'CHANGED-REJECTED',
		connected: verdict.valid && engineResult.signatureValid,
		summary: verdict.valid
			? 'Connected via @cert-authority despite the host-key rotation. No TOFU warning fired — the CA covered it.'
			: 'REJECTED — even with the CA path, cert verification failed.',
		steps: [
			...engineResult.steps.slice(0, -1),
			{
				label: '@cert-authority',
				detail: verdict.reason,
				ok: verdict.valid,
			},
		],
	};
	output.innerHTML = renderScenarioResult(result, 'Operations · Rotate host under same CA (no warning)', state.server.publicIdentity())
		+ `<div class="ssh-warning ssh-warning--pending recovery-card" role="status">
			<p class="ssh-warning-title">Why no warning?</p>
			<p class="ssh-warning-body">The client never pinned the host key directly. It pinned the CA. As long as a new CA-signed cert names this host and binds the new pubkey, the rotation is invisible to users — exactly how OpenSSH host certificates avoid the recurring TOFU pain in fleets.</p>
		</div>`
		+ renderTranscript(tap.transcript, result);
	state.logScenario(
		'CA rotation: re-signed the rotated host key under the same trusted CA — no host-key-changed warning. This is the value @cert-authority delivers.',
	);
	state.rerenderSetup();
	state.rerenderConnect();
}

async function scenarioRogueCa(state: AppState, output: HTMLElement): Promise<void> {
	if (!state.ca || !state.caTrusted) {
		output.innerHTML = `<p class="panel-copy ssh-empty">Trust a CA and sign the host first.</p>`;
		return;
	}
	// A different CA signs an attacker's host key. The client only trusts the
	// real CA, so the rogue cert must NOT verify — even though both are
	// "certificates".
	const rogueCa = await HostCA.create('Rogue CA');
	const attacker = await makeMitm(HOST_NAME);
	const rogueCert = await rogueCa.sign(HOST_NAME, attacker.identity.hostPubJwk);
	const tap = tapResponder(HOST_NAME, attacker, algoNames());
	const subClient = new SshClient();
	const engineResult = await subClient.connect(HOST_NAME, tap);
	// The client checks the cert against the TRUSTED CA's pubkey (not the rogue one).
	const verdict = await verifyCert(
		rogueCert,
		state.ca.publicIdentity().pubJwk,
		HOST_NAME,
		attacker.identity.hostPubJwk,
	);
	const result: ConnectResult = {
		...engineResult,
		hostKeyDecision: 'CHANGED-REJECTED',
		connected: false,
		summary: 'REJECTED — rogue CA cert does not verify under the trusted CA. The attacker can mint certs but not under your trust anchor.',
		steps: [
			...engineResult.steps.slice(0, -1),
			{
				label: '@cert-authority (rejected)',
				detail: verdict.reason,
				ok: false,
			},
		],
	};
	output.innerHTML = renderScenarioResult(result, 'Attack · Rogue CA signs the attacker\'s host', attacker.identity)
		+ renderTranscript(tap.transcript, result);
	state.logScenario(
		'Rogue CA: a different CA signed the attacker\'s host. The cert is well-formed but the client\'s @cert-authority list does not include the rogue CA — rejected.',
	);
}

async function scenarioRotatePlanned(state: AppState, output: HTMLElement): Promise<void> {
	if (!state.client.knownHosts.has(HOST_NAME)) {
		output.innerHTML = `<p class="panel-copy ssh-empty">Connect to the real server at least once first — rotation only matters once there is a pin to compare against.</p>`;
		return;
	}
	// Server is reinstalled with a new host key — same name, new identity.
	state.server = await SshServer.create(HOST_NAME);
	const tap = tapResponder(HOST_NAME, state.server, algoNames());
	const result = await state.client.connect(HOST_NAME, tap);
	output.innerHTML = renderRecoverableScenario(
		result,
		'Operations · Planned key rotation (maintenance)',
		state.server.publicIdentity(),
		tap.transcript,
		`Planned rotation: the operator reinstalled the host. The warning is identical to a MITM — the difference is the operator told you in advance (and you can verify the new fingerprint out of band). Use <code>ssh-keygen -R ${HOST_NAME}</code> in section 2 to drop the stale pin, then reconnect.`,
	);
	state.logScenario(
		'Planned rotation: the SAME "host key changed" warning fires. Recovery is ssh-keygen -R + reconnect after operator verifies new fingerprint.',
	);
	state.rerenderSetup();
	state.rerenderConnect();
}

async function scenarioRotateEmergency(state: AppState, output: HTMLElement): Promise<void> {
	if (!state.client.knownHosts.has(HOST_NAME)) {
		output.innerHTML = `<p class="panel-copy ssh-empty">Connect to the real server at least once first.</p>`;
		return;
	}
	state.server = await SshServer.create(HOST_NAME);
	const tap = tapResponder(HOST_NAME, state.server, algoNames());
	const result = await state.client.connect(HOST_NAME, tap);
	output.innerHTML = renderRecoverableScenario(
		result,
		'Operations · Emergency rotation (compromise response)',
		state.server.publicIdentity(),
		tap.transcript,
		`Emergency rotation: the host private key was potentially exposed and was regenerated. Same warning — operator must distribute the new fingerprint through a channel the attacker cannot influence, then users drop the old pin and reconnect.`,
	);
	state.logScenario(
		'Emergency rotation: TOFU treats compromise response the same way as attack. The recovery flow is the channel security work, not anything in the protocol.',
	);
	state.rerenderSetup();
	state.rerenderConnect();
}

function renderRecoverableScenario(
	result: ConnectResult,
	label: string,
	identity: HostPublic,
	transcript: Transcript,
	guidance: string,
): string {
	return renderScenarioResult(result, label, identity)
		+ `<div class="ssh-warning ssh-warning--pending recovery-card" role="status">
			<p class="ssh-warning-title">Recovery — what to do next</p>
			<p class="ssh-warning-body">${guidance}</p>
		</div>`
		+ renderTranscript(transcript, result);
}

function renderScenarioResult(result: ConnectResult, label: string, attacker: HostPublic | null): string {
	const stepLis = result.steps
		.map((step) => {
			const cls = step.ok ? 'scenario-status--valid' : 'scenario-status--invalid';
			const badge = step.ok ? 'OK' : 'FAIL';
			return `
				<li class="handshake-step">
					<div class="handshake-step-head">
						<span class="handshake-step-label">${step.label}</span>
						<span class="handshake-step-badge ${cls}">${badge}</span>
					</div>
					<p class="handshake-step-detail">${step.detail}</p>
				</li>
			`;
		})
		.join('');
	const attackerLine = attacker
		? `<p class="handshake-attacker"><span class="fp-tag">Presented key</span><code>${attacker.fingerprint}</code></p>`
		: '';
	const summary = scenarioMarkdownSummary(result, label, attacker);
	return `
		<div class="handshake-card">
			<div class="handshake-card-head">
				<p class="hero-metric-label">${label}</p>
				<span class="handshake-decision ${decisionAccent(result.hostKeyDecision)}">${decisionLabel(result.hostKeyDecision)}</span>
			</div>
			${attackerLine}
			<ol class="handshake-step-list">${stepLis}</ol>
			${decisionBanner(result)}
			<p class="handshake-summary">${result.summary}</p>
			<div class="transcript-actions">
				<button class="tab-button transcript-copy" type="button" data-json='${encodeForAttr(summary)}'>Copy summary as Markdown</button>
				<span class="transcript-copy-msg" aria-live="polite"></span>
			</div>
		</div>
	`;
}

function scenarioMarkdownSummary(result: ConnectResult, label: string, attacker: HostPublic | null): string {
	const lines = [
		`# ${label}`,
		'',
		`- decision: \`${result.hostKeyDecision}\``,
		`- connected: ${result.connected}`,
		`- signature valid: ${result.signatureValid}`,
		`- shared agrees: ${result.sharedAgrees}`,
	];
	if (attacker) lines.push(`- presented host fingerprint: \`${attacker.fingerprint}\``);
	lines.push('');
	lines.push('## Handshake steps');
	for (const s of result.steps) {
		lines.push(`- [${s.ok ? 'OK' : 'FAIL'}] **${s.label}** — ${s.detail}`);
	}
	lines.push('');
	lines.push(`## Summary`);
	lines.push(result.summary);
	return lines.join('\n');
}

// ---------- 5. Three trust models / concepts --------------------------------

function renderConceptsSection(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'models';
	section.setAttribute('aria-labelledby', 'models-heading');

	const compareRows = THREE_TRUST_MODELS.map(
		(r) => `
		<tr>
			<th scope="row">${r.axis}</th>
			<td>${r.pki}</td>
			<td>${r.wot}</td>
			<td>${r.ssh}</td>
		</tr>
	`,
	).join('');

	const concepts = HANDSHAKE_CONCEPTS.map(
		(c) => `
		<div class="panel-card">
			<h3>${c.title}</h3>
			<p class="panel-copy">${c.body}</p>
		</div>
	`,
	).join('');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 4</p>
				<h2 id="models-heading">Three trust models</h2>
				<p class="panel-copy">Three ways to decide which public keys are real. Hierarchical PKI ships roots in your OS (<a href="https://systemslibrarian.github.io/crypto-lab-pki-chain/">crypto-lab-pki-chain</a>). PGP’s Web of Trust grows a graph through people (<a href="https://systemslibrarian.github.io/crypto-lab-web-of-trust/">crypto-lab-web-of-trust</a>). SSH skips both and pins on first sight.</p>
			</div>
		</div>
		<div class="table-shell" tabindex="0" role="region" aria-label="Comparison of three trust models">
			<table class="math-table">
				<thead>
					<tr><th>Axis</th><th>Hierarchical PKI</th><th>Web of Trust</th><th>SSH TOFU</th></tr>
				</thead>
				<tbody>${compareRows}</tbody>
			</table>
		</div>
		<h3 class="ssh-section-h">First contact: the same event in all three demos</h3>
		<div class="reuse-grid trust-callouts">
			<div class="panel-card trust-callout trust-callout--pki">
				<h3>PKI / TLS</h3>
				<p class="panel-copy">"Is this <em>certificate</em> signed by a CA I already trust, and does the name match?" The browser walks the chain to a pre-installed root. First contact is invisible because trust was delegated to the OS vendor ahead of time.</p>
				<p class="panel-copy"><a href="https://systemslibrarian.github.io/crypto-lab-pki-chain/">Open crypto-lab-pki-chain →</a></p>
			</div>
			<div class="panel-card trust-callout trust-callout--wot">
				<h3>Web of Trust / PGP</h3>
				<p class="panel-copy">"Has anyone I trust signed this key? If marginals add up, accept it." Trust flows through people, not authorities. First contact is invisible only if a chain through your social graph already exists.</p>
				<p class="panel-copy"><a href="https://systemslibrarian.github.io/crypto-lab-web-of-trust/">Open crypto-lab-web-of-trust →</a></p>
			</div>
			<div class="panel-card trust-callout trust-callout--ssh">
				<h3>SSH / TOFU (this demo)</h3>
				<p class="panel-copy">"Have I seen this host's key before? If not, ask the user." There is no third party. First contact is loud, unverified, and entirely on you — unless an SSHFP record or an @cert-authority cert closes the gap.</p>
				<p class="panel-copy"><strong>You are here.</strong></p>
			</div>
		</div>
		<h3 class="ssh-section-h">Inside the SSH handshake</h3>
		<div class="reuse-grid">${concepts}</div>
	`;
	return section;
}

// ---------- 6. Real world / TOFU lessons ------------------------------------

function renderRealWorldSection(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'realworld';
	section.setAttribute('aria-labelledby', 'realworld-heading');

	const real = REAL_WORLD.map(
		(r) => `
		<div class="panel-card">
			<h3>${r.title}</h3>
			<p class="panel-copy">${r.body}</p>
		</div>
	`,
	).join('');

	const lessons = TOFU_LESSONS.map(
		(l) => `
		<div class="panel-card">
			<h3>${l.title}</h3>
			<p class="panel-copy">${l.body}</p>
		</div>
	`,
	).join('');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 5</p>
				<h2 id="realworld-heading">In the real world</h2>
				<p class="panel-copy">Where TOFU actually lives: the files, the record types, the configuration knobs operators tune. And the honest lessons about what the model does and does not protect.</p>
			</div>
		</div>
		<div class="reuse-grid">${real}</div>
		<h3 class="ssh-section-h">What TOFU teaches</h3>
		<div class="reuse-grid">${lessons}</div>
	`;
	return section;
}

// ---------- 6.5 Scope + citations -------------------------------------------

function renderScopeSection(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'scope';
	section.setAttribute('aria-labelledby', 'scope-heading');

	const scopeCards = SCOPE.map(
		(s) => `
		<div class="panel-card scope-card">
			<h3>${s.heading}</h3>
			<ul class="scope-list">${s.bullets.map((b) => `<li>${b}</li>`).join('')}</ul>
		</div>
	`,
	).join('');

	const citationItems = CITATIONS.map(
		(c) => `
		<li class="citation-item">
			<a class="citation-link" href="${c.url}" target="_blank" rel="noopener noreferrer">${c.label}</a>
			<p class="citation-note">${c.note}</p>
		</li>
	`,
	).join('');

	const crosswalkRows = OPENSSH_CROSSWALK.map(
		(r) => `
			<tr>
				<td>${r.demo}</td>
				<td><code>${r.openssh}</code></td>
				<td class="crosswalk-notes">${r.notes}</td>
			</tr>
		`,
	).join('');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 6</p>
				<h2 id="scope-heading">Scope &amp; provenance</h2>
				<p class="panel-copy">What the demo claims to model, what it leaves out, and where to read the authoritative versions. Every claim above this section should map to one of the references below.</p>
			</div>
		</div>
		<div class="reuse-grid scope-grid">${scopeCards}</div>
		<h3 class="ssh-section-h">Take it back to the terminal — OpenSSH crosswalk</h3>
		<p class="panel-copy">Each artifact in this demo, mapped to the closest command or file in real OpenSSH.</p>
		<div class="table-shell" tabindex="0" role="region" aria-label="Mapping of demo artifacts to real OpenSSH commands">
			<table class="math-table crosswalk-table">
				<thead>
					<tr><th>In this demo</th><th>In OpenSSH</th><th>Notes</th></tr>
				</thead>
				<tbody>${crosswalkRows}</tbody>
			</table>
		</div>
		<h3 class="ssh-section-h">References</h3>
		<ul class="citation-list">${citationItems}</ul>
	`;
	return section;
}

// ---------- 7. Footer (scripture) -------------------------------------------

function renderFooter(): HTMLElement {
	const footer = el('footer', 'lab-section');
	const reviewed = '2026-06';
	footer.innerHTML = `
		<div class="footer-meta">
			<div class="footer-meta-item">
				<p class="hero-metric-label">Last reviewed</p>
				<p class="mono-inline">${reviewed}</p>
			</div>
			<div class="footer-meta-item">
				<p class="hero-metric-label">Status</p>
				<p class="panel-copy">Educational model. The crypto (ephemeral X25519/ECDH P-256 + Ed25519/ECDSA P-256 via Web Crypto) is real; the trust logic mirrors OpenSSH known_hosts. The SSH binary packet protocol and algorithm negotiation are not modelled — use OpenSSH or a vetted library for production.</p>
			</div>
		</div>
		<p class="scripture">"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31</p>
	`;
	return footer;
}

// ---------- mountApp ---------------------------------------------------------

export function mountApp(root: HTMLDivElement): void {
	const state: AppState = {
		server: null,
		client: new SshClient(),
		mode: 'ask',
		ca: null,
		caTrusted: false,
		currentCert: null,
		lastResult: null,
		lastResultLabel: '',
		lastTranscript: null,
		pending: null,
		pendingLabel: '',
		rerenderSetup: () => {},
		rerenderConnect: () => {},
		rerenderScenarios: () => {},
		logScenario: () => {},
	};

	const shell = el('div', 'page-shell');
	shell.id = 'playground-heading';

	shell.appendChild(renderHero());
	shell.appendChild(renderSetupSection(state));
	shell.appendChild(renderConnectSection(state));
	shell.appendChild(renderScenariosSection(state));
	shell.appendChild(renderConceptsSection());
	shell.appendChild(renderRealWorldSection());
	shell.appendChild(renderScopeSection());
	shell.appendChild(renderFooter());

	// Deep-link: ?scenario=<id> auto-triggers a scenario after the page mounts.
	// Server is auto-started so the linked scenario can actually run.
	void (async () => {
		const params = new URLSearchParams(location.search);
		const scn = params.get('scenario');
		if (!scn) return;
		if (!state.server) {
			state.server = await SshServer.create(HOST_NAME);
			state.rerenderSetup();
			state.rerenderConnect();
			state.rerenderScenarios();
		}
		// If the scenario needs a pin, run an explicit accept-new connect first
		// so the demo lands in a runnable state.
		if (['mitm-after', 'rotate-planned', 'rotate-emergency'].includes(scn)) {
			const tap = tapResponder(HOST_NAME, state.server!, algoNames());
			await connectWithPolicy(state.client, HOST_NAME, tap, 'accept-new');
			state.rerenderConnect();
			state.rerenderScenarios();
		}
		const btnId = `scn-${scn}`;
		const btn = shell.querySelector<HTMLButtonElement>(`#${btnId}`);
		btn?.click();
		btn?.scrollIntoView({ behavior: 'smooth', block: 'start' });
	})();

	// Delegated handler for transcript "Copy as JSON" buttons.
	shell.addEventListener('click', (e) => {
		const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('.transcript-copy');
		if (!btn) return;
		const json = btn.dataset.json ?? '';
		const msg = btn.parentElement?.querySelector<HTMLElement>('.transcript-copy-msg');
		void navigator.clipboard.writeText(json).then(
			() => {
				if (msg) {
					msg.textContent = 'Copied.';
					setTimeout(() => { if (msg.textContent === 'Copied.') msg.textContent = ''; }, 2000);
				}
			},
			() => {
				if (msg) msg.textContent = 'Copy failed — your browser may not allow it here.';
			},
		);
	});

	root.replaceChildren(shell);
}

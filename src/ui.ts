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
	HANDSHAKE_CONCEPTS,
	REAL_WORLD,
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
	lastResult: ConnectResult | null;
	lastResultLabel: string;
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
	`;

	const startBtn = section.querySelector<HTMLButtonElement>('#start-btn')!;
	const restartBtn = section.querySelector<HTMLButtonElement>('#restart-btn')!;
	const status = section.querySelector<HTMLElement>('#start-status')!;
	const host = section.querySelector<HTMLElement>('#host-display')!;

	function refresh(): void {
		if (!state.server) {
			host.innerHTML = `<p class="panel-copy ssh-empty">No server running yet. The handshake needs a host key — generate one to continue.</p>`;
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
				<p class="panel-copy">This is the server’s long-term identity. Every legitimate connection to <code>${id.name}</code> should present exactly this fingerprint.</p>
			</div>
		`;
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
		<div class="ssh-actions">
			<button id="connect-btn" class="tab-button" type="button">ssh ${HOST_NAME}</button>
			<button id="reset-btn" class="tab-button" type="button">Reset known_hosts</button>
			<span id="connect-status" class="ssh-status"></span>
		</div>
		<div id="connect-result" class="ssh-output" aria-live="polite"></div>
		<div id="connect-pins" class="ssh-pins-wrap"></div>
	`;

	const connectBtn = section.querySelector<HTMLButtonElement>('#connect-btn')!;
	const resetBtn = section.querySelector<HTMLButtonElement>('#reset-btn')!;
	const status = section.querySelector<HTMLElement>('#connect-status')!;
	const resultBox = section.querySelector<HTMLElement>('#connect-result')!;
	const pinsBox = section.querySelector<HTMLElement>('#connect-pins')!;

	function refresh(): void {
		if (!state.server) {
			resultBox.innerHTML = `<p class="panel-copy ssh-empty">Start the server first, then run the handshake.</p>`;
			pinsBox.replaceChildren(renderKnownHosts(state));
			connectBtn.disabled = true;
			return;
		}
		connectBtn.disabled = false;
		const pinned = state.client.knownHosts.get(HOST_NAME);
		connectBtn.textContent = pinned ? `ssh ${HOST_NAME} (reconnect)` : `ssh ${HOST_NAME}`;
		if (state.lastResult) {
			resultBox.innerHTML = renderConnectResult(state.lastResult, state.lastResultLabel);
		} else {
			const hint = pinned
				? `<p class="panel-copy ssh-empty">Click <strong>ssh ${HOST_NAME} (reconnect)</strong> — the pinned fingerprint should match.</p>`
				: `<p class="panel-copy ssh-empty">Click <strong>ssh ${HOST_NAME}</strong> to run the first connection. The fingerprint will be pinned on first use.</p>`;
			resultBox.innerHTML = hint;
		}
		pinsBox.replaceChildren(renderKnownHosts(state));
	}

	state.rerenderConnect = refresh;
	refresh();

	connectBtn.addEventListener('click', () => {
		void (async () => {
			if (!state.server) return;
			connectBtn.disabled = true;
			status.textContent = 'Running handshake…';
			try {
				const pinnedBefore = state.client.knownHosts.has(HOST_NAME);
				const result = await state.client.connect(HOST_NAME, state.server);
				state.lastResult = result;
				state.lastResultLabel = pinnedBefore ? 'Reconnect to legitimate server' : 'First contact';
				status.textContent = result.connected ? 'Connection established.' : result.summary;
				state.rerenderConnect();
				state.rerenderScenarios();
			} catch (err) {
				status.textContent = `Failed: ${(err as Error).message}`;
			} finally {
				connectBtn.disabled = false;
			}
		})();
	});

	resetBtn.addEventListener('click', () => {
		state.client = new SshClient();
		state.lastResult = null;
		state.lastResultLabel = '';
		status.textContent = 'known_hosts cleared. The next connection will be first contact again.';
		state.rerenderConnect();
		state.rerenderScenarios();
	});

	return section;
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
	const rows = Array.from(state.client.knownHosts.entries())
		.map(([name, fp]) => `<li class="pin-row"><span class="pin-host">${name}</span><code class="pin-fp">${fp}</code></li>`)
		.join('');
	wrap.innerHTML = `
		<p class="hero-metric-label">known_hosts</p>
		<ul class="pin-list">${rows}</ul>
	`;
	return wrap;
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
				<h2 id="scenarios-heading">Break it</h2>
				<p class="panel-copy">Three scenarios. The first two run a real attacker handshake; the third tampers with the host signature in transit. Each one shows where TOFU works and where it does not.</p>
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
		buttons.innerHTML = `
			<button id="scn-mitm-after" class="tab-button" type="button" ${pinned ? '' : 'disabled'}>MITM after pinning ${pinned ? '' : '— connect once first'}</button>
			<button id="scn-mitm-first" class="tab-button" type="button">MITM on first contact (fresh client)</button>
			<button id="scn-tamper" class="tab-button" type="button">Tampered host signature</button>
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
	const result = await state.client.connect(HOST_NAME, attacker);
	state.lastResult = result;
	state.lastResultLabel = 'MITM after pinning';
	output.innerHTML = renderScenarioResult(result, 'MITM after pinning', attacker.identity);
	state.logScenario(
		result.hostKeyDecision === 'CHANGED-REJECTED'
			? 'MITM after pinning: known_hosts caught the substituted host key. Connection refused. This is the protection working.'
			: `MITM after pinning gave an unexpected decision: ${result.hostKeyDecision}.`,
	);
	state.rerenderConnect();
}

async function scenarioMitmFirst(state: AppState, output: HTMLElement): Promise<void> {
	// Use a fresh client with no pins to model "first contact".
	const freshClient = new SshClient();
	const attacker = await makeMitm(HOST_NAME);
	const result = await freshClient.connect(HOST_NAME, attacker);
	output.innerHTML = renderScenarioResult(result, 'MITM on first contact (fresh client)', attacker.identity);
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
	const result = await state.client.connect(HOST_NAME, tampered);
	output.innerHTML = renderScenarioResult(result, 'Tampered host signature', null);
	state.logScenario(
		!result.signatureValid
			? 'Tampered host signature: the client recomputed the exchange hash, the signature did not verify, connection refused. The host could not prove key ownership.'
			: 'Tampered host signature unexpectedly verified — engine bug.',
	);
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
		? `<p class="handshake-attacker"><span class="fp-tag">Attacker key</span><code>${attacker.fingerprint}</code></p>`
		: '';
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
		</div>
	`;
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
		lastResult: null,
		lastResultLabel: '',
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
	shell.appendChild(renderFooter());

	root.replaceChildren(shell);
}

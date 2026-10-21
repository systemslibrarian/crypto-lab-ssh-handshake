import {
	APW_EXPECTED_14,
	APW_EXPECTED_32,
	classifyIdealised,
	classifyPre52OpenSsh,
	recoverablePrefixBits,
	recoverTargetPlaintext,
	verifyRecoveredPrefix,
} from './attack-apw.ts';
import { deleteExtInfo, makeIgnoreWire, type WirePacket } from './attack-terrapin.ts';
import {
	CbcEncryptAndMacDirection,
	aesCbcDecryptRaw,
	aesCbcEncryptRaw,
} from './cbc-and-mac.ts';
import { openOpenSshChaCha, protectOpenSshChaCha } from './chachapoly.ts';
import { aesCtrTransform } from './ctr.ts';
import {
	buildTerrapinKex,
	hashWithOptionalIgnore,
	strippedStrictHash,
	type RfcKexTranscript,
} from './kex.ts';
import {
	blocks,
	encodePacket,
	equalBytes,
	randomBytes,
	toHex,
	uint32,
	xorBytes,
} from './packet.ts';
import { countersBeforeNewKeys, type SequenceCounters } from './seq.ts';
import { checkInitialKexMessage, negotiateStrictKex } from './strict-kex.ts';

const encoder = new TextEncoder();

// Verdict wording is kept separate from the computed conditions below.
// Mutation tests change the underlying recovery, cipher, and protocol logic.
export const APW_IDEALISED_ALARM = 'ALARM — PLAINTEXT LEAKED (32 bits)';
export const APW_OPENSSH_ALARM_14 = 'ALARM — PLAINTEXT LEAKED (14 bits)';
export const APW_OPENSSH_ALARM_32 = 'ALARM — PLAINTEXT LEAKED (32 bits)';
export const CTR_DEFENCE = 'DEFENCE HELD — AES-CTR USED AN UNRELATED KEYSTREAM BLOCK';
export const CHACHA_DEFENCE = 'DEFENCE HELD — POLY1305 REJECTED BEFORE PAYLOAD DECRYPTION';
export const TERRAPIN_ALARM = 'ALARM — PACKET DELETED, MAC VALID';
export const STRICT_DEFENCE = 'DEFENCE HELD — STRICT KEX REJECTED SSH_MSG_IGNORE';

function element<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	className?: string,
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (className) node.className = className;
	return node;
}

function bits(bytes: Uint8Array, count: number): string {
	return Array.from(bytes, (byte) => byte.toString(2).padStart(8, '0')).join('').slice(0, count);
}

function shortHex(bytes: Uint8Array): string {
	const hex = toHex(bytes);
	return hex.length > 40 ? `${hex.slice(0, 40)}…` : hex;
}

interface ApwCapture {
	key: Uint8Array;
	trueBlock: Uint8Array;
	predecessor: Uint8Array;
	target: Uint8Array;
	targetPacketLastBlock: Uint8Array;
	tag: Uint8Array;
}

async function createApwCapture(): Promise<ApwCapture> {
	const key = randomBytes(16);
	const direction = new CbcEncryptAndMacDirection(key, randomBytes(32), randomBytes(16));
	// Eleven bytes place PASS at the beginning of the second plaintext block:
	// 4 length bytes + 1 padding byte + 11 payload bytes = 16.
	const payload = encoder.encode('USER=alice\nPASS=hunter2; recurring secret');
	const protectedPacket = await direction.protect(7, payload, randomBytes(32));
	const plainBlocks = blocks(protectedPacket.plain.wire);
	const cipherBlocks = blocks(protectedPacket.ciphertext);
	return {
		key,
		trueBlock: plainBlocks[1]!,
		predecessor: cipherBlocks[0]!,
		target: cipherBlocks[1]!,
		targetPacketLastBlock: protectedPacket.lastBlock,
		tag: protectedPacket.mac.slice(0, 16),
	};
}

function desiredPrime(length: number): Uint8Array {
	const block = randomBytes(16);
	block.set(uint32(length), 0);
	return block;
}

function renderBytes(label: string, value: Uint8Array, id: string): string {
	return `<div class="packet-byte-row"><span>${label}</span><code id="${id}" data-bytes="${toHex(value)}">${shortHex(value)}</code></div>`;
}

function mountApw(root: HTMLElement): void {
	root.innerHTML = `
		<article class="packet-exhibit" aria-labelledby="apw-heading">
			<div class="packet-exhibit-heading">
				<p class="hero-metric-label">EXHIBIT 4A · APW / BONEH–SHOUP</p>
				<h3 id="apw-heading">The length that is read too early</h3>
				<p class="panel-copy">In the old encrypt-and-MAC order, a receiver decrypts the first AES-CBC block and acts on its four-byte length <em>before</em> authenticating the packet. Its reaction therefore becomes a decryption oracle.</p>
			</div>
			<div class="packet-format" aria-label="SSH binary packet format">
				<span>uint32 packet_length</span><span>byte padding_length</span><span>payload</span><span>random padding ≥ 4</span>
			</div>
			<p class="packet-equation"><code>P′ = D(c*) ⊕ L</code> &nbsp; then &nbsp; <code>P* = P′ ⊕ L ⊕ c*₋₁</code></p>
			<p class="panel-copy">The one-frame evidence below pins a successful oracle reaction so its XOR is inspectable; it does not pretend a random attempt always succeeds. The worker experiment measures the rare attempts, with each sample standing in for a fresh key exchange.</p>
			<div class="packet-controls">
				<label>Receiver
					<select id="apw-receiver">
						<option value="none" selected>Secure path — choose a break mode</option>
						<option value="ideal">BROKEN · book’s idealised receiver</option>
						<option value="openssh">BROKEN · pre-5.2 OpenSSH-style receiver</option>
					</select>
				</label>
				<label>OpenSSH recovery
					<select id="apw-depth" disabled>
						<option value="14">14 bits · range reaction</option>
						<option value="32">32 bits · aligned wait length</option>
					</select>
				</label>
				<label>Target
					<select id="apw-target">
						<option value="payload">payload block containing PASS</option>
						<option value="tag">MAC tag block (edge case)</option>
						<option value="budget">idealised ℓ beyond page budget</option>
					</select>
				</label>
			</div>
			<div class="reaction-key" aria-label="Pre-5.2 OpenSSH reaction key"><span><strong>DISCONNECT</strong> outside 5…256 KiB</span><span><strong>FIN</strong> range passes, alignment fails</span><span><strong>WAIT → MAC error</strong> range and alignment pass</span></div>
			<div class="ssh-actions">
				<button id="apw-capture" class="tab-button" type="button">Capture target</button>
				<button id="apw-inject" class="tab-button" type="button" disabled>Inject c*</button>
				<span id="apw-status" class="ssh-status" aria-live="polite"></span>
			</div>
			<div id="apw-capture-out" class="packet-output"></div>
			<div id="apw-reaction" class="packet-output" aria-live="polite"></div>

			<h4>Re-run the same injection against a fixed construction</h4>
			<div class="packet-controls packet-controls--fix">
				<label>Fix
					<select id="apw-fix">
						<option value="ctr">AES-CTR (OpenSSH 5.2 preference)</option>
						<option value="chacha">chacha20-poly1305@openssh.com</option>
					</select>
				</label>
				<button id="apw-run-fix" class="tab-button" type="button" disabled>Re-run injection</button>
			</div>
			<div id="apw-fix-out" class="packet-output" aria-live="polite"></div>

			<h4>Measure the pre-5.2 reactions</h4>
			<p class="panel-copy">Each pseudorandom sample stands in for a fresh in-page connection and fresh key exchange carrying the same secret at the same position. APW note that connections terminate with high probability on each attempt. No network traffic is sent.</p>
			<div class="packet-controls packet-controls--rate">
				<label>Attempts
					<select id="apw-attempts">
						<option value="1048576">1,048,576</option>
						<option value="4194304" selected>4,194,304</option>
						<option value="16777216">16,777,216</option>
					</select>
				</label>
				<button id="apw-run-rate" class="tab-button" type="button">Run attempts in worker</button>
			</div>
			<progress id="apw-progress" max="1" value="0" aria-label="APW rate experiment progress"></progress>
			<div id="apw-rate-out" class="packet-output" aria-live="polite"></div>
			<details class="packet-notes">
				<summary>Exact model and source notes</summary>
				<ul>
					<li>RFC 4253 packet: <code>length ‖ padding_length ‖ payload ‖ padding</code>; total aligned to 16 bytes. AES-128-CBC carries the preceding ciphertext block forward.</li>
					<li>HMAC-SHA-256 covers <code>uint32 sequence_number ‖ unencrypted_packet</code>. Boneh–Shoup name required HMAC-SHA1; the MAC choice does not change this pre-authentication oracle.</li>
					<li>APW report success near 2⁻¹⁴ for the range distinction and 2⁻¹⁸ for the aligned wait; at most 2¹⁸/16 blocks reveal the wait length. Their later <code>packet.c</code> response unification blocks the 14-bit distinction, not the 32-bit wait variant.</li>
				</ul>
			</details>
		</article>
	`;

	const receiver = root.querySelector<HTMLSelectElement>('#apw-receiver')!;
	const depth = root.querySelector<HTMLSelectElement>('#apw-depth')!;
	const targetChoice = root.querySelector<HTMLSelectElement>('#apw-target')!;
	const captureButton = root.querySelector<HTMLButtonElement>('#apw-capture')!;
	const injectButton = root.querySelector<HTMLButtonElement>('#apw-inject')!;
	const status = root.querySelector<HTMLElement>('#apw-status')!;
	const captureOut = root.querySelector<HTMLElement>('#apw-capture-out')!;
	const reactionOut = root.querySelector<HTMLElement>('#apw-reaction')!;
	const fixChoice = root.querySelector<HTMLSelectElement>('#apw-fix')!;
	const fixButton = root.querySelector<HTMLButtonElement>('#apw-run-fix')!;
	const fixOut = root.querySelector<HTMLElement>('#apw-fix-out')!;
	const runRate = root.querySelector<HTMLButtonElement>('#apw-run-rate')!;
	const attempts = root.querySelector<HTMLSelectElement>('#apw-attempts')!;
	const progress = root.querySelector<HTMLProgressElement>('#apw-progress')!;
	const rateOut = root.querySelector<HTMLElement>('#apw-rate-out')!;
	let capture: ApwCapture | null = null;
	let lastInjectionBlock: Uint8Array | null = null;
	let fixRevision = 0;
	const previousValues = new Map([receiver, depth, targetChoice, fixChoice].map((control) => [control, control.value]));

	for (const control of [receiver, depth, targetChoice, fixChoice]) {
		control.addEventListener('change', () => {
			if (previousValues.get(control) === control.value) return;
			previousValues.set(control, control.value);
			depth.disabled = receiver.value !== 'openssh';
			if (control === targetChoice) {
				capture = null;
				lastInjectionBlock = null;
				fixRevision++;
				captureOut.replaceChildren();
				reactionOut.replaceChildren();
				fixOut.replaceChildren();
				injectButton.disabled = true;
				fixButton.disabled = true;
				status.textContent = 'Previous target and results retired. Capture the newly selected target.';
			} else if (control === fixChoice) {
				fixRevision++;
				if (fixOut.hasChildNodes()) fixOut.innerHTML = '<p class="packet-edge">Previous defence result retired. Re-run the injection with the selected fix.</p>';
			} else if (reactionOut.hasChildNodes()) {
				lastInjectionBlock = null;
				reactionOut.innerHTML = '<p class="packet-edge">Previous recovery result retired. Inject again with the selected receiver and recovery setting.</p>';
			}
		});
	}

	captureButton.addEventListener('click', () => {
		void (async () => {
			captureButton.disabled = true;
			fixRevision++;
			lastInjectionBlock = null;
			status.textContent = 'Encrypting a real SSH packet…';
			try {
				capture = await createApwCapture();
				const selected = targetChoice.value === 'tag' ? capture.tag : capture.target;
				captureOut.innerHTML = `
					<p class="packet-stage"><span aria-hidden="true">①</span> CAPTURED FROM THE WIRE</p>
					${renderBytes('c*₋₁ · predecessor', capture.predecessor, 'apw-cprev')}
					${renderBytes(targetChoice.value === 'tag' ? 'tag bytes · not CBC ciphertext' : 'c* · target ciphertext', selected, 'apw-cstar')}
					<p class="panel-copy">The target plaintext block begins <code>PASS</code>. Only ciphertext is handed to the attacker.</p>`;
				injectButton.disabled = false;
				fixButton.disabled = false;
				status.textContent = 'Target captured.';
				reactionOut.replaceChildren();
				fixOut.replaceChildren();
			} finally {
				captureButton.disabled = false;
			}
		})();
	});

	injectButton.addEventListener('click', () => {
		if (!capture) return;
		if (targetChoice.value === 'tag') {
			reactionOut.innerHTML = '<p class="packet-edge"><strong>REFUSED — the tag is not CBC ciphertext.</strong> Select a ciphertext block from the encrypted packet.</p>';
			return;
		}
		if (receiver.value === 'none') {
			reactionOut.innerHTML = '<p class="packet-edge"><strong>No broken receiver selected.</strong> The safe starting state does not expose a pre-MAC length oracle.</p>';
			return;
		}
		const wantsBudgetEdge = targetChoice.value === 'budget';
		const openSsh32 = receiver.value === 'openssh' && depth.value === '32';
		const chosenLength = wantsBudgetEdge ? 0xfffffff0 : openSsh32 ? 65_548 : 65_549;
		const pPrimeWanted = desiredPrime(chosenLength);
		const rawDecryption = aesCbcDecryptRaw(capture.key, new Uint8Array(16), capture.target);
		const desiredLastCiphertext = xorBytes(rawDecryption, pPrimeWanted);
		// Materialise that selected L as the real last ciphertext block of a
		// valid three-block SSH cover packet on the same CBC chain. Its final
		// block is 12 attacker-irrelevant payload bytes plus four legal random
		// padding bytes, so the evidence builder can select all 16 bytes without
		// changing the packet framing. This pins a successful transcript; the
		// worker below measures how rarely a random fresh connection supplies it.
		const cover = encodePacket(new Uint8Array(39), new Uint8Array(32));
		const encryptedPrefix = aesCbcEncryptRaw(capture.key, capture.targetPacketLastBlock, cover.wire.slice(0, 32));
		const coverPredecessor = encryptedPrefix.slice(-16);
		const requiredLastPlain = aesCbcDecryptRaw(capture.key, coverPredecessor, desiredLastCiphertext);
		cover.wire.set(requiredLastPlain, 32);
		const encryptedCover = aesCbcEncryptRaw(capture.key, capture.targetPacketLastBlock, cover.wire);
		const lastCiphertext = encryptedCover.slice(-16);
		lastInjectionBlock = lastCiphertext;
		const pPrime = aesCbcDecryptRaw(capture.key, lastCiphertext, capture.target);
		const reaction = receiver.value === 'ideal'
			? classifyIdealised(pPrime, 1_048_576)
			: classifyPre52OpenSsh(pPrime, openSsh32);
		const leakedBits = recoverablePrefixBits(receiver.value === 'ideal' ? 'idealised' : 'openssh-5.1', reaction);
		const recovered = leakedBits === 0 ? null : recoverTargetPlaintext(pPrime, lastCiphertext, capture.predecessor);
		const verified = recovered !== null && verifyRecoveredPrefix(recovered, capture.trueBlock, leakedBits);
		const budgetStopsRun = receiver.value === 'ideal' && reaction.kind === 'WAIT';
		const alarm = receiver.value === 'ideal'
			? APW_IDEALISED_ALARM
			: leakedBits === 32 ? APW_OPENSSH_ALARM_32 : APW_OPENSSH_ALARM_14;
		reactionOut.innerHTML = `
			<p class="packet-stage"><span aria-hidden="true">②</span> INJECTED AS THE NEXT FIRST BLOCK</p>
			${renderBytes('L · last received ciphertext', lastCiphertext, 'apw-last')}
			${renderBytes('P′ · receiver decrypts', pPrime, 'apw-prime')}
			<div class="reaction-log"><strong data-reaction-final="${reaction.kind}">${openSsh32 && reaction.kind === 'MAC_ERROR' ? 'WAIT → MAC_ERROR' : reaction.kind}</strong><span>${reaction.detail}</span><span>ℓ = ${reaction.packetLength.toLocaleString()} · bytes counted = ${reaction.bytesCounted.toLocaleString()}</span></div>
			${budgetStopsRun ? `<p class="packet-edge"><strong>Cost shown; run not performed.</strong> The page budget is 1,048,576 bytes. This model counted bytes—it did not send them.</p>` : recovered === null ? `
				<p class="packet-edge"><strong>No plaintext prefix recovered.</strong> This receiver reaction does not establish a 14-bit or 32-bit recovery.</p>` : !verified ? `
				<p class="packet-edge"><strong>Recovery check failed.</strong> The computed candidate does not match the target plaintext. No successful recovery is claimed.</p>` : `
				<div class="packet-verdict packet-verdict--alarm" id="apw-verdict" role="status">⚠ ${alarm}</div>
				<div class="bit-proof">
					<p>Recovered <code id="apw-recovered" data-recovered-bits="${bits(recovered, leakedBits)}">${bits(recovered, leakedBits)}</code></p>
					<p>True bits <code id="apw-true-bits">${bits(capture.trueBlock, leakedBits)}</code></p>
					<p class="bit-proof-result">✓ computed bits match the true plaintext</p>
				</div>`}
		`;
	});

	fixButton.addEventListener('click', () => {
		if (!capture) return;
		const activeCapture = capture;
		const selectedFix = fixChoice.value;
		const revision = ++fixRevision;
		void (async () => {
			fixButton.disabled = true;
			try {
				if (selectedFix === 'ctr') {
					const key = randomBytes(16);
					const counter = randomBytes(16);
					const last = lastInjectionBlock ?? activeCapture.targetPacketLastBlock;
					const transformed = await aesCtrTransform(key, counter, activeCapture.target);
					const falseRecovery = xorBytes(transformed, last, activeCapture.predecessor);
					const unrelated = !equalBytes(falseRecovery.slice(0, 4), activeCapture.trueBlock.slice(0, 4));
					if (revision !== fixRevision) return;
					fixOut.innerHTML = `
						${unrelated ? `<div class="packet-verdict packet-verdict--safe" id="apw-ctr-verdict" role="status">✓ ${CTR_DEFENCE}</div>` : '<p class="packet-edge"><strong>INCONCLUSIVE — the candidate prefix matched by chance.</strong> One matching prefix does not establish a decryption oracle. Capture a new sample.</p>'}
						<p class="panel-copy" id="apw-ctr-proof" data-candidate="${toHex(falseRecovery.slice(0, 4))}" data-target="${toHex(activeCapture.trueBlock.slice(0, 4))}" data-unrelated="${unrelated}">The same 16 injected bytes were XORed with the keystream at a fresh counter position. The candidate prefix <code>${toHex(falseRecovery.slice(0, 4))}</code> ${unrelated ? 'does not match' : 'happened to match'} target <code>${toHex(activeCapture.trueBlock.slice(0, 4))}</code>. This sample tests the CBC recovery relation; it is not a proof of AES-CTR security.</p>
						<details class="packet-notes"><summary>Inspect the AES-CTR calculation</summary>
							${renderBytes('sample key · in-page only', key, 'apw-ctr-key')}
							${renderBytes('fresh counter', counter, 'apw-ctr-counter')}
							${renderBytes('injected ciphertext', activeCapture.target, 'apw-ctr-input')}
							${renderBytes('AES-CTR output', transformed, 'apw-ctr-output')}
							${renderBytes('L · comparison chain block', last, 'apw-ctr-last')}
							${renderBytes('c*₋₁ · target predecessor', activeCapture.predecessor, 'apw-ctr-predecessor')}
						</details>`;
				} else {
					const key = randomBytes(64);
					const packet = encodePacket(encoder.encode('same recurring secret'), randomBytes(32)).wire;
					const sealed = protectOpenSshChaCha(key, 9, packet);
					const tampered = sealed.wire.slice();
					tampered.set(activeCapture.target.slice(0, Math.min(16, sealed.ciphertext.length - 4)), 4);
					let rejected = false;
					try {
						openOpenSshChaCha(key, 9, tampered);
					} catch {
						rejected = true;
					}
					if (revision !== fixRevision) return;
					fixOut.innerHTML = `
						${rejected ? `<div class="packet-verdict packet-verdict--safe" id="apw-chacha-verdict" role="status">✓ ${CHACHA_DEFENCE}</div>` : '<p class="packet-edge"><strong>DEFENCE FAILED — substituted bytes were accepted.</strong> No successful tag rejection is claimed.</p>'}
						<p class="panel-copy" id="apw-chacha-proof" data-rejected="${rejected}">Length uses the second key half; payload and one-time Poly1305 key use the first. Tag verification ran before payload decryption and ${rejected ? 'rejected' : 'did not reject'} the substituted bytes.</p>`;
				}
			} finally {
				fixButton.disabled = capture === null;
			}
		})();
	});

	runRate.addEventListener('click', () => {
		const total = Number(attempts.value);
		const worker = new Worker(new URL('./rate-worker.ts', import.meta.url), { type: 'module' });
		runRate.disabled = true;
		progress.value = 0;
		rateOut.textContent = 'Starting reproducible worker run…';
		worker.addEventListener('message', (event: MessageEvent<{
			type: 'progress' | 'done';
			completed: number;
			attempts: number;
			fourteenBitHits: number;
			thirtyTwoBitHits: number;
		}>) => {
			const result = event.data;
			progress.value = result.completed / result.attempts;
			if (result.type === 'done') {
				const rate14 = result.fourteenBitHits / result.attempts;
				const rate32 = result.thirtyTwoBitHits / result.attempts;
				rateOut.innerHTML = `
					<div class="rate-grid" id="apw-rate-result" data-attempts="${result.attempts}" data-hits-14="${result.fourteenBitHits}" data-hits-32="${result.thirtyTwoBitHits}">
						<p><strong>14-bit reaction</strong><span>${result.fourteenBitHits.toLocaleString()} hits ÷ ${result.attempts.toLocaleString()} attempts</span><code data-rate="${rate14}">${rate14.toExponential(4)}</code><small>paper: 2⁻¹⁴ = ${APW_EXPECTED_14.toExponential(4)}</small></p>
						<p><strong>32-bit wait</strong><span>${result.thirtyTwoBitHits.toLocaleString()} hits ÷ ${result.attempts.toLocaleString()} attempts</span><code data-rate="${rate32}">${rate32.toExponential(4)}</code><small>paper: 2⁻¹⁸ = ${APW_EXPECTED_32.toExponential(4)}</small></p>
					</div>`;
				runRate.disabled = false;
				worker.terminate();
			} else {
				rateOut.textContent = `${result.completed.toLocaleString()} of ${result.attempts.toLocaleString()} attempts…`;
			}
		});
		worker.postMessage({ attempts: total, seed: 0x5eed1234 });
	});
}

interface TerrapinState {
	kex: RfcKexTranscript;
	counters: SequenceCounters;
	injected: boolean;
	newKeys: boolean;
	deleted: boolean;
	terminated: boolean;
	packets: WirePacket[];
}

function counterMarkup(state: TerrapinState): string {
	const values = state.counters.snapshot();
	return `
		<div class="counter-card"><span>C.Snd</span><strong data-counter="client-send">${values.clientSend}</strong></div>
		<div class="counter-card ${values.clientReceive !== values.serverSend ? 'counter-card--apart' : ''}"><span>C.Rcv</span><strong data-counter="client-receive">${values.clientReceive}</strong></div>
		<div class="counter-card ${values.serverSend !== values.clientReceive ? 'counter-card--apart' : ''}"><span>S.Snd</span><strong data-counter="server-send">${values.serverSend}</strong></div>
		<div class="counter-card"><span>S.Rcv</span><strong data-counter="server-receive">${values.serverReceive}</strong></div>`;
}

function mountTerrapin(root: HTMLElement): void {
	root.innerHTML = `
		<article class="packet-exhibit" aria-labelledby="terrapin-heading">
			<div class="packet-exhibit-heading">
				<p class="hero-metric-label">EXHIBIT 4B · TERRAPIN</p>
				<h3 id="terrapin-heading">The packet that vanished</h3>
				<p class="panel-copy">SSH counts every packet from sequence zero, including unauthenticated packets before NEWKEYS. Inject one cleartext IGNORE, delete the first encrypted server packet, and the two counter changes cancel.</p>
			</div>
			<div class="strict-controls">
				<label><input id="strict-client" type="checkbox" checked> client offers <code>kex-strict-c-v00@openssh.com</code></label>
				<label><input id="strict-server" type="checkbox" checked> server offers <code>kex-strict-s-v00@openssh.com</code></label>
				<p id="strict-state" class="packet-mode"></p>
			</div>
			<div id="terrapin-loading" class="packet-output" role="status">Generating real X25519 keys and RFC-shaped H…</div>
			<div id="terrapin-demo" hidden>
				<div class="terrapin-board">
					<div class="terrapin-timeline" aria-label="Client and server packet timeline">
						<div class="lane-head"><strong>CLIENT</strong><strong>SERVER</strong></div>
						<ol id="terrapin-events" class="timeline-events">
							<li>↔ KEXINIT <small>seq 0 each way</small></li>
							<li>↔ X25519 ECDH_INIT / ECDH_REPLY <small>seq 1</small></li>
						</ol>
					</div>
					<div id="terrapin-counters" class="counter-grid"></div>
				</div>
				<div class="ssh-actions packet-action-row">
					<button id="terrapin-inject" class="tab-button" type="button">Inject IGNORE before NEWKEYS</button>
					<button id="terrapin-delete" class="tab-button" type="button">Delete EXT_INFO</button>
					<button id="terrapin-deliver" class="tab-button" type="button" disabled>Deliver next packet</button>
					<button id="terrapin-late" class="tab-button" type="button">Try IGNORE after NEWKEYS</button>
					<button id="terrapin-reset" class="tab-button" type="button">Reset packet run</button>
				</div>
				<div id="terrapin-result" class="packet-output" aria-live="polite"></div>
				<div id="terrapin-h" class="packet-output"></div>
				<div id="extension-table" class="extension-table" aria-label="Client extension table">
					<div><span>server-sig-algs</span><strong id="ext-sig">waiting</strong></div>
					<div><span>ping@openssh.com</span><strong id="ext-ping">waiting</strong></div>
				</div>
			</div>
			<div class="mode-notes">
				<h4>What the Terrapin paper found</h4>
				<ul>
					<li><strong>ChaCha20-Poly1305:</strong> deterministic exploitation—the run above.</li>
					<li><strong>CBC-EtM:</strong> exploitable with significant probability; the strict-kex draft describes high probability.</li>
					<li><strong>CTR-EtM:</strong> cryptographically affected but of limited exploitability; the strict-kex draft says not practically exploitable.</li>
					<li><strong>AES-GCM:</strong> not affected by this prefix-truncation construction.</li>
				</ul>
				<p class="panel-copy">Deleting EXT_INFO hides <code>server-sig-algs</code>, enabling a user-auth signature downgrade, and <code>ping@openssh.com</code>, which OpenSSH 9.5 used in a keystroke-timing countermeasure. Those consequences are described, not executed.</p>
			</div>
		</article>`;

	const clientStrict = root.querySelector<HTMLInputElement>('#strict-client')!;
	const serverStrict = root.querySelector<HTMLInputElement>('#strict-server')!;
	const strictState = root.querySelector<HTMLElement>('#strict-state')!;
	const loading = root.querySelector<HTMLElement>('#terrapin-loading')!;
	const demo = root.querySelector<HTMLElement>('#terrapin-demo')!;
	const counters = root.querySelector<HTMLElement>('#terrapin-counters')!;
	const events = root.querySelector<HTMLOListElement>('#terrapin-events')!;
	const inject = root.querySelector<HTMLButtonElement>('#terrapin-inject')!;
	const remove = root.querySelector<HTMLButtonElement>('#terrapin-delete')!;
	const deliver = root.querySelector<HTMLButtonElement>('#terrapin-deliver')!;
	const late = root.querySelector<HTMLButtonElement>('#terrapin-late')!;
	const reset = root.querySelector<HTMLButtonElement>('#terrapin-reset')!;
	const result = root.querySelector<HTMLElement>('#terrapin-result')!;
	const hOut = root.querySelector<HTMLElement>('#terrapin-h')!;
	const extSig = root.querySelector<HTMLElement>('#ext-sig')!;
	const extPing = root.querySelector<HTMLElement>('#ext-ping')!;
	let state: TerrapinState | null = null;

	const negotiation = () => negotiateStrictKex(clientStrict.checked, serverStrict.checked);
	const renderStrict = (): void => {
		const mode = negotiation();
		strictState.className = `packet-mode ${mode.active ? 'packet-mode--safe' : 'packet-mode--broken'}`;
		strictState.textContent = mode.active
			? '✓ STRICT KEX ACTIVE — both pseudo-algorithms were offered (safe default).'
			: clientStrict.checked || serverStrict.checked
				? '⚠ STRICT KEX INACTIVE — one-sided support is not negotiation.'
				: '⚠ BROKEN MODE — non-strict initial key exchange permits the prefix attack.';
	};

	const renderCounters = (): void => {
		if (state) counters.innerHTML = counterMarkup(state);
	};

	const appendEvent = (html: string): void => {
		const item = document.createElement('li');
		item.innerHTML = html;
		events.appendChild(item);
	};

	const resetRun = (): void => {
		if (!state) return;
		state = {
			kex: state.kex,
			counters: countersBeforeNewKeys(),
			injected: false,
			newKeys: false,
			deleted: false,
			terminated: false,
			packets: [],
		};
		events.innerHTML = '<li>↔ KEXINIT <small>seq 0 each way</small></li><li>↔ X25519 ECDH_INIT / ECDH_REPLY <small>seq 1</small></li>';
		result.replaceChildren();
		hOut.innerHTML = `<p><strong>Host signature:</strong> <span id="terrapin-signature">${state.kex.hostSignatureValid ? 'VERIFIED' : 'FAILED'}</span></p><p><strong>H:</strong> <code id="terrapin-hash">${shortHex(state.kex.exchangeHash)}</code></p>`;
		extSig.textContent = 'waiting';
		extPing.textContent = 'waiting';
		deliver.disabled = true;
		renderCounters();
	};

	const advanceNewKeys = (): void => {
		if (!state || state.newKeys || state.terminated) return;
		state.counters.clientToServer();
		state.counters.serverToClient();
		if (negotiation().active) {
			state.counters.resetAfterClientNewKeys();
			state.counters.resetAfterServerNewKeys();
		}
		state.newKeys = true;
		appendEvent('↔ NEWKEYS <small>both directions</small>');
		renderCounters();
	};

	const prepareEncryptedPackets = (): void => {
		if (!state || state.packets.length > 0) return;
		const extSequence = state.counters.serverToClient(false);
		const appSequence = state.counters.serverToClient(false);
		const extPacket = encodePacket(
			encoder.encode('EXT_INFO server-sig-algs,ping@openssh.com'),
			new Uint8Array(32).fill(0x41),
		).wire;
		const appPacket = encodePacket(encoder.encode('SSH_MSG_CHANNEL_DATA hello'), new Uint8Array(32).fill(0x42)).wire;
		state.packets = [
			{
				kind: 'EXT_INFO',
				sequence: extSequence,
				wire: protectOpenSshChaCha(state.kex.serverToClientKey, extSequence, extPacket).wire,
			},
			{
				kind: 'APPLICATION',
				sequence: appSequence,
				wire: protectOpenSshChaCha(state.kex.serverToClientKey, appSequence, appPacket).wire,
			},
		];
	};

	for (const checkbox of [clientStrict, serverStrict]) {
		checkbox.addEventListener('change', () => {
			renderStrict();
			resetRun();
		});
	}

	inject.addEventListener('click', () => {
		if (!state || state.terminated) return;
		if (state.newKeys) {
			result.innerHTML = '<p class="packet-edge"><strong>REFUSED — IGNORE is now encrypted traffic.</strong> The attacker cannot forge it after NEWKEYS.</p>';
			return;
		}
		const check = checkInitialKexMessage(negotiation(), 'IGNORE', 4);
		if (!check.accepted) {
			state.terminated = true;
			result.innerHTML = `<div class="packet-verdict packet-verdict--safe" id="strict-verdict" role="status">✓ ${STRICT_DEFENCE}</div><p class="panel-copy">${check.rule}. Connection terminated before any encrypted packet.</p>`;
			appendEvent('✕ injected SSH_MSG_IGNORE <small>strict kex terminated</small>');
			renderCounters();
			return;
		}
		makeIgnoreWire();
		state.counters.injectToClient();
		state.injected = true;
		appendEvent('← <strong>ATTACKER INJECTS IGNORE</strong> <small>C.Rcv + 1</small>');
		advanceNewKeys();
		void (async () => {
			if (!state) return;
			const withIgnore = await hashWithOptionalIgnore(state.kex, makeIgnoreWire().wire);
			const unchanged = equalBytes(withIgnore, state.kex.exchangeHash);
			hOut.innerHTML = `<p><strong>Host signature:</strong> <span id="terrapin-signature">${state.kex.hostSignatureValid ? 'VERIFIED' : 'FAILED'}</span></p><p><strong>H after IGNORE:</strong> <code id="terrapin-hash">${shortHex(withIgnore)}</code> <span id="terrapin-h-unchanged">${unchanged ? 'UNCHANGED' : 'CHANGED'}</span></p>`;
		})();
	});

	remove.addEventListener('click', () => {
		if (!state || state.terminated || state.deleted) return;
		advanceNewKeys();
		prepareEncryptedPackets();
		const attacked = deleteExtInfo(state.packets);
		state.packets = attacked.delivered;
		state.deleted = attacked.deleted !== null;
		appendEvent(`↢ <strong>ATTACKER DELETES EXT_INFO</strong> <small>wire seq ${attacked.deleted?.sequence ?? '?'}</small>`);
		extSig.textContent = 'MISSING';
		extPing.textContent = 'MISSING';
		deliver.disabled = false;
		result.innerHTML = '<p class="packet-stage">EXT_INFO removed. Deliver the next authenticated packet.</p>';
		renderCounters();
	});

	deliver.addEventListener('click', () => {
		if (!state || state.terminated || !state.deleted || state.packets.length === 0) return;
		const packet = state.packets[0]!;
		const expected = state.counters.clientReceive;
		try {
			openOpenSshChaCha(state.kex.serverToClientKey, expected, packet.wire);
			state.counters.clientReceive = (state.counters.clientReceive + 1) >>> 0;
			appendEvent(`← application packet <small>wire seq <span id="delivered-sequence">${packet.sequence}</span>, client expected <span id="expected-sequence">${expected}</span> · tag valid</small>`);
			result.innerHTML = `
				<div class="packet-verdict packet-verdict--alarm" id="terrapin-verdict" role="status">⚠ ${TERRAPIN_ALARM}</div>
				<div class="negative-proof" id="terrapin-negative-fixture" data-client-receive-used="${expected}" data-delivered-sequence="${packet.sequence}">
					<strong>AUTHENTICATED — AND TRUNCATED</strong>
					<p>A valid MAC on every delivered packet does not mean no packet was deleted.</p>
					<ul><li data-proof="signature">handshake signature VERIFIED</li><li data-proof="tags">every delivered Poly1305 tag VERIFIED</li><li data-proof="ext-info">EXT_INFO NEVER ARRIVED</li></ul>
				</div>`;
		} catch {
			appendEvent(`✕ application packet <small>wire seq ${packet.sequence}, client expected ${expected}</small>`);
			result.innerHTML = '<p class="packet-edge"><strong>REJECTED — sequence-number mismatch makes Poly1305 fail.</strong> Delete-without-IGNORE leaves the client expecting seq 3 while the next wire packet was protected as seq 4.</p>';
		}
		deliver.disabled = true;
		renderCounters();
	});

	late.addEventListener('click', () => {
		if (!state || state.terminated) return;
		advanceNewKeys();
		result.innerHTML = '<p class="packet-edge"><strong>REFUSED — IGNORE after NEWKEYS would need a valid encrypted packet and tag.</strong> The attacker cannot forge it.</p>';
	});

	reset.addEventListener('click', resetRun);

	renderStrict();
	void (async () => {
		try {
			const kex = await buildTerrapinKex();
			state = {
				kex,
				counters: countersBeforeNewKeys(),
				injected: false,
				newKeys: false,
				deleted: false,
				terminated: false,
				packets: [],
			};
			const stripped = await strippedStrictHash(kex);
			const strippedSignatureValid = await crypto.subtle.verify(
				'Ed25519',
				kex.hostPublicKey,
				kex.hostSignature.buffer as ArrayBuffer,
				stripped.buffer as ArrayBuffer,
			);
			loading.innerHTML = `<p>✓ Real X25519 shared secret; RFC 4253 §8-shaped H; Ed25519 host signature verified; RFC 4253 §7.2 expanded 64 key bytes.</p><p id="strict-strip-proof">Strip either strict marker from KEXINIT → H changes → host signature ${strippedSignatureValid ? 'still verifies (unexpected)' : 'FAILS'}.</p>`;
			demo.hidden = false;
			resetRun();
		} catch (error) {
			loading.textContent = `Packet exhibit could not initialize: ${(error as Error).message}`;
		}
	})();
}

export function renderPacketLayerSection(): HTMLElement {
	const section = element('section', 'lab-section packet-layer-section');
	section.id = 'packet-layer';
	section.setAttribute('aria-labelledby', 'packet-layer-heading');
	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 4</p>
				<h2 id="packet-layer-heading">After the handshake: the packet layer</h2>
				<p class="panel-copy packet-layer-lede">The handshake gives both sides keys. Every byte after that travels in packets that are encrypted and authenticated one at a time. Two real attacks show that <em>how</em> a receiver decrypts—and <em>what</em> it counts—matters as much as the cipher.</p>
				<p class="packet-local-note">All “connections” below are in-page models. Nothing is sent over a network.</p>
			</div>
		</div>
		<div id="apw-mount"></div>
		<div id="terrapin-mount"></div>`;
	mountApw(section.querySelector<HTMLElement>('#apw-mount')!);
	mountTerrapin(section.querySelector<HTMLElement>('#terrapin-mount')!);
	return section;
}

// policy.ts — wraps the engine's known_hosts/TOFU policy without modifying the
// cryptographic core. Adds OpenSSH-style StrictHostKeyChecking modes and an
// explicit first-contact decision step, plus helpers that mirror the
// ssh-keygen -F (lookup) and ssh-keygen -R (remove) operations.

import type { ConnectResult, ServerHello, SshClient } from './engine.ts';
import { sshPublicKeyBase64, sshPublicKeyBlob } from './wire.ts';

export type StrictMode =
	| 'yes'         // refuse unknown hosts entirely
	| 'ask'         // prompt the user on first contact (engine TOFU happens but is held)
	| 'accept-new'  // pin on first contact, reject on change (the engine default)
	| 'no';         // accept whatever shows up

// A connect attempt under the policy wrapper. On first contact in 'ask' mode
// the connect is held: the engine's auto-pin has been rolled back and the
// caller must either accept the fingerprint or reject the connection.
export interface PolicyConnectResult {
	result: ConnectResult;
	// Present only when the user must decide (ask + first contact + valid signature).
	pendingFirstContact?: {
		presentedFingerprint: string;
		accept: () => void;            // pin and treat as connected
		reject: () => void;            // leave knownHosts empty (no-op)
	};
	// True if the engine actually completed (handshake bits + final decision).
	// In 'ask' mode with a pending decision, this is false.
	connected: boolean;
}

// ssh-keygen -F equivalent: look up a pinned fingerprint.
export function findPin(client: SshClient, hostName: string): string | undefined {
	return client.knownHosts.get(hostName);
}

// ssh-keygen -R equivalent: remove a pin.
export function removePin(client: SshClient, hostName: string): boolean {
	return client.knownHosts.delete(hostName);
}

// Clear every pin (the "Reset known_hosts" UI action).
export function clearKnownHosts(client: SshClient): void {
	client.knownHosts.clear();
}

// Connect under a StrictHostKeyChecking mode. In 'ask' mode this rolls back
// the engine's auto-pin so the UI can present an explicit Accept/Reject/Verify
// prompt. All other modes preserve the existing engine semantics, with 'yes'
// additionally refusing unknown hosts and 'no' additionally accepting changes
// (treating change as if it were first contact — dangerous, kept for fidelity).
export async function connectWithPolicy(
	client: SshClient,
	hostName: string,
	responder: { respond: (clientEphPubJwk: JsonWebKey) => Promise<ServerHello> },
	mode: StrictMode,
): Promise<PolicyConnectResult> {
	const wasPinned = client.knownHosts.has(hostName);
	const result = await client.connect(hostName, responder);

	// First-contact branch
	if (!wasPinned && result.hostKeyDecision === 'tofu-pinned') {
		const presentedFingerprint = client.knownHosts.get(hostName)!;
		if (mode === 'yes') {
			// Refuse unknown hosts — roll back the engine's auto-pin.
			client.knownHosts.delete(hostName);
			return {
				result: {
					...result,
					hostKeyDecision: 'unknown',
					connected: false,
					summary: 'REJECTED — StrictHostKeyChecking=yes refuses unknown hosts.',
					steps: replaceLastDecisionStep(
						result.steps,
						'known_hosts (refused)',
						`StrictHostKeyChecking=yes — no pin on file for "${hostName}". Connection refused without prompting.`,
						false,
					),
				},
				connected: false,
			};
		}
		if (mode === 'ask') {
			// Hold the decision: roll back the auto-pin and let the caller choose.
			client.knownHosts.delete(hostName);
			return {
				result: {
					...result,
					hostKeyDecision: 'unknown',
					connected: false,
					summary: 'PENDING — first contact requires explicit user decision.',
					steps: replaceLastDecisionStep(
						result.steps,
						'known_hosts (prompt)',
						`No pin on file for "${hostName}". The authenticity of host can't be established — accept the fingerprint, reject, or verify out of band.`,
						true,
					),
				},
				pendingFirstContact: {
					presentedFingerprint,
					accept: () => {
						client.knownHosts.set(hostName, presentedFingerprint);
					},
					reject: () => {
						// no-op: known_hosts already rolled back
					},
				},
				connected: false,
			};
		}
		// 'accept-new' or 'no' — keep the engine's auto-pin (no change needed).
		return { result, connected: result.connected };
	}

	// Changed-host branch under 'no' mode: overwrite the pin and treat as connected.
	if (
		(mode as StrictMode) === 'no' &&
		result.hostKeyDecision === 'CHANGED-REJECTED' &&
		result.signatureValid
	) {
		// Trust whatever is on the wire. (Dangerous; kept for OpenSSH parity.)
		// The engine's transcript embeds the presented fingerprint in the
		// "WARNING: host key changed! pinned X but got Y" detail string.
		const detail = result.steps[result.steps.length - 1]?.detail ?? '';
		const presented = detail.match(/but got (SHA256:[A-Za-z0-9+/=]+)/)?.[1];
		if (presented) {
			client.knownHosts.set(hostName, presented);
		}
		return {
			result: {
				...result,
				hostKeyDecision: 'tofu-pinned',
				connected: true,
				summary: 'Connected — StrictHostKeyChecking=no accepted a changed host key (dangerous).',
				steps: replaceLastDecisionStep(
					result.steps,
					'known_hosts (no check)',
					`StrictHostKeyChecking=no — accepted the new host key without prompting. The pin was silently overwritten.`,
					true,
				),
			},
			connected: true,
		};
	}

	// All other paths: engine decision is final.
	return { result, connected: result.connected };
}

// Replace the last "known_hosts" step in the engine's transcript with one
// that better reflects the policy-wrapper outcome.
function replaceLastDecisionStep(
	steps: ConnectResult['steps'],
	label: string,
	detail: string,
	ok: boolean,
): ConnectResult['steps'] {
	const copy = steps.slice();
	const last = copy[copy.length - 1];
	if (last && last.label.startsWith('known_hosts')) {
		copy[copy.length - 1] = { label, detail, ok };
	} else {
		copy.push({ label, detail, ok });
	}
	return copy;
}

// Render an OpenSSH known_hosts entry — exact wire format:
// `hostname keytype base64(SSH-wire-format-pubkey)`. The third field is
// byte-identical to what ssh-keyscan would produce for the same key, so a
// learner can copy/paste into ~/.ssh/known_hosts and reason about it.
export function knownHostsLine(
	hostName: string,
	hostPubJwk: JsonWebKey,
	sigAlgoName: string,
): string {
	const keytype = sshKeyType(sigAlgoName);
	try {
		const blob = sshPublicKeyBlob(hostPubJwk, sigAlgoName);
		return `${hostName} ${keytype} ${sshPublicKeyBase64(blob)}`;
	} catch {
		return `${hostName} ${keytype} (key material unavailable)`;
	}
}

export function sshKeyType(sigAlgoName: string): string {
	if (sigAlgoName === 'Ed25519') return 'ssh-ed25519';
	if (sigAlgoName === 'ECDSA P-256') return 'ecdsa-sha2-nistp256';
	return 'ssh-unknown';
}

// ssh-keygen -F output — present-or-absent plus a realistic line if found.
export function sshKeygenF(
	client: SshClient,
	hostName: string,
	currentHostJwk: JsonWebKey | null,
	sigAlgoName: string,
): string {
	const pin = findPin(client, hostName);
	if (!pin) return `# Host ${hostName} not found in known_hosts.\n# (exit status 1)`;
	if (!currentHostJwk) {
		return `# Host ${hostName} found in known_hosts (line synthesized from pin):\n` +
			`${hostName} ${sshKeyType(sigAlgoName)} ${pin}`;
	}
	return `# Host ${hostName} found in known_hosts:\n${knownHostsLine(hostName, currentHostJwk, sigAlgoName)}`;
}

export function explainMode(mode: StrictMode): string {
	switch (mode) {
		case 'yes':
			return 'StrictHostKeyChecking=yes — refuse unknown hosts; never auto-pin.';
		case 'ask':
			return 'StrictHostKeyChecking=ask — prompt the user on first contact (OpenSSH default).';
		case 'accept-new':
			return 'StrictHostKeyChecking=accept-new — silently pin on first contact, reject on change.';
		case 'no':
			return 'StrictHostKeyChecking=no — trust whatever responds. Dangerous; pin can be silently overwritten.';
	}
}

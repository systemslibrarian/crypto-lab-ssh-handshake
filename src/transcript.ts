// transcript.ts — capture every artifact exchanged during the handshake by
// tapping the responder. The engine's `connect()` passes the client ephemeral
// pubkey INTO the responder, so wrapping the responder is enough to see both
// sides of the exchange without modifying engine.ts.

import type { ServerHello } from './engine.ts';

export interface Transcript {
	hostName: string;
	clientEphemeralPubJwk: JsonWebKey | null;
	serverEphemeralPubJwk: JsonWebKey | null;
	hostPubJwk: JsonWebKey | null;
	exchangeHash: string | null;
	hostSignatureB64: string | null;
	sharedSecretB64: string | null; // display-only — the engine's own derivation result
	algoKex: string;
	algoSig: string;
	capturedAt: string; // ISO timestamp
}

export interface TappedResponder {
	respond: (clientEphPubJwk: JsonWebKey) => Promise<ServerHello>;
	transcript: Transcript;
}

// Wrap any responder (real server, MITM, tampered) to record the bytes that
// flow through. The returned object has the same .respond shape — pass it
// directly to client.connect().
export function tapResponder(
	hostName: string,
	inner: { respond: (clientEphPubJwk: JsonWebKey) => Promise<ServerHello> },
	algoNames: { kex: string; sig: string },
): TappedResponder {
	const transcript: Transcript = {
		hostName,
		clientEphemeralPubJwk: null,
		serverEphemeralPubJwk: null,
		hostPubJwk: null,
		exchangeHash: null,
		hostSignatureB64: null,
		sharedSecretB64: null,
		algoKex: algoNames.kex,
		algoSig: algoNames.sig,
		capturedAt: new Date().toISOString(),
	};

	return {
		transcript,
		respond: async (clientEphPubJwk: JsonWebKey): Promise<ServerHello> => {
			transcript.clientEphemeralPubJwk = clientEphPubJwk;
			const hello = await inner.respond(clientEphPubJwk);
			transcript.serverEphemeralPubJwk = hello.serverEphPubJwk;
			transcript.hostPubJwk = hello.hostPubJwk;
			transcript.exchangeHash = hello.exchangeHash;
			transcript.hostSignatureB64 = hello.hostSignatureB64;
			transcript.sharedSecretB64 = hello.sharedSecretHex;
			return hello;
		},
	};
}

// Truncate a long base64 value to a head/tail preview suitable for the UI.
export function shortBytes(value: string | null, head = 18, tail = 8): string {
	if (!value) return '(none)';
	if (value.length <= head + tail + 3) return value;
	return value.slice(0, head) + '…' + value.slice(-tail);
}

// A focused, RFC 4253-shaped key exchange for the Terrapin exhibit. The
// original teaching engine is left untouched; this path includes the exact §8
// H fields and §7.2 key expansion needed by the packet-protection example.

import { concat, sshPublicKeyBlob, wireMpint, wireString } from '../wire.ts';

const encoder = new TextEncoder();

export const TERRAPIN_V_C = 'SSH-2.0-CryptoLab_Client';
export const TERRAPIN_V_S = 'SSH-2.0-CryptoLab_Server';

export interface RfcKexTranscript {
	vClient: Uint8Array;
	vServer: Uint8Array;
	iClient: Uint8Array;
	iServer: Uint8Array;
	hostKey: Uint8Array;
	qClient: Uint8Array;
	qServer: Uint8Array;
	sharedSecret: Uint8Array;
	exchangeHash: Uint8Array;
	sessionId: Uint8Array;
	hostSignature: Uint8Array;
	hostPublicKey: CryptoKey;
	hostSignatureValid: boolean;
	serverToClientKey: Uint8Array;
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
	const digest = await crypto.subtle.digest('SHA-256', concat(...parts).buffer as ArrayBuffer);
	return new Uint8Array(digest);
}

export function rfcExchangeHashInput(fields: {
	vClient: Uint8Array;
	vServer: Uint8Array;
	iClient: Uint8Array;
	iServer: Uint8Array;
	hostKey: Uint8Array;
	qClient: Uint8Array;
	qServer: Uint8Array;
	sharedSecret: Uint8Array;
}): Uint8Array {
	return concat(
		wireString(fields.vClient),
		wireString(fields.vServer),
		wireString(fields.iClient),
		wireString(fields.iServer),
		wireString(fields.hostKey),
		wireString(fields.qClient),
		wireString(fields.qServer),
		wireMpint(fields.sharedSecret),
	);
}

export async function deriveRfc4253Key(
	sharedSecret: Uint8Array,
	exchangeHash: Uint8Array,
	letter: string,
	sessionId: Uint8Array,
	length: number,
): Promise<Uint8Array> {
	if (!/^[A-F]$/.test(letter)) throw new Error('RFC 4253 key letter must be A through F');
	const encodedK = wireMpint(sharedSecret);
	let material = await sha256(encodedK, exchangeHash, encoder.encode(letter), sessionId);
	while (material.length < length) {
		const next = await sha256(encodedK, exchangeHash, material);
		material = concat(material, next);
	}
	return material.slice(0, length);
}

export async function buildTerrapinKex(
	clientKexInit = encoder.encode('SSH_MSG_KEXINIT client: curve25519-sha256,ssh-ed25519,kex-strict-c-v00@openssh.com'),
	serverKexInit = encoder.encode('SSH_MSG_KEXINIT server: curve25519-sha256,ssh-ed25519,kex-strict-s-v00@openssh.com'),
): Promise<RfcKexTranscript> {
	const clientPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
	const serverPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
	const qClient = new Uint8Array(await crypto.subtle.exportKey('raw', clientPair.publicKey));
	const qServer = new Uint8Array(await crypto.subtle.exportKey('raw', serverPair.publicKey));
	const clientSecret = new Uint8Array(await crypto.subtle.deriveBits(
		{ name: 'X25519', public: serverPair.publicKey },
		clientPair.privateKey,
		256,
	));
	const serverSecret = new Uint8Array(await crypto.subtle.deriveBits(
		{ name: 'X25519', public: clientPair.publicKey },
		serverPair.privateKey,
		256,
	));
	if (!clientSecret.every((byte, index) => byte === serverSecret[index])) {
		throw new Error('X25519 peers derived different shared secrets');
	}

	const hostPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
	const hostJwk = await crypto.subtle.exportKey('jwk', hostPair.publicKey);
	const hostKey = sshPublicKeyBlob(hostJwk, 'Ed25519');
	const vClient = encoder.encode(TERRAPIN_V_C);
	const vServer = encoder.encode(TERRAPIN_V_S);
	const input = rfcExchangeHashInput({
		vClient,
		vServer,
		iClient: clientKexInit,
		iServer: serverKexInit,
		hostKey,
		qClient,
		qServer,
		sharedSecret: clientSecret,
	});
	const exchangeHash = await sha256(input);
	const hostSignature = new Uint8Array(await crypto.subtle.sign(
		'Ed25519',
		hostPair.privateKey,
		exchangeHash.buffer as ArrayBuffer,
	));
	const hostSignatureValid = await crypto.subtle.verify(
		'Ed25519',
		hostPair.publicKey,
		hostSignature.buffer as ArrayBuffer,
		exchangeHash.buffer as ArrayBuffer,
	);
	const sessionId = exchangeHash.slice();
	const serverToClientKey = await deriveRfc4253Key(
		clientSecret,
		exchangeHash,
		'D',
		sessionId,
		64,
	);
	return {
		vClient,
		vServer,
		iClient: clientKexInit.slice(),
		iServer: serverKexInit.slice(),
		hostKey,
		qClient,
		qServer,
		sharedSecret: clientSecret,
		exchangeHash,
		sessionId,
		hostSignature,
		hostPublicKey: hostPair.publicKey,
		hostSignatureValid,
		serverToClientKey,
	};
}

export async function hashWithOptionalIgnore(
	transcript: RfcKexTranscript,
	_ignoredWireMessage?: Uint8Array,
): Promise<Uint8Array> {
	// SSH_MSG_IGNORE is intentionally absent: RFC 4253 §8 names only these
	// fields. The unused argument makes that exclusion explicit to the exhibit.
	return sha256(rfcExchangeHashInput({
		vClient: transcript.vClient,
		vServer: transcript.vServer,
		iClient: transcript.iClient,
		iServer: transcript.iServer,
		hostKey: transcript.hostKey,
		qClient: transcript.qClient,
		qServer: transcript.qServer,
		sharedSecret: transcript.sharedSecret,
	}));
}

export async function strippedStrictHash(transcript: RfcKexTranscript): Promise<Uint8Array> {
	const strip = (bytes: Uint8Array): Uint8Array => encoder.encode(
		new TextDecoder().decode(bytes).replace(/,kex-strict-[cs]-v00@openssh\.com/g, ''),
	);
	return sha256(rfcExchangeHashInput({
		vClient: transcript.vClient,
		vServer: transcript.vServer,
		iClient: strip(transcript.iClient),
		iServer: strip(transcript.iServer),
		hostKey: transcript.hostKey,
		qClient: transcript.qClient,
		qServer: transcript.qServer,
		sharedSecret: transcript.sharedSecret,
	}));
}

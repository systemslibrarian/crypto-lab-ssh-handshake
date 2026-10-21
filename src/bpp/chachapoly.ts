// chacha20-poly1305@openssh.com, following draft-ietf-sshm-chacha20-poly1305-04
// §§6–7 by key position: first 32 bytes protect payload/tag; second 32 bytes
// protect the four-byte length. This is not RFC 8439's AEAD framing.

import { poly1305 } from '@noble/ciphers/_poly1305.js';
import { chacha20orig } from '@noble/ciphers/chacha.js';
import { concatBytes, equalBytes } from './packet.ts';

export interface OpenSshChaChaPacket {
	sequence: number;
	ciphertext: Uint8Array;
	tag: Uint8Array;
	wire: Uint8Array;
}

export interface OpenedOpenSshChaChaPacket {
	packet: Uint8Array;
	length: number;
	tagValid: true;
}

export class OpenSshChaChaError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'OpenSshChaChaError';
	}
}

export function sequenceNonce(sequence: number): Uint8Array {
	const nonce = new Uint8Array(8);
	new DataView(nonce.buffer).setUint32(4, sequence >>> 0, false);
	return nonce;
}

function splitKey(keyMaterial: Uint8Array): { payloadKey: Uint8Array; lengthKey: Uint8Array } {
	if (keyMaterial.length !== 64) throw new Error('OpenSSH ChaCha20-Poly1305 needs 64 key bytes');
	return { payloadKey: keyMaterial.slice(0, 32), lengthKey: keyMaterial.slice(32, 64) };
}

function oneTimePolyKey(payloadKey: Uint8Array, nonce: Uint8Array): Uint8Array {
	return chacha20orig(payloadKey, nonce, new Uint8Array(32), undefined, 0);
}

export function protectOpenSshChaCha(
	keyMaterial: Uint8Array,
	sequence: number,
	packet: Uint8Array,
): OpenSshChaChaPacket {
	if (packet.length < 5) throw new Error('SSH packet needs a length and body');
	const { payloadKey, lengthKey } = splitKey(keyMaterial);
	const nonce = sequenceNonce(sequence);
	const encryptedLength = chacha20orig(lengthKey, nonce, packet.slice(0, 4), undefined, 0);
	const encryptedPayload = chacha20orig(payloadKey, nonce, packet.slice(4), undefined, 1);
	const ciphertext = concatBytes(encryptedLength, encryptedPayload);
	const tag = poly1305(ciphertext, oneTimePolyKey(payloadKey, nonce));
	return { sequence, ciphertext, tag, wire: concatBytes(ciphertext, tag) };
}

export function openOpenSshChaCha(
	keyMaterial: Uint8Array,
	sequence: number,
	wire: Uint8Array,
): OpenedOpenSshChaChaPacket {
	if (wire.length < 20) throw new OpenSshChaChaError('packet is too short');
	const { payloadKey, lengthKey } = splitKey(keyMaterial);
	const nonce = sequenceNonce(sequence);
	const ciphertext = wire.slice(0, -16);
	const suppliedTag = wire.slice(-16);
	const expectedTag = poly1305(ciphertext, oneTimePolyKey(payloadKey, nonce));
	// Per draft §7: authenticate the encrypted length and payload before the
	// payload is decrypted. Only the separately keyed length is read first.
	if (!equalBytes(suppliedTag, expectedTag)) {
		throw new OpenSshChaChaError(`Poly1305 rejected packet at expected sequence ${sequence}`);
	}
	const lengthBytes = chacha20orig(lengthKey, nonce, ciphertext.slice(0, 4), undefined, 0);
	const length = new DataView(lengthBytes.buffer, lengthBytes.byteOffset, 4).getUint32(0, false);
	const body = chacha20orig(payloadKey, nonce, ciphertext.slice(4), undefined, 1);
	const packet = concatBytes(lengthBytes, body);
	if (length + 4 !== packet.length) throw new OpenSshChaChaError('authenticated packet length mismatch');
	return { packet, length, tagValid: true };
}

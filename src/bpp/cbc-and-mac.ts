// RFC 4253 encrypt-and-MAC packet protection with raw AES-128-CBC.
// @noble/ciphers is needed because WebCrypto's AES-CBC always adds PKCS#7.

import { cbc } from '@noble/ciphers/aes.js';
import { concat, wireUint32 } from '../wire.ts';
import {
	SSH_BLOCK_SIZE,
	blocks,
	encodePacket,
	equalBytes,
	randomBytes,
	type EncodedPacket,
} from './packet.ts';

export interface CbcProtectedPacket {
	sequence: number;
	plain: EncodedPacket;
	ciphertext: Uint8Array;
	mac: Uint8Array;
	precedingBlock: Uint8Array;
	lastBlock: Uint8Array;
}

async function importHmac(key: Uint8Array): Promise<CryptoKey> {
	return crypto.subtle.importKey(
		'raw',
		key.buffer as ArrayBuffer,
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign', 'verify'],
	);
}

export async function hmacSha256(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
	const cryptoKey = await importHmac(key);
	const tag = await crypto.subtle.sign('HMAC', cryptoKey, message.buffer as ArrayBuffer);
	return new Uint8Array(tag);
}

export async function verifyHmacSha256(
	key: Uint8Array,
	message: Uint8Array,
	tag: Uint8Array,
): Promise<boolean> {
	const expected = await hmacSha256(key, message);
	return equalBytes(expected, tag);
}

export function aesCbcEncryptRaw(key: Uint8Array, iv: Uint8Array, plain: Uint8Array): Uint8Array {
	return cbc(key, iv, { disablePadding: true }).encrypt(plain);
}

export function aesCbcDecryptRaw(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
	return cbc(key, iv, { disablePadding: true }).decrypt(ciphertext);
}

export class CbcEncryptAndMacDirection {
	readonly #encryptionKey: Uint8Array;
	readonly #macKey: Uint8Array;
	#lastCiphertext: Uint8Array;

	constructor(
		encryptionKey: Uint8Array = randomBytes(16),
		macKey: Uint8Array = randomBytes(32),
		iv: Uint8Array = randomBytes(SSH_BLOCK_SIZE),
	) {
		if (encryptionKey.length !== 16) throw new Error('AES-128 needs a 16-byte key');
		if (iv.length !== SSH_BLOCK_SIZE) throw new Error('CBC IV must be 16 bytes');
		this.#encryptionKey = encryptionKey.slice();
		this.#macKey = macKey.slice();
		this.#lastCiphertext = iv.slice();
	}

	async protect(sequence: number, payload: Uint8Array, padding?: Uint8Array): Promise<CbcProtectedPacket> {
		const plain = encodePacket(payload, padding);
		const precedingBlock = this.#lastCiphertext.slice();
		const ciphertext = aesCbcEncryptRaw(this.#encryptionKey, precedingBlock, plain.wire);
		const mac = await hmacSha256(this.#macKey, concat(wireUint32(sequence), plain.wire));
		const cipherBlocks = blocks(ciphertext);
		const lastBlock = cipherBlocks.at(-1)!.slice();
		this.#lastCiphertext = lastBlock.slice();
		return { sequence, plain, ciphertext, mac, precedingBlock, lastBlock };
	}

	decryptInjectedFirstBlock(ciphertextBlock: Uint8Array): Uint8Array {
		if (ciphertextBlock.length !== SSH_BLOCK_SIZE) throw new Error('injection must be one AES block');
		return aesCbcDecryptRaw(this.#encryptionKey, this.#lastCiphertext, ciphertextBlock);
	}

	currentChainBlock(): Uint8Array {
		return this.#lastCiphertext.slice();
	}
}

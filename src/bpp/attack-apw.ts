// Attacker-side APW/Boneh–Shoup logic. This module receives only wire bytes
// and observable receiver reactions; it deliberately imports no cipher keys.

import { SSH_BLOCK_SIZE, SSH_MAX_PACKET_LENGTH, readUint32, xorBytes } from './packet.ts';

export type BrokenReceiver = 'idealised' | 'openssh-5.1';
export type ApwReactionKind = 'DISCONNECT' | 'FIN' | 'WAIT' | 'MAC_ERROR';

export interface ApwReaction {
	kind: ApwReactionKind;
	packetLength: number;
	need: number;
	bytesCounted: number;
	detail: string;
}

export function classifyPre52OpenSsh(firstPlainBlock: Uint8Array, feedWait = false): ApwReaction {
	const packetLength = readUint32(firstPlainBlock);
	if (packetLength < 5 || packetLength > SSH_MAX_PACKET_LENGTH) {
		return {
			kind: 'DISCONNECT',
			packetLength,
			need: 0,
			bytesCounted: SSH_BLOCK_SIZE,
			detail: 'Bad packet length: a distinguishable SSH DISCONNECT is emitted.',
		};
	}
	const need = 4 + packetLength - SSH_BLOCK_SIZE;
	if (need % SSH_BLOCK_SIZE !== 0) {
		return {
			kind: 'FIN',
			packetLength,
			need,
			bytesCounted: SSH_BLOCK_SIZE,
			detail: 'Length passed the range check but failed block alignment: FIN only.',
		};
	}
	return {
		kind: feedWait ? 'MAC_ERROR' : 'WAIT',
		packetLength,
		need,
		bytesCounted: SSH_BLOCK_SIZE + (feedWait ? need + 32 : 0),
		detail: feedWait
			? 'The model advances the byte counter to the end; the receiver then emits a MAC error.'
			: 'The receiver waits for the computed packet remainder and 32-byte MAC.',
	};
}

export function classifyIdealised(firstPlainBlock: Uint8Array, pageBudget: number): ApwReaction {
	const packetLength = readUint32(firstPlainBlock);
	const bytesCounted = 4 + packetLength + 32;
	const overBudget = bytesCounted > pageBudget;
	return {
		kind: overBudget ? 'WAIT' : 'MAC_ERROR',
		packetLength,
		need: packetLength,
		bytesCounted,
		detail: overBudget
			? 'Cost computed, but this page does not perform a multi-gigabyte wait. Bytes were counted, not sent.'
			: 'The byte counter advances to the claimed end and the unauthentic packet reaches the MAC error. Bytes were counted, not sent.',
	};
}

export function recoverTargetPlaintext(
	primePlaintext: Uint8Array,
	lastCiphertext: Uint8Array,
	targetPredecessor: Uint8Array,
): Uint8Array {
	return xorBytes(primePlaintext, lastCiphertext, targetPredecessor);
}

// Verification is intentionally separate: attack code never calls this helper.
export function verifyRecoveredPrefix(
	recovered: Uint8Array,
	truePlaintext: Uint8Array,
	bits: number,
): boolean {
	if (bits < 0 || bits > recovered.length * 8 || bits > truePlaintext.length * 8) return false;
	const wholeBytes = Math.floor(bits / 8);
	for (let i = 0; i < wholeBytes; i++) if (recovered[i] !== truePlaintext[i]) return false;
	const remaining = bits % 8;
	if (remaining === 0) return true;
	const mask = (0xff << (8 - remaining)) & 0xff;
	return (recovered[wholeBytes]! & mask) === (truePlaintext[wholeBytes]! & mask);
}

export interface RateResult {
	attempts: number;
	fourteenBitHits: number;
	thirtyTwoBitHits: number;
}

export function measureOpenSshRates(attempts: number, seed = 0x5eed1234): RateResult {
	let state = seed >>> 0;
	let fourteenBitHits = 0;
	let thirtyTwoBitHits = 0;
	for (let i = 0; i < attempts; i++) {
		// xorshift32 is fixed only to make the experiment reproducible. Each output
		// stands in for the uniformly distributed decrypted uint32 length.
		state ^= state << 13;
		state ^= state >>> 17;
		state ^= state << 5;
		const length = state >>> 0;
		if (length >= 5 && length <= SSH_MAX_PACKET_LENGTH) {
			fourteenBitHits++;
			if ((4 + length - SSH_BLOCK_SIZE) % SSH_BLOCK_SIZE === 0) thirtyTwoBitHits++;
		}
	}
	return { attempts, fourteenBitHits, thirtyTwoBitHits };
}

export const APW_EXPECTED_14 = 2 ** -14;
export const APW_EXPECTED_32 = 2 ** -18;

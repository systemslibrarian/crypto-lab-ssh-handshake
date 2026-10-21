import { poly1305 } from '@noble/ciphers/_poly1305.js';
import { chacha20orig } from '@noble/ciphers/chacha.js';
import { describe, expect, it } from 'vitest';
import { concat, wireMpint } from '../wire.ts';
import {
	APW_EXPECTED_14,
	APW_EXPECTED_32,
	classifyIdealised,
	classifyPre52OpenSsh,
	measureOpenSshRates,
	recoverablePrefixBits,
	recoverTargetPlaintext,
	verifyRecoveredPrefix,
} from './attack-apw.ts';
import { deleteExtInfo, makeIgnoreWire, type WirePacket } from './attack-terrapin.ts';
import {
	CbcEncryptAndMacDirection,
	aesCbcDecryptRaw,
	aesCbcEncryptRaw,
	hmacSha256,
} from './cbc-and-mac.ts';
import { openOpenSshChaCha, protectOpenSshChaCha } from './chachapoly.ts';
import {
	buildTerrapinKex,
	deriveRfc4253Key,
	hashWithOptionalIgnore,
	strippedStrictHash,
} from './kex.ts';
import {
	blocks,
	concatBytes,
	encodePacket,
	equalBytes,
	fromHex,
	packetPayload,
	toHex,
	uint32,
	xorBytes,
} from './packet.ts';
import { countersBeforeNewKeys } from './seq.ts';
import { checkInitialKexMessage, negotiateStrictKex } from './strict-kex.ts';

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const attackSources = import.meta.glob('./attack-*.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

describe('RFC 4253 packet encoding', () => {
	it('encodes a block-aligned packet with at least four padding bytes', () => {
		const encoded = encodePacket(utf8('hello'), new Uint8Array(32).fill(0xa5));
		expect(encoded.wire.length % 16).toBe(0);
		expect(encoded.paddingLength).toBeGreaterThanOrEqual(4);
		expect(packetPayload(encoded.wire)).toEqual(utf8('hello'));
	});
});

describe('KATs — AES-128-CBC and HMAC-SHA-256', () => {
	it('matches all four blocks of NIST SP 800-38A Appendix F.2.1', async () => {
		const key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
		const iv = fromHex('000102030405060708090a0b0c0d0e0f');
		const plain = fromHex(`
			6bc1bee22e409f96e93d7e117393172a
			ae2d8a571e03ac9c9eb76fac45af8e51
			30c81c46a35ce411e5fbc1191a0a52ef
			f69f2445df4f9b17ad2b417be66c3710`);
		const expected = fromHex(`
			7649abac8119b246cee98e9b12e9197d
			5086cb9b507219ee95db113a917678b2
			73bed6b8e3c1743b7116e69e22229516
			3ff1caa1681fac09120eca307586e1a7`);
		const encrypted = aesCbcEncryptRaw(key, iv, plain);
		expect(encrypted).toEqual(expected);
		expect(aesCbcDecryptRaw(key, iv, encrypted)).toEqual(plain);

		// WebCrypto adds a whole PKCS#7 block. Its first four ciphertext blocks
		// nevertheless independently cross-check the raw noble result.
		const webKey = await crypto.subtle.importKey('raw', key.buffer as ArrayBuffer, 'AES-CBC', false, ['encrypt']);
		const paddedWeb = new Uint8Array(await crypto.subtle.encrypt(
			{ name: 'AES-CBC', iv: iv.buffer as ArrayBuffer },
			webKey,
			plain.buffer as ArrayBuffer,
		));
		expect(paddedWeb.slice(0, expected.length)).toEqual(expected);
	});

	it('matches RFC 4231 HMAC-SHA-256 Test Case 1', async () => {
		const tag = await hmacSha256(new Uint8Array(20).fill(0x0b), utf8('Hi There'));
		expect(toHex(tag)).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
	});

	it('matches RFC 4231 Test Case 7 (131-byte key, 152-byte data)', async () => {
		const data = utf8('This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.');
		expect(data.length).toBe(152);
		const tag = await hmacSha256(new Uint8Array(131).fill(0xaa), data);
		expect(toHex(tag)).toBe('9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2');
	});
});

describe('KATs — ChaCha20 and Poly1305 from RFC 8439', () => {
	it('maps §2.4.2 onto the original 64-bit-nonce layout (114 bytes, two blocks)', () => {
		const key = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
		// RFC nonce 00000000 || 0000004a00000000: the leading word belongs to
		// the IETF counter layout, leaving this eight-byte original-ChaCha nonce.
		const nonce = fromHex('0000004a00000000');
		const plain = utf8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
		const expected = fromHex(`
			6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
			f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
			07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
			5af90bbf74a35be6b40b8eedf2785e42874d`);
		expect(plain.length).toBe(114);
		expect(chacha20orig(key, nonce, plain, undefined, 1)).toEqual(expected);
	});

	it('matches Appendix A.1 block-function vector 1', () => {
		const expected = fromHex(`
			76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7
			da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586`);
		expect(chacha20orig(new Uint8Array(32), new Uint8Array(8), new Uint8Array(64), undefined, 0)).toEqual(expected);
	});

	it('matches Appendix A.2 encryption vector 3 (127 bytes, two blocks)', () => {
		const key = fromHex('1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0');
		const plain = utf8("'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.");
		const expected = fromHex(`
			62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf
			166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb
			f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77
			04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1`);
		expect(plain.length).toBe(127);
		expect(chacha20orig(key, fromHex('0000000000000002'), plain, undefined, 42)).toEqual(expected);
	});

	it('matches §2.5.2 Poly1305', () => {
		const key = fromHex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
		expect(toHex(poly1305(utf8('Cryptographic Forum Research Group'), key))).toBe('a8061dc1305136c6c22b8baf0c0127a9');
	});

	it('matches Appendix A.3 vector 4 (127-byte message)', () => {
		const key = fromHex('1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0');
		const message = utf8("'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.");
		expect(toHex(poly1305(message, key))).toBe('4541669a7eaaee61e708dc7cbcc5eb62');
	});
});

describe('KAT — draft-ietf-sshm-chacha20-poly1305-04 Appendix A', () => {
	it('matches the complete 92-byte worked packet (72-byte body exceeds one block)', () => {
		const key = fromHex(`
			8bbff6855fc102338c373e73aac0c914f076a905b2444a32eecaffeae22becc5
			e9b7a7a5825a8249346ec1c28301cf394543fc7569887d76e168f37562ac0740`);
		const packet = fromHex(`
			00000048065e00000000000000384c6f72656d20697073756d20646f6c6f7220
			73697420616d65742c20636f6e7365637465747572206164697069736963696e
			6720656c69744e43e804dc6c`);
		const expected = fromHex(`
			2c3ecce4a5bc05895bf07a7ba956b6c68829ac7c83b780b7000ecde745afc705
			bbc378ce03a280236b87b53bed5839662302b164b6286a48cd1e097138e3cb90
			9b8b2b829dd18d2a35ff82d995349e855bf02c298ef775f2d1a7e8b8`);
		expect(packet.slice(4).length).toBe(72);
		const protectedPacket = protectOpenSshChaCha(key, 7, packet);
		expect(protectedPacket.wire).toEqual(expected);
		expect(openOpenSshChaCha(key, 7, expected).packet).toEqual(packet);
	});
});

describe('APW receiver and recovery model', () => {
	it.each([
		[0, false, 0],
		[4, false, 0],
		[5, false, 14],
		[13, false, 14],
		[12, false, 14],
		[12, true, 32],
		[65_549, false, 14],
		[65_548, true, 32],
		[262_144, false, 0],
		[262_145, false, 0],
		[0xfffffff0, false, 0],
		[0xfffffff0, true, 0],
	] as const)('claims only an observable prefix for length %i (complete wait %s)', (length, feedWait, expectedBits) => {
		const reaction = classifyPre52OpenSsh(concatBytes(uint32(length), new Uint8Array(12)), feedWait);
		expect(recoverablePrefixBits('openssh-5.1', reaction)).toBe(expectedBits);
	});

	it('claims idealised recovery only after the wait completes within the page budget', () => {
		const completed = classifyIdealised(concatBytes(uint32(65_549), new Uint8Array(12)), 1_048_576);
		const overBudget = classifyIdealised(concatBytes(uint32(0xfffffff0), new Uint8Array(12)), 1_048_576);
		expect(recoverablePrefixBits('idealised', completed)).toBe(32);
		expect(recoverablePrefixBits('idealised', overBudget)).toBe(0);
	});
	it.each([4, 20])('rejects a changed protected byte at offset %i before returning plaintext', (offset) => {
		const key = new Uint8Array(64).fill(0x5a);
		const packet = encodePacket(utf8('test payload'), new Uint8Array(32).fill(0x11)).wire;
		const wire = protectOpenSshChaCha(key, 9, packet).wire.slice();
		wire[offset] ^= 1;
		expect(() => openOpenSshChaCha(key, 9, wire)).toThrow(/Poly1305 rejected/);
	});

	it('recovers a real CBC target block using P-prime XOR L XOR predecessor', async () => {
		const direction = new CbcEncryptAndMacDirection(
			fromHex('000102030405060708090a0b0c0d0e0f'),
			new Uint8Array(32).fill(0x42),
			fromHex('101112131415161718191a1b1c1d1e1f'),
		);
		const packet = await direction.protect(0, utf8('USER=alice\nPASS=hunter2; recurring secret'), new Uint8Array(32).fill(0xa5));
		const cipherBlocks = blocks(packet.ciphertext);
		const plainBlocks = blocks(packet.plain.wire);
		const targetIndex = 1;
		const last = packet.lastBlock;
		const target = cipherBlocks[targetIndex]!;
		const predecessor = cipherBlocks[targetIndex - 1]!;
		const pPrime = aesCbcDecryptRaw(fromHex('000102030405060708090a0b0c0d0e0f'), last, target);
		const recovered = recoverTargetPlaintext(pPrime, last, predecessor);
		expect(recovered).toEqual(plainBlocks[targetIndex]);
		expect(verifyRecoveredPrefix(recovered, plainBlocks[targetIndex]!, 32)).toBe(true);
	});

	it('distinguishes pre-5.2 length, alignment, and wait/MAC reactions', () => {
		expect(classifyPre52OpenSsh(concatBytes(uint32(0x400001), new Uint8Array(12))).kind).toBe('DISCONNECT');
		expect(classifyPre52OpenSsh(concatBytes(uint32(13), new Uint8Array(12))).kind).toBe('FIN');
		expect(classifyPre52OpenSsh(concatBytes(uint32(12), new Uint8Array(12))).kind).toBe('WAIT');
		expect(classifyPre52OpenSsh(concatBytes(uint32(12), new Uint8Array(12)), true).kind).toBe('MAC_ERROR');
	});

	it('measures seeded rates near the paper’s 2^-14 and 2^-18 probabilities', () => {
		const result = measureOpenSshRates(16_777_216);
		const rate14 = result.fourteenBitHits / result.attempts;
		const rate32 = result.thirtyTwoBitHits / result.attempts;
		expect(rate14).toBeGreaterThan(APW_EXPECTED_14 * 0.85);
		expect(rate14).toBeLessThan(APW_EXPECTED_14 * 1.15);
		expect(rate32).toBeGreaterThan(APW_EXPECTED_32 * 0.65);
		expect(rate32).toBeLessThan(APW_EXPECTED_32 * 1.35);
	});
});

describe('Terrapin, exact H, key expansion, and strict kex', () => {
	it('uses real X25519; IGNORE leaves H unchanged while stripping strict markers changes H', async () => {
		const kex = await buildTerrapinKex();
		expect(kex.hostSignatureValid).toBe(true);
		expect(await hashWithOptionalIgnore(kex, makeIgnoreWire().wire)).toEqual(kex.exchangeHash);
		expect(await strippedStrictHash(kex)).not.toEqual(kex.exchangeHash);
		expect(kex.serverToClientKey).toHaveLength(64);
	});

	it('derives RFC 4253 §7.2 K1 and K2 by an independent test re-derivation', async () => {
		const shared = fromHex('80ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
		const h = fromHex('58b4f0a9b4f4c93a24ddfa8b18b13a516083aa74b6fc65b987f20cf6c3935547');
		const session = h;
		const firstInput = concat(wireMpint(shared), h, utf8('D'), session);
		const k1 = new Uint8Array(await crypto.subtle.digest('SHA-256', firstInput.buffer as ArrayBuffer));
		const secondInput = concat(wireMpint(shared), h, k1);
		const k2 = new Uint8Array(await crypto.subtle.digest('SHA-256', secondInput.buffer as ArrayBuffer));
		expect(await deriveRfc4253Key(shared, h, 'D', session, 64)).toEqual(concat(k1, k2));
	});

	it('deletes EXT_INFO and real ChaCha/Poly1305 accepts the next packet only after IGNORE', async () => {
		const kex = await buildTerrapinKex();
		const counters = countersBeforeNewKeys();
		counters.injectToClient();
		counters.clientToServer(); // client NEWKEYS
		counters.serverToClient(); // server NEWKEYS
		const extSequence = counters.serverToClient(false);
		const appSequence = counters.serverToClient(false);
		const ext = protectOpenSshChaCha(kex.serverToClientKey, extSequence, encodePacket(utf8('EXT_INFO server-sig-algs,ping@openssh.com'), new Uint8Array(32).fill(0x11)).wire);
		const app = protectOpenSshChaCha(kex.serverToClientKey, appSequence, encodePacket(utf8('SSH_MSG_CHANNEL_DATA'), new Uint8Array(32).fill(0x22)).wire);
		const packets: WirePacket[] = [
			{ kind: 'EXT_INFO', sequence: extSequence, wire: ext.wire },
			{ kind: 'APPLICATION', sequence: appSequence, wire: app.wire },
		];
		const attacked = deleteExtInfo(packets);
		expect(attacked.deleted?.kind).toBe('EXT_INFO');
		expect(counters.clientReceive).toBe(appSequence);
		expect(openOpenSshChaCha(kex.serverToClientKey, counters.clientReceive, attacked.delivered[0]!.wire).tagValid).toBe(true);
	});

	it('rejects deletion without IGNORE because the expected sequence does not match', async () => {
		const kex = await buildTerrapinKex();
		const counters = countersBeforeNewKeys();
		counters.clientToServer();
		counters.serverToClient();
		const extSequence = counters.serverToClient(false);
		const appSequence = counters.serverToClient(false);
		const app = protectOpenSshChaCha(kex.serverToClientKey, appSequence, encodePacket(utf8('SSH_MSG_CHANNEL_DATA'), new Uint8Array(32).fill(0x33)).wire);
		expect(extSequence).toBe(counters.clientReceive);
		expect(() => openOpenSshChaCha(kex.serverToClientKey, counters.clientReceive, app.wire)).toThrow(/expected sequence 3/);
	});

	it('strict kex needs both peers and kills the injected IGNORE at the named rule', () => {
		expect(negotiateStrictKex(true, false).active).toBe(false);
		const both = negotiateStrictKex(true, true);
		expect(checkInitialKexMessage(both, 'IGNORE', 4)).toEqual({
			accepted: false,
			rule: 'strict kex terminates on a non-KEX message during initial key exchange',
		});
	});
});

describe('attacker boundary', () => {
	it('attack modules import no key material or primitive implementations', () => {
		for (const [name, source] of Object.entries(attackSources)) {
			expect(name).toMatch(/attack-(apw|terrapin)\.ts/);
			expect(source).not.toMatch(/from ['"].*(cbc-and-mac|chachapoly|kex|@noble)/);
			expect(source).not.toMatch(/\b(encryptionKey|macKey|privateKey|serverToClientKey)\b/);
		}
	});

	it('the separate recovered-plaintext verifier is never called by attacker code', () => {
		const source = attackSources['./attack-apw.ts']!;
		expect(source.match(/verifyRecoveredPrefix\s*\(/g)).toHaveLength(1);
	});

	it('wire-only deletion returns copies and does not mutate the source', () => {
		const source: WirePacket[] = [
			{ kind: 'EXT_INFO', sequence: 3, wire: Uint8Array.of(1, 2) },
			{ kind: 'APPLICATION', sequence: 4, wire: Uint8Array.of(3, 4) },
		];
		const result = deleteExtInfo(source);
		result.delivered[0]!.wire[0] = 0xff;
		expect(source[1]!.wire[0]).toBe(3);
	});

	it('XOR helper is its own inverse', () => {
		const a = fromHex('00112233');
		const b = fromHex('deadbeef');
		expect(xorBytes(xorBytes(a, b), b)).toEqual(a);
		expect(equalBytes(a, a.slice())).toBe(true);
	});
});


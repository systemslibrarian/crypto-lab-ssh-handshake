// wire.ts — canonical OpenSSH public-key wire serialization. Produces the
// exact bytes that ssh-keygen prints in the .pub file and hashes for
// SHA256:<base64> fingerprints. Lets fingerprints in this demo match
// ssh-keygen -lf output for the same key material.
//
// Format (RFC 4253 §6.6, RFC 5656 §3.1, RFC 8709 §4):
//   ssh-ed25519       : string "ssh-ed25519"          string key(32B)
//   ecdsa-sha2-nistp256: string "ecdsa-sha2-nistp256"  string "nistp256"
//                        string Q (uncompressed: 0x04 || X || Y, 65 bytes)

const enc = new TextEncoder();

export function b64urlToBytes(s: string): Uint8Array {
	const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
	const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
	const bin = atob(b64 + pad);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function bytesToB64(u: Uint8Array): string {
	let s = '';
	for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
	return btoa(s);
}

export function wireString(data: string | Uint8Array): Uint8Array {
	const bytes = typeof data === 'string' ? enc.encode(data) : data;
	const out = new Uint8Array(4 + bytes.length);
	new DataView(out.buffer).setUint32(0, bytes.length, false);
	out.set(bytes, 4);
	return out;
}

export function wireUint32(val: number): Uint8Array {
	const out = new Uint8Array(4);
	new DataView(out.buffer).setUint32(0, val, false);
	return out;
}

export function wireMpint(buf: ArrayBuffer | Uint8Array): Uint8Array {
	const u = new Uint8Array(buf);
	// Trim leading zero bytes
	let start = 0;
	while (start < u.length && u[start] === 0) start++;
	if (start === u.length) return wireString(new Uint8Array(0));
	const trimmed = u.slice(start);
	
	// If the high bit of the first byte is set, prepend a zero byte.
	if (trimmed[0] & 0x80) {
		const out = new Uint8Array(trimmed.length + 1);
		out.set(trimmed, 1);
		return wireString(out);
	}
	return wireString(trimmed);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const p of parts) total += p.length;
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

export type SshKeyType = 'ssh-ed25519' | 'ecdsa-sha2-nistp256';

export function sshKeyTypeFromSigAlgo(sigAlgo: string): SshKeyType {
	if (sigAlgo === 'Ed25519') return 'ssh-ed25519';
	if (sigAlgo === 'ECDSA P-256') return 'ecdsa-sha2-nistp256';
	throw new Error('unsupported signature algorithm for SSH wire encoding: ' + sigAlgo);
}

// Build the canonical SSH wire-format public key blob from a JWK + the
// algorithm name the engine selected at init time.
export function sshPublicKeyBlob(jwk: JsonWebKey, sigAlgo: string): Uint8Array {
	const keyType = sshKeyTypeFromSigAlgo(sigAlgo);
	if (keyType === 'ssh-ed25519') {
		// Ed25519: 32-byte raw public key in JWK.x (base64url)
		return concat(wireString('ssh-ed25519'), wireString(b64urlToBytes(jwk.x ?? '')));
	}
	// ecdsa-sha2-nistp256: uncompressed EC point (0x04 || X || Y, 65 bytes)
	const xBytes = b64urlToBytes(jwk.x ?? '');
	const yBytes = b64urlToBytes(jwk.y ?? '');
	const point = new Uint8Array(1 + xBytes.length + yBytes.length);
	point[0] = 0x04;
	point.set(xBytes, 1);
	point.set(yBytes, 1 + xBytes.length);
	return concat(
		wireString('ecdsa-sha2-nistp256'),
		wireString('nistp256'),
		wireString(point),
	);
}

// SHA-256 fingerprint of an SSH wire-format blob, formatted as OpenSSH prints
// it: "SHA256:" + base64(hash) with trailing '=' stripped.
export async function sshFingerprint(blob: Uint8Array): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', blob.buffer as ArrayBuffer);
	return 'SHA256:' + bytesToB64(new Uint8Array(digest)).replace(/=+$/, '');
}

// Base64 of the wire blob — the third field in a ~/.ssh/known_hosts line.
export function sshPublicKeyBase64(blob: Uint8Array): string {
	return bytesToB64(blob);
}

// SSHFP DNS RR rdata: <algorithm> <fp-type> <fingerprint-hex>.
//   algorithm: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519
//   fp-type:   1=SHA-1, 2=SHA-256
export function sshfpAlgorithmCode(keyType: SshKeyType): number {
	if (keyType === 'ssh-ed25519') return 4;
	if (keyType === 'ecdsa-sha2-nistp256') return 3;
	throw new Error('unsupported key type for SSHFP: ' + keyType);
}

export async function sshfpRecord(
	hostName: string,
	blob: Uint8Array,
	keyType: SshKeyType,
	ttl = 3600,
): Promise<{ rr: string; hashHex: string; algo: number; fpType: number }> {
	const digest = await crypto.subtle.digest('SHA-256', blob.buffer as ArrayBuffer);
	const bytes = new Uint8Array(digest);
	let hex = '';
	for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
	const algo = sshfpAlgorithmCode(keyType);
	const fpType = 2;
	return {
		rr: `${hostName}. ${ttl} IN SSHFP ${algo} ${fpType} ${hex}`,
		hashHex: hex,
		algo,
		fpType,
	};
}

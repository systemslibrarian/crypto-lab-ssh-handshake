// ca.ts — OpenSSH host certificate model. A small CA signs host public keys;
// clients trust the CA via @cert-authority instead of pinning each host. Real
// crypto: a CA keypair using the engine's Ed25519/ECDSA P-256 fallback, a
// signature over the certificate body, and verification on the client side.
//
// Lives outside engine.ts so engine.ts stays verbatim from Appendix A.

import { sshFingerprint, sshKeyTypeFromSigAlgo, sshPublicKeyBlob } from './wire.ts';

const enc = new TextEncoder();

let SIG_ALGO: EcKeyGenParams | { name: 'Ed25519' };
let SIG_PARAMS: AlgorithmIdentifier | EcdsaParams;
let caAlgoName = 'Ed25519';
let inited = false;

async function init(): Promise<void> {
	if (inited) return;
	try {
		await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
		SIG_ALGO = { name: 'Ed25519' };
		SIG_PARAMS = { name: 'Ed25519' };
		caAlgoName = 'Ed25519';
	} catch {
		SIG_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
		SIG_PARAMS = { name: 'ECDSA', hash: 'SHA-256' };
		caAlgoName = 'ECDSA P-256';
	}
	inited = true;
}

export function caAlgo(): string {
	return caAlgoName;
}

function b64(buf: ArrayBuffer): string {
	const u = new Uint8Array(buf);
	let s = '';
	for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
	return btoa(s);
}
function unb64(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}
// Fingerprint in OpenSSH's exact format: SHA-256 over the CANONICAL SSH
// wire-format public-key blob (RFC 4253 §6.6 / RFC 8709 §4), base64 with the
// trailing '=' stripped — byte-for-byte what `ssh-keygen -lf` prints.
//
// This deliberately shares wire.ts with engine.ts's host-key fingerprint. An
// earlier version hashed the ASCII of the base64url JWK coordinates
// ((jwk.x + jwk.y) as text), which produced a well-formed-looking "SHA256:…"
// string that matched no real tool and disagreed with every other SHA256: on
// the page. Every `SHA256:` this demo shows now means the same thing.
async function fingerprint(pubJwk: JsonWebKey): Promise<string> {
	await init();
	return sshFingerprint(sshPublicKeyBlob(pubJwk, caAlgoName));
}

// Kept alongside fingerprint() so the CA's key type is always named with the
// same string the wire encoder used to build the blob we hashed.
export function caKeyType(): string {
	return sshKeyTypeFromSigAlgo(caAlgoName);
}

// OpenSSH host certificate — same field set as PROTOCOL.certkeys (nonce,
// serial, type, key id, principals, valid-after/before, critical options,
// extensions, reserved, signature key, signature). The wire layout here is a
// JSON envelope rather than ssh-string-prefixed bytes, so the certificate
// LOGIC is faithful but the on-disk format is compressed for the demo.
export interface HostCert {
	nonce: string;               // 32 random bytes (base64) — anti-pre-signing
	hostName: string;            // legacy single-principal field this demo uses
	hostPubJwk: JsonWebKey;      // the host pubkey this cert authorizes
	serial: string;              // OpenSSH's 64-bit serial (string for JSON safety)
	certType: 'host';            // SSH_CERT_TYPE_HOST = 2
	keyId: string;               // free-form operator id (man-page "key_id")
	validPrincipals: string[];   // hostnames the cert authorizes
	validAfter: string;          // ISO — "after this instant the cert is valid"
	validBefore: string;         // ISO — historical name for the expiry
	criticalOptions: Record<string, string>;
	extensions: Record<string, string>;
	reserved: string;            // OpenSSH cert always carries an empty reserved field
	issuer: string;              // CA display name (signature_key in OpenSSH)
	issuerFingerprint: string;
	issuedAt: string;            // ISO — convenience mirror of validAfter
	validUntil: string;          // ISO — convenience mirror of validBefore
	signature: string;           // base64 of CA signature over the body
}

function certBody(cert: Omit<HostCert, 'signature'>): string {
	return [
		cert.nonce,
		cert.hostName,
		(cert.hostPubJwk.x ?? '') + (cert.hostPubJwk.y ?? ''),
		cert.serial,
		cert.certType,
		cert.keyId,
		cert.validPrincipals.join(','),
		cert.validAfter,
		cert.validBefore,
		JSON.stringify(cert.criticalOptions),
		JSON.stringify(cert.extensions),
		cert.reserved,
		cert.issuer,
		cert.issuerFingerprint,
		cert.issuedAt,
		cert.validUntil,
	].join('|');
}

function randomNonceB64(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	let s = '';
	for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
	return btoa(s);
}

function randomSerial(): string {
	// 64-bit unsigned serial — two 32-bit halves to stay inside JS number safety.
	const hi = Math.floor(Math.random() * 0x100000000);
	const lo = Math.floor(Math.random() * 0x100000000);
	return (BigInt(hi) * 0x100000000n + BigInt(lo)).toString();
}

export class HostCA {
	readonly name: string;
	private priv!: CryptoKey;
	pub!: JsonWebKey;
	fingerprint = '';

	private constructor(name: string) {
		this.name = name;
	}

	static async create(name: string): Promise<HostCA> {
		await init();
		const ca = new HostCA(name);
		const kp = (await crypto.subtle.generateKey(SIG_ALGO, true, ['sign', 'verify'])) as CryptoKeyPair;
		ca.priv = kp.privateKey;
		ca.pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
		ca.fingerprint = await fingerprint(ca.pub);
		return ca;
	}

	publicIdentity(): { name: string; pubJwk: JsonWebKey; fingerprint: string } {
		return { name: this.name, pubJwk: this.pub, fingerprint: this.fingerprint };
	}

	async sign(
		hostName: string,
		hostPubJwk: JsonWebKey,
		options: {
			validityDays?: number;
			keyId?: string;
			validPrincipals?: string[];
			criticalOptions?: Record<string, string>;
			extensions?: Record<string, string>;
		} = {},
	): Promise<HostCert> {
		await init();
		const issuedAt = new Date();
		const validUntil = new Date(issuedAt.getTime() + (options.validityDays ?? 365) * 24 * 3600 * 1000);
		const issuedAtIso = issuedAt.toISOString();
		const validUntilIso = validUntil.toISOString();
		const body: Omit<HostCert, 'signature'> = {
			nonce: randomNonceB64(),
			hostName,
			hostPubJwk,
			serial: randomSerial(),
			certType: 'host',
			keyId: options.keyId ?? `host-cert:${hostName}@${issuedAtIso.slice(0, 10)}`,
			validPrincipals: options.validPrincipals ?? [hostName],
			validAfter: issuedAtIso,
			validBefore: validUntilIso,
			criticalOptions: options.criticalOptions ?? {},
			extensions: options.extensions ?? {},
			reserved: '',
			issuer: this.name,
			issuerFingerprint: this.fingerprint,
			issuedAt: issuedAtIso,
			validUntil: validUntilIso,
		};
		const sig = await crypto.subtle.sign(SIG_PARAMS, this.priv, enc.encode(certBody(body)) as BufferSource);
		return { ...body, signature: b64(sig) };
	}
}

export type CertVerdict =
	| { valid: true; reason: string }
	| { valid: false; reason: string };

export async function verifyCert(
	cert: HostCert,
	caPubJwk: JsonWebKey,
	expectedHostName: string,
	presentedHostPubJwk: JsonWebKey,
): Promise<CertVerdict> {
	await init();
	if (cert.hostName !== expectedHostName) {
		return { valid: false, reason: `cert principal "${cert.hostName}" does not match expected "${expectedHostName}"` };
	}
	const presentedFp = await fingerprint(presentedHostPubJwk);
	const certHostFp = await fingerprint(cert.hostPubJwk);
	if (presentedFp !== certHostFp) {
		return { valid: false, reason: 'cert binds a different host pubkey than the one presented in the handshake' };
	}
	const now = new Date();
	if (new Date(cert.validUntil) < now) {
		return { valid: false, reason: `cert expired at ${cert.validUntil}` };
	}
	if (new Date(cert.issuedAt) > now) {
		return { valid: false, reason: `cert issuedAt ${cert.issuedAt} is in the future` };
	}
	if (!cert.validPrincipals.includes(expectedHostName)) {
		return { valid: false, reason: `cert valid_principals ${JSON.stringify(cert.validPrincipals)} does not include ${expectedHostName}` };
	}
	if (cert.certType !== 'host') {
		return { valid: false, reason: `cert type "${cert.certType}" is not "host" — refusing to use it for host authentication` };
	}
	try {
		const caKey = await crypto.subtle.importKey('jwk', caPubJwk, SIG_ALGO, false, ['verify']);
		const { signature, ...rest } = cert;
		void signature;
		const body = certBody(rest);
		const ok = await crypto.subtle.verify(SIG_PARAMS, caKey, unb64(cert.signature) as BufferSource, enc.encode(body) as BufferSource);
		if (!ok) return { valid: false, reason: 'CA signature on cert did not verify' };
	} catch (err) {
		return { valid: false, reason: `cert verification threw: ${(err as Error).message}` };
	}
	return { valid: true, reason: `cert valid; signed by ${cert.issuer} (${cert.issuerFingerprint}), serial ${cert.serial}, key_id "${cert.keyId}". Binds ${expectedHostName} to ${certHostFp}.` };
}

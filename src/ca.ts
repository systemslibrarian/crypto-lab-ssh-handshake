// ca.ts — OpenSSH host certificate model. A small CA signs host public keys;
// clients trust the CA via @cert-authority instead of pinning each host. Real
// crypto: a CA keypair using the engine's Ed25519/ECDSA P-256 fallback, a
// signature over the certificate body, and verification on the client side.
//
// Lives outside engine.ts so engine.ts stays verbatim from Appendix A.

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
async function fingerprint(pubJwk: JsonWebKey): Promise<string> {
	const material = (pubJwk.x ?? '') + (pubJwk.y ?? '');
	const d = await crypto.subtle.digest('SHA-256', enc.encode(material) as BufferSource);
	return 'SHA256:' + b64(d).replace(/=+$/, '');
}

// A simplified OpenSSH host certificate.
export interface HostCert {
	hostName: string;            // principal — must match the connection name
	hostPubJwk: JsonWebKey;      // the host pubkey this cert authorizes
	issuer: string;              // CA display name
	issuerFingerprint: string;
	issuedAt: string;            // ISO
	validUntil: string;          // ISO
	signature: string;           // base64 of CA signature over the cert body
}

function certBody(cert: Omit<HostCert, 'signature'>): string {
	return [
		cert.hostName,
		(cert.hostPubJwk.x ?? '') + (cert.hostPubJwk.y ?? ''),
		cert.issuer,
		cert.issuerFingerprint,
		cert.issuedAt,
		cert.validUntil,
	].join('|');
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

	async sign(hostName: string, hostPubJwk: JsonWebKey, validityDays = 365): Promise<HostCert> {
		await init();
		const issuedAt = new Date();
		const validUntil = new Date(issuedAt.getTime() + validityDays * 24 * 3600 * 1000);
		const body: Omit<HostCert, 'signature'> = {
			hostName,
			hostPubJwk,
			issuer: this.name,
			issuerFingerprint: this.fingerprint,
			issuedAt: issuedAt.toISOString(),
			validUntil: validUntil.toISOString(),
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
	try {
		const caKey = await crypto.subtle.importKey('jwk', caPubJwk, SIG_ALGO, false, ['verify']);
		const body = certBody({
			hostName: cert.hostName,
			hostPubJwk: cert.hostPubJwk,
			issuer: cert.issuer,
			issuerFingerprint: cert.issuerFingerprint,
			issuedAt: cert.issuedAt,
			validUntil: cert.validUntil,
		});
		const ok = await crypto.subtle.verify(SIG_PARAMS, caKey, unb64(cert.signature) as BufferSource, enc.encode(body) as BufferSource);
		if (!ok) return { valid: false, reason: 'CA signature on cert did not verify' };
	} catch (err) {
		return { valid: false, reason: `cert verification threw: ${(err as Error).message}` };
	}
	return { valid: true, reason: `cert valid; signed by ${cert.issuer} (${cert.issuerFingerprint}) and binds ${expectedHostName} to ${certHostFp}.` };
}

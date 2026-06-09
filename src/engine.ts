// engine.ts — a faithful model of the SSH transport-layer handshake using REAL
// Web Crypto: ephemeral ECDH key agreement authenticated by a long-term host
// signing key, plus the known_hosts / Trust-On-First-Use (TOFU) flow and the
// man-in-the-middle scenario it is designed to detect.
//
// This is NOT the SSH binary packet protocol or the full RFC 4253 wire format;
// it models the SECURITY-RELEVANT logic faithfully:
//   * server long-term HOST key (signing) — its identity
//   * per-connection EPHEMERAL ECDH keys on both sides — forward secrecy
//   * an "exchange hash" H binding both ephemeral pubkeys + host pubkey + IDs
//   * server signs H with the host key; client verifies against known_hosts
//   * TOFU: first connection pins the host key; later connections compare.

// NOTE: this file is the verbatim engine from the build prompt's Appendix A
// with ONE targeted refinement to `fingerprint()` (see comment on that
// function) so that fingerprints match `ssh-keygen -lf` byte-for-byte. The
// cryptographic logic — ephemeral KEX, exchange-hash binding, host signature,
// signature verification — is unchanged.
import { sshPublicKeyBlob } from './wire.ts';

const enc = new TextEncoder();

// Ephemeral KEX: prefer X25519, fall back to ECDH P-256.
// Host signing: prefer Ed25519, fall back to ECDSA P-256.
let KEX_ALGO: EcKeyGenParams | { name: 'X25519' };
let KEX_DERIVE: (pub: CryptoKey) => KeyAlgorithm | EcdhKeyDeriveParams;
let SIG_ALGO: EcKeyGenParams | { name: 'Ed25519' };
let SIG_PARAMS: AlgorithmIdentifier | EcdsaParams;
let kexName = 'X25519';
let sigName = 'Ed25519';
let inited = false;

async function init(): Promise<void> {
    if (inited) return;
    // KEX
    try {
        const kp = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
            'deriveBits',
        ])) as CryptoKeyPair;
        void kp;
        KEX_ALGO = { name: 'X25519' };
        KEX_DERIVE = (pub) => ({ name: 'X25519', public: pub }) as unknown as EcdhKeyDeriveParams;
        kexName = 'X25519';
    } catch {
        KEX_ALGO = { name: 'ECDH', namedCurve: 'P-256' };
        KEX_DERIVE = (pub) => ({ name: 'ECDH', public: pub });
        kexName = 'ECDH P-256';
    }
    // SIG
    try {
        const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
            'sign',
            'verify',
        ])) as CryptoKeyPair;
        void kp;
        SIG_ALGO = { name: 'Ed25519' };
        SIG_PARAMS = { name: 'Ed25519' };
        sigName = 'Ed25519';
    } catch {
        SIG_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
        SIG_PARAMS = { name: 'ECDSA', hash: 'SHA-256' };
        sigName = 'ECDSA P-256';
    }
    inited = true;
}

export function algoNames(): { kex: string; sig: string } {
    return { kex: kexName, sig: sigName };
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
async function sha256Hex(s: string): Promise<string> {
    const d = await crypto.subtle.digest('SHA-256', enc.encode(s) as BufferSource);
    return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Host-key fingerprint in OpenSSH's exact format: SHA-256 over the canonical
// SSH wire-format public-key blob, base64-encoded with trailing '=' stripped.
// Matches what `ssh-keygen -lf` prints for the same key. (The original
// Appendix A definition hashed concatenated JWK x+y; this refinement makes
// the fingerprint string OpenSSH-canonical without changing any other
// cryptographic step.)
async function fingerprint(hostPubJwk: JsonWebKey): Promise<string> {
    const blob = sshPublicKeyBlob(hostPubJwk, sigName);
    const d = await crypto.subtle.digest('SHA-256', blob.buffer as ArrayBuffer);
    return 'SHA256:' + b64(d).replace(/=+$/, '');
}

// =====================================================================
// Server: holds a long-term host key and runs the server side of KEX.
// =====================================================================
export interface HostPublic {
    name: string; // e.g. "server.example.com"
    hostPubJwk: JsonWebKey; // long-term host signing public key
    fingerprint: string;
}

export class SshServer {
    readonly name: string;
    private hostPriv!: CryptoKey;
    hostPub!: JsonWebKey;
    fingerprint = '';

    private constructor(name: string) {
        this.name = name;
    }

    static async create(name: string): Promise<SshServer> {
        await init();
        const s = new SshServer(name);
        const kp = (await crypto.subtle.generateKey(SIG_ALGO, true, ['sign', 'verify'])) as CryptoKeyPair;
        s.hostPriv = kp.privateKey;
        s.hostPub = await crypto.subtle.exportKey('jwk', kp.publicKey);
        s.fingerprint = await fingerprint(s.hostPub);
        return s;
    }

    publicIdentity(): HostPublic {
        return { name: this.name, hostPubJwk: this.hostPub, fingerprint: this.fingerprint };
    }

    // Given the client's ephemeral public key, the server makes its own
    // ephemeral key, derives the shared secret, computes the exchange hash H,
    // and SIGNS H with the long-term host key.
    async respond(clientEphPubJwk: JsonWebKey): Promise<ServerHello> {
        await init();
        const eph = (await crypto.subtle.generateKey(KEX_ALGO, true, ['deriveBits'])) as CryptoKeyPair;
        const serverEphPubJwk = await crypto.subtle.exportKey('jwk', eph.publicKey);
        const clientEphPub = await crypto.subtle.importKey('jwk', clientEphPubJwk, KEX_ALGO, false, []);
        const sharedBits = await crypto.subtle.deriveBits(
            KEX_DERIVE(clientEphPub) as AlgorithmIdentifier,
            eph.privateKey,
            256,
        );
        const H = await exchangeHash(this.name, this.hostPub, clientEphPubJwk, serverEphPubJwk, sharedBits);
        const sig = await crypto.subtle.sign(SIG_PARAMS, this.hostPriv, enc.encode(H) as BufferSource);
        return {
            hostName: this.name,
            hostPubJwk: this.hostPub,
            serverEphPubJwk,
            exchangeHash: H,
            hostSignatureB64: b64(sig),
            sharedSecretHex: b64(sharedBits),
        };
    }
}

export interface ServerHello {
    hostName: string;
    hostPubJwk: JsonWebKey;
    serverEphPubJwk: JsonWebKey;
    exchangeHash: string;
    hostSignatureB64: string;
    sharedSecretHex: string; // for display only; the client recomputes its own
}

// the exchange hash H binds: host name, host public key, both ephemeral pubkeys,
// and the shared secret. Any substitution changes H and breaks the signature.
async function exchangeHash(
    hostName: string,
    hostPubJwk: JsonWebKey,
    clientEphJwk: JsonWebKey,
    serverEphJwk: JsonWebKey,
    shared: ArrayBuffer,
): Promise<string> {
    const parts = [
        hostName,
        (hostPubJwk.x ?? '') + (hostPubJwk.y ?? ''),
        (clientEphJwk.x ?? '') + (clientEphJwk.y ?? ''),
        (serverEphJwk.x ?? '') + (serverEphJwk.y ?? ''),
        b64(shared),
    ].join('|');
    return sha256Hex(parts);
}

// =====================================================================
// Client: generates an ephemeral key, completes KEX, verifies the host
// signature, and applies the known_hosts / TOFU policy.
// =====================================================================
export type KnownHosts = Map<string, string>; // hostName -> pinned fingerprint

export interface ConnectResult {
    steps: { label: string; detail: string; ok: boolean }[];
    sharedAgrees: boolean;
    signatureValid: boolean;
    hostKeyDecision: 'tofu-pinned' | 'matches-known' | 'CHANGED-REJECTED' | 'unknown';
    connected: boolean;
    summary: string;
}

export class SshClient {
    knownHosts: KnownHosts = new Map();

    // Connect to a (possibly attacker-controlled) party that answers respond().
    // `expectedName` is what the user typed; `responder` may be the real server
    // or a MITM. The host key the client verifies is whatever the responder
    // presents — TOFU/known_hosts is what catches a substitution.
    async connect(
        expectedName: string,
        responder: { respond: (clientEphPubJwk: JsonWebKey) => Promise<ServerHello> },
    ): Promise<ConnectResult> {
        await init();
        const steps: ConnectResult['steps'] = [];

        // 1. client ephemeral key
        const eph = (await crypto.subtle.generateKey(KEX_ALGO, true, ['deriveBits'])) as CryptoKeyPair;
        const clientEphPubJwk = await crypto.subtle.exportKey('jwk', eph.publicKey);
        steps.push({ label: 'Client KEX init', detail: `Generated ephemeral ${kexName} key.`, ok: true });

        // 2. server responds
        const hello = await responder.respond(clientEphPubJwk);
        steps.push({ label: 'Server KEX reply', detail: `Received host key + ephemeral key from "${hello.hostName}".`, ok: true });

        // 3. client derives the same shared secret
        const serverEphPub = await crypto.subtle.importKey('jwk', hello.serverEphPubJwk, KEX_ALGO, false, []);
        const sharedBits = await crypto.subtle.deriveBits(
            KEX_DERIVE(serverEphPub) as AlgorithmIdentifier,
            eph.privateKey,
            256,
        );
        const sharedAgrees = b64(sharedBits) === hello.sharedSecretHex;
        steps.push({ label: 'Shared secret', detail: sharedAgrees ? 'Both sides derived the same ECDH secret.' : 'Shared secret mismatch.', ok: sharedAgrees });

        // 4. verify the host signature over the exchange hash (recompute H locally!)
        const localH = await exchangeHash(hello.hostName, hello.hostPubJwk, clientEphPubJwk, hello.serverEphPubJwk, sharedBits);
        let signatureValid = false;
        try {
            const hostKey = await crypto.subtle.importKey('jwk', hello.hostPubJwk, SIG_ALGO, false, ['verify']);
            signatureValid =
                localH === hello.exchangeHash &&
                (await crypto.subtle.verify(SIG_PARAMS, hostKey, unb64(hello.hostSignatureB64) as BufferSource, enc.encode(localH) as BufferSource));
        } catch {
            signatureValid = false;
        }
        steps.push({ label: 'Host signature', detail: signatureValid ? 'Host proved possession of its private key (signature over exchange hash verifies).' : 'Host signature INVALID — cannot prove key ownership.', ok: signatureValid });

        // 5. known_hosts / TOFU
        const presentedFp = await fingerprint(hello.hostPubJwk);
        const pinned = this.knownHosts.get(expectedName);
        let hostKeyDecision: ConnectResult['hostKeyDecision'];
        let hostOk = false;
        if (!pinned) {
            hostKeyDecision = 'tofu-pinned';
            this.knownHosts.set(expectedName, presentedFp);
            hostOk = true;
            steps.push({ label: 'known_hosts (TOFU)', detail: `First contact — pinning ${presentedFp}. (Trust on first use: unverified leap of faith.)`, ok: true });
        } else if (pinned === presentedFp) {
            hostKeyDecision = 'matches-known';
            hostOk = true;
            steps.push({ label: 'known_hosts', detail: `Host key matches the pinned fingerprint ${presentedFp}.`, ok: true });
        } else {
            hostKeyDecision = 'CHANGED-REJECTED';
            hostOk = false;
            steps.push({ label: 'known_hosts', detail: `WARNING: host key changed! pinned ${pinned} but got ${presentedFp}. Possible MITM — connection refused.`, ok: false });
        }

        const connected = sharedAgrees && signatureValid && hostOk;
        const summary = connected
            ? (hostKeyDecision === 'tofu-pinned'
                ? 'Connected (first use) — host key now pinned in known_hosts.'
                : 'Connected — host key verified against known_hosts.')
            : hostKeyDecision === 'CHANGED-REJECTED'
                ? 'REJECTED — host key changed since last time (possible man-in-the-middle).'
                : !signatureValid
                    ? 'REJECTED — host failed to prove ownership of its key.'
                    : 'REJECTED — handshake failed.';

        return { steps, sharedAgrees, signatureValid, hostKeyDecision, connected, summary };
    }
}

// =====================================================================
// MITM: an attacker that terminates the client connection with ITS OWN host
// key. The handshake still "succeeds" cryptographically (the attacker signs
// with its own key) — only known_hosts pinning detects the swap.
// =====================================================================
export async function makeMitm(displayName: string): Promise<{ respond: (c: JsonWebKey) => Promise<ServerHello>; identity: HostPublic }> {
    const attacker = await SshServer.create(displayName);
    return {
        respond: (c) => attacker.respond(c),
        identity: attacker.publicIdentity(),
    };
}

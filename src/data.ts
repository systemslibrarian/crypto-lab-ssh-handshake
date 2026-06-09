// data.ts — narrative corpus for the SSH Handshake & known_hosts demo.
//
// The crypto lives in engine.ts. Everything here is plain content the UI
// renders into cards and tables: the three trust models the crypto-lab suite
// covers, the moving parts of the SSH transport handshake, the limits of
// Trust-On-First-Use, and where the model is actually deployed today.

export interface TrustModelRow {
	axis: string;
	pki: string;
	wot: string;
	ssh: string;
}

// Three answers to "how do I decide which public keys are real?":
//   - Hierarchical PKI (TLS) — sibling demo: crypto-lab-pki-chain
//   - Web of Trust (PGP)     — sibling demo: crypto-lab-web-of-trust
//   - SSH known_hosts (TOFU) — this demo
export const THREE_TRUST_MODELS: TrustModelRow[] = [
	{
		axis: 'Root of trust',
		pki: 'A small set of root CAs your OS or browser ships in a root store.',
		wot: 'You. Trust propagates through a graph of certifications between people.',
		ssh: 'The host key the server presented the FIRST time you connected.',
	},
	{
		axis: 'How a new key becomes trusted',
		pki: 'A CA validates the request and issues a certificate that chains to a root.',
		wot: 'Someone you trust signs it (a certification). Marginal signatures accumulate.',
		ssh: 'You see the fingerprint on first connect and type "yes" — pinned into ~/.ssh/known_hosts.',
	},
	{
		axis: 'Shape of trust',
		pki: 'A tree: root → intermediate(s) → leaf. One chain per cert.',
		wot: 'A directed graph through people. Many paths can reach the same key.',
		ssh: 'A flat per-host pin list. No chain, no graph — just "is this the key I saw before?"',
	},
	{
		axis: 'What it protects',
		pki: 'Identity of any server with a CA-issued cert, on any device that trusts that CA.',
		wot: 'Identity of people in your social graph, with as much rigor as the chain has.',
		ssh: 'A specific server you have connected to before. Detects a substituted host key.',
	},
	{
		axis: 'What it does NOT protect',
		pki: 'A misissued cert from any trusted CA validates any name.',
		wot: 'A careless introducer with full trust validates whatever they sign.',
		ssh: 'The FIRST connection. TOFU cannot tell a real server from a MITM on first contact.',
	},
	{
		axis: 'Sibling crypto-lab demo',
		pki: 'crypto-lab-pki-chain',
		wot: 'crypto-lab-web-of-trust',
		ssh: 'crypto-lab-ssh-handshake (this one)',
	},
];

export interface ConceptCard {
	title: string;
	body: string;
}

// Moving parts of the SSH transport-layer handshake. These are the pieces
// engine.ts actually implements with real Web Crypto.
export const HANDSHAKE_CONCEPTS: ConceptCard[] = [
	{
		title: 'Host key (long-term identity)',
		body: 'A keypair the server holds for its entire life — sshd reuses it across every connection. The PUBLIC half is the server\'s identity, and its SHA-256 fingerprint is what known_hosts pins. If the private half ever leaves the server, the server\'s identity is compromised.',
	},
	{
		title: 'Ephemeral ECDH (per-connection)',
		body: 'Both sides generate a fresh keypair JUST for this connection, exchange the public halves, and derive a shared secret. The ephemeral private keys are thrown away when the session ends — so even if the host key leaks later, recorded ciphertext stays unreadable. This is forward secrecy.',
	},
	{
		title: 'The exchange hash H',
		body: 'A single SHA-256 binding the host name, the host public key, BOTH ephemeral public keys, and the shared secret. Any substitution — different host key, swapped ephemeral, different name — changes H. Whatever the server signs commits it to this exact handshake; the client recomputes H and the signature only verifies if the bits match end to end.',
	},
	{
		title: 'Signing H with the host key',
		body: 'The server signs the exchange hash with its long-term host key. Verification of that signature is what proves "the party I\'m talking to holds the private half of the host key I just received." Without this signature step, ECDH alone would happily agree on a secret with a man in the middle.',
	},
	{
		title: 'known_hosts (Trust On First Use)',
		body: 'The first time the client sees a host key for a given name, it pins the fingerprint. Every subsequent connection compares the presented fingerprint to the pin. Mismatch → the famous "REMOTE HOST IDENTIFICATION HAS CHANGED" warning and a refused connection.',
	},
];

export interface LessonCard {
	title: string;
	body: string;
}

// What TOFU does and does not buy you, stated honestly.
export const TOFU_LESSONS: LessonCard[] = [
	{
		title: 'First contact is an unverified leap of faith',
		body: 'TOFU cannot tell a legitimate server from an attacker on the FIRST connection. If you type "yes" without checking the fingerprint somehow else, you may be pinning the attacker\'s key. The model only catches changes — and on first contact there is nothing to change from.',
	},
	{
		title: 'But it catches every change after that',
		body: 'Once a key is pinned, swapping it triggers the loud "REMOTE HOST IDENTIFICATION HAS CHANGED!" warning and refuses the connection. That single check is what makes SSH usable without a CA — most servers really do keep the same host key for years, and a sudden change is almost always either reinstallation or attack.',
	},
	{
		title: 'Out-of-band fingerprint verification is the fix',
		body: 'To close the first-contact gap, verify the fingerprint through another channel: a vendor docs page, a colleague who already connected, an SSHFP DNS record, a printed datacenter runbook. If the channel you check is independent of the SSH session, the attacker would need to compromise BOTH to succeed.',
	},
	{
		title: 'Blindly typing "yes" defeats the protection',
		body: 'The prompt asks "Are you sure you want to continue connecting (yes/no/[fingerprint])?" for a reason. Habitually typing "yes" without comparing the fingerprint converts TOFU into "trust whoever answers the port" — which is exactly the property TOFU is designed to avoid.',
	},
	{
		title: 'Host-key reuse is the contract',
		body: 'TOFU assumes the server keeps the same host key. Legitimate key rotation (reinstall, hardware swap, key compromise response) trips the same warning a MITM does — operators have to update users out of band before the change. That coupling is the price of having no CA.',
	},
];

export interface RealWorldCard {
	title: string;
	body: string;
}

// Where this model actually lives — file paths, RFCs, configuration that real
// operators touch.
export const REAL_WORLD: RealWorldCard[] = [
	{
		title: '~/.ssh/known_hosts',
		body: 'OpenSSH\'s flat per-user pin file. One line per host with the host name (optionally hashed via HashKnownHosts), the key type, and the base64 public key. ssh-keygen -R removes a stale pin; ssh-keygen -F looks one up. The change-detection logic is just file comparison.',
	},
	{
		title: 'SHA256: fingerprints',
		body: 'OpenSSH prints host keys as "SHA256:<base64 hash>" — the same format this demo uses. The older "MD5:aa:bb:cc:…" colon-hex form is still around in legacy docs but should not be trusted; MD5 collisions are decades old.',
	},
	{
		title: 'Host key types (ed25519, ecdsa, rsa)',
		body: 'A modern sshd offers multiple host keys and the client picks one it knows. Ed25519 is the default-recommended type today; ECDSA on a NIST curve is widely supported; RSA is still common on older hosts. The client pins the type it actually used, so a server offering ed25519 + rsa can be pinned independently for each.',
	},
	{
		title: 'SSHFP DNS records (RFC 4255)',
		body: 'Publish the host key fingerprint as a DNS record signed with DNSSEC. ssh with VerifyHostKeyDNS=yes can use it to skip the TOFU prompt on first contact — pushing the trust decision onto whoever controls the zone. Adoption is limited, but it is the standards-track answer to first-contact MITM.',
	},
	{
		title: 'Certificate-based SSH (OpenSSH CA)',
		body: 'A second answer to first-contact trust: have an organization-internal CA sign host (and user) certificates. Clients trust the CA via @cert-authority lines in known_hosts and stop pinning individual hosts. This is hierarchical PKI re-introduced ON TOP of the SSH transport, used heavily at companies running fleets of SSH bastions.',
	},
	{
		title: 'StrictHostKeyChecking modes',
		body: 'OpenSSH lets you tune the TOFU policy: "yes" refuses any unknown key, "ask" (default) prompts, "accept-new" auto-pins on first contact but still rejects changes, "no" trusts whatever shows up. The accept-new mode is the honest TOFU default for automation.',
	},
];

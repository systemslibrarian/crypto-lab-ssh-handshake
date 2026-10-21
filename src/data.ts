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
		body: 'In the core teaching engine, a single SHA-256 binds the host name, host public key, BOTH ephemeral public keys, and shared secret. Any substitution in those selected fields changes H. Real RFC 4253 H has its own exact field list; it does not cover every transport message or the implicit sequence numbers. Section 4 builds that exact shape and shows why an injected SSH_MSG_IGNORE can leave H unchanged.',
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

export interface ScopeCard {
	heading: string;
	bullets: string[];
}

// Honest scope panel: what this demo models faithfully and what it leaves
// out. Repeated in the UI rather than buried in the README.
export const SCOPE: ScopeCard[] = [
	{
		heading: 'What this models faithfully',
		bullets: [
			'Long-term host key generation, signing, and verification (real Ed25519, falling back to ECDSA P-256).',
			'Per-connection ephemeral ECDH key agreement (real X25519, falling back to ECDH P-256).',
			'An exchange hash H over host name, host pubkey, both ephemeral pubkeys, and the shared secret.',
			'Host signature over H — the proof of key ownership.',
			'known_hosts pin lookup, change detection, and the recovery flow (ssh-keygen -R).',
			'StrictHostKeyChecking modes yes / ask / accept-new / no, including OpenSSH-style first-contact prompt.',
			'Trust on first use and its honest first-contact limitation.',
			'Two focused RFC 4253 binary-packet paths: AES-128-CBC plus HMAC-SHA-256 for the APW oracle, and chacha20-poly1305@openssh.com for Terrapin.',
			'An RFC 4253 §8-shaped X25519 exchange hash and §7.2 64-byte key expansion inside the isolated Terrapin exhibit.',
		],
	},
	{
		heading: 'What this deliberately does NOT model',
		bullets: [
			'A general SSH binary packet stack — the core handshake still exchanges JSON; only Section 4’s two isolated packet paths use RFC-shaped wire frames.',
			'Full algorithm negotiation — the engine picks one KEX + one SIG algorithm at init, and each packet exhibit pins the algorithms it teaches.',
			'User authentication — there are no passwords, no public-key auth, no Kerberos.',
			'SSH channels, port forwarding, sftp, scp — only the transport-layer handshake.',
			'Re-keying mid-session, compression, general MAC negotiation, and general cipher selection.',
			'OpenSSH host certificates and SSHFP / DNSSEC bootstrap (modelled in later sections, not in the core engine).',
		],
	},
	{
		heading: 'Where exactness is compressed for teaching',
		bullets: [
			'The core engine’s "exchange hash H" is a teaching surrogate. Real RFC 4253 §8 H commits the version strings (V_C, V_S), both KEXINIT payloads (I_C, I_S), host key (K_S), both ephemeral values (e, f), and shared secret (K)—not every transport message. Section 4’s Terrapin path builds that exact field shape and demonstrates that SSH_MSG_IGNORE and sequence numbers are absent.',
			'Host public keys are JWK-derived internally for the engine, then re-serialised as canonical OpenSSH wire-format blobs for fingerprints and known_hosts display. The fingerprints in the UI match what ssh-keygen -lf would print for the same key.',
			'Multi-key hosts (an sshd offering ed25519 + ecdsa + rsa at the same hostname) are illustrated in the known_hosts panel but only ONE algorithm runs end-to-end per demo session — the engine initializes one KEX and one SIG algorithm at startup.',
			'OpenSSH host certificates here use a compact JSON body and an Ed25519/ECDSA signature. Real OpenSSH certs are SSH-wire-format blobs with serial, nonce, principals, valid-after/before, critical-options, and extensions — the trust logic is faithful, the byte layout is compressed.',
		],
	},
];

export interface Citation {
	label: string;
	url: string;
	note: string;
}

// Provenance: where the model's claims come from. Linking the demo to
// authoritative sources is what separates "neat toy" from "credible
// teaching aid".
export const CITATIONS: Citation[] = [
	{
		label: 'Boneh–Shoup — A Graduate Course in Applied Cryptography v0.6, §9.9',
		url: 'https://toc.cryptobook.us/book.pdf',
		note: 'The non-atomic SSH decryption case study and idealised length-oracle receiver.',
	},
	{
		label: 'RFC 4251 — SSH Protocol Architecture',
		url: 'https://www.rfc-editor.org/rfc/rfc4251',
		note: 'Defines the three layers (transport / userauth / connection) and the trust model.',
	},
	{
		label: 'RFC 4253 — SSH Transport Layer',
		url: 'https://www.rfc-editor.org/rfc/rfc4253',
		note: 'Binary packets, chained encryption, sequence-number MAC input, key expansion, exact exchange-hash fields, and SSH_MSG_IGNORE.',
	},
	{
		label: 'RFC 6668 — SHA-2 MACs for SSH',
		url: 'https://www.rfc-editor.org/rfc/rfc6668',
		note: 'Defines hmac-sha2-256, used by the focused AES-CBC encrypt-and-MAC path.',
	},
	{
		label: 'RFC 8308 — SSH extension negotiation',
		url: 'https://www.rfc-editor.org/rfc/rfc8308',
		note: 'Defines SSH_MSG_EXT_INFO, the first encrypted packet removed in the Terrapin exhibit.',
	},
	{
		label: 'Albrecht–Paterson–Watson — Plaintext Recovery Attacks against SSH',
		url: 'https://www.cs.umd.edu/~jkatz/security/downloads/PlaintextRecoverySSH.pdf',
		note: 'Primary paper for the pre-5.2 OpenSSH length reactions, 14-bit and 32-bit recovery probabilities, and AES-CTR mitigation.',
	},
	{
		label: 'Bäumer–Brinkmann–Schwenk — Terrapin Attack',
		url: 'https://www.usenix.org/conference/usenixsecurity24/presentation/baumer',
		note: 'Primary paper for sequence-number manipulation, prefix truncation, affected modes, and extension downgrades.',
	},
	{
		label: 'draft-ietf-sshm-strict-kex-02',
		url: 'https://datatracker.ietf.org/doc/html/draft-ietf-sshm-strict-kex-02',
		note: 'Strict initial-key-exchange negotiation, permitted messages, KEXINIT-first rule, and sequence-number reset.',
	},
	{
		label: 'draft-ietf-sshm-chacha20-poly1305-04',
		url: 'https://datatracker.ietf.org/doc/html/draft-ietf-sshm-chacha20-poly1305-04',
		note: 'OpenSSH key-half positions, length encryption, packet nonce/counters, MAC-before-payload rule, and the 92-byte Appendix A vector.',
	},
	{
		label: 'RFC 8439 — ChaCha20 and Poly1305',
		url: 'https://www.rfc-editor.org/rfc/rfc8439',
		note: 'Published primitive vectors: §2.4.2 and Appendix A for ChaCha20; §2.5.2 and Appendix A.3 for Poly1305.',
	},
	{
		label: 'RFC 4231 — HMAC-SHA-256 test vectors',
		url: 'https://www.rfc-editor.org/rfc/rfc4231',
		note: 'Published HMAC-SHA-256 vectors, including Test Case 7’s 131-byte key and 152-byte data.',
	},
	{
		label: 'NIST SP 800-38A — block-cipher modes',
		url: 'https://csrc.nist.gov/pubs/sp/800/38/a/final',
		note: 'Appendix F.2.1 four-block AES-128-CBC known-answer vector.',
	},
	{
		label: 'RFC 4255 — SSHFP DNS Records',
		url: 'https://www.rfc-editor.org/rfc/rfc4255',
		note: 'Publish the host key fingerprint in DNS (with DNSSEC) to bootstrap first-contact trust.',
	},
	{
		label: 'RFC 5656 — ECC Algorithms for SSH',
		url: 'https://www.rfc-editor.org/rfc/rfc5656',
		note: 'Adds ECDH / ECDSA on NIST curves, including the P-256 fallback this demo uses.',
	},
	{
		label: 'RFC 8709 — Ed25519 and Ed448 host/user keys in SSH',
		url: 'https://www.rfc-editor.org/rfc/rfc8709',
		note: 'Adds the ssh-ed25519 host-key algorithm this demo uses by default — same wire format as OpenSSH.',
	},
	{
		label: 'RFC 8731 — Curve25519 and Curve448 key exchange in SSH',
		url: 'https://www.rfc-editor.org/rfc/rfc8731',
		note: 'Standards-track curve25519-sha256 / curve448-sha512 KEX — the preferred SSH KEX today.',
	},
	{
		label: 'OpenSSH PROTOCOL.certkeys — host certificates',
		url: 'https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys',
		note: 'The @cert-authority mechanism that turns SSH host trust into a small PKI when needed.',
	},
	{
		label: 'man 5 ssh_config — StrictHostKeyChecking',
		url: 'https://man.openbsd.org/ssh_config.5#StrictHostKeyChecking',
		note: 'Authoritative docs for the yes / ask / accept-new / off modes the demo selector exposes.',
	},
	{
		label: 'man 1 ssh-keygen — fingerprint, -F, -R',
		url: 'https://man.openbsd.org/ssh-keygen.1',
		note: 'Lookup and removal of known_hosts entries — what the demo buttons mimic.',
	},
	{
		label: 'man 8 sshd — host keys, multiple algorithms per host',
		url: 'https://man.openbsd.org/sshd.8',
		note: 'How real sshd holds an ed25519, ecdsa, and (legacy) rsa host key all under one name.',
	},
];

export interface CrosswalkRow {
	demo: string;       // what you see in this demo
	openssh: string;    // the closest real-OpenSSH command or file
	notes: string;
}

// "Take it back to the terminal" map: each demo artifact lined up with the
// command or file that produces the same thing in real OpenSSH.
export const OPENSSH_CROSSWALK: CrosswalkRow[] = [
	{
		demo: 'Host fingerprint badge in section 1',
		openssh: 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub',
		notes: 'Both render SHA256:<base64> of the host public key blob.',
	},
	{
		demo: 'The known_hosts (file format) panel',
		openssh: '~/.ssh/known_hosts',
		notes: 'One line per host+algorithm: <hostname> <keytype> <base64-key>. The demo synthesises one active line plus an illustrative multi-key panel.',
	},
	{
		demo: 'ssh-keygen -F server.example.com button',
		openssh: 'ssh-keygen -F server.example.com',
		notes: 'Looks up an entry in known_hosts; exit status 0 = found, 1 = not found.',
	},
	{
		demo: 'ssh-keygen -R server.example.com button',
		openssh: 'ssh-keygen -R server.example.com',
		notes: 'Removes a stale entry from known_hosts — the standard recovery from a legitimate host-key rotation.',
	},
	{
		demo: 'First-contact prompt (ask mode)',
		openssh: 'ssh user@server.example.com',
		notes: 'OpenSSH prints "The authenticity of host \'server.example.com\' can\'t be established. <type> key fingerprint is SHA256:… Are you sure you want to continue connecting (yes/no/[fingerprint])?".',
	},
	{
		demo: 'Discover the host key without connecting',
		openssh: 'ssh-keyscan -t ed25519 server.example.com',
		notes: 'Server presents host keys WITHOUT the userauth/connection layers — useful for pre-seeding known_hosts from a trusted source.',
	},
	{
		demo: 'Transcript inspector (handshake artifacts)',
		openssh: 'ssh -vvv user@server.example.com',
		notes: 'Real ssh prints algorithm negotiation, exchange-hash inputs, KEXINIT cookies, and signature bytes at -vvv. The demo skips negotiation and surfaces the rest.',
	},
	{
		demo: 'SSHFP DNS RR card in section 1',
		openssh: 'dig +dnssec SSHFP server.example.com',
		notes: 'Real DNSSEC-aware dig shows the SSHFP RDATA plus an ad flag if validated.',
	},
	{
		demo: 'HostCA / @cert-authority panel',
		openssh: 'ssh-keygen -s ca_key -I id -h -n server.example.com host_key.pub',
		notes: 'Issues an OpenSSH host certificate. Clients trust the CA via @cert-authority lines in known_hosts; one CA pin replaces many host pins.',
	},
	{
		demo: 'StrictHostKeyChecking selector',
		openssh: 'ssh -o StrictHostKeyChecking={yes,ask,accept-new,no}',
		notes: 'Same four-value setting. accept-new is the modern default for automation, ask is the interactive default, yes is paranoid, no is dangerous.',
	},
	{
		demo: 'HOST KEY CHANGED warning banner',
		openssh: 'ssh server.example.com (after a key change)',
		notes: '"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" — exact wording lifted from OpenSSH. The recovery flow is ssh-keygen -R, then reconnect (after verifying the new fingerprint OOB).',
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
		body: 'OpenSSH lets you tune the TOFU policy: "yes" refuses any unknown key, "ask" (default) prompts, "accept-new" auto-pins on first contact but still rejects changes, "no" auto-pins new hosts but warns and permits restricted continuation on changed keys while retaining the old pin. Password/interactive authentication and forwarding restrictions are modeled here; those SSH layers are not implemented. The accept-new mode is the honest TOFU default for automation.',
	},
];

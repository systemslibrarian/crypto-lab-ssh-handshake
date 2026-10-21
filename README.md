# crypto-lab-ssh-handshake

## What It Is

An interactive model of the **SSH transport-layer handshake** and the **`known_hosts` / Trust-On-First-Use** flow that authenticates the server. The server holds a long-term host key; every connection generates fresh ephemeral ECDH keys on both sides; the server signs a single teaching-model "exchange hash" over selected KEX fields to prove possession of its host private key, and the client verifies that signature and then compares the host fingerprint against its known_hosts pin. The crypto is real: ephemeral **X25519** with an automatic **ECDH P-256** fallback for key agreement, and **Ed25519** with an automatic **ECDSA P-256** fallback for the host signature, all via the Web Crypto API. The problem SSH solves with this is **authenticating a server you have no CA path and no web-of-trust path to**: the first connection pins the host key (an unverified leap of faith), and every connection after that detects whether the key changed. A focused packet-layer section then builds real AES-CBC/HMAC-SHA-256 and `chacha20-poly1305@openssh.com` packets to expose the APW length oracle and the Terrapin prefix-truncation attack, plus their AES-CTR/strict-kex defenses. The core engine still uses compact JSON messages, and the lab does not implement general algorithm negotiation, channels, or user authentication; it is not a re-implementation of OpenSSH.

## When to Use It

- **Understanding the SSH host-key prompt** — see exactly what the client is being asked to commit to when it prints `The authenticity of host '…' can't be established` and a fingerprint. The demo's `ask` mode rolls back the engine's auto-pin so you have to actually accept, reject, or verify the fingerprint yourself.
- **Reasoning about `known_hosts` warnings** — when `REMOTE HOST IDENTIFICATION HAS CHANGED!` appears, this is what is happening underneath. The transcript inspector highlights the field that broke the handshake (host pubkey, signature, etc.) so you can see *which* part of the check fired.
- **Contrasting the three trust models** — read alongside the sibling [`crypto-lab-pki-chain`](https://systemslibrarian.github.io/crypto-lab-pki-chain/) (hierarchical CA / TLS) and [`crypto-lab-web-of-trust`](https://systemslibrarian.github.io/crypto-lab-web-of-trust/) (decentralized PGP) demos. SSH sits between them: no CA, no graph, just a per-host pin — unless you opt into SSHFP+DNSSEC or OpenSSH `@cert-authority`, which the demo also models.
- **Teaching ephemeral KEX + signature authentication** — the same shape shows up in TLS 1.3 and Noise; SSH is the cleanest place to see it because there is no certificate machinery in the way.
- **Comparing `StrictHostKeyChecking` modes** — toggle between `yes` (refuse unknown), `ask` (prompt), `accept-new` (silent pin, reject change), and `no` (auto-pin new hosts, permit restricted changed-key continuation without replacing the saved pin) and watch the same connection produce very different decisions.
- **Do NOT use this to reason about first-contact safety in production** — TOFU does **not** protect a first connection against an active man-in-the-middle. The demo includes the *MITM on first contact* and *DNS spoof of SSHFP without DNSSEC* scenarios specifically to make that limitation undeniable.
- **Do NOT use this as a real SSH implementation** — this is a toy for learning. For production use OpenSSH, libssh, or another vetted library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/)**

The page walks through seven sections: starting a server; connecting with a real handshake and TOFU policy; a guided eight-scenario “break it and recover” lab; the APW and Terrapin packet-layer exhibits; a three-trust-models comparison; an “in the real world” reference; and scope/provenance. The URL accepts `?scenario=<id>` for deep links—e.g. `?scenario=mitm-after`.

## What Can Go Wrong

- **TOFU does not protect first contact** — an active man-in-the-middle on the very first connection is pinned as if legitimate; trust-on-first-use only detects *changes* afterward.
- **Ignoring `REMOTE HOST IDENTIFICATION HAS CHANGED!`** — dismissing the known_hosts warning, or reflexively removing the pin, discards the one signal that distinguishes a planned key rotation from an attack.
- **`StrictHostKeyChecking no`** — a changed key still triggers a warning and the existing pin remains. OpenSSH may continue with password/keyboard-interactive authentication, forwarding and UpdateHostkeys disabled; this does not restore trust in the host identity. This demo explicitly models those restrictions as transport-policy metadata, because it has no user-authentication or forwarding layers. The policy wrapper rolls back the engine's first-contact auto-pin after a failed signature or key exchange, and never offers that failed handshake for acceptance. Intentional pin replacement requires out-of-band verification and an explicit remove/reconnect flow. Other OpenSSH conditions (such as ExitOnForwardFailure) may still abort; this is not full client parity. Source: [pinned OpenSSH HOST_CHANGED/continue_unsafe](https://github.com/openssh/openssh-portable/blob/813f670ccc086aeb48ca6bf701e6a73c098a65bb/sshconnect.c#L1231-L1344).
- **SSHFP without DNSSEC** — verifying a fingerprint via an unsigned DNS record can itself be spoofed, so the "out-of-band" check lies.
- **Accepting a fingerprint without real out-of-band verification** — clicking through the `ask` prompt without comparing the fingerprint through a trusted channel defeats the purpose of the prompt.
- **Reading CBC packet length before checking the MAC** — the APW/Boneh–Shoup exhibit shows how distinguishable receiver reactions disclose 14 or 32 plaintext bits even though the eventual HMAC fails.
- **Assuming valid packet tags prove completeness** — Terrapin manipulates pre-NEWKEYS sequence numbers, deletes EXT_INFO, and still gives the client a valid Poly1305 tag on every packet it receives.

## Real-World Usage

- **OpenSSH `known_hosts`** — every SSH client pins host keys on first connection and warns on change, exactly the TOFU flow modeled here.
- **Server and infrastructure administration** — interactive shells, configuration management, and automation authenticate hosts via these host keys.
- **Git over SSH** — pushing and pulling from GitHub, GitLab, and self-hosted servers relies on SSH host-key verification.
- **SSHFP + DNSSEC** — publishing host fingerprints in signed DNS lets clients bootstrap trust without a prior connection (RFC 4255).
- **OpenSSH certificate authorities** — `@cert-authority` lets an organization sign host keys so clients trust a CA instead of pinning every host.
- **Strict key exchange** — both peers advertise the strict-kex pseudo-algorithms, reject non-KEX messages during initial KEX, require KEXINIT first, and reset sequence numbers after NEWKEYS to close Terrapin’s prefix-truncation path.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ssh-handshake
cd crypto-lab-ssh-handshake
npm install
npm run dev
```

## Testing

The shared CI/Pages build gate runs `npm test`, `npm run build`, and
`npm run test:e2e`, which includes both the functional teaching flows and the
accessibility specs. `npm run test:a11y` is the accessibility-only subset for
local focused checks; it does not replace the full browser gate.
The browser gate checks first contact, changed-key rejection, and explicit
pin-replacement recovery at 320px, 380px, and desktop width, including complete
fingerprint text, page reflow, and accessibility scans.
Sequence rows reveal at full text contrast while keeping their staggered motion;
the accessibility regression samples the actual entrance animation and includes
an intentional low-contrast negative control. Reduced motion reveals all rows.

The packet path pins **nine published known-answer cases**: one four-block
AES-128-CBC case from NIST SP 800-38A F.2.1; two HMAC-SHA-256 cases from RFC
4231 (Cases 1 and 7, including its 131-byte key and 152-byte data); five RFC
8439 cases (three ChaCha20 cases from §2.4.2/A.1/A.2 and two Poly1305 cases from
§2.5.2/A.3); and the 92-byte packet from
draft-ietf-sshm-chacha20-poly1305-04 Appendix A, whose 72-byte encrypted body
crosses a 64-byte ChaCha block boundary. The RFC 4253 §7.2 expansion also has an
independent test re-derivation.

Recovery verdicts require an observable receiver reaction and a matching plaintext
check. Invalid-length disconnects and unfinished over-budget waits never claim a
recovered prefix. Changing the receiver, recovery depth, target, or fix retires
the corresponding stale evidence; selecting the same value preserves it.
The AES-CTR browser claim independently checks the displayed calculation against
Node/OpenSSL, rather than trusting two values produced by the same implementation.

`npm run test:mutations` replays seven behavioral source changes: corrupt CBC
recovery, invert the receiver range check, corrupt AES-CTR output, invert Poly1305
tag rejection, delete the wrong Terrapin packet, invert strict-kex rejection, and
reintroduce a recovery claim after a disconnect. Verdict wording is left unchanged.
Each case requires the owning browser test to pass first, a successful mutated
build with a different bundle hash, an assertion failure in that exact test, and
restoration to the original passing bundle. Build failures, browser startup errors,
timeouts, skips, and absent tests cannot count as kills. Commit source changes
before running the mutation script; it refuses to mutate uncommitted source.
The deployment workflow runs this gate after the full browser suite and before
uploading the restored production bundle.

## Related Demos

- [crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — hierarchical X.509 CA trust, the centralized counterpart to SSH's TOFU model.
- [crypto-lab-web-of-trust](https://systemslibrarian.github.io/crypto-lab-web-of-trust/) — PGP/OpenPGP decentralized trust graphs, the third trust model SSH is compared against.
- [crypto-lab-noise-pipe](https://systemslibrarian.github.io/crypto-lab-noise-pipe/) — the Noise/WireGuard handshake patterns that share SSH's ephemeral-KEX shape.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — Ed25519/EdDSA signatures, the algorithm signing the SSH exchange hash.
- [crypto-lab-x3dh-wire](https://systemslibrarian.github.io/crypto-lab-x3dh-wire/) — X3DH ephemeral key agreement from the Signal protocol.

## Exhibits

1. **Start the server** generates a real host keypair in your browser and shows its `SHA256:` fingerprint. The two second-order trust-bootstrap mechanisms—SSHFP with a DNSSEC toggle and an OpenSSH host CA—live behind an optional progressive-disclosure gate so plain TOFU lands first.
2. **Connect** runs the handshake as a two-party sequence diagram under a `StrictHostKeyChecking` selector. Its exchange-hash lab mutates one of the core model’s five selected fields and re-runs real SHA-256 and signature verification; its authentication lab separates KEX, proof of host-key possession, and comparison against a pre-existing pin. A transcript inspector and realistic `known_hosts` view expose the computed evidence.
3. **Break it (and recover)** runs eight guided scenarios: MITM after pinning, MITM on first contact, tampered host signature, unsigned SSHFP spoofing, a rogue CA, planned rotation, emergency rotation, and rotation beneath the same trusted CA.
4. **After the handshake: the packet layer** contains two real-computation exhibits. APW/Boneh–Shoup captures AES-128-CBC ciphertext, injects a block, derives `P′ = D(c*) ⊕ L`, and measures the pre-5.2 receiver’s 2⁻¹⁴/2⁻¹⁸ reactions in a worker; AES-CTR and OpenSSH ChaCha20-Poly1305 stop the same injection. Terrapin performs real X25519, exact RFC-shaped H and §7.2 key expansion, then protects packets with `chacha20-poly1305@openssh.com`; an injected IGNORE balances a deleted EXT_INFO so the next tag verifies. Strict kex rejects the injection and binds its negotiation markers through KEXINIT and H.
5. **Three trust models** compares hierarchical PKI, Web of Trust, and SSH TOFU, with first-contact callouts linking to the sibling demos.
6. **In the real world** documents `~/.ssh/known_hosts`, `SHA256:` fingerprints, host key types, SSHFP, certificate-based SSH, and `StrictHostKeyChecking` modes.
7. **Scope & provenance** states the exact model boundaries and links the RFCs, drafts, primary attack papers, published-vector sources, OpenSSH protocol notes, and relevant man pages.

The URL accepts `?scenario=<id>` for deep links — e.g. `?scenario=mitm-after` auto-starts the server, pins the legitimate host once, then triggers the MITM-after-pinning scenario.

## Implementation Notes

Additional npm scripts:

```bash
npm run build      # type-check + production build to dist/
npm run preview    # serve the built dist/ locally
npm test           # vitest — engine, policy, wire format, SSHFP, CA
npm run test:e2e   # playwright — teaching flows + WCAG a11y gate (needs `npx playwright install chromium`)
```

No environment variables, no API keys, no servers. Everything runs client-side in the browser. The existing engine in `src/engine.ts` remains the compact teaching path: its exchange hash covers the host name, host key, both ephemerals, and shared secret, and its helpers re-run the same SHA-256 and signature verification for the binding exhibit. The isolated `src/bpp/` path builds RFC 4253 §8’s exact H field shape—V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K—and demonstrates that optional IGNORE messages and implicit sequence numbers are not among those fields. It uses Web Crypto for X25519, Ed25519, HMAC-SHA-256, and AES-CTR; `@noble/ciphers` supplies raw no-padding AES-CBC plus the 64-bit-nonce ChaCha20 and Poly1305 primitives Web Crypto lacks. The StrictHostKeyChecking policy, SSHFP registry, host CA, and transcript capture continue to sit on top of the original engine without changing its cryptographic logic.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## OpenSSH deployment context

A visible dated comparison links [OpenSSH release notes](https://www.openssh.org/releasenotes.html) and [PQ guidance](https://www.openssh.org/pq.html), separates PQ key exchange, host signatures and trust bootstrap, and keeps the lab’s classical JSON-model engine explicit.

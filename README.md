# crypto-lab-ssh-handshake

## What It Is

An interactive model of the **SSH transport-layer handshake** and the **`known_hosts` / Trust-On-First-Use** flow that authenticates the server. The server holds a long-term host key; every connection generates fresh ephemeral ECDH keys on both sides; the server signs a single "exchange hash" — a SHA-256 binding the host name, the host public key, both ephemeral public keys, and the shared secret — to prove possession of its host private key, and the client verifies that signature and then compares the host fingerprint against its known_hosts pin. The crypto is real: ephemeral **X25519** with an automatic **ECDH P-256** fallback for key agreement, and **Ed25519** with an automatic **ECDSA P-256** fallback for the host signature, all via the Web Crypto API. The problem SSH solves with this is **authenticating a server you have no CA path and no web-of-trust path to**: the first connection pins the host key (an unverified leap of faith), and every connection after that detects whether the key changed — the model gets you forward-secret sessions and change detection without a central authority. What is deliberately **not** modelled is the SSH binary packet protocol, the RFC 4253 algorithm negotiation, channels, or user authentication: messages here are plain JSON objects. This is a faithful model of the transport-security and trust logic, not a re-implementation of OpenSSH's wire format.

## When to Use It

- **Understanding the SSH host-key prompt** — see exactly what the client is being asked to commit to when it prints `The authenticity of host '…' can't be established` and a fingerprint. The demo's `ask` mode rolls back the engine's auto-pin so you have to actually accept, reject, or verify the fingerprint yourself.
- **Reasoning about `known_hosts` warnings** — when `REMOTE HOST IDENTIFICATION HAS CHANGED!` appears, this is what is happening underneath. The transcript inspector highlights the field that broke the handshake (host pubkey, signature, etc.) so you can see *which* part of the check fired.
- **Contrasting the three trust models** — read alongside the sibling [`crypto-lab-pki-chain`](https://systemslibrarian.github.io/crypto-lab-pki-chain/) (hierarchical CA / TLS) and [`crypto-lab-web-of-trust`](https://systemslibrarian.github.io/crypto-lab-web-of-trust/) (decentralized PGP) demos. SSH sits between them: no CA, no graph, just a per-host pin — unless you opt into SSHFP+DNSSEC or OpenSSH `@cert-authority`, which the demo also models.
- **Teaching ephemeral KEX + signature authentication** — the same shape shows up in TLS 1.3 and Noise; SSH is the cleanest place to see it because there is no certificate machinery in the way.
- **Comparing `StrictHostKeyChecking` modes** — toggle between `yes` (refuse unknown), `ask` (prompt), `accept-new` (silent pin, reject change), and `no` (trust whatever responds) and watch the same connection produce very different decisions.
- **Do NOT use this to reason about first-contact safety in production** — TOFU does **not** protect a first connection against an active man-in-the-middle. The demo includes the *MITM on first contact* and *DNS spoof of SSHFP without DNSSEC* scenarios specifically to make that limitation undeniable.
- **Do NOT use this as a real SSH implementation** — this is a toy for learning. For production use OpenSSH, libssh, or another vetted library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/)**

The page walks through six sections: starting a server (which generates a real host keypair in the browser and shows its `SHA256:` fingerprint, with SSHFP-DNS and host-CA trust bootstrap behind a progressive-disclosure gate), connecting (running the full handshake as an animated two-party sequence diagram under a `StrictHostKeyChecking` selector, with an interactive exchange-hash binding lab, a forward-secrecy-vs-authentication toggle, and a complete transcript inspector), a guided eight-scenario "break it and recover" lab covering MITM, tampered signatures, DNS spoofing, rogue CAs, and key rotation, a three-trust-models comparison, an "in the real world" reference, and a scope/provenance section. The URL accepts `?scenario=<id>` for deep links — e.g. `?scenario=mitm-after`.

## What Can Go Wrong

- **TOFU does not protect first contact** — an active man-in-the-middle on the very first connection is pinned as if legitimate; trust-on-first-use only detects *changes* afterward.
- **Ignoring `REMOTE HOST IDENTIFICATION HAS CHANGED!`** — dismissing the known_hosts warning, or reflexively removing the pin, discards the one signal that distinguishes a planned key rotation from an attack.
- **`StrictHostKeyChecking no`** — blindly trusting whatever responds disables change detection entirely and accepts any impostor.
- **SSHFP without DNSSEC** — verifying a fingerprint via an unsigned DNS record can itself be spoofed, so the "out-of-band" check lies.
- **Accepting a fingerprint without real out-of-band verification** — clicking through the `ask` prompt without comparing the fingerprint through a trusted channel defeats the purpose of the prompt.

## Real-World Usage

- **OpenSSH `known_hosts`** — every SSH client pins host keys on first connection and warns on change, exactly the TOFU flow modeled here.
- **Server and infrastructure administration** — interactive shells, configuration management, and automation authenticate hosts via these host keys.
- **Git over SSH** — pushing and pulling from GitHub, GitLab, and self-hosted servers relies on SSH host-key verification.
- **SSHFP + DNSSEC** — publishing host fingerprints in signed DNS lets clients bootstrap trust without a prior connection (RFC 4255).
- **OpenSSH certificate authorities** — `@cert-authority` lets an organization sign host keys so clients trust a CA instead of pinning every host.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ssh-handshake
cd crypto-lab-ssh-handshake
npm install
npm run dev
```

## Related Demos

- [crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — hierarchical X.509 CA trust, the centralized counterpart to SSH's TOFU model.
- [crypto-lab-web-of-trust](https://systemslibrarian.github.io/crypto-lab-web-of-trust/) — PGP/OpenPGP decentralized trust graphs, the third trust model SSH is compared against.
- [crypto-lab-noise-pipe](https://systemslibrarian.github.io/crypto-lab-noise-pipe/) — the Noise/WireGuard handshake patterns that share SSH's ephemeral-KEX shape.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — Ed25519/EdDSA signatures, the algorithm signing the SSH exchange hash.
- [crypto-lab-x3dh-wire](https://systemslibrarian.github.io/crypto-lab-x3dh-wire/) — X3DH ephemeral key agreement from the Signal protocol.

## Walkthrough

* **Start the server** generates a real host keypair in your browser and shows its `SHA256:` fingerprint. The two second-order trust-bootstrap mechanisms — publish an **SSHFP DNS record** (with a DNSSEC toggle, RFC 4255) and start an **OpenSSH host CA** that can `@cert-authority`-sign the host's pubkey so clients trust the CA instead of pinning each host — now live behind an **Advanced trust bootstrap (optional)** disclosure that unlocks only after you complete one TOFU connect and one *MITM after pinning* scenario, so plain TOFU lands before DNSSEC and certificates arrive.
* **Connect** runs the handshake and renders it as a **two-party sequence diagram** — a client lane and a server lane with the actual messages animating across between them (client ephemeral →, server hello ← carrying ephemeral + host key + signature), each arrow resolving OK or FAIL — so the handshake reads as a conversation, not a checklist (the step-by-step list is still there under a disclosure). Two interactive exhibits pull apart the ideas newcomers conflate: an **exchange-hash binding lab** renders `H`'s five inputs as tiles feeding an `H = SHA256(…)` box and lets you swap one (as a MITM would) to watch the real `H` change and the real host signature flip to FAIL in the same frame; and a **what actually catches a MITM** lab runs a real man-in-the-middle against three settings of the client's checking — *KEX only*, *KEX + signature*, *KEX + signature + known_hosts pin* — to separate three things that get collapsed into one. With KEX only the attacker connects silently. Adding signature verification **does not** stop it: the attacker presents its own host key and signs the real exchange hash with the matching private key, so the signature comes back genuinely `VALID` and the attacker is still in the session — a valid signature proves the peer holds the private key for the key it just showed you, not that the key is the host's. Only the `known_hosts` comparison rejects it, and the exhibit shows the two fingerprints side by side so you can see the comparison being made. Every badge, verdict, and colour is derived from the handshake's real result, not from the control you clicked. A `StrictHostKeyChecking` selector lets you pick `yes` / `ask` / `accept-new` / `no` — `ask` produces an explicit Accept / Reject / Verify-out-of-band / Verify-via-SSHFP prompt instead of silently pinning. Each handshake exposes a full transcript inspector (client and server ephemerals, host pubkey, exchange hash, signature, decision) with copy-as-JSON; the field that broke the connection is highlighted. A realistic `~/.ssh/known_hosts` file view sits next to the pin list, alongside `ssh-keygen -F` and `ssh-keygen -R` outputs. A **Reset everything** control wipes the demo to its initial state.
* **Break it (and recover)** opens with a **guided path ribbon** (Start → Connect → Reconnect → MITM-after → MITM-first) that narrates the prerequisite order so the disabled scenario buttons read as a sequence rather than dead-ends. It runs eight scenarios — *MITM after pinning* (caught by known_hosts), *MITM on first contact* (TOFU pins the attacker — the honest limitation), *tampered host signature* (signature verification fires), *DNS spoof of SSHFP without DNSSEC* (the "verify out of band" path lies), *rogue CA signs the attacker's host* (rejected because the rogue CA is not the trust anchor), and three operational scenarios: *planned key rotation*, *emergency rotation*, and *rotate host under same CA* (the only one that connects without a warning). Each scenario has a "Copy summary as Markdown" button for sharing.
* **Three trust models** compares hierarchical PKI, Web of Trust, and SSH TOFU, with first-contact-in-three-demos callouts linking to the sibling demos.
* **In the real world** documents `~/.ssh/known_hosts`, `SHA256:` fingerprints, host key types, SSHFP DNS records, certificate-based SSH, and `StrictHostKeyChecking` modes, with honest "what TOFU teaches" cards.
* **Scope & provenance** spells out what the demo models faithfully and what it deliberately omits, with links to RFC 4251 / 4253 / 4255 / 5656, OpenSSH `PROTOCOL.certkeys`, and the relevant `man` pages.

The URL accepts `?scenario=<id>` for deep links — e.g. `?scenario=mitm-after` auto-starts the server, pins the legitimate host once, then triggers the MITM-after-pinning scenario.

## Implementation Notes

Additional npm scripts:

```bash
npm run build      # type-check + production build to dist/
npm run preview    # serve the built dist/ locally
npm test           # vitest — 40 unit tests (engine, policy, wire format, SSHFP, CA)
npm run test:e2e   # playwright — 25 browser tests for the teaching flows + WCAG a11y gate (needs `npx playwright install chromium`)
```

No environment variables, no API keys, no servers. Everything runs client-side in the browser. The engine in `src/engine.ts` is the verbatim source from the build prompt; the only post-hoc refinement is `fingerprint()`, which now hashes the canonical OpenSSH wire-format public-key blob (via `src/wire.ts`) instead of concatenated JWK coordinates so the demo's `SHA256:` strings match what `ssh-keygen -lf` prints. The engine also exports two thin teaching helpers — `recomputeExchangeHash()` and `verifyHostSignature()` — that call the *same* real SHA-256 and Web Crypto verify the handshake uses; the exchange-hash binding lab in `src/hashlab.ts` drives them so a mutated input tile really does change `H` and really does break the captured signature (nothing there is simulated). The other modules — StrictHostKeyChecking policy in `src/policy.ts`, SSHFP registry in `src/sshfp.ts`, host CA in `src/ca.ts`, transcript capture in `src/transcript.ts` — sit on top of the engine without touching its cryptographic logic. The CA's own fingerprint goes through the same `src/wire.ts` path as the host-key fingerprint, so every `SHA256:` string on the page is the same construction — SHA-256 over the canonical OpenSSH wire blob — and means the same thing.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

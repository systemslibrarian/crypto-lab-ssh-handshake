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

[**https://systemslibrarian.github.io/crypto-lab-ssh-handshake/**](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/)

The page walks through six sections.

* **Start the server** generates a real host keypair in your browser and shows its `SHA256:` fingerprint. Two optional trust-bootstrap mechanisms also live here: publish an **SSHFP DNS record** (with a DNSSEC toggle, RFC 4255) and start an **OpenSSH host CA** that can sign the host's pubkey so clients can `@cert-authority` trust the CA instead of pinning each host.
* **Connect** runs the handshake. A `StrictHostKeyChecking` selector lets you pick `yes` / `ask` / `accept-new` / `no` — `ask` produces an explicit Accept / Reject / Verify-out-of-band / Verify-via-SSHFP prompt instead of silently pinning. Each handshake exposes a full transcript inspector (client and server ephemerals, host pubkey, exchange hash, signature, decision) with copy-as-JSON; the field that broke the connection is highlighted. A realistic `~/.ssh/known_hosts` file view sits next to the pin list, alongside `ssh-keygen -F` and `ssh-keygen -R` outputs. A **Reset everything** control wipes the demo to its initial state.
* **Break it (and recover)** runs eight scenarios — *MITM after pinning* (caught by known_hosts), *MITM on first contact* (TOFU pins the attacker — the honest limitation), *tampered host signature* (signature verification fires), *DNS spoof of SSHFP without DNSSEC* (the "verify out of band" path lies), *rogue CA signs the attacker's host* (rejected because the rogue CA is not the trust anchor), and three operational scenarios: *planned key rotation*, *emergency rotation*, and *rotate host under same CA* (the only one that connects without a warning). Each scenario has a "Copy summary as Markdown" button for sharing.
* **Three trust models** compares hierarchical PKI, Web of Trust, and SSH TOFU, with first-contact-in-three-demos callouts linking to the sibling demos.
* **In the real world** documents `~/.ssh/known_hosts`, `SHA256:` fingerprints, host key types, SSHFP DNS records, certificate-based SSH, and `StrictHostKeyChecking` modes, with honest "what TOFU teaches" cards.
* **Scope & provenance** spells out what the demo models faithfully and what it deliberately omits, with links to RFC 4251 / 4253 / 4255 / 5656, OpenSSH `PROTOCOL.certkeys`, and the relevant `man` pages.

The URL accepts `?scenario=<id>` for deep links — e.g. `?scenario=mitm-after` auto-starts the server, pins the legitimate host once, then triggers the MITM-after-pinning scenario.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ssh-handshake.git
cd crypto-lab-ssh-handshake
npm install
npm run dev        # local dev server with HMR
npm run build      # type-check + production build to dist/
npm run preview    # serve the built dist/ locally
npm test           # vitest — 40 unit tests (engine, policy, wire format, SSHFP, CA)
npm run test:e2e   # playwright — 13 browser tests for the teaching flows (needs `npx playwright install chromium`)
```

No environment variables, no API keys, no servers. Everything runs client-side in the browser. The engine in `src/engine.ts` is the verbatim source from the build prompt; the only post-hoc refinement is `fingerprint()`, which now hashes the canonical OpenSSH wire-format public-key blob (via `src/wire.ts`) instead of concatenated JWK coordinates so the demo's `SHA256:` strings match what `ssh-keygen -lf` prints. The other modules — StrictHostKeyChecking policy in `src/policy.ts`, SSHFP registry in `src/sshfp.ts`, host CA in `src/ca.ts`, transcript capture in `src/transcript.ts` — sit on top of the engine without touching its cryptographic logic.

## Part of the Crypto-Lab Suite

This is one demo in a wider portfolio of interactive cryptography labs — see [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) for the rest, including the five PQC families overview, hybrid TLS, harvest-now-decrypt-later timelines, and deep-dives on individual schemes.

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31

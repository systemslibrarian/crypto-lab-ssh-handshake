# crypto-lab-ssh-handshake

## What It Is

An interactive model of the **SSH transport-layer handshake** and the **`known_hosts` / Trust-On-First-Use** flow that authenticates the server. The server holds a long-term host key; every connection generates fresh ephemeral ECDH keys on both sides; the server signs a single "exchange hash" — a SHA-256 binding the host name, the host public key, both ephemeral public keys, and the shared secret — to prove possession of its host private key, and the client verifies that signature and then compares the host fingerprint against its known_hosts pin. The crypto is real: ephemeral **X25519** with an automatic **ECDH P-256** fallback for key agreement, and **Ed25519** with an automatic **ECDSA P-256** fallback for the host signature, all via the Web Crypto API. The problem SSH solves with this is **authenticating a server you have no CA path and no web-of-trust path to**: the first connection pins the host key (an unverified leap of faith), and every connection after that detects whether the key changed — the model gets you forward-secret sessions and change detection without a central authority. What is deliberately **not** modelled is the SSH binary packet protocol, the RFC 4253 algorithm negotiation, channels, or user authentication: messages here are plain JSON objects. This is a faithful model of the transport-security and trust logic, not a re-implementation of OpenSSH's wire format.

## When to Use It

- **Understanding the SSH host-key prompt** — see exactly what the client is being asked to commit to when it prints `The authenticity of host '…' can't be established` and a fingerprint.
- **Reasoning about `known_hosts` warnings** — when `REMOTE HOST IDENTIFICATION HAS CHANGED!` appears, this is what is happening underneath and why refusing the connection is the right default.
- **Contrasting the three trust models** — read alongside the sibling [`crypto-lab-pki-chain`](https://systemslibrarian.github.io/crypto-lab-pki-chain/) (hierarchical CA / TLS) and [`crypto-lab-web-of-trust`](https://systemslibrarian.github.io/crypto-lab-web-of-trust/) (decentralized PGP) demos. SSH sits between them: no CA, no graph, just a per-host pin.
- **Teaching ephemeral KEX + signature authentication** — the same shape shows up in TLS 1.3 and Noise; SSH is the cleanest place to see it because there is no certificate machinery in the way.
- **Do NOT use this to reason about first-contact safety** — TOFU does **not** protect a first connection against an active man-in-the-middle. Out-of-band fingerprint verification (SSHFP, vendor docs, a colleague who already connected) is the only fix. The demo includes a scenario that makes this honest limitation visible.
- **Do NOT use this as a real SSH implementation** — this is a toy for learning. For production use OpenSSH, libssh, or another vetted library.

## Live Demo

[**https://systemslibrarian.github.io/crypto-lab-ssh-handshake/**](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/)

The page walks through five sections. **Start the server** generates a real host keypair in your browser and shows its `SHA256:` fingerprint — this is the long-term identity. **Connect** runs the handshake: the client generates an ephemeral KEX key, the server replies with its ephemeral key and a signature over the exchange hash, and the client verifies the signature and applies the `known_hosts` policy. The first run pins the fingerprint (TOFU); a "ssh server.example.com (reconnect)" button shows the matches-known path. **Break it** runs three scenarios — *MITM after pinning* (the attacker's substituted host key is caught by the pin and the connection is rejected with the familiar "host identification has changed" warning), *MITM on first contact* (a fresh client with no pins connects through the attacker and pins the **attacker's** fingerprint — the honest lesson that TOFU cannot detect a first-contact MITM), and *tampered host signature* (a flipped byte in transit makes the signature verification fail and the connection is refused). A **Reset known_hosts** control clears the pin map so scenarios can be re-run cleanly. The remaining sections contrast the three trust models in the crypto-lab suite and document where TOFU actually lives in the real world — `~/.ssh/known_hosts`, `SHA256:` fingerprints, host key types, SSHFP DNS records, certificate-based SSH, and the `StrictHostKeyChecking` modes.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ssh-handshake.git
cd crypto-lab-ssh-handshake
npm install
npm run dev      # local dev server with HMR
npm run build    # type-check + production build to dist/
npm run preview  # serve the built dist/ locally
```

No environment variables, no API keys, no servers. Everything runs client-side in the browser.

## Part of the Crypto-Lab Suite

This is one demo in a wider portfolio of interactive cryptography labs — see [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) for the rest, including the five PQC families overview, hybrid TLS, harvest-now-decrypt-later timelines, and deep-dives on individual schemes.

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31

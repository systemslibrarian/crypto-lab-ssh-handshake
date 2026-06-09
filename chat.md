# What Would Make This the Gold Standard

## Current Read

This demo is already stronger than most educational crypto demos because it:

- uses real Web Crypto for ephemeral key agreement and host signatures in [src/engine.ts](src/engine.ts)
- teaches TOFU honestly, including MITM-after-pin, MITM-on-first-contact, and tampered-signature cases in [src/ui.ts](src/ui.ts)
- grounds the story in real SSH practice in [src/data.ts](src/data.ts)
- builds cleanly with `npm run build`

If the goal is a gold-standard educational demo rather than a mini OpenSSH reimplementation, the missing pieces are not more protocol surface. The missing pieces are better trust-decision UX, better visibility into the transcript, stronger proof, and a more complete operational story.

## Must-Haves

### 1. Make first-contact trust an explicit user action

- Right now first contact auto-pins.
- Gold-standard behavior is to force a choice: accept, reject, or verify through a trusted channel.
- Show the exact fingerprint and why the choice is dangerous.
- Offer a simple out-of-band verification path so the user can see the safe and unsafe flows side by side.

Reason: this is the conceptual center of SSH TOFU. Auto-accept hides the hardest part.

### 2. Add a transcript inspector

- Show the client ephemeral public key, server ephemeral public key, host key fingerprint, exchange-hash inputs, exchange hash output, signature, and `known_hosts` decision.
- Let the user expand raw values or copy the transcript as JSON.
- In attack scenarios, highlight the exact field that changed and the exact check that caught it.

Reason: users remember what they can inspect, not what they are merely told.

### 3. Add legitimate host-key rotation as a first-class scenario

- Planned rotation after maintenance
- Emergency rotation after compromise
- User workflow for removing or updating a stale `known_hosts` entry

Reason: in real life, the same warning is caused by attack and by ordinary operations. A gold-standard demo distinguishes those clearly.

### 4. Add stronger credibility than the dev-only self-test in [src/main.ts](src/main.ts)

- Create actual automated tests for the engine behavior.
- Cover first-use pinning, reconnect success, MITM-after-pin rejection, MITM-first-contact acceptance, tampered-signature rejection, and server-restart warnings.
- Keep the tests deterministic and narrow.

Reason: if this is meant to be authoritative, the core claims should be mechanically checked.

### 5. Add citations and provenance

- Link key ideas to OpenSSH documentation and the relevant SSH RFCs.
- Keep a short “what is modeled / what is intentionally omitted” panel in the UI, not only in [README.md](README.md).

Reason: the demo becomes much harder to dismiss as hand-wavy.

## High-Value Upgrades

### 1. Improve OpenSSH fidelity at the trust boundary

- Render a realistic `known_hosts` line.
- Show host key algorithm names explicitly.
- Model multiple host key types for one host.
- Optionally show hashed hostnames and `ssh-keygen -F` or `ssh-keygen -R` style operations.

Reason: this helps learners map the demo to the tool they actually use.

### 2. Show the trust-upgrade paths beyond plain TOFU

- SSHFP with DNSSEC
- OpenSSH host certificates and `@cert-authority`
- `StrictHostKeyChecking yes|ask|accept-new|no`

Reason: the best SSH demo does not stop at “TOFU exists”; it shows how operators reduce TOFU’s first-contact weakness.

### 3. Add teacher-friendly controls

- Step mode and autoplay mode
- Deep links to scenarios
- `Reset all` plus `Reset only known_hosts`
- Copyable scenario summaries

Reason: this makes the demo useful in a classroom, talk, or documentation page.

### 4. Make the comparison with the sibling demos sharper

- Use one shared comparison frame: how does a client decide a key is real on first contact?
- Contrast TLS PKI, PGP Web of Trust, and SSH TOFU using the same event and the same failure mode.

Reason: gold standard here is not just a good SSH page; it is the clearest member of the crypto-lab trio.

## What Not To Do

- Do not try to implement the SSH binary packet protocol just to sound more real.
- Do not add user authentication, channels, or full algorithm negotiation unless they directly improve the trust story.
- Do not bury the main lesson under too many knobs.

The scoping in [README.md](README.md) is already right: this should become the best demo of SSH trust and transport authentication, not a browser OpenSSH clone.

## Recommended Path

1. Explicit first-contact accept or reject or verify flow
2. Transcript inspector with raw artifacts and highlighted failures
3. Legitimate host-key rotation scenario
4. Real automated tests around [src/engine.ts](src/engine.ts)
5. Short in-app citations and provenance panel
6. Optional OpenSSH fidelity features like realistic `known_hosts` lines and multi-key hosts

## Bottom Line

Right now this is already a strong demo. It becomes gold standard when the user can:

- see the exact cryptographic transcript
- make the dangerous first-contact decision themselves
- distinguish attack from legitimate rotation
- connect the model directly to OpenSSH behavior
- trust the demo because its claims are tested and cited
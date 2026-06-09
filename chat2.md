# Second Pass: What Still Separates This from Gold Standard

## Revised Read

After a second pass, this repo is much closer to gold standard than my first note gave it credit for.

It already has the big educational pieces in place:

- explicit first-contact trust decisions and `StrictHostKeyChecking` modes in [src/policy.ts](src/policy.ts)
- transcript inspection, recovery scenarios, SSHFP, and CA-based trust paths in [src/ui.ts](src/ui.ts)
- scope and provenance panels with RFC and OpenSSH citations in [src/data.ts](src/data.ts)
- automated coverage across engine, policy, SSHFP, and CA flows in [src/engine.test.ts](src/engine.test.ts)

Current baseline also verifies cleanly:

- `npm test` → 30 tests passed
- `npm run build` → production build passed

So the question is no longer “what major feature class is missing?”

The real remaining gap is this: **some of the demo’s artifacts are SSH-like rather than SSH-exact.**

If you want this to be the gold standard, the next work should go into protocol fidelity and calibration, not more surface area.

## The Real Remaining Gaps

### 1. Use actual SSH key material, not JWK-shaped stand-ins

This is the biggest remaining issue.

Right now the demo computes fingerprints from concatenated JWK coordinates in [src/engine.ts](src/engine.ts) and synthesizes `known_hosts` lines from the same kind of material in [src/policy.ts](src/policy.ts). The code even says the `known_hosts` line is JWK-derived rather than literal SSH wire format.

That is good enough for teaching shape, but not yet gold standard.

Gold-standard version:

- serialize host public keys as actual SSH public-key blobs
- derive the `SHA256:` fingerprint from that blob, as OpenSSH does
- render realistic `known_hosts` base64 key fields from the same blob
- use the same canonical key material across fingerprints, SSHFP, CA signing, and transcript display

Reason: once the artifacts are exact, the learner can compare this demo directly against `ssh-keyscan`, `ssh-keygen -lf`, and real `known_hosts` entries without caveats.

### 2. Either implement the real RFC 4253 exchange hash framing or label the current hash more carefully

In [src/engine.ts](src/engine.ts), the exchange hash is a SHA-256 over a simplified string containing host name, host key material, both ephemeral public keys, and the shared secret.

That is a defensible teaching surrogate, but it is not the RFC 4253 exchange hash.

Gold-standard version:

- either compute a transcript much closer to RFC 4253 framing
- or explicitly relabel the current `H` as a pedagogical stand-in rather than “the” SSH exchange hash

Why this matters:

- real SSH `H` includes version strings and KEX payload context that are not present here
- current wording risks teaching that the transport layer signs the hostname directly
- the current “faithful model” language is slightly stronger than the implementation really earns

This is the main place where the demo should get stricter about what is exact versus what is compressed for teaching.

### 3. Model multiple host keys per host, not one pin per hostname

The current core model uses `Map<string, string>` in [src/engine.ts](src/engine.ts) for `known_hosts`.

That is the next most important realism gap.

Real OpenSSH commonly stores multiple host keys for the same host, one per algorithm. Your own UI copy already explains this in [src/ui.ts](src/ui.ts), but the underlying model still collapses the host to one fingerprint.

Gold-standard version:

- pin by host plus key type, not just host name
- allow the server to present multiple host key algorithms
- show how a client chooses one and why `known_hosts` may contain several lines for the same hostname

Reason: this is where many users’ real files stop matching the mental model unless the demo shows it directly.

### 4. Tighten the CA and SSHFP sections from “trust-shape accurate” to “artifact accurate”

The CA and SSHFP additions are strong. They teach the right trust lessons.

But they are still simplified models:

- the CA certificate body in [src/ca.ts](src/ca.ts) is a compact teaching structure, not an OpenSSH host certificate
- the SSHFP flow teaches the DNSSEC trust lesson, but it does not appear to expose record fields in real DNS RR shape

Gold-standard version:

- show an actual-looking SSHFP record format
- show what an OpenSSH host certificate contains at a higher-fidelity field level
- distinguish clearly between “this is the trust logic” and “this is the exact artifact OpenSSH writes on disk or wire”

Reason: the trust lesson is already there. The remaining gain is operational exactness.

### 5. Add end-to-end browser validation for the teaching flows

The repo now has solid unit coverage, which materially changes the evaluation. That work already exists and matters.

The remaining testing gap is at the UI and scenario layer.

Gold-standard version:

- add browser-level tests for `ask` accept and reject flows
- validate SSHFP with and without DNSSEC
- validate deep-linked scenarios
- validate transcript copy and scenario summary copy
- validate recovery flows like `ssh-keygen -R` style reset and reconnect

Reason: for an educational demo, regressions in the visible teaching path matter at least as much as regressions in the cryptographic core.

### 6. Add a direct crosswalk to real OpenSSH output

This is optional, but it is probably the highest-value polish item left after protocol fidelity.

Gold-standard version:

- map each demo artifact to the closest real command or file output
- e.g. fingerprint ↔ `ssh-keygen -lf`, host key line ↔ `known_hosts`, first-contact prompt ↔ `ssh`, discovery ↔ `ssh-keyscan`, debug flow ↔ `ssh -vvv`

Reason: that turns the demo from “excellent explainer” into “definitive explainer users can carry back into the terminal.”

### 7. Tighten one provenance detail

The citations are materially better now, but one detail is still worth cleaning up if the goal is “gold standard”.

In [src/data.ts](src/data.ts), the modern-curve citation currently points at a draft reference for the preferred X25519 and Ed25519 story. That should be replaced with the final SSH RFCs for those algorithms.

Reason: once the demo is otherwise this strong, citation precision starts to matter. Gold-standard teaching material should not rely on an outdated draft when standards-track references exist.

## What Is Already Good Enough

I would not spend more time adding unrelated protocol breadth.

Do not prioritize:

- user authentication
- channels, port forwarding, scp, or sftp
- packet encryption/MAC/cipher negotiation beyond what improves transcript fidelity
- turning this into a browser OpenSSH clone

The repo is already scoped correctly. The remaining work is about **making the existing claims exact**, not making the app larger.

## Bottom Line

This demo is already near gold standard.

What still separates it from that label is mostly one class of issue:

- some outputs look like SSH artifacts without yet being the exact SSH artifacts

If you fix that, especially for:

1. fingerprints
2. `known_hosts` lines
3. exchange-hash framing
4. per-algorithm host-key pinning
5. exact standards references

then this stops being merely a very strong teaching demo and starts being the reference version.
# Extension brief — `crypto-lab-ssh-handshake`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-ssh-handshake` at `b7e334bc33fa` and `audits/_MASTER-TEMPLATE.md` (catalog
`20cb434d89e4`). Template §5: "Extend, never restructure." Source of the gap: Boneh–Shoup v0.6
§9.9 "Case study: an attack on non-atomic decryption in SSH"; second act post-dates the book
(Terrapin, 2023).

**Verdict: extension — one new section (two exhibits) after "Break it (and recover)".**

## What the lab has now

- **Engine** `src/engine.ts`: WebCrypto X25519 (fallback ECDH P-256) ephemerals and Ed25519
  (fallback ECDSA P-256) host keys, chosen once in `init()` (`:33–65`). `SshServer.respond()`
  (`:110–158`), `SshClient.connect()` (`:210–300`), `makeMitm()` (`:302`),
  `recomputeExchangeHash()` / `verifyHostSignature()` (`:320–362`). The private
  `exchangeHash()` (`:171–195`) binds host name, host key blob, both ephemerals and K — a
  teaching surrogate, as `src/data.ts:151` says.
- **Wire helpers** `src/wire.ts`: `wireString`, `wireUint32`, `wireMpint`, `concat`,
  `sshPublicKeyBlob`, `sshFingerprint` (RFC 4253 §6.6 encodings). Reuse these; do not re-implement.
- **Transcript tap** `src/transcript.ts` (`tapResponder`). **Hash-binding exhibit**
  `src/hashlab.ts`.
- **Page** `src/ui.ts` `mountApp` (`:1996–2011`) appends: hero, Section 1 setup (`:123`),
  Section 2 connect (`:294`), Section 3 "Break it (and recover)" (`:1336`), Section 4 three trust
  models (`:1787`), Section 5 real world (`:1854`), Section 6 scope & provenance (`:1894`).
  Kickers are literal strings `Section · N` at `:131,302,1344,1815,1880,1930`.
- **Honest-scope data** `src/data.ts:122–158`: the "does NOT model" card says *"The SSH binary
  packet protocol — messages here are JSON, not RFC 4253 wire frames"* and *"Re-keying
  mid-session, compression, MAC negotiation, and cipher selection."* Citations
  `src/data.ts:168+`.
- **Tests:** Vitest units `src/*.test.ts` (ca 8, engine 11, policy 11, sshfp 6, wire 7);
  Playwright `testDir: './tests/e2e'` (`playwright.config.ts:7`) with `a11y.spec.ts`,
  `teaching-flows.spec.ts`, `theme.spec.ts`; preview on port 4214 with `--strictPort`
  (`playwright.config.ts:25`). **There is no claims spec** — no `e2e/claims.spec.ts` and no
  `tests/e2e/claims.spec.ts`. Create `tests/e2e/claims.spec.ts` per template §4.1b (this lab's
  e2e directory is `tests/e2e`, not `e2e/`). No mutation script exists.
- **Dependencies:** none at runtime (`package.json` has devDependencies only).

## Defect to fix as part of this work (propagation rule)

`src/data.ts:151` says: *"The PROPERTY — H commits the entire handshake transcript so a
substitution breaks the host signature — is faithful."* RFC 4253 §8 lists exactly what H
hashes — V_C, V_S, I_C, I_S, K_S, e, f, K — and nothing else. Messages such as
SSH_MSG_IGNORE (RFC 4253 §11.2, accepted "at any time") and the implicit sequence numbers are
not in H, which is precisely what Terrapin exploits. Reword to "H commits the version strings,
both KEXINIT payloads, the host key, both ephemerals and the shared secret" and cross-reference
the new exhibit. Sweep every restatement: `src/hashlab.ts:216` ("why one signature covers
everything"), `src/ui.ts:1037` footnote, `src/data.ts:76`, README "What It Is" and line ~72.

## What to add

New **Section · 4 — "After the handshake: the packet layer"**, inserted after Section 3;
renumber the later kickers 4→5, 5→6, 6→7 and the README's "six sections" sentence. Plain
intro: "The handshake gives both sides keys. Every byte after that travels in packets that are
encrypted and authenticated one at a time. Two real attacks show that *how* a receiver
decrypts — and *what* it counts — matters as much as the cipher."

### Exhibit 4A — the length that is read too early (B–S §9.9; Albrecht–Paterson–Watson 2009)

Headline mechanism: the receiver decrypts the first block and **acts on the 4-byte length field
before the MAC is checked**, so the length field becomes a decryption oracle.

- Modelled RFC 4253 §6 binary packet protocol, one direction: `uint32 packet_length ‖ byte
  padding_length ‖ payload ‖ random padding` (≥ 4 bytes, total a multiple of 16), AES-128-CBC
  with the IV carried from the end of one packet to the next (§6.3), MAC = HMAC-SHA-256
  (RFC 6668 `hmac-sha2-256`) over `uint32 sequence_number ‖ unencrypted_packet` (§6.4),
  encrypt-and-MAC. Note on the page: B–S name HMAC-SHA1 as the required MAC; the MAC choice
  does not affect the attack.
- The attacker captures a target ciphertext block c\* and its predecessor c\*₋₁, then injects
  c\* into the same connection as the first block of a new packet. The receiver decrypts
  `P′ = D(c*) ⊕ L`, where L is the last ciphertext block it received. The attacker recovers the
  target plaintext bytes as `P′ ⊕ L ⊕ c*₋₁` — it knows both L and c\*₋₁ from the wire.
- Two receivers, selectable:
  1. **Book's idealised receiver** (B–S's high-level description): no length sanity checks;
     the attacker feeds bytes until the MAC error and learns all 32 bits. The page computes the
     real ℓ from real AES and shows the byte cost (ℓ is effectively uniform over 32 bits).
     The transport is modelled: the byte counter may be advanced in one step to the point where
     the receiver's rule fires, and the page must say that bytes were counted, not sent.
  2. **Pre-5.2 OpenSSH-style receiver**, exactly as APW describe it: reject
     `packet_length < 5 || packet_length > 256·1024` with a "Bad packet length" DISCONNECT
     (distinguishable by its size); then require `need = 4 + packet_length − block_size` to be
     a multiple of the block size, else close with no message (FIN only); else wait for
     `need + maclen` bytes, then the MAC check fails with an error. Distinguishing those three
     reactions gives APW's 14-bit attack (success ≈ 2⁻¹⁴ per attempt) and, from the wait state,
     the 32-bit attack (≈ 2⁻¹⁸) by feeding blocks until the MAC error — at most 2¹⁸/16 blocks.
     These probabilities are quoted from the paper's abstract; the page also **measures** the
     hit rate over many attempts and prints measured vs 2⁻¹⁴ / 2⁻¹⁸. Footnote, not modelled:
     APW also report an OpenSSH `packet.c` change that made two of the failure responses
     indistinguishable, which blocks the 14-bit variant but not the 32-bit one.
- Each attempt costs a connection (APW: connections are "terminated with high probability at
  each attempt"). Model repeated attempts as fresh connections with fresh random keys (labelled
  as standing in for a new key exchange) carrying the same secret at the same position. Before
  writing copy for that setting, confirm against APW's text how they frame repeated attempts on
  a recurring plaintext; if the paper frames it differently, follow the paper.
- Break-it-yourself: pick the receiver, pick the target block, run; the recovered bits are
  checked against the true plaintext and shown bit by bit.
- **Fixes, re-run with the same injection:** AES-CTR (APW: OpenSSH 5.2 changed the default
  preference to the AES CTR modes) — the injected block is XORed with an unrelated keystream
  block, so the length read reveals nothing about the target; `chacha20-poly1305@openssh.com`
  (Exhibit 4B's mode) — the length is encrypted under its own key and the MAC is checked before
  the payload is decrypted. Each fix gets its own verdict.

### Exhibit 4B — the packet that vanished (Terrapin)

Headline mechanism: sequence numbers count **every** packet from the first one and are never
reset (RFC 4253 §6.4), but the handshake hash H does not cover optional messages like
SSH_MSG_IGNORE. An attacker who injects one IGNORE before NEWKEYS and deletes one encrypted
packet after it leaves both counters back in step — so the deletion verifies.

- Model the message sequence with explicit per-direction counters (`C.Snd`, `C.Rcv`, `S.Snd`,
  `S.Rcv`): both KEXINITs, ECDH init/reply, NEWKEYS, then server→client encrypted EXT_INFO
  (RFC 8308) followed by a second encrypted message. Real X25519 via WebCrypto (as the engine
  does), an RFC 4253 §8-shaped H over V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K built with the
  existing `wire.ts` helpers (new module; leave `engine.ts`'s surrogate H alone), keys derived
  per RFC 4253 §7.2 including the key-extension rule (K1 = HASH(K‖H‖X‖session_id),
  K2 = HASH(K‖H‖K1)) to reach the 64 bytes chacha20-poly1305 needs.
- Record protection: `chacha20-poly1305@openssh.com` with the packet sequence number as the
  64-bit nonce. Key split, from the IETF draft (§6–7): of the 64 bytes of key material, the
  **second** 32 bytes key the instance that encrypts only the 4-byte length; the **first** 32
  bytes key the payload instance (block counter starting at 1) and generate the Poly1305 key
  (block counter 0); the tag covers encrypted length ‖ encrypted payload; the receiver decrypts
  the length, then checks the tag before decrypting the payload. Naming warning for the agent:
  OpenSSH's `PROTOCOL.chacha20poly1305` and the IETF draft label the two halves differently —
  implement by position as stated here and cite the draft.
- Attack, per Bäumer–Brinkmann–Schwenk §4.2: inject one IGNORE **to the client before
  NEWKEYS** (C.Rcv becomes S.Snd + 1); delete the server's first encrypted message (EXT_INFO);
  the next server packet carries exactly the sequence number the client now expects, so its
  Poly1305 tag verifies. Show the counters, show H unchanged (the IGNORE is not hashed), and
  show the consequence as the client's extension table: no `server-sig-algs`, no
  `ping@openssh.com` — the paper's downgrade of user-auth signature algorithms and of OpenSSH
  9.5's keystroke-timing countermeasure, described in prose, not executed.
- Mode notes on the page, quoted from the paper/site: ChaCha20-Poly1305 is deterministically
  exploitable; CBC-EtM only probabilistically; CTR-EtM is cryptographically affected but of
  "limited exploitability"; AES-GCM is not affected. Build only the ChaCha20-Poly1305 run.
- **Fix: strict kex** (draft-ietf-sshm-strict-kex): the `kex-strict-c-v00@openssh.com` /
  `kex-strict-s-v00@openssh.com` pseudo-algorithms in KEXINIT; when both sides offer them,
  terminate on any non-KEX message during the initial key exchange, require KEXINIT to be the
  first message, and reset the sending sequence number to zero after every SSH_MSG_NEWKEYS.
  Re-run the identical attack: the injected IGNORE ends the connection. Because the
  pseudo-algorithms travel in KEXINIT, which *is* in H, show that stripping them breaks the host
  signature — the countermeasure cannot itself be downgraded.

## Why it belongs here and not in a new lab

Both attacks live in the transport immediately after the handshake this lab already builds, and
Terrapin is specifically a statement about what this lab's headline object — the exchange hash
— does and does not cover. A separate lab would have to rebuild the KEX, the wire encoding and
the H story that are already here.

## SECURITY / CORRECTNESS INVARIANTS

1. New code lives in `src/bpp/` (`packet.ts`, `cbc-and-mac.ts`, `ctr.ts`, `chachapoly.ts`,
   `kex.ts`, `seq.ts`, `attack-apw.ts`, `attack-terrapin.ts`, `strict-kex.ts`). The existing
   engine, policy, CA and SSHFP modules are not modified.
2. Deliberately weak receivers (idealised, OpenSSH-5.1-style, non-strict kex) are isolated,
   never the default, and visibly marked broken.
3. The attacker uses only wire bytes; a unit test asserts the attack modules import no key
   material.
4. Recovered plaintext bits are verified against the true plaintext by a function the attack
   code does not call.
5. Real primitives: AES via `@noble/ciphers` `cbc` with padding disabled (WebCrypto's AES-CBC
   always applies PKCS#7) and cross-checked against WebCrypto on whole-block inputs; ChaCha20
   (64-bit nonce variant) and Poly1305 from `@noble/ciphers`. Adding `@noble/ciphers` is
   justified because WebCrypto exposes neither raw ChaCha20 nor Poly1305; match the version line
   sibling labs use (crypto-lab-stream-ward and crypto-lab-poly1305-mac, which I checked, import
   `@noble/ciphers` 2.x — re-check the exact pin). Confirm the library
   exposes the 64-bit-nonce ChaCha20; if not, hand-roll it and test it.
6. No network. Every "connection" is an in-page model and says so.

## UI

Exhibit 4A: receiver selector → **Capture target** (shows c\*₋₁, c\*) → **Inject** → reaction
log (DISCONNECT / FIN / wait / MAC error) → recovered bits vs true bits → **Run N attempts**
(Web Worker, progress, measured rate) → fix selector re-runs. Exhibit 4B: a two-lane message
timeline with four live counters; **Inject IGNORE**, **Delete EXT_INFO**, **Deliver**; the
client's extension table; strict-kex toggle. Stacks below 640px with the counters kept beside
the timeline.

## VISUAL SEMANTICS

A deletion the client accepted reads **ALARM — PACKET DELETED, MAC VALID**; a successful length
leak reads **ALARM — PLAINTEXT LEAKED (n bits)**; a fix that stops the attack reads as the
defence holding, naming the check that fired. Icon + text + colour throughout; counters that
disagree are marked with text, not colour alone.

## EDGE CASES

- Target block chosen inside the MAC tag → refused: "the tag is not CBC ciphertext".
- Idealised receiver with ℓ beyond the page's byte budget → cost shown, run not performed, page
  says why.
- Delete without prior IGNORE → client's counter mismatches; Poly1305 rejects; verdict names the
  sequence-number mismatch.
- IGNORE injected after NEWKEYS → it is encrypted traffic the attacker cannot forge; the model
  refuses and explains.
- Strict kex offered by one side only → not active (both must support it, per the draft and the
  Terrapin site); show that.

## Tests

- **KATs:** AES-128-CBC: NIST SP 800-38A Appendix F.2.1 CBC-AES128.Encrypt (four blocks)
  `[confirm section number against the NIST PDF]`; HMAC-SHA-256: RFC 4231 test cases including
  the larger-than-block-size key-and-data case (Test Case 7) `[confirm case number and data
  length]`; ChaCha20: RFC 8439
  §2.4.2 (114-byte plaintext, two blocks) mapped onto the 64-bit-nonce layout, plus RFC 8439
  A.1/A.2; Poly1305: RFC 8439 §2.5.2 and A.3; chacha20-poly1305@openssh.com: the IETF draft's
  Appendix A worked example (one packet; check whether its payload exceeds 64 bytes and say so);
  RFC 4253 §7.2 key derivation checked by an independent re-derivation in the test.
- **Vitest:** APW recovery correct on every success; measured rates over a fixed seeded run
  within a stated tolerance of 2⁻¹⁴ and 2⁻¹⁸; Terrapin succeeds on non-strict chacha20-poly1305
  and fails under strict kex at the named rule; H unchanged by an injected IGNORE.
- **tests/e2e/claims.spec.ts (new, §4.1b):** XOR the three blocks the page displays
  (P′, L, c\*₋₁) and assert they equal the displayed recovered bits; parse the four counters and
  assert the client's receive counter equals the sequence number shown on the delivered packet;
  assert the measured-rate text matches hits ÷ attempts shown; retirement and no-op guard.
- **§4.1c:** one mutation per new verdict (each receiver's leak verdict, each fix verdict, the
  Terrapin verdict, the strict-kex verdict), the five steps reported for each.
- **§4.1d negative claim:** "A valid MAC on every delivered packet does not mean no packet was
  deleted." Evidence fixture: Exhibit 4B after the attack — handshake signature verifies, every
  delivered packet's Poly1305 tag verifies, and EXT_INFO never arrived. Verdict shape:
  `AUTHENTICATED — AND TRUNCATED`.

## README and card follow-up

What It Is gains one sentence on the packet layer; the numbered section list gains Section 4 and
renumbers; "What Can Go Wrong" gains both attacks; "Real-World Usage" gains strict kex. Update
the SCOPE card in `src/data.ts` (the binary packet protocol is now modelled for these two
exhibits only; the core engine still exchanges JSON). Handoff chips: candidates `AES-CBC`,
`ChaCha20-Poly1305` (as `chacha20-poly1305@openssh.com`), `HMAC-SHA-256`, `Terrapin` as an
attack — apply the chip rule; do not edit `../crypto-lab`.

## Do not touch

The engine's surrogate exchange hash and its existing exhibits, the eight scenarios, the
StrictHostKeyChecking modes, known_hosts behaviour, the theme pin, header and deploy workflow.

## Sources

- D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*, v0.6, §9.9 —
  https://toc.cryptobook.us/
- M. R. Albrecht, K. G. Paterson, G. J. Watson, "Plaintext Recovery Attacks against SSH," IEEE
  Symposium on Security and Privacy 2009, doi:10.1109/SP.2009.5 — abstract checked at
  https://www.cs.umd.edu/~jkatz/security/downloads/PlaintextRecoverySSH.pdf (14 bits w.p. 2⁻¹⁴,
  32 bits w.p. 2⁻¹⁸, CBC; the two OpenSSH checks; OpenSSH 5.2 preferring CTR).
- F. Bäumer, M. Brinkmann, J. Schwenk, "Terrapin Attack: Breaking SSH Channel Integrity By
  Sequence Number Manipulation," USENIX Security 2024 —
  https://www.usenix.org/conference/usenixsecurity24/presentation/b%C3%A4umer ; arXiv:2312.12422;
  CVE-2023-48795; https://terrapin-attack.com/
- draft-ietf-sshm-strict-kex-02 (22 July 2026) §3.1–3.3 —
  https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/
- draft-ietf-sshm-chacha20-poly1305-04 (26 May 2026) §6–7, Appendix A —
  https://datatracker.ietf.org/doc/draft-ietf-sshm-chacha20-poly1305/
- RFC 4253 §6, §6.1, §6.3, §6.4, §7.2, §7.3, §8, §11.2 — https://www.rfc-editor.org/rfc/rfc4253
- RFC 6668 (hmac-sha2-256) — https://www.rfc-editor.org/rfc/rfc6668
- RFC 8308 (EXT_INFO) — https://www.rfc-editor.org/rfc/rfc8308
- RFC 8439 §2.3, §2.4.2, §2.5.2, Appendix A — https://www.rfc-editor.org/rfc/rfc8439
- NIST SP 800-38A Appendix F —
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

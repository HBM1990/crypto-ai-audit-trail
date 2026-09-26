# Architecture Notes

## Why a hash chain

A single signature on each entry proves authenticity. But what about **ordering** and **completeness**? An attacker with access to the log could delete entries or reorder them while keeping individual signatures valid.

The fix is a **hash chain**: each entry contains the hash of the previous entry. So:

- **Deletion** breaks the chain at the next entry (its `prev_hash` no longer matches).
- **Reordering** breaks both the previous entry (its `prev_hash` references the wrong prior hash) and the next entry (same reason).
- **Insertion** breaks the chain at the inserted point (the original next entry's `prev_hash` references the pre-insertion hash, not the inserted one).

This gives a third guarantee on top of authenticity and integrity: **continuity**. The chain is provably complete and in-order.

## Why Ed25519

Ed25519 is the right choice for signing audit entries because:

1. **Speed** — signing and verification are fast, much faster than RSA.
2. **Compact** — 64-byte signatures, 32-byte public keys.
3. **Deterministic** — same input always produces the same signature, which simplifies verification.
4. **Side-channel resistant** — the reference implementation is designed to be constant-time.
5. **Standard** — RFC 8032, supported by every major language's crypto library.

For audit logging specifically, Ed25519 is the modern best practice. RSA signatures are larger and slower; ECDSA (without EdDSA's deterministic nonce) has historically been a source of key-reuse bugs.

## Why SHA256 for the chain

SHA256 is the right choice for the hash chain because:

1. **Collision resistance** — finding two inputs with the same SHA256 is computationally infeasible.
2. **Speed** — fast enough that chain verification is cheap.
3. **Ubiquity** — every language and platform has a SHA256 implementation.
4. **Canonical output** — 64 hex chars, predictable size.

For higher security margin, SHA3-256 is an option but adds little practical value at the cost of platform support. SHA256 is the right default.

## Why sort_keys=True for canonical JSON

The signature is over the canonical JSON representation of the entry. If we just `json.dumps(entry)`, Python's default ordering depends on insertion order, which is fragile and breaks verification across implementations.

`json.dumps(entry, sort_keys=True, separators=(",", ":"))` produces a **canonical form**: the same logical object always produces the same bytes. This is essential for cross-implementation verification.

## What's missing for production

This is a reference implementation. Production would need:

1. **Multi-signer threshold** — multiple parties sign each entry; require k-of-n signatures.
2. **Public anchoring** — periodically publish the chain head to a public ledger (blockchain, transparency log, signed timestamp service) so even the signer can't rewrite history.
3. **Key rotation** — signing keys should rotate; old keys should remain verifiable.
4. **Tamper-evident storage** — the log file itself should be on append-only or write-once storage.
5. **Replay protection** — nonces or sequence checks beyond just `seq` to prevent replay of an old entry into a new context.

Each of these is a non-trivial addition. The reference implementation shows the **core cryptographic primitive**: signed hash chain. The rest is engineering.

## Threat model

**Trusted:**
- The signer (holder of the private key)
- The implementation (this code)

**Untrusted:**
- The log file (might be modified, deleted, or replaced by an attacker)
- The storage medium (might fail, be backed up inconsistently, or be tampered with at rest)

**Adversary capabilities:**
- Read the log
- Modify any byte of any entry
- Delete entries
- Reorder entries
- Insert forged entries (without the private key)

**What the chain does NOT protect against:**
- The signer themselves lying (use multi-signer for that)
- The signer signing both the real entry and a forged one (use nonces + external attestation for that)
- Loss of the private key (key management is out of scope)

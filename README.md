# Cryptographic AI Audit Trail

Tamper-evident audit logging for AI workflows using Ed25519 signatures and SHA256 hash chains.

## What this is

A reference implementation showing how to make AI workflow logs **cryptographically verifiable**. Each entry is:

1. **Signed** with Ed25519 — proves it was written by the holder of the private key.
2. **Hashed** with SHA256 — produces a deterministic fingerprint of the entry contents.
3. **Chained** to the previous entry's hash — any tampering with order, content, or completeness is detectable.

If anyone modifies a single byte of any entry, deletes an entry, or reorders entries, verification fails with the exact line number and what mismatched.

## What this is not (yet)

- A production-deployed system with live users.
- A replacement for centralized logging infrastructure.
- A consensus mechanism (this is single-signer; multi-signer would need a threshold scheme).

## Why this matters for AI

AI systems need audit trails that survive scrutiny:

- **Regulators** want to know what your model actually did, not what you say it did.
- **Customers** want to verify the AI's outputs match what they were promised.
- **Engineers** want to debug failures without trusting the logs blindly.
- **You** want to prove your system wasn't compromised after the fact.

A cryptographically-signed chain is the answer: it's a log that **can't lie**.

## Quick start

### 1. Install

```bash
pip install -r requirements.txt
```

### 2. Generate a signing key

```bash
python src/audit_trail.py keygen --out ./keys/signer.pem
```

This creates `keys/signer.pem` (private, mode 0600) and `keys/signer.pub` (public, shareable).

### 3. Append entries

```bash
python src/audit_trail.py append \
    --key ./keys/signer.pem \
    --log ./audit.jsonl \
    --event "model.invoke" \
    --data '{"model": "claude-3.5-sonnet", "prompt_hash": "abc123"}'

python src/audit_trail.py append \
    --key ./keys/signer.pem \
    --log ./audit.jsonl \
    --event "tool.call" \
    --data '{"tool": "search", "query": "hybrid embeddings"}'
```

### 4. Verify the chain

```bash
python src/audit_trail.py verify \
    --log ./audit.jsonl \
    --pubkey ./keys/signer.pub
```

Returns:
```json
{
  "status": "ok",
  "entries": 2,
  "verified": 2,
  "errors": []
}
```

## Try breaking it

The point of a tamper-evident log is that you can prove tampering. Try:

```bash
# Delete an entry (sed the file, then re-verify)
sed -i '2d' audit.jsonl
python src/audit_trail.py verify --log audit.jsonl --pubkey keys/signer.pub
# → "line 2: prev_hash mismatch"

# Modify an entry (change a character)
sed -i 's/claude/claudeXX/' audit.jsonl
python src/audit_trail.py verify --log audit.jsonl --pubkey keys/signer.pub
# → "line 1: signature invalid"

# Reorder entries (swap lines 2 and 3)
python src/audit_trail.py verify --log audit.jsonl --pubkey keys/signer.pub
# → "line 2: prev_hash mismatch"
```

Every tamper attempt is caught at the exact line that broke the chain.

## File layout

```
.
├── README.md
├── requirements.txt
├── LICENSE
├── src/
│   └── audit_trail.py    # Keygen, append, verify
├── docs/
│   └── architecture.md
└── examples/
    ├── run_demo.sh        # End-to-end demo
    └── audit.jsonl        # Sample verified log
```

## The three guarantees

| Guarantee | Mechanism | Catches |
|---|---|---|
| **Authenticity** | Ed25519 signature | Forged entries, entries not from the signer |
| **Integrity** | SHA256 entry hash | Modified entry contents |
| **Ordering & completeness** | Hash chain (prev_hash) | Deleted, inserted, or reordered entries |

## License

MIT
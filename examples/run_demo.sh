#!/usr/bin/env bash
# run_demo.sh — End-to-end demo of the audit trail.
#
# 1. Generate a keypair in examples/keys
# 2. Append four entries to examples/audit.jsonl
# 3. Verify the chain (should pass)
# 4. Tamper with an entry
# 5. Re-verify (should fail with line number + mismatch reason)
#
# Run from repo root:  bash examples/run_demo.sh

set -e
cd "$(dirname "$0")/.."

echo "=== Step 1: Generate keypair ==="
mkdir -p examples/keys
python3 src/audit_trail.py keygen --out ./examples/keys/signer.pem

echo ""
echo "=== Step 2: Append four entries ==="
python3 src/audit_trail.py append \
    --key ./examples/keys/signer.pem \
    --log ./examples/audit.jsonl \
    --event "rag.populate.start" \
    --data '{"collection": "documents", "total_docs": 12}'

python3 src/audit_trail.py append \
    --key ./examples/keys/signer.pem \
    --log ./examples/audit.jsonl \
    --event "embedding.generate" \
    --data '{"model": "text-embedding-3-small", "chunks": 12}'

python3 src/audit_trail.py append \
    --key ./examples/keys/signer.pem \
    --log ./examples/audit.jsonl \
    --event "qdrant.upsert" \
    --data '{"collection": "documents", "points": 12}'

python3 src/audit_trail.py append \
    --key ./examples/keys/signer.pem \
    --log ./examples/audit.jsonl \
    --event "rag.populate.complete" \
    --data '{"status": "ok", "duration_ms": 4321}'

echo ""
echo "=== Step 3: Verify (should pass) ==="
python3 src/audit_trail.py verify \
    --log ./examples/audit.jsonl \
    --pubkey ./examples/keys/signer.pub

echo ""
echo "=== Step 4: Tamper with an entry (change model name) ==="
sed -i 's/text-embedding-3-small/text-embedding-FAKE/' ./examples/audit.jsonl

echo "=== Step 5: Re-verify (should fail) ==="
set +e
python3 src/audit_trail.py verify \
    --log ./examples/audit.jsonl \
    --pubkey ./examples/keys/signer.pub
EXIT=$?
set -e

echo ""
if [ $EXIT -eq 0 ]; then
    echo "ERROR: verification passed after tampering (bug!)"
    exit 1
else
    echo "OK: tampering detected (exit $EXIT)"
fi
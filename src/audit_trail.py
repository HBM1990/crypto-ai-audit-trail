#!/usr/bin/env python3
"""
audit_trail.py — Tamper-evident cryptographic audit trail for AI workflows.

Each audit entry is signed with Ed25519 and chained to the previous
entry's hash. Verifying the chain detects any tampering, reordering,
or deletion.

Usage:
    # Generate a signing key
    python audit_trail.py keygen --out ./keys/signer.pem

    # Append an entry to a log
    python audit_trail.py append --key ./keys/signer.pem --log ./audit.jsonl \
        --event "model.invoke" --data '{"prompt_hash": "abc123"}'

    # Verify the chain
    python audit_trail.py verify --log ./audit.jsonl --pubkey ./keys/signer.pub
"""
import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

GENESIS_HASH = "0" * 64  # SHA256 hex digest of empty string


def log(event: str, **detail) -> None:
    """Single-line JSON audit entry to stderr."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **detail,
    }
    print(json.dumps(entry), file=sys.stderr)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_payload(entry: dict) -> bytes:
    """Compute the bytes that get signed: everything except signature AND entry_hash.

    entry_hash is derived from the canonical payload, so including it would
    create a circular definition. The chain link is established via prev_hash
    which IS in the signed payload.
    """
    payload = {k: v for k, v in entry.items() if k not in ("signature", "entry_hash")}
    return canonical_json(payload)


def keygen(out_path: str) -> tuple:
    """Generate an Ed25519 keypair. Returns (priv_path, pub_path)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = Path(out_path)
    pub_path = priv_path.with_suffix(".pub")
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    os.chmod(priv_path, 0o600)
    return str(priv_path), str(pub_path)


def load_priv(path: str) -> Ed25519PrivateKey:
    pem = Path(path).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def load_pub(path: str) -> Ed25519PublicKey:
    pem = Path(path).read_bytes()
    return serialization.load_pem_public_key(pem)


def append_entry(log_path: str, priv: Ed25519PrivateKey, event: str, data: dict) -> dict:
    """Append a signed entry to the log. Chains to the previous entry's hash."""
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Read previous entry to get prev_hash
    prev_hash = GENESIS_HASH
    seq = 0
    if log_path.exists():
        with log_path.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                prev_entry = json.loads(line)
                prev_hash = prev_entry["entry_hash"]
                seq = prev_entry["seq"] + 1

    # Build new entry (without signature or entry_hash yet)
    entry = {
        "seq": seq,
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "data": data,
        "prev_hash": prev_hash,
    }

    # Compute entry hash over the canonical payload (no signature, no entry_hash)
    entry_bytes = canonical_payload(entry)
    entry["entry_hash"] = sha256_hex(entry_bytes)

    # Sign the same canonical bytes
    signature = priv.sign(entry_bytes)
    entry["signature"] = base64.b64encode(signature).decode("ascii")

    # Append
    with log_path.open("a") as f:
        f.write(json.dumps(entry) + "\n")

    log("entry.appended", seq=seq, event_name=event, entry_hash=entry["entry_hash"][:16])
    return entry


def verify_chain(log_path: str, pub: Ed25519PublicKey) -> dict:
    """Verify every entry: signature, hash, and chain linkage."""
    log_path = Path(log_path)
    if not log_path.exists():
        return {"status": "empty", "entries": 0, "verified": 0}

    verified = 0
    errors = []
    prev_hash = GENESIS_HASH
    expected_seq = 0

    with log_path.open("r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            entry = json.loads(line)
            line_errors_before = len(errors)

            # Check sequence
            if entry["seq"] != expected_seq:
                errors.append(
                    f"line {line_num}: seq mismatch "
                    f"(expected {expected_seq}, got {entry['seq']})"
                )

            # Check chain linkage
            if entry["prev_hash"] != prev_hash:
                errors.append(
                    f"line {line_num}: prev_hash mismatch "
                    f"(expected {prev_hash[:16]}..., got {entry['prev_hash'][:16]}...)"
                )

            # Check entry hash
            entry_bytes = canonical_payload(entry)
            computed_hash = sha256_hex(entry_bytes)
            if entry["entry_hash"] != computed_hash:
                errors.append(
                    f"line {line_num}: entry_hash mismatch "
                    f"(stored {entry['entry_hash'][:16]}..., "
                    f"computed {computed_hash[:16]}...)"
                )

            # Check signature
            try:
                signature = base64.b64decode(entry["signature"])
                pub.verify(signature, entry_bytes)
            except Exception as e:
                errors.append(f"line {line_num}: signature invalid: {e}")

            if len(errors) == line_errors_before:
                verified += 1

            prev_hash = entry["entry_hash"]
            expected_seq += 1

    status = "ok" if not errors else "tampered"
    return {
        "status": status,
        "entries": expected_seq,
        "verified": verified,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tamper-evident cryptographic audit trail."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate Ed25519 keypair")
    p_keygen.add_argument("--out", required=True, help="Private key output path")

    # append
    p_append = sub.add_parser("append", help="Append a signed entry")
    p_append.add_argument("--key", required=True, help="Private key path")
    p_append.add_argument("--log", required=True, help="Audit log path")
    p_append.add_argument("--event", required=True, help="Event name")
    p_append.add_argument("--data", required=True, help="JSON data string")

    # verify
    p_verify = sub.add_parser("verify", help="Verify the chain")
    p_verify.add_argument("--log", required=True, help="Audit log path")
    p_verify.add_argument("--pubkey", required=True, help="Public key path")

    args = parser.parse_args()

    if args.cmd == "keygen":
        priv_path, pub_path = keygen(args.out)
        print(f"Private key: {priv_path}")
        print(f"Public key:  {pub_path}")
        return 0

    if args.cmd == "append":
        priv = load_priv(args.key)
        data = json.loads(args.data)
        entry = append_entry(args.log, priv, args.event, data)
        print(json.dumps(entry, indent=2))
        return 0

    if args.cmd == "verify":
        pub = load_pub(args.pubkey)
        result = verify_chain(args.log, pub)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "ok" else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
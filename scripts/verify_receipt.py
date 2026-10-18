#!/usr/bin/env python3
"""
Hermes Canary receipt verifier.

Usage:
    python scripts/verify_receipt.py <receipt.json> <signing-key-hex>

Exit codes:
    0  — receipt is authentic (HMAC matches, schema valid)
    1  — receipt is invalid or tampered
    2  — usage error

Algorithm:
    1. Parse the receipt JSON.
    2. Create a copy with BOTH "signature" and "hmac_sha256" set to empty string "".
    3. Serialize the copy to canonical JSON (sort_keys=True, no spaces).
    4. Compute HMAC-SHA256 over the canonical bytes using the raw UTF-8 signing key.
    5. Compare (constant-time) with receipt["signature"].
"""

import hashlib
import hmac
import json
import sys
from typing import Any, Dict


RECEIPT_SCHEMA_VERSION = "1.0"

REQUIRED_FIELDS = [
    "schema_version",
    "action_version",
    "run_id",
    "commit_sha",
    "timestamp",
    "ruleset",
    "canary_vectors",
    "status",
    "signed",
    "signature",
    "hmac_sha256",
]


def _canonical(receipt: Dict[str, Any]) -> str:
    """Return canonical JSON with both signature fields zeroed."""
    body = dict(receipt)
    body["signature"] = ""
    body["hmac_sha256"] = ""
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def verify_receipt(receipt: Dict[str, Any], signing_key: str) -> bool:
    """Return True iff the receipt HMAC is valid.

    Args:
        receipt:     Parsed receipt dict (as loaded from JSON).
        signing_key: 64-character hex string (32 bytes) — raw UTF-8 as the key.
    """
    canonical = _canonical(receipt)
    expected = hmac.new(
        signing_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    stored = receipt.get("signature", "")
    return hmac.compare_digest(expected, stored)


def validate_schema(receipt: Dict[str, Any]) -> list[str]:
    """Return a list of schema errors (empty list = valid)."""
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in receipt:
            errors.append(f"Missing required field: {field!r}")
    version = receipt.get("schema_version")
    if version and version != RECEIPT_SCHEMA_VERSION:
        errors.append(
            f"Unknown schema_version {version!r}; expected {RECEIPT_SCHEMA_VERSION!r}"
        )
    if receipt.get("signed") is not True:
        errors.append("Field 'signed' must be boolean true for a signed receipt")
    return errors


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: python scripts/verify_receipt.py <receipt.json> <signing-key-hex>",
            file=sys.stderr,
        )
        return 2

    receipt_path = sys.argv[1]
    signing_key = sys.argv[2].strip()

    # Validate key format
    import re
    if not re.fullmatch(r"[0-9a-fA-F]{64}", signing_key):
        print(
            "Error: signing key must be exactly 64 hex characters (32 bytes).",
            file=sys.stderr,
        )
        return 2

    # Load receipt
    try:
        with open(receipt_path, "r", encoding="utf-8") as fh:
            receipt = json.load(fh)
    except FileNotFoundError:
        print(f"Error: receipt file not found: {receipt_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in receipt: {exc}", file=sys.stderr)
        return 2

    # Schema check
    schema_errors = validate_schema(receipt)
    if schema_errors:
        print("Receipt schema errors:")
        for err in schema_errors:
            print(f"  - {err}")
        return 1

    # HMAC verification
    ok = verify_receipt(receipt, signing_key)
    if ok:
        print(f"✓ Receipt AUTHENTIC  — run_id={receipt.get('run_id')}  status={receipt.get('status')}")
        return 0
    else:
        print("✗ Receipt INVALID — HMAC mismatch (tampered or wrong key)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

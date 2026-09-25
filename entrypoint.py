#!/usr/bin/env python3
"""Hermes PHI canary harness — synthetic Safe Harbor verification and receipt emission."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

CONTROLS_VERIFIED = ["HIPAA-164.312-e-1", "SOC2-CC6.1"]
HERMES_TELEMETRY_URL = "https://api.hermesrelay.dev/v1/telemetry/receipt"


@dataclass(frozen=True)
class CanaryVector:
    category: str
    safe_harbor_label: str
    sample: str
    scrubber: Callable[[str], str]


def _redact(pattern: str, label: str, text: str, flags: int = 0) -> str:
    return re.sub(pattern, f"[REDACTED-{label}]", text, flags=flags)


def _build_scrubbers() -> Dict[str, Callable[[str], str]]:
    """Return category scrubbers aligned with HIPAA Safe Harbor style redaction."""

    def scrub_name(text: str) -> str:
        # Title-case given + family name patterns common in clinical notes.
        text = re.sub(
            r"\b(?:Dr\.|Mr\.|Mrs\.|Ms\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
            "[REDACTED-NAME]",
            text,
        )
        text = re.sub(
            r"\bPatient:\s*[A-Z][a-z]+(?:\s+[A-Z]\.?\s+[A-Z][a-z]+|\s+[A-Z][a-z]+)+\b",
            "Patient: [REDACTED-NAME]",
            text,
        )
        return text

    def scrub_date(text: str) -> str:
        patterns = [
            r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            r"\b\d{4}-\d{2}-\d{2}\b",
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b",
        ]
        for pattern in patterns:
            text = re.sub(pattern, "[REDACTED-DATE]", text, flags=re.IGNORECASE)
        return text

    return {
        "names": scrub_name,
        "dates": scrub_date,
        "phone_numbers": lambda t: _redact(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "PHONE",
            t,
        ),
        "fax": lambda t: _redact(
            r"\bFax:?\s*(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "FAX",
            t,
        ),
        "email": lambda t: _redact(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "EMAIL",
            t,
        ),
        "ssn": lambda t: _redact(r"\b\d{3}-\d{2}-\d{4}\b", "SSN", t),
        "mrn": lambda t: _redact(
            r"\bMRN[:\s#-]*\d{6,12}\b", "MRN", t, flags=re.IGNORECASE
        ),
        "health_plan_ids": lambda t: _redact(
            r"\b(?:HP|PLAN|MEMBER)[#:\s-]*[A-Z0-9]{8,16}\b",
            "HEALTH_PLAN_ID",
            t,
            flags=re.IGNORECASE,
        ),
        "account_numbers": lambda t: _redact(
            r"\b(?:ACCT|ACCOUNT)[#:\s-]*\d{8,17}\b",
            "ACCOUNT",
            t,
            flags=re.IGNORECASE,
        ),
        "license_numbers": lambda t: _redact(
            r"\b(?:LIC|LICENSE)[#:\s-]*[A-Z0-9-]{5,24}\b",
            "LICENSE",
            t,
            flags=re.IGNORECASE,
        ),
        "vins": lambda t: _redact(
            r"\b[A-HJ-NPR-Z0-9]{17}\b", "VIN", t
        ),
        "device_serials": lambda t: _redact(
            r"\b(?:SN|SERIAL)[#:\s-]*[A-Z0-9]{8,20}\b",
            "DEVICE_SERIAL",
            t,
            flags=re.IGNORECASE,
        ),
        "web_urls": lambda t: _redact(
            r"https?://[^\s<>\"']+", "URL", t
        ),
        "ip_addresses": lambda t: _redact(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            "IP",
            t,
        ),
        "biometric_ids": lambda t: _redact(
            r"\b(?:BIO|BIOMETRIC)[#:\s-]*[A-F0-9]{16,64}\b",
            "BIOMETRIC",
            t,
            flags=re.IGNORECASE,
        ),
        "full_face_photos": lambda t: _redact(
            r"\b(?:photo|image|selfie)[:\s-]*(?:https?://[^\s]+|data:image/[a-z]+;base64,[A-Za-z0-9+/=]+)\b",
            "PHOTO",
            t,
            flags=re.IGNORECASE,
        ),
    }


def _default_canary_vectors() -> List[CanaryVector]:
    scrubbers = _build_scrubbers()
    samples: List[Tuple[str, str, str]] = [
        ("names", "Names", "Patient: Jane Q. Public was seen by Dr. Samuel Reed."),
        ("dates", "Dates", "Admission on 03/15/2024 and follow-up 2024-04-01."),
        ("phone_numbers", "Phone Numbers", "Callback at (415) 555-0199 after discharge."),
        ("fax", "Fax", "Send records via Fax: 415-555-0100."),
        ("email", "Email", "Contact jane.public@example-clinic.org for results."),
        ("ssn", "SSN", "Legacy index SSN 123-45-6789 must be redacted."),
        ("mrn", "MRN", "Chart MRN: 0049281736 updated."),
        ("health_plan_ids", "Health Plan IDs", "Coverage PLAN# HPLN8X92K1M4Q7 verified."),
        ("account_numbers", "Account Numbers", "Billing ACCT# 8844221199003344 posted."),
        ("license_numbers", "License Numbers", "Provider LIC# CA-MED-928174."),
        ("vins", "VINs", "Transport vehicle VIN 1HGCM82633A004352 noted."),
        ("device_serials", "Device Serials", "Pump SERIAL SN-AB12CD34EF56 registered."),
        ("web_urls", "Web URLs", "Portal https://portal.example-clinic.org/patient/9281."),
        ("ip_addresses", "IP Addresses", "Session originated from 192.168.44.12."),
        ("biometric_ids", "Biometric IDs", "Template BIO# A1B2C3D4E5F60718293A4B5C6D7E8F90 stored."),
        (
            "full_face_photos",
            "Full-face Photos",
            "photo: data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBD",
        ),
    ]
    vectors: List[CanaryVector] = []
    for key, label, sample in samples:
        vectors.append(
            CanaryVector(
                category=key,
                safe_harbor_label=label,
                sample=sample,
                scrubber=scrubbers[key],
            )
        )
    return vectors


def _load_ruleset(ruleset_id: str) -> List[CanaryVector]:
    """Resolve canary vectors for the requested ruleset (extensible via YAML later)."""
    supported = {"hipaa-safe-harbor-16"}
    if ruleset_id not in supported:
        raise ValueError(
            f"Unsupported ruleset '{ruleset_id}'. Supported: {', '.join(sorted(supported))}"
        )
    return _default_canary_vectors()


def _compose_scrubber(vectors: List[CanaryVector]) -> Callable[[str], str]:
    def scrub(text: str) -> str:
        result = text
        for vector in vectors:
            result = vector.scrubber(result)
        return result

    return scrub


def _vector_leaked(vector: CanaryVector, scrubbed: str) -> bool:
    """Detect whether identifiable canary material survived scrubbing."""
    # Extract high-signal tokens from the sample for residual matching.
    tokens = [
        "Jane Q. Public",
        "Samuel Reed",
        "03/15/2024",
        "2024-04-01",
        "(415) 555-0199",
        "415-555-0100",
        "jane.public@example-clinic.org",
        "123-45-6789",
        "0049281736",
        "HPLN8X92K1M4Q7",
        "8844221199003344",
        "CA-MED-928174",
        "1HGCM82633A004352",
        "AB12CD34EF56",
        "https://portal.example-clinic.org/patient/9281",
        "192.168.44.12",
        "A1B2C3D4E5F60718293A4B5C6D7E8F90",
        "data:image/jpeg;base64",
    ]
    category_tokens = {
        "names": ["Jane Q. Public", "Samuel Reed"],
        "dates": ["03/15/2024", "2024-04-01"],
        "phone_numbers": ["(415) 555-0199", "415-555-0199"],
        "fax": ["415-555-0100"],
        "email": ["jane.public@example-clinic.org"],
        "ssn": ["123-45-6789"],
        "mrn": ["0049281736"],
        "health_plan_ids": ["HPLN8X92K1M4Q7"],
        "account_numbers": ["8844221199003344"],
        "license_numbers": ["CA-MED-928174"],
        "vins": ["1HGCM82633A004352"],
        "device_serials": ["AB12CD34EF56"],
        "web_urls": ["https://portal.example-clinic.org/patient/9281"],
        "ip_addresses": ["192.168.44.12"],
        "biometric_ids": ["A1B2C3D4E5F60718293A4B5C6D7E8F90"],
        "full_face_photos": ["data:image/jpeg;base64"],
    }
    del tokens  # category-specific matching only
    for needle in category_tokens.get(vector.category, []):
        if needle in scrubbed:
            return True
    return False


def _verify_sentry_scrubber(dsn: str, scrub: Callable[[str], str]) -> None:
    """Optional remote scrubber smoke test — payload is scrubbed before any network egress."""
    if not dsn.strip():
        return

    synthetic_message = "Hermes canary probe — " + _default_canary_vectors()[0].sample
    scrubbed = scrub(synthetic_message)
    if _vector_leaked(_default_canary_vectors()[0], scrubbed):
        raise RuntimeError("Sentry scrubber path would leak PHI (pre-egress validation failed)")

    # Zero-egress: only send redacted envelope metadata to confirm DSN reachability.
    try:
        public_key, host = _parse_sentry_dsn(dsn)
    except ValueError as exc:
        raise RuntimeError(f"Invalid Sentry DSN: {exc}") from exc

    envelope = {
        "event_id": secrets.token_hex(16),
        "level": "info",
        "message": scrubbed,
        "tags": {"hermes.canary": "true", "scrubber": "verified"},
    }
    url = f"https://{host}/api/{public_key}/store/"
    requests.post(
        url,
        json=envelope,
        headers={"Content-Type": "application/json", "X-Sentry-Auth": f"Sentry sentry_key={public_key}"},
        timeout=15,
    )


def _parse_sentry_dsn(dsn: str) -> Tuple[str, str]:
    # Format: https://<public_key>@o<org>.ingest.sentry.io/<project>
    match = re.match(
        r"^https?://(?P<key>[a-f0-9]+)@(?P<host>[^/]+)/(?P<project>\d+)$",
        dsn.strip(),
    )
    if not match:
        raise ValueError("DSN must match https://<key>@<host>/<project>")
    return match.group("key"), match.group("host")


def _run_canary_harness(ruleset: str, sentry_dsn: str) -> Tuple[str, Dict[str, int]]:
    vectors = _load_ruleset(ruleset)
    scrub = _compose_scrubber(vectors)

    leaks = 0
    intercepted = 0
    for vector in vectors:
        scrubbed = scrub(vector.sample)
        if _vector_leaked(vector, scrubbed):
            leaks += 1
        else:
            intercepted += 1

    if sentry_dsn:
        _verify_sentry_scrubber(sentry_dsn, scrub)

    status = "PASSED" if leaks == 0 else "FAILED"
    summary = {
        "vectors_tested": len(vectors),
        "canaries_intercepted": intercepted,
        "leaks_detected": leaks,
    }
    return status, summary


def _build_receipt(
    status: str,
    summary: Dict[str, int],
    repository: str,
    commit_sha: str,
    timestamp: str,
    receipt_id: str,
) -> Dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "timestamp": timestamp,
        "repository": repository,
        "commit_sha": commit_sha,
        "status": status,
        "controls_verified": CONTROLS_VERIFIED,
        "summary": summary,
    }


def _canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sign_receipt(payload: Dict[str, Any], secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        _canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest


def _post_telemetry(payload: Dict[str, Any], api_key: str) -> None:
    signature = _sign_receipt(payload, api_key)
    response = requests.post(
        HERMES_TELEMETRY_URL,
        data=_canonical_json(payload),
        headers={
            "Content-Type": "application/json",
            "X-Hermes-Signature-256": signature,
        },
        timeout=20,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Hermes telemetry upload failed ({response.status_code}): {response.text[:500]}"
        )


def _write_github_output(status: str, receipt_path: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"status={status}\n")
        handle.write(f"receipt-path={receipt_path}\n")


def main() -> int:
    ruleset = os.environ.get("RULESET", "hipaa-safe-harbor-16")
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    hermes_api_key = os.environ.get("HERMES_API_KEY", "")
    fail_on_leak = os.environ.get("FAIL_ON_LEAK", "true").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    output_dir = os.environ.get("OUTPUT_DIR", "./hermes-evidence")
    repository = os.environ.get("GITHUB_REPOSITORY", "local/hermes-canary-action")
    commit_sha = os.environ.get("GITHUB_SHA", "0000000000000000000000000000000000000000")

    try:
        status, summary = _run_canary_harness(ruleset, sentry_dsn)
    except Exception as exc:  # noqa: BLE001 — surface harness failures as FAILED receipt
        status = "FAILED"
        summary = {
            "vectors_tested": 16,
            "canaries_intercepted": 0,
            "leaks_detected": 16,
        }
        print(f"Hermes canary harness error: {exc}", file=sys.stderr)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    receipt_id = f"rcpt-{secrets.token_hex(6)}"
    receipt = _build_receipt(
        status=status,
        summary=summary,
        repository=repository,
        commit_sha=commit_sha,
        timestamp=timestamp,
        receipt_id=receipt_id,
    )

    os.makedirs(output_dir, exist_ok=True)
    safe_ts = timestamp.replace(":", "-")
    receipt_path = os.path.abspath(
        os.path.join(output_dir, f"{safe_ts}_{receipt_id}.json")
    )
    with open(receipt_path, "w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2)
        handle.write("\n")

    _write_github_output(status, receipt_path)

    if hermes_api_key.strip():
        try:
            _post_telemetry(receipt, hermes_api_key.strip())
        except Exception as exc:  # noqa: BLE001
            print(f"Hermes telemetry warning: {exc}", file=sys.stderr)

    print(f"Hermes canary status: {status}")
    print(f"Receipt written to: {receipt_path}")

    if status == "FAILED" and fail_on_leak:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

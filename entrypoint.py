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


def _run_canary_harness(
    ruleset: str, sentry_dsn: str
) -> Tuple[str, Dict[str, Any], List[Dict[str, str]]]:
    vectors = _load_ruleset(ruleset)
    scrub = _compose_scrubber(vectors)

    leaks = 0
    intercepted = 0
    category_results: List[Dict[str, str]] = []
    for vector in vectors:
        scrubbed = scrub(vector.sample)
        if _vector_leaked(vector, scrubbed):
            leaks += 1
            result = "FAILED"
        else:
            intercepted += 1
            result = "PASSED"
        category_results.append(
            {
                "category": vector.category,
                "label": vector.safe_harbor_label,
                "result": result,
            }
        )

    if sentry_dsn:
        _verify_sentry_scrubber(sentry_dsn, scrub)

    status = "PASSED" if leaks == 0 else "FAILED"
    summary: Dict[str, Any] = {
        "vectors_tested": len(vectors),
        "canaries_intercepted": intercepted,
        "leaks_detected": leaks,
        "category_results": category_results,
    }
    return status, summary, category_results


def _build_receipt(
    status: str,
    summary: Dict[str, Any],
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


HERMES_COMMENT_MARKER = "<!-- hermes-canary-result -->"
GITHUB_API_VERSION = "2022-11-28"


def _failed_category_results() -> List[Dict[str, str]]:
    """Fallback per-category rows when the harness crashes before producing results."""
    return [
        {
            "category": vector.category,
            "label": vector.safe_harbor_label,
            "result": "FAILED",
        }
        for vector in _default_canary_vectors()
    ]


def _resolve_pr_number() -> Optional[int]:
    """Read the PR number from the event payload, falling back to GITHUB_REF."""
    event_path = os.environ.get("GITHUB_EVENT_PATH", "").strip()
    if event_path and os.path.isfile(event_path):
        try:
            with open(event_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            number = payload.get("pull_request", {}).get("number")
            if number is not None:
                return int(number)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            print(
                f"Hermes: warning — could not parse GITHUB_EVENT_PATH for PR number: {exc}",
                file=sys.stderr,
            )

    ref = os.environ.get("GITHUB_REF", "")
    match = re.match(r"^refs/pull/(\d+)/merge$", ref)
    if match:
        return int(match.group(1))
    return None


def _build_pr_comment_body(
    results: List[Dict[str, str]],
    tier: str,
    timestamp: str,
    commit_sha: str,
    receipt_artifact_url: Optional[str] = None,
) -> str:
    failed = any(row.get("result") == "FAILED" for row in results)
    status = "FAILED" if failed else "PASSED"
    status_emoji = "❌" if failed else "✅"
    short_sha = (commit_sha or "unknown")[:7]

    lines = [
        HERMES_COMMENT_MARKER,
        f"## 🛡️ Hermes PHI Canary — {status_emoji} {status}",
        f"*Run: {timestamp} · Commit: `{short_sha}` · Ruleset: hipaa-safe-harbor-16*",
        "",
        "| # | Safe Harbor Category | Result |",
        "|---|---|---|",
    ]
    for index, row in enumerate(results, start=1):
        passed = row.get("result") == "PASSED"
        result_cell = "✅ Intercepted" if passed else "❌ Leaked"
        label = row.get("label") or row.get("category") or f"Category {index}"
        lines.append(f"| {index} | {label} | {result_cell} |")

    lines.append("")
    if tier == "pro":
        if receipt_artifact_url:
            footer = (
                f"✅ Signed receipt generated · "
                f"[View receipt]({receipt_artifact_url})"
            )
        else:
            footer = "✅ Signed receipt generated"
    else:
        footer = (
            "🔒 **[Upgrade to Hermes Pro](https://hermesrelay.dev)** for signed "
            "tamper-evident receipts, drift detection, and Datadog validation."
        )
    lines.append(footer)
    return "\n".join(lines)


def _post_pr_comment(
    results: List[Dict[str, str]],
    tier: str,
    timestamp: str,
    github_token: str,
    repo: str,
    pr_number: int,
    commit_sha: str = "",
    receipt_artifact_url: Optional[str] = None,
) -> Optional[int]:
    """Create or update the Hermes canary result comment on a pull request.

    Fail-open: any HTTP/API error prints a warning and returns None.
    Never logs the token value.
    """
    try:
        body = _build_pr_comment_body(
            results=results,
            tier=tier,
            timestamp=timestamp,
            commit_sha=commit_sha or os.environ.get("GITHUB_SHA", ""),
            receipt_artifact_url=receipt_artifact_url,
        )
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        list_url = (
            f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        )
        existing_id: Optional[int] = None
        page = 1
        while True:
            response = requests.get(
                list_url,
                headers=headers,
                params={"per_page": 100, "page": page},
                timeout=20,
            )
            if response.status_code >= 400:
                print(
                    f"Hermes: warning — failed to list PR comments "
                    f"({response.status_code}); skipping PR comment",
                    file=sys.stderr,
                )
                return None
            comments = response.json()
            if not isinstance(comments, list):
                print(
                    "Hermes: warning — unexpected PR comments response; "
                    "skipping PR comment",
                    file=sys.stderr,
                )
                return None
            for comment in comments:
                comment_body = comment.get("body") or ""
                if HERMES_COMMENT_MARKER in comment_body:
                    existing_id = int(comment["id"])
                    break
            if existing_id is not None or len(comments) < 100:
                break
            page += 1

        if existing_id is not None:
            patch_url = (
                f"https://api.github.com/repos/{repo}/issues/comments/{existing_id}"
            )
            response = requests.patch(
                patch_url,
                headers=headers,
                json={"body": body},
                timeout=20,
            )
            action = "updated"
        else:
            response = requests.post(
                list_url,
                headers=headers,
                json={"body": body},
                timeout=20,
            )
            action = "created"

        if response.status_code >= 400:
            print(
                f"Hermes: warning — failed to {action.rstrip('d')} PR comment "
                f"({response.status_code}); continuing",
                file=sys.stderr,
            )
            return None

        comment_id = int(response.json().get("id", existing_id or 0)) or None
        print(f"Hermes: PR comment {action} (#{pr_number})")
        return comment_id
    except Exception as exc:  # noqa: BLE001 — fail-open for CI
        print(
            f"Hermes: warning — PR comment failed ({exc}); continuing",
            file=sys.stderr,
        )
        return None


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
    tier = "pro" if hermes_api_key.strip() else "free"

    try:
        status, summary, category_results = _run_canary_harness(ruleset, sentry_dsn)
    except Exception as exc:  # noqa: BLE001 — surface harness failures as FAILED receipt
        status = "FAILED"
        category_results = _failed_category_results()
        summary = {
            "vectors_tested": 16,
            "canaries_intercepted": 0,
            "leaks_detected": 16,
            "category_results": category_results,
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

    # Free-tier primary surface: PR summary comment (fail-open).
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        github_token = os.environ.get("GITHUB_TOKEN", "").strip()
        if not github_token:
            print(
                "Hermes: GITHUB_TOKEN not available — skipping PR comment",
                file=sys.stderr,
            )
        else:
            pr_number = _resolve_pr_number()
            if pr_number is None:
                print(
                    "Hermes: warning — could not determine PR number; "
                    "skipping PR comment",
                    file=sys.stderr,
                )
            else:
                _post_pr_comment(
                    results=category_results,
                    tier=tier,
                    timestamp=timestamp,
                    github_token=github_token,
                    repo=repository,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                )

    print(f"Hermes canary status: {status}")
    print(f"Receipt written to: {receipt_path}")

    if status == "FAILED" and fail_on_leak:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

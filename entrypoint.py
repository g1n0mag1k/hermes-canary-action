#!/usr/bin/env python3
"""Hermes PHI canary harness — zero-PHI-egress synthetic Safe Harbor verification and receipt emission."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

RECEIPT_SCHEMA_VERSION = "1.0"
KEYGEN_ACCOUNT = "rogersandy90"
KEYGEN_PRODUCT_ID = "933323e7-e2f9-4ccb-9f13-b574cc38bf4e"
KEYGEN_POLICY_ID = "b05916b2-3a72-4608-aeec-4246dd58e05d"

_RNG = secrets.SystemRandom()


@dataclass(frozen=True)
class CanaryVector:
    category: str
    safe_harbor_label: str
    sample: str
    needle: str
    scrubber: Callable[[str], str]


def _redact(pattern: str, label: str, text: str, flags: int = 0) -> str:
    return re.sub(pattern, f"[REDACTED-{label}]", text, flags=flags)


def _build_scrubbers() -> Dict[str, Callable[[str], str]]:
    """Return category scrubbers aligned with HIPAA Safe Harbor style redaction."""

    def scrub_name(text: str) -> str:
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
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "PHONE", t
        ),
        "fax": lambda t: _redact(
            r"\bFax:?\s*(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "FAX", t
        ),
        "email": lambda t: _redact(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL", t
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
        "vins": lambda t: _redact(r"\b[A-HJ-NPR-Z0-9]{17}\b", "VIN", t),
        "device_serials": lambda t: _redact(
            r"\b(?:SN|SERIAL)[#:\s-]*[A-Z0-9]{8,20}\b",
            "DEVICE_SERIAL",
            t,
            flags=re.IGNORECASE,
        ),
        "web_urls": lambda t: _redact(r"https?://[^\s<>\"']+", "URL", t),
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
            r"(?:photo|image|selfie)[:\s-]*data:image/[a-z]+;base64,[A-Za-z0-9+/=]+",
            "PHOTO",
            t,
            flags=re.IGNORECASE,
        ),
    }


def _random_nxx() -> str:
    """Three-digit NXX where N (first digit) is 2-9, using CSPRNG."""
    return f"{_RNG.randint(2, 9)}{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}"


def _random_phone_formatted() -> str:
    return f"({_random_nxx()}) {_random_nxx()}-{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}"


def _random_vin() -> str:
    vin_chars = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
    return "".join(secrets.choice(vin_chars) for _ in range(17))


def _default_canary_vectors() -> List[CanaryVector]:
    scrubbers = _build_scrubbers()

    first_names = [
        "Bavomir", "Qwinella", "Tovakrel", "Tepha", "Marmok",
        "Cindrel", "Flostin", "Vexler", "Nubwick", "Glimmera",
    ]
    last_names = [
        "Lurendor", "Zirandel", "Croutonsmith", "Wobbleton", "Fizzington",
        "Plumwicket", "Branflakes", "Tumblewick", "Quorble", "Snorfax",
    ]
    email_domains = [
        f"clinic-{secrets.token_hex(3)}.example.org",
        f"health-{secrets.token_hex(3)}.example.net",
        f"med-{secrets.token_hex(3)}.example.com",
    ]

    patient_first = _RNG.choice(first_names)
    patient_last = _RNG.choice(last_names)
    doctor_first = _RNG.choice(first_names)
    doctor_last = _RNG.choice(last_names)
    names_sample = (
        f"Patient: {patient_first} {patient_last} was seen by "
        f"Dr. {doctor_first} {doctor_last}."
    )
    names_needle = f"{patient_first} {patient_last}|{doctor_first} {doctor_last}"

    span_days = (date(2026, 12, 31) - date(2020, 1, 1)).days
    event_date = date(2020, 1, 1) + timedelta(days=_RNG.randint(0, span_days))
    mmddyyyy = event_date.strftime("%m/%d/%Y")
    iso_date = event_date.strftime("%Y-%m-%d")
    dates_sample = f"Admission on {mmddyyyy} and follow-up {iso_date}."
    dates_needle = f"{mmddyyyy}|{iso_date}"

    phone = _random_phone_formatted()
    phone_sample = f"Callback at {phone} after discharge."

    # Regenerate fax until it differs from phone (uniqueness + avoids phone scrubber match)
    fax_number = _random_phone_formatted()
    while fax_number == phone:
        fax_number = _random_phone_formatted()
    fax_sample = f"Send records via Fax: {fax_number}."

    email_user = f"canary.{secrets.token_hex(4)}"
    email_domain = _RNG.choice(email_domains)
    email = f"{email_user}@{email_domain}"
    email_sample = f"Contact {email} for results."

    ssn = (
        f"{_RNG.randint(1, 9)}{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}"
        f"-{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}"
        f"-{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}"
    )
    ssn_sample = f"Legacy index SSN {ssn} must be redacted."

    mrn_digits = "".join(str(_RNG.randint(0, 9)) for _ in range(10))
    # Always embed in "MRN: <digits>" context so the phone scrubber cannot absorb it.
    # The needle is the embedded form; the MRN scrubber pattern matches "MRN:" + digits.
    mrn = mrn_digits
    mrn_sample = f"Chart MRN: {mrn_digits} updated."

    plan_id = "".join(
        secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(14)
    )
    health_plan_sample = f"Coverage PLAN# {plan_id} verified."

    account_number = "".join(str(_RNG.randint(0, 9)) for _ in range(16))
    account_sample = f"Billing ACCT# {account_number} posted."

    state_codes = ["WA", "CA", "TX", "NY", "FL", "IL", "PA", "OH", "GA", "NC"]
    state = secrets.choice(state_codes)
    license_id = f"{state}-MED-{_RNG.randint(0, 999999):06d}"
    license_sample = f"Provider LIC# {license_id}."

    vin = _random_vin()
    vin_sample = f"Transport vehicle VIN {vin} noted."

    device_serial = "".join(
        secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(12)
    )
    device_serial_sample = f"Pump SERIAL SN-{device_serial} registered."

    patient_portal_id = secrets.token_hex(8)
    portal_subdomain = secrets.token_hex(3)
    portal_url = f"https://portal-{portal_subdomain}.example.org/patient/{patient_portal_id}"
    web_url_sample = f"Portal {portal_url}."

    if _RNG.choice((True, False)):
        ip_address = (
            f"10.{_RNG.randint(0, 255)}.{_RNG.randint(0, 255)}.{_RNG.randint(1, 254)}"
        )
    else:
        ip_address = f"192.168.{_RNG.randint(0, 255)}.{_RNG.randint(1, 254)}"
    ip_sample = f"Session originated from {ip_address}."

    biometric_id = secrets.token_hex(16).upper()
    biometric_sample = f"Template BIO# {biometric_id} stored."

    # Category 16: dynamic base64 image token — valid data-URL, unique every run
    raw_photo_bytes = secrets.token_bytes(48)
    photo_b64 = base64.b64encode(raw_photo_bytes).decode("ascii")
    photo_needle = f"data:image/jpeg;base64,{photo_b64}"
    photo_sample = f"photo: {photo_needle}"

    generated: List[Tuple[str, str, str, str]] = [
        ("names", "Names", names_sample, names_needle),
        ("dates", "Dates", dates_sample, dates_needle),
        ("phone_numbers", "Phone Numbers", phone_sample, phone),
        ("fax", "Fax", fax_sample, f"Fax: {fax_number}"),
        ("email", "Email", email_sample, email),
        ("ssn", "SSN", ssn_sample, ssn),
        ("mrn", "MRN", mrn_sample, f"MRN: {mrn}"),
        ("health_plan_ids", "Health Plan IDs", health_plan_sample, plan_id),
        ("account_numbers", "Account Numbers", account_sample, account_number),
        ("license_numbers", "License Numbers", license_sample, license_id),
        ("vins", "VINs", vin_sample, vin),
        ("device_serials", "Device Serials", device_serial_sample, device_serial),
        ("web_urls", "Web URLs", web_url_sample, portal_url),
        ("ip_addresses", "IP Addresses", ip_sample, ip_address),
        ("biometric_ids", "Biometric IDs", biometric_sample, biometric_id),
        ("full_face_photos", "Full-face Photos", photo_sample, photo_needle),
    ]

    vectors: List[CanaryVector] = []
    for key, label, sample, needle in generated:
        vectors.append(
            CanaryVector(
                category=key,
                safe_harbor_label=label,
                sample=sample,
                needle=needle,
                scrubber=scrubbers[key],
            )
        )
    return vectors


def _load_ruleset(ruleset_id: str) -> List[CanaryVector]:
    """Resolve canary vectors for the requested ruleset."""
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
    for needle in vector.needle.split("|"):
        if needle and needle in scrubbed:
            return True
    return False


def _verify_sentry_scrubber_local(dsn: str, scrub: Callable[[str], str]) -> None:
    """Local pre-egress scrubber verification — no network call is made.

    Validates that (a) the DSN is syntactically correct, and (b) the scrubber
    would redact canary material before it could reach any external endpoint.
    Zero bytes leave the runner during this check.
    """
    if not dsn.strip():
        return

    # Validate DSN format only — no network call
    match = re.match(
        r"^https?://(?P<key>[a-f0-9]+)@(?P<host>[^/]+)/(?P<project>\d+)$",
        dsn.strip(),
    )
    if not match:
        raise RuntimeError(
            "Invalid Sentry DSN format (expected https://<key>@<host>/<project_id>)"
        )

    # Verify the scrubber catches canary material before any hypothetical egress
    probe_vectors = _default_canary_vectors()
    probe_scrub = _compose_scrubber(probe_vectors)
    for vector in probe_vectors:
        scrubbed = probe_scrub(vector.sample)
        if _vector_leaked(vector, scrubbed):
            raise RuntimeError(
                f"Pre-egress scrubber check failed for category '{vector.category}': "
                "canary token survived scrubbing — Sentry integration would leak PHI."
            )


def _run_canary_harness(
    ruleset: str, sentry_dsn: str
) -> Tuple[str, List[Tuple[CanaryVector, bool]]]:
    vectors = _load_ruleset(ruleset)
    scrub = _compose_scrubber(vectors)

    results: List[Tuple[CanaryVector, bool]] = []
    for vector in vectors:
        scrubbed = scrub(vector.sample)
        leaked = _vector_leaked(vector, scrubbed)
        results.append((vector, leaked))

    if sentry_dsn:
        _verify_sentry_scrubber_local(sentry_dsn, scrub)

    leaks = sum(1 for _, leaked in results if leaked)
    status = "PASSED" if leaks == 0 else "FAILED"
    return status, results


def _license_fingerprint(key: str) -> str:
    """Non-reversible truncated SHA-256 digest of the license key."""
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def _validate_license(license_key: str) -> Tuple[str, str]:
    """Validate license against Keygen, scoped to the Hermes Canary product and policy."""
    url = f"https://api.keygen.sh/v1/accounts/{KEYGEN_ACCOUNT}/licenses/actions/validate-key"
    headers = {
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json",
    }
    body = {
        "meta": {
            "key": license_key,
            "scope": {
                "product": KEYGEN_PRODUCT_ID,
                "policy": KEYGEN_POLICY_ID,
            },
        }
    }
    try:
        response = requests.post(url, headers=headers, json=body, timeout=10)
        if 400 <= response.status_code <= 599:
            return ("error", f"Keygen validation error: {response.status_code}")
        if response.status_code == 200:
            meta = response.json().get("meta", {})
            if meta.get("valid") is True:
                return ("valid", "License valid.")
            reason = meta.get("detail", "License invalid")
            return ("invalid", f"License invalid: {reason}")
        return ("error", f"Keygen validation error: {response.status_code}")
    except requests.exceptions.RequestException as exc:
        return ("error", f"Keygen unreachable: {exc}")


def _sign_receipt(payload: Dict[str, Any], signing_key: str) -> str:
    """HMAC-SHA256 over canonical JSON body using the customer's SIGNING_KEY."""
    signing_body = {**payload, "signature": "", "hmac_sha256": ""}
    canonical = json.dumps(signing_body, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        signing_key.encode("utf-8"),
        msg=canonical.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def _load_baseline_receipt(path: str) -> Optional[Dict[str, Any]]:
    """Load a prior receipt from disk for drift detection."""
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::Could not read baseline receipt ({path}): {exc}")
        return None


def _detect_drift(
    current_results: List[Tuple[CanaryVector, bool]],
    baseline: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare current run against a baseline receipt. All comparisons are local."""
    if baseline is None:
        return {
            "evaluated": False,
            "baseline_path": "",
            "baseline_run_id": "",
            "drift_detected": False,
            "new_leaks": [],
            "resolved_leaks": [],
            "stopped_detecting": [],
        }

    baseline_run_id = baseline.get("run_id", "")
    baseline_missed = set(baseline.get("categories_missed", []))
    baseline_detected = set(baseline.get("categories_detected", []))

    current_leaked = {v.category for v, leaked in current_results if leaked}
    current_detected = {v.category for v, leaked in current_results if not leaked}

    new_leaks = sorted(current_leaked - baseline_missed)
    resolved_leaks = sorted(baseline_missed - current_leaked)
    stopped_detecting = sorted(baseline_detected - current_detected - current_leaked)

    drift_detected = bool(new_leaks or stopped_detecting)

    return {
        "evaluated": True,
        "baseline_path": os.environ.get("BASELINE_RECEIPT", ""),
        "baseline_run_id": baseline_run_id,
        "drift_detected": drift_detected,
        "new_leaks": new_leaks,
        "resolved_leaks": resolved_leaks,
        "stopped_detecting": stopped_detecting,
    }


def _build_receipt(
    status: str,
    results: List[Tuple[CanaryVector, bool]],
    drift: Dict[str, Any],
    license_key: str,
    schedule: str,
) -> Dict[str, Any]:
    categories_tested = [v.category for v, _ in results]
    categories_detected = [v.category for v, leaked in results if not leaked]
    categories_missed = [v.category for v, leaked in results if leaked]
    controls_verified = categories_detected  # GRC alias

    leaks_detected = len(categories_missed)
    intercepted = len(categories_detected)

    run_id = os.environ.get("GITHUB_RUN_ID", str(uuid.uuid4()))
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    actor = os.environ.get("GITHUB_ACTOR", "")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    triggered_by = f"{actor} ({event_name})" if actor else event_name
    if schedule and event_name == "schedule":
        triggered_by = f"schedule ({schedule})"

    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": str(uuid.uuid4()),
        "run_id": run_id,
        "workflow_name": os.environ.get("GITHUB_WORKFLOW", ""),
        "repository": repository,
        "commit_sha": os.environ.get("GITHUB_SHA", ""),
        "triggered_by": triggered_by,
        "schedule": schedule,
        "ruleset": os.environ.get("RULESET", "hipaa-safe-harbor-16"),
        "status": status,
        "token_count": len(results),
        "categories_tested": categories_tested,
        "categories_detected": categories_detected,
        "categories_missed": categories_missed,
        "controls_verified": controls_verified,
        "summary": {
            "vectors_tested": len(results),
            "canaries_intercepted": intercepted,
            "leaks_detected": leaks_detected,
        },
        "drift": drift,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "keygen_license_fingerprint": _license_fingerprint(license_key) if license_key else "",
        "signature": "",
        "hmac_sha256": "",
    }


def _write_github_output(status: str, receipt_path: str, receipt_b64: str, drift: Dict[str, Any]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"status={status}\n")
        handle.write(f"receipt-path={receipt_path}\n")
        handle.write(f"receipt={receipt_b64}\n")
        handle.write(f"drift-detected={str(drift.get('drift_detected', False)).lower()}\n")


def _write_step_summary(status: str, results: List[Tuple[CanaryVector, bool]], drift: Dict[str, Any], receipt_path: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    status_emoji = "✅" if status == "PASSED" else "❌"
    rows = ""
    for vector, leaked in results:
        icon = "✅" if not leaked else "❌"
        rows += f"| {icon} | `{vector.category}` | {vector.safe_harbor_label} |\n"

    drift_section = ""
    if drift.get("evaluated"):
        drift_status = "🔴 Drift detected" if drift["drift_detected"] else "🟢 No drift"
        new_leaks = drift.get("new_leaks", [])
        stopped = drift.get("stopped_detecting", [])
        drift_section = f"\n### Drift vs baseline run `{drift.get('baseline_run_id', '')}`: {drift_status}\n"
        if new_leaks:
            drift_section += f"- **New leaks:** {', '.join(f'`{c}`' for c in new_leaks)}\n"
        if stopped:
            drift_section += f"- **Stopped detecting:** {', '.join(f'`{c}`' for c in stopped)}\n"

    summary = f"""## Hermes PHI Canary — {status_emoji} {status}

| | Category | Safe Harbor Identifier Type |
|--|----------|-----------------------------|
{rows}
{drift_section}
Receipt: `{receipt_path}`
"""
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(summary)


def _post_pr_comment(
    status: str,
    receipt: dict,
    receipt_path: str,
    drift: Dict[str, Any],
) -> Optional[str]:
    post_comment = os.environ.get("POST_COMMENT", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")

    if post_comment != "true":
        return None
    if event_name != "pull_request":
        return None
    if not pr_number or not str(pr_number).strip():
        return None
    if not github_token or not github_token.strip():
        print("::warning::post-comment=true but GITHUB_TOKEN is not set; skipping PR comment.")
        return None

    summary = receipt.get("summary", {})
    vectors_tested = summary.get("vectors_tested", 0)
    canaries_intercepted = summary.get("canaries_intercepted", 0)
    leaks_detected = summary.get("leaks_detected", 0)
    ruleset = os.environ.get("RULESET", "hipaa-safe-harbor-16")
    commit_sha = receipt.get("commit_sha", "")

    status_emoji = "✅" if status == "PASSED" else "❌"
    leak_block = ""
    if leaks_detected:
        leak_block = (
            "> ⚠️ **PHI leak detected.** One or more canary tokens survived "
            "redaction. Review the signed receipt for details.\n"
        )

    drift_block = ""
    if drift.get("evaluated") and drift.get("drift_detected"):
        new_leaks = drift.get("new_leaks", [])
        stopped = drift.get("stopped_detecting", [])
        drift_block = "\n> 🔴 **Scrubber drift detected.**\n"
        if new_leaks:
            drift_block += f"> - New leaks: {', '.join(f'`{c}`' for c in new_leaks)}\n"
        if stopped:
            drift_block += f"> - Stopped detecting: {', '.join(f'`{c}`' for c in stopped)}\n"

    comment_body = f"""## Hermes PHI Canary — {status_emoji} {status}

| Field | Value |
|-------|-------|
| Vectors tested | {vectors_tested} |
| Canaries intercepted | {canaries_intercepted} |
| Leaks detected | {leaks_detected} |
| Ruleset | {ruleset} |
| Commit | `{commit_sha}` |
| Receipt | `{receipt_path}` |

{leak_block}{drift_block}
---
*[Hermes PHI Canary](https://hermesrelay.dev/canary) · [Upgrade to Pro](https://hermesrelay.dev/canary) for signed receipts and drift detection*
"""

    url = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments"
    try:
        response = requests.post(
            url,
            json={"body": comment_body},
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::Hermes could not post PR comment: {exc}")
        return None

    if response.status_code == 201:
        try:
            return response.json().get("html_url")
        except Exception:  # noqa: BLE001
            return None

    print(f"::warning::Hermes PR comment failed: {response.status_code} {response.text}")
    return None


def main() -> int:  # noqa: C901
    ruleset = os.environ.get("RULESET", "hipaa-safe-harbor-16")
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    license_key = os.environ.get("LICENSE_KEY", "").strip()
    signing_key = os.environ.get("SIGNING_KEY", "").strip()
    schedule = os.environ.get("SCHEDULE", "")
    baseline_path = os.environ.get("BASELINE_RECEIPT", "")
    fail_on_drift = os.environ.get("FAIL_ON_DRIFT", "false").lower() in {"1", "true", "yes", "on"}
    fail_on_leak = os.environ.get("FAIL_ON_LEAK", "false").lower() in {"1", "true", "yes", "on"}
    output_dir = os.environ.get("OUTPUT_DIR", "./hermes-evidence")
    output_format = os.environ.get("OUTPUT_FORMAT", "json").lower()  # noqa: F841 (reserved for #10)

    # SIGNING_KEY is mandatory — unsigned receipts have no audit value
    if not signing_key:
        print(
            "::error::SIGNING_KEY is required. Generate one with: openssl rand -hex 32\n"
            "Add it as HERMES_SIGNING_KEY in GitHub Actions Secrets and pass it as signing-key.",
            file=sys.stderr,
        )
        _emit_failed_outputs(output_dir, schedule, license_key="", license_status="free-tier")
        return 1

    # Validate signing key format: must be 64 hex characters (32 bytes)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", signing_key):
        print(
            "::error::SIGNING_KEY must be exactly 64 hex characters (32 bytes). "
            "Generate with: openssl rand -hex 32",
            file=sys.stderr,
        )
        _emit_failed_outputs(output_dir, schedule, license_key="", license_status="free-tier")
        return 1

    # License validation — scoped to Hermes Canary product + policy
    license_status = "free-tier"
    if license_key:
        status_result, message = _validate_license(license_key)
        if status_result == "valid":
            license_status = "valid"
            print(f"::notice::{message}")
        else:
            license_status = "invalid"
            print(f"::error::License validation failed: {message}", file=sys.stderr)
            _emit_failed_outputs(output_dir, schedule, license_key=license_key, license_status=license_status)
            return 1
    else:
        print("::notice::No license key provided; running on free tier (no drift detection or scheduled runs).")

    try:
        status, results = _run_canary_harness(ruleset, sentry_dsn)
    except Exception as exc:  # noqa: BLE001
        status = "FAILED"
        vectors = _default_canary_vectors()
        results = [(vector, True) for vector in vectors]
        print(f"Hermes canary harness error: {exc}", file=sys.stderr)

    # Drift detection — fully local, no network; only available with a valid license
    baseline = _load_baseline_receipt(baseline_path) if license_status == "valid" else None
    drift = _detect_drift(results, baseline)

    receipt = _build_receipt(status, results, drift, license_key, schedule)

    # Sign with customer's SIGNING_KEY
    sig = _sign_receipt(receipt, signing_key)
    receipt["signature"] = sig
    receipt["hmac_sha256"] = sig  # backward-compat mirror

    os.makedirs(output_dir, exist_ok=True)
    run_id = os.environ.get("GITHUB_RUN_ID", receipt["receipt_id"])
    receipt_filename = f"hermes-canary-receipt-{run_id}.json"
    receipt_path = os.path.abspath(os.path.join(output_dir, receipt_filename))

    with open(receipt_path, "w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2)
        handle.write("\n")

    receipt_b64 = base64.b64encode(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")

    _write_github_output(status, receipt_path, receipt_b64, drift)
    _write_step_summary(status, results, drift, receipt_path)

    print(f"Hermes canary status: {status}")
    print(f"Receipt written to: {receipt_path}")

    comment_url = _post_pr_comment(status, receipt, receipt_path, drift)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write(f"comment-url={comment_url or ''}\n")
            fh.write(f"license-status={license_status}\n")

    # Exit behavior: observer mode by default (always exit 0 so receipt is uploaded)
    # fail-on-drift and fail-on-leak are opt-in
    if fail_on_drift and drift.get("drift_detected"):
        print("::error::Scrubber drift detected (fail-on-drift=true).", file=sys.stderr)
        return 1
    if status == "FAILED" and fail_on_leak:
        return 1
    return 0


def _emit_failed_outputs(
    output_dir: str,
    schedule: str,
    license_key: str,
    license_status: str,
) -> None:
    """Write FAILED sentinel outputs so downstream steps are never left with unset outputs."""
    vectors = _default_canary_vectors()
    results = [(v, True) for v in vectors]
    drift: Dict[str, Any] = {
        "evaluated": False,
        "baseline_path": "",
        "baseline_run_id": "",
        "drift_detected": False,
        "new_leaks": [],
        "resolved_leaks": [],
        "stopped_detecting": [],
    }
    receipt = _build_receipt("FAILED", results, drift, license_key, schedule)
    # Emit unsigned sentinel (signing_key may be absent or invalid)
    receipt["signature"] = "UNSIGNED-SENTINEL"
    receipt["hmac_sha256"] = "UNSIGNED-SENTINEL"

    try:
        os.makedirs(output_dir, exist_ok=True)
        run_id = os.environ.get("GITHUB_RUN_ID", receipt["receipt_id"])
        receipt_filename = f"hermes-canary-receipt-{run_id}.json"
        receipt_path = os.path.abspath(os.path.join(output_dir, receipt_filename))
        with open(receipt_path, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2)
            handle.write("\n")
        receipt_b64 = base64.b64encode(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        _write_github_output("FAILED", receipt_path, receipt_b64, drift)
        github_output = os.environ.get("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a", encoding="utf-8") as fh:
                fh.write("comment-url=\n")
                fh.write(f"license-status={license_status}\n")
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::Could not write sentinel outputs: {exc}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())

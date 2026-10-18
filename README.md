![HIPAA](https://img.shields.io/badge/HIPAA-Safe%20Harbor%2016-blue) ![License](https://img.shields.io/github/license/g1n0mag1k/hermes-canary-action) ![GitHub Actions](https://img.shields.io/badge/GitHub%20Action-ready-green)

# hermes-canary-action

Zero-PHI-egress synthetic PHI canary tests and tamper-evident compliance receipts for healthtech CI/CD pipelines. Drop this composite GitHub Action into your workflow to verify that error monitoring scrubbers (for example Sentry `before_send`, Relay processors, or Drata CCT-linked policies) redact all **16 HIPAA Safe Harbor** identifier categories before telemetry leaves your boundary.

## How zero-PHI-egress canary mechanics work

Traditional PHI tests often require copying realistic patient data into staging or sending payloads to third-party observability vendors. That increases breach surface and complicates BAA scope.

Hermes uses **synthetic canaries** only: fixed, obviously fake Safe Harbor patterns (names, MRNs, SSN-shaped strings, and so on) embedded in a controlled harness. The runner:

1. **Materializes** one vector per Safe Harbor category (16 total).
2. **Applies** the selected scrubber ruleset (`hipaa-safe-harbor-16` by default) the same way an in-process or Sentry-side scrubber should.
3. **Detects leaks** if any raw canary token survives redaction.
4. **Optionally validates Sentry DSN** by scrubbing *before* any network call; only redacted probe metadata is emitted when a DSN is configured.
5. **Writes a cryptographic receipt** (JSON) to your workspace for auditors, GRC tools, or Hermes Relay Pro.

No real patient data is used. Canary strings never leave the runner in cleartext when scrubbing succeeds.

### Safe Harbor categories exercised

| # | Category | Example canary shape |
|---|----------|----------------------|
| 1 | Names | `Patient: Jane Q. Public` |
| 2 | Dates | `03/15/2024`, ISO dates |
| 3 | Phone numbers | `(415) 555-0199` |
| 4 | Fax | `Fax: 415-555-0100` |
| 5 | Email | `user@example-clinic.org` |
| 6 | SSN | `123-45-6789` |
| 7 | MRN | `MRN: 0049281736` |
| 8 | Health plan IDs | `PLAN# HPLN…` |
| 9 | Account numbers | `ACCT# …` |
| 10 | License numbers | `LIC# CA-MED-…` |
| 11 | VINs | 17-character VIN |
| 12 | Device serials | `SERIAL SN-…` |
| 13 | Web URLs | `https://…` |
| 14 | IP addresses | IPv4 literals |
| 15 | Biometric IDs | `BIO#` hex templates |
| 16 | Full-face photos | `photo: data:image/…` markers |

## Free tier

- Full 16-category synthetic Safe Harbor canary harness
- Local JSON compliance receipts on every run
- PR comment with pass/fail summary

## Quick start

```yaml
name: PHI scrubber canary

on:
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 06:00 UTC

jobs:
  hermes-canary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Hermes PHI canary
        uses: g1n0mag1k/hermes-canary-action@v1
        with:
          sentry-dsn: ${{ secrets.SENTRY_DSN }}
          ruleset: hipaa-safe-harbor-16
          fail-on-leak: 'true'
          output-dir: ./hermes-evidence

      - name: Upload compliance receipt
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: hermes-receipt
          path: ./hermes-evidence/*.json
```

### PR comment

When triggered on a pull request, Hermes posts a pass/fail summary comment automatically (requires `pull-requests: write` permission). Set `post-comment: 'false'` to disable.

## Hermes Relay Pro and Drata CCT syncing

When you attach a **Hermes Relay Pro** license key, the action signs every receipt with **HMAC-SHA256**. Drata (and similar GRC platforms) can ingest those signed receipts via CCT sync to prove continuous scrubber verification tied to `repository` and `commit_sha`.

```yaml
      - name: Run Hermes PHI canary (Pro)
        id: canary
        uses: g1n0mag1k/hermes-canary-action@v1
        with:
          signing-key: ${{ secrets.HERMES_SIGNING_KEY }}
          license-key: ${{ secrets.HERMES_LICENSE_KEY }}
          ruleset: hipaa-safe-harbor-16
          fail-on-leak: 'true'
          output-dir: ./hermes-evidence

      - name: Surface receipt path
        run: echo "Receipt at ${{ steps.canary.outputs.receipt-path }}"
```

## Pro license validation

When `license-key` is set, Hermes validates it against the Keygen.sh license API before running:

```
POST https://api.keygen.sh/v1/accounts/rogersandy90/licenses/actions/validate-key
```

An invalid or expired key falls back to **free-tier mode** — the canary harness still runs and the receipt is still signed with `signing-key`, but drift detection and Pro outputs are disabled. The `license-status` output reports one of: `valid`, `invalid`, `error`, or `free-tier`.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `signing-key` | **Yes** | — | 64-hex-char HMAC-SHA256 signing key. Generate: `openssl rand -hex 32`. Store as `HERMES_SIGNING_KEY` secret. |
| `license-key` | No | `''` | Keygen.sh Pro license key for drift detection and Pro features. Store as `HERMES_LICENSE_KEY` secret. |
| `sentry-dsn` | No | `''` | Sentry project DSN. The harness performs local pre-egress scrubber verification only; no data is sent to Sentry. |
| `ruleset` | No | `hipaa-safe-harbor-16` | Scrubber ruleset identifier. Currently only `hipaa-safe-harbor-16` is supported. |
| `schedule` | No | `''` | Cron expression for scheduled runs (e.g. `0 6 * * 1`). Recorded in the receipt for audit trail. |
| `baseline-receipt` | No | `''` | Path to a prior `hermes-canary-receipt-*.json` for drift detection (Pro). |
| `fail-on-drift` | No | `false` | Exit non-zero when scrubber drift is detected against the baseline (Pro). |
| `fail-on-leak` | No | `false` | Exit non-zero when any PHI canary token survives scrubbing. |
| `output-dir` | No | `./hermes-evidence` | Directory where the signed JSON receipt is written. |
| `output-format` | No | `json` | Receipt output format — `json`, `summary`, or `both`. |
| `post-comment` | No | `true` | Post a pass/fail summary comment to the pull request. Requires `pull-requests: write`. |

## Outputs

| Output | Description |
|--------|-------------|
| `status` | `PASSED` or `FAILED` based on canary harness outcome. |
| `receipt-path` | Absolute path to the signed JSON receipt on the runner. |
| `receipt` | Base64-encoded signed receipt JSON for downstream GRC gates. |
| `drift-detected` | Whether scrubber drift was detected against the baseline (`true`/`false`). |
| `comment-url` | URL of the pull request comment posted by Hermes, if any. |
| `license-status` | Keygen license validation result: `valid`, `invalid`, `error`, or `free-tier`. |

## Receipt schema

Every run writes a signed JSON receipt to `output-dir` (default `./hermes-evidence`). The `signature` and `hmac_sha256` fields contain the HMAC-SHA256 over the canonical receipt body (both fields set to `""` before hashing). The `signed` field is `true` once the signature is written.

```json
{
  "schema_version": "1.0",
  "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
  "run_id": "12345678901",
  "workflow_name": "CI",
  "repository": "your-org/your-repo",
  "commit_sha": "abc123def456abc123def456abc123def456abc123",
  "triggered_by": "octocat (push)",
  "schedule": "",
  "ruleset": "hipaa-safe-harbor-16",
  "status": "PASSED",
  "token_count": 16,
  "categories_tested": [
    "names", "dates", "phone_numbers", "fax", "email", "ssn",
    "mrn", "health_plan_ids", "account_numbers", "license_numbers",
    "vins", "device_serials", "web_urls", "ip_addresses",
    "biometric_ids", "full_face_photos"
  ],
  "categories_detected": [
    "names", "dates", "phone_numbers", "fax", "email", "ssn",
    "mrn", "health_plan_ids", "account_numbers", "license_numbers",
    "vins", "device_serials", "web_urls", "ip_addresses",
    "biometric_ids", "full_face_photos"
  ],
  "categories_missed": [],
  "controls_verified": [
    "names", "dates", "phone_numbers", "fax", "email", "ssn",
    "mrn", "health_plan_ids", "account_numbers", "license_numbers",
    "vins", "device_serials", "web_urls", "ip_addresses",
    "biometric_ids", "full_face_photos"
  ],
  "summary": {
    "vectors_tested": 16,
    "canaries_intercepted": 16,
    "leaks_detected": 0
  },
  "drift": {
    "evaluated": false,
    "baseline_path": "",
    "baseline_run_id": "",
    "drift_detected": false,
    "new_leaks": [],
    "resolved_leaks": [],
    "stopped_detecting": []
  },
  "timestamp": "2026-10-02T06:00:00Z",
  "keygen_license_fingerprint": "",
  "signed": true,
  "signature": "a1b2c3d4e5f6...",
  "hmac_sha256": "a1b2c3d4e5f6..."
}
```

## Verifying a receipt

Use the bundled verifier script:

```bash
python scripts/verify_receipt.py hermes-evidence/hermes-canary-receipt-*.json "$HERMES_SIGNING_KEY"
```

Or verify programmatically — **both `"signature"` and `"hmac_sha256"` must be zeroed before hashing**:

```python
import hmac, hashlib, json

def verify_receipt(receipt: dict, signing_key: str) -> bool:
    # Zero BOTH signature fields before computing the canonical body
    body = {**receipt, "signature": "", "hmac_sha256": ""}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    expected = hmac.new(
        signing_key.encode("utf-8"),   # raw UTF-8 key — NOT hex-decoded bytes
        msg=canonical.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, receipt.get("signature", ""))
```

## Local development

```bash
python3 -m pip install -r requirements.txt
export SIGNING_KEY=$(openssl rand -hex 32)   # generate a local test key
export RULESET=hipaa-safe-harbor-16
export OUTPUT_DIR=./hermes-evidence
export FAIL_ON_LEAK=false
python3 entrypoint.py
```

## License

Open source — see repository license file for terms.

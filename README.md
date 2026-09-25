# hermes-canary-action

Zero-egress synthetic PHI canary tests and tamper-evident compliance receipts for healthtech CI/CD pipelines. Drop this composite GitHub Action into your workflow to verify that error monitoring scrubbers (for example Sentry `before_send`, Relay processors, or Drata CCT-linked policies) redact all **16 HIPAA Safe Harbor** identifier categories before telemetry leaves your boundary.

## How zero-egress canary mechanics work

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
        uses: your-org/hermes-canary-action@v1
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

## Hermes Relay Pro and Drata CCT syncing

When you attach a **Hermes Relay Pro** API key, the action signs the receipt with **HMAC-SHA256** and POSTs it to Hermes Relay. Drata (and similar GRC platforms) can ingest those receipts via CCT sync to prove continuous scrubber verification tied to `repository` and `commit_sha`.

```yaml
      - name: Run Hermes PHI canary (Relay Pro)
        id: canary
        uses: your-org/hermes-canary-action@v1
        with:
          sentry-dsn: ${{ secrets.SENTRY_DSN }}
          hermes-api-key: ${{ secrets.HERMES_API_KEY }}
          output-dir: ./hermes-evidence

      - name: Surface receipt path
        run: echo "Receipt at ${{ steps.canary.outputs.receipt-path }}"
```

Telemetry endpoint: `POST https://api.hermesrelay.dev/v1/telemetry/receipt`  
Header: `X-Hermes-Signature-256` — HMAC-SHA256 of the canonical JSON body using `hermes-api-key` as the secret.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `sentry-dsn` | No | `''` | Sentry project DSN for optional scrubber reachability checks. Payloads are redacted before egress. |
| `hermes-api-key` | No | `''` | Hermes Relay API key. When set, uploads a signed receipt to Hermes telemetry. |
| `ruleset` | No | `hipaa-safe-harbor-16` | Scrubber ruleset identifier to execute. |
| `fail-on-leak` | No | `true` | When `true`, the action exits with code `1` if any leak is detected. |
| `output-dir` | No | `./hermes-evidence` | Directory for JSON receipts. |

## Outputs

| Output | Description |
|--------|-------------|
| `status` | `PASSED` or `FAILED` based on canary harness outcome. |
| `receipt-path` | Absolute path to the generated receipt file on the runner. |

## Receipt schema

Each run writes `{output-dir}/{timestamp}_{receipt_id}.json`:

```json
{
  "receipt_id": "rcpt-<12-hex-characters>",
  "timestamp": "<ISO-8601-UTC-timestamp>",
  "repository": "<GITHUB_REPOSITORY>",
  "commit_sha": "<GITHUB_SHA>",
  "status": "PASSED",
  "controls_verified": [
    "HIPAA-164.312-e-1",
    "SOC2-CC6.1"
  ],
  "summary": {
    "vectors_tested": 16,
    "canaries_intercepted": 16,
    "leaks_detected": 0
  }
}
```

Receipts are suitable as evidence for HIPAA **164.312(e)(1)** transmission integrity and SOC 2 **CC6.1** logical access / data protection control testing when paired with your scrubber configuration.

## Local development

```bash
python3 -m pip install -r requirements.txt
export RULESET=hipaa-safe-harbor-16
export OUTPUT_DIR=./hermes-evidence
python3 entrypoint.py
```

## License

Open source — see repository license file for terms.

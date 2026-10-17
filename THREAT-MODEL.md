# Threat Model — Hermes PHI Canary

## What this action does

1. Validates the customer's `license-key` against Keygen.sh (`api.keygen.sh`) scoped to the Hermes Canary Pro product and policy, exiting non-zero if absent or invalid.
2. Verifies that a cryptographic `signing-key` is present in the runner environment before executing, raising an explicit error if absent.
3. Dynamically materializes 16 randomized synthetic HIPAA Safe Harbor canary tokens per run using `secrets.SystemRandom` (zero real patient data, zero static tokens).
4. Applies the configured scrubber ruleset locally on the GitHub Actions runner and detects whether any raw canary token survives redaction.
5. Optionally compares the current run's category detection results against a prior receipt (`baseline-receipt`) on the runner to detect scrubber drift (`new_leaks`, `stopped_detecting`, `resolved_leaks`).
6. Signs the canonical JSON receipt locally using HMAC-SHA256 with the customer's `signing-key`, writes `hermes-canary-receipt-{run_id}.json` to `output-dir`, exports the base64-encoded receipt to `$GITHUB_OUTPUT`, and writes a Markdown report to `$GITHUB_STEP_SUMMARY`.

## Trust boundaries

| Boundary | What crosses it | What does not cross it |
|----------|----------------|------------------------|
| Runner → Keygen.sh (`api.keygen.sh`) | `license-key`, product ID, policy ID for license validation | `signing-key`, canary tokens, receipt contents, repository code |
| Runner → GitHub API (`api.github.com`, optional) | Pass/fail summary table on PR comment (when `post-comment: 'true'` on `pull_request` events) | Raw canary tokens, `license-key`, `signing-key` |
| Runner → Customer GitHub Workspace / Outputs | Signed `hermes-canary-receipt-{run_id}.json`, base64 receipt in `$GITHUB_OUTPUT`, table in `$GITHUB_STEP_SUMMARY` | Raw unredacted canary strings |

## What the publisher receives

The publisher receives **zero telemetry, zero receipts, zero customer payload data, zero PHI, and zero signing keys** from action runs. Only Keygen.sh receives the license validation request over TLS during startup.

## Zero-PHI-egress guarantee

Canary strings are dynamically randomized synthetic tokens and do not meet the HIPAA definition of PHI under **45 CFR § 160.103**. No canary test logic makes external network calls. When `sentry-dsn` is provided, the harness performs local DSN syntax verification and pre-egress scrubber verification without transmitting canary probes over the network. Customers remain responsible for ensuring their CI workflow does not route production ePHI into test runners.

## Secret handling

- `license-key` (`LICENSE_KEY`) and `signing-key` (`SIGNING_KEY`) are passed as environment variables to the Python process.
- Neither secret is ever logged or written in cleartext to the JSON receipt, `$GITHUB_OUTPUT`, or `$GITHUB_STEP_SUMMARY`.
- The receipt stores only a truncated non-reversible SHA-256 digest of the license key (`keygen_license_fingerprint`, format `sha256:<16-hex-chars>`).
- In `netlify/functions/stripe-webhook.js`, webhook signatures are verified with `STRIPE_WEBHOOK_SECRET`, and logs record only the Stripe event type, customer email, and Keygen license ID — never the license key value or raw webhook payload.

## Signing

Every receipt is signed locally with HMAC-SHA256 using `signing-key` as the secret over the canonical JSON body (`sort_keys=True, separators=(",", ":")` with `signature` and `hmac_sha256` set to `""`). The resulting hex digest is written to `signature` (and mirrored to `hmac_sha256` for backward compatibility). Verifiers within the customer's organization can re-derive the signature using their `signing-key` to confirm the receipt was not altered after the run.

## Observer mode & exit behavior

- If `signing-key` is missing, the Action fails fast with a non-zero exit code and an actionable error message.
- If `license-key` is provided and invalid, the Action fails fast with a non-zero exit code.
- Once authenticated, the Action operates as a non-blocking compliance observer: it exits `0` even when synthetic PHI leaks are detected so the signed receipt is always emitted and uploaded for audit evidence, unless the caller explicitly sets `fail-on-drift: 'true'` and drift is detected against `baseline-receipt`, or sets `fail-on-leak: 'true'`.

## Out of scope

- Control design, BAA scope, and compliance program decisions remain the customer's responsibility.
- Hermes does not certify HIPAA compliance or SOC 2 conformance.

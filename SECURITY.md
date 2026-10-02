# Security Policy

## Reporting a Vulnerability

Contact: security@hermesrelay.dev

Response SLA: Acknowledgment within 48 hours, initial assessment within 7 days, patch target within 30 days for confirmed high/critical issues.

Do not open a public GitHub issue for security vulnerabilities.

## Data Handling

- Hermes Canary Action uses only fully synthetic data that does not meet the HIPAA definition of PHI under 45 CFR 160.103. No real patient data is processed.
- The synthetic canary suite exercises the 16 HIPAA Safe Harbor identifier categories and produces local compliance receipts that support HIPAA **164.312(b)** (audit controls) evidence collection and **164.316(b)** documentation of scrubber verification procedures. This is not a certification and does not constitute a business associate agreement.
- When no optional egress inputs are configured (no Hermes API key, no Sentry DSN, no Datadog keys), no data leaves the GitHub Actions runner.
- When a Hermes API key is provided (Pro tier), a signed JSON receipt — containing repository name, commit SHA, run timestamp, status, and test-result summary — is transmitted to api.hermesrelay.dev. No canary payload content is included in the transmission.
- When a Sentry DSN is provided, a scrubbed probe message (containing no raw canary token) is sent to the customer's configured Sentry endpoint. This is egress to Sentry's or the customer's own Sentry infrastructure, not to Hermes.
- When Datadog keys are provided (Pro tier), synthetic log events containing canary tokens are sent to the customer's Datadog account. Hermes does not retain a copy.

## Permissions

This action requires only: `pull-requests: write` (for PR comments). It does not require `contents: write`, `secrets: read`, or any other elevated permission.

## Supply Chain

Pin to a full commit SHA:

```yaml
uses: g1n0mag1k/hermes-canary-action@{SHA}
```

All releases are tagged and the SHA is documented in [RELEASING.md](./RELEASING.md) and [RELEASES.md](./RELEASES.md).

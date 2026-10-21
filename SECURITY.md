# Security Policy

## Supported versions

| Version | Supported |
|---------|----------|
| `main` (latest) | ✅ |
| `v1` tag | ✅ |
| Older tags | ❌ |

## Reporting a vulnerability

Email **security@hermesrelay.dev** with:

- A description of the issue
- Steps to reproduce
- Affected versions

You will receive acknowledgment within **48 hours** and a status update within **7 days**. Please do not open a public GitHub issue for security vulnerabilities.

## Scope

This policy covers the `hermes-canary-action` GitHub Action repository, `entrypoint.py` execution harness, and the license provisioning webhook (`netlify/functions/stripe-webhook.js`).

## Data handling (runner-local)

`hermes-canary-action` executes entirely inside the customer's GitHub Actions runner environment:

- **No publisher telemetry:** No customer source code, pipeline payloads, synthetic canary strings, or signed JSON receipts are transmitted to the publisher.
- **License validation only:** The runner contacts `https://api.keygen.sh` solely to validate the `license-key` against the Hermes Canary Pro product (`933323e7-e2f9-4ccb-9f13-b574cc38bf4e`) and policy (`b05916b2-3a72-4608-aeec-4246dd58e05d`). Only the SHA-256 fingerprint (`keygen_license_fingerprint`) is recorded in the receipt — the key value itself is never written anywhere.
- **Customer-owned signing key:** The cryptographic `signing-key` stays inside the customer's GitHub Actions secrets and is never transmitted over the network or logged. Receipts are tagged with HMAC-SHA256 using that key; anyone with the key can verify or forge the tag.
- **`sentry-dsn` input:** When provided, the DSN is parsed and validated for format only. No HTTP request is made to Sentry in this release.

See [THREAT-MODEL.md](./THREAT-MODEL.md) for full trust boundary documentation.

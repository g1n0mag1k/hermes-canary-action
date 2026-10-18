# GitHub Marketplace — Hermes PHI Canary

## Short description (≤ 300 characters)

Use in the Marketplace **Summary** field. Character count: **259**.

```text
Synthetic HIPAA Safe Harbor canary tests for CI/CD with zero PHI egress. Verifies all 16 scrubber categories and PR pass/fail. Pro adds signed receipts, drift detection, and Datadog checks—launch pricing $29/mo per repo on hermesrelay.dev, not GitHub billing.
```

---

## Full listing body

### Prove your scrubbers catch synthetic PHI—before real data leaks

Healthtech teams rely on Sentry, Datadog, and similar tools for incident response. Those pipelines sit on the boundary where a misconfigured `before_send` hook or log processor can ship identifiers into a vendor you may not have under BAA. Manual spot checks do not scale, and copying realistic patient data into staging for tests creates its own compliance risk.

**Hermes PHI Canary** is a composite GitHub Action that runs **synthetic** Safe Harbor canary vectors on every workflow trigger. No real patient data is used. When scrubbing succeeds, canary tokens never leave the runner in cleartext. Optional integrations validate remote scrubber behavior (for example Sentry DSN reachability with scrub-before-egress).

Each run exercises **all 16 HIPAA Safe Harbor identifier categories**—names, dates, phone and fax, email, SSN, MRN, health plan and account numbers, license numbers, VINs, device serials, URLs, IP addresses, biometric identifiers, and full-face photo markers—against your selected ruleset (`hipaa-safe-harbor-16` by default).

**Pro** subscribers get a **tamper-evident signed receipt** per run, drift detection against prior baselines, Datadog log intake validation, extended rulesets, and optional archival via Hermes Relay. **Free** tier includes the full 16-category canary harness and PR-friendly pass/fail signaling.

---

### Why this maps to HIPAA audit and evaluation expectations

Hermes is a **testing and documentation aid**, not a certification. It helps teams produce evidence that supports common Security Rule obligations:

| CFR reference | Theme | How Hermes helps |
|---------------|--------|------------------|
| **45 CFR 164.312(b)** | Audit controls | Repeated, automated canary runs create a timestamped record of scrubber behavior tied to repository and commit. |
| **45 CFR 164.316(b)** | Documentation | JSON receipts (Pro) and workflow artifacts document what was tested, when, and the outcome. |
| **45 CFR 164.308(a)(8)** | Evaluation | Scheduled and PR-triggered runs support periodic evaluation of technical safeguards without production PHI. |

Your assessor, counsel, and GRC platform still own control design and scope. Hermes gives engineers a repeatable way to **show** scrubber verification in CI/CD.

---

### How it works (zero-PHI-egress)

1. **Materialize** one synthetic vector per Safe Harbor category (16 total).
2. **Apply** the configured scrubber ruleset the same way in-process or vendor-side scrubbers should.
3. **Fail the job** when any canary survives redaction (`fail-on-leak`, default `true`).
4. **Optionally probe Sentry** using a DSN: payloads are scrubbed before network egress.
5. **Write evidence**: Every run writes a cryptographically signed JSON receipt to `output-dir` on the runner. **Pro** additionally enables drift detection against prior baselines and extended rulesets.

Receipts include `receipt_id`, UTC timestamp, `repository`, `commit_sha`, `status`, `controls_verified`, and a `summary` block (`vectors_tested`, `canaries_intercepted`, `leaks_detected`). See the repository README for the full schema.

---

### Quick start (two steps)

Add a job to your workflow:

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

- name: Run Hermes PHI canary
  uses: g1n0mag1k/hermes-canary-action@v1
  with:
    signing-key: ${{ secrets.HERMES_SIGNING_KEY }}
    ruleset: hipaa-safe-harbor-16
    fail-on-leak: 'true'
    output-dir: ./hermes-evidence
```

Optionally set `sentry-dsn` from secrets and `license-key: ${{ secrets.HERMES_LICENSE_KEY }}` for Pro drift detection. Upload `./hermes-evidence/*.json` as a workflow artifact for auditors.

---

### Plans and pricing

**Payment is processed on [hermesrelay.dev](https://hermesrelay.dev/canary)—not through GitHub Marketplace billing.** GitHub lists the Action; Pro subscription, license keys, and receipts are managed on Hermes Relay. **$29/month per repository** is **launch pricing** and may change; existing subscribers will be notified before increases.

| Feature | Free | Pro (launch pricing $29/mo per repo) |
|---------|------|--------------------------------------|
| 16 Safe Harbor canary tests | ✅ | ✅ |
| PR comment with results | ✅ | ✅ |
| Signed tamper-evident receipt | ❌ | ✅ |
| Drift detection | ❌ | ✅ |
| Datadog log intake validation | ❌ | ✅ |
| Extended rulesets | ❌ | ✅ |
| Hermes Relay receipt archive | ❌ | ✅ |

Subscribe at [hermesrelay.dev/canary](https://hermesrelay.dev/canary). After Stripe checkout, your license key appears on the Hermes dashboard — store it as `HERMES_LICENSE_KEY` in GitHub Secrets and pass it as the `license-key` input.

---

### Free tier install analytics (GitHub Insights)

The Free tier is installed directly from this repository or Marketplace without a Hermes account. To understand adoption:

1. Open the **hermes-canary-action** repository on GitHub.
2. Go to **Insights → Traffic** (or **Community → Traffic** depending on UI).
3. Review **GitHub Actions usage** / clone and referrer metrics alongside workflow forks referencing `uses: g1n0mag1k/hermes-canary-action@…`.

Marketplace install counts appear on the Action’s Marketplace page once published. Use these signals for launch traction; they do not replace Pro billing metrics in Stripe.

---

### Security and threat model

- [SECURITY.md](https://github.com/g1n0mag1k/hermes-canary-action/blob/main/SECURITY.md) — vulnerability reporting and supported versions.
- [THREAT-MODEL.md](https://github.com/g1n0mag1k/hermes-canary-action/blob/main/THREAT-MODEL.md) — trust boundaries, zero-PHI-egress guarantees, and Pro signing.

Questions: security@hermesrelay.dev

---

### Support

Documentation: repository README and [hermesrelay.dev/canary](https://hermesrelay.dev/canary). Pro customers: in-dashboard support contact after checkout.

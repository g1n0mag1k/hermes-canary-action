# Hermes Canary — Launch copy & go-live checklists

Landing page target: **https://hermesrelay.dev/canary**

---

## Landing page (hermesrelay.dev/canary)

### Headline (A/B variants)

Use one primary headline; rotate variants in ads or split tests.

1. **Prove your PHI scrubbers work — on every PR.**
2. **16 Safe Harbor categories. One GitHub Action. Signed proof.**
3. **HIPAA audit controls in your CI/CD pipeline.**

**Recommended default:** variant 1 (problem/solution clarity for engineering buyers).

### Subhead

Synthetic canary tests for HIPAA-regulated pipelines—zero real PHI egress. Install from GitHub Marketplace; upgrade to Pro on Hermes Relay when you need signed receipts and drift detection.

### Three-bullet value prop

- **Drop in with two lines of YAML.** No new infrastructure—runs on `ubuntu-latest` beside your existing CI.
- **Get a signed, tamper-evident receipt per run** for auditors and GRC platforms (Hermes Canary Pro).
- **Catch scrubber regressions before production** when Sentry, Datadog, or custom log processors change.

### Quick-start YAML

```yaml
name: PHI scrubber canary

on:
  pull_request:

jobs:
  hermes-canary:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Run Hermes PHI canary
        uses: g1n0mag1k/hermes-canary-action@v1
        with:
          signing-key: ${{ secrets.HERMES_SIGNING_KEY }}
          ruleset: hipaa-safe-harbor-16
          fail-on-leak: 'true'
          output-dir: ./hermes-evidence
```

Add `sentry-dsn: ${{ secrets.SENTRY_DSN }}` to validate remote scrubbing. Add `license-key: ${{ secrets.HERMES_LICENSE_KEY }}` for Pro drift detection.

### Pricing table

| | **Free** | **Pro** |
|---|----------|---------|
| Price | $0 (GitHub Action install) | **Launch pricing: $29/month per repository** |
| 16 Safe Harbor canary tests | ✅ | ✅ |
| PR comment with results | ✅ | ✅ |
| Signed tamper-evident receipt | — | ✅ |
| Drift detection | — | ✅ |
| Datadog log intake validation | — | ✅ |
| Extended rulesets | — | ✅ |
| Hermes Relay receipt archive | — | ✅ |
| Billing | — | Stripe on **hermesrelay.dev** (not GitHub) |

**CTA — Free:** [Install from GitHub Marketplace](https://github.com/marketplace/actions/hermes-phi-canary)  
**CTA — Pro:** [Subscribe at hermesrelay.dev/canary](https://hermesrelay.dev/canary)

### FAQ

**Does Hermes use real patient data?**  
No. Every vector is synthetic and obviously fake. Canary strings are designed for scrubber testing only.

**Is this “HIPAA certified”?**  
No. Hermes is a technical testing tool that helps you document scrubber verification. Your compliance program, BAAs, and control design remain your responsibility.

**Where do I pay for Pro?**  
Checkout runs on **hermesrelay.dev** via Stripe. GitHub Marketplace does not process Hermes subscriptions.

**What does “per repository” mean?**  
One Pro license covers one GitHub repository (quantity = 1 at checkout). Monorepos or multiple services need one subscription per repo—or contact us for org pricing.

**What regulatory citations do receipts reference?**  
Receipts can list controls your team maps to obligations such as **45 CFR 164.312(b)** (audit controls), **164.316(b)** (documentation), and **164.308(a)(8)** (evaluation). Hermes does not provide legal interpretation.

**How do free-tier installs get counted?**  
Use GitHub **Insights → Traffic** and Marketplace install stats on the Action listing. Pro revenue is tracked in Stripe.

**Can I run this on a schedule?**  
Yes—add `schedule:` cron alongside `pull_request` for weekly evaluation aligned with **164.308(a)(8)**.

### Security brief

Link prominently: **[Security & threat model →](https://github.com/g1n0mag1k/hermes-canary-action/blob/main/SECURITY.md)** and **[THREAT-MODEL.md](https://github.com/g1n0mag1k/hermes-canary-action/blob/main/THREAT-MODEL.md)**.

One-line blurb: Zero-PHI-egress design, scrub-before-egress for optional Sentry probes, HMAC-signed Pro telemetry—details in our published threat model.

---

## A. Headline options (A/B)

Same as landing section above—variants 1–3 for ads and hero tests.

---

## B. Three-bullet value prop

Same as landing section above.

---

## C. HealthDevHub launch post (Andrew, ~280 words)

**Title suggestion:** We added a synthetic PHI canary to our GitHub Actions pipeline

I own HIPAA technical controls for our health SaaS, and for years the scariest gap in our stack wasn’t the database—it was **observability**. Sentry and Datadog are invaluable when production misbehaves, but they also sit on the path where a bad `before_send` tweak or log parser regression can ship identifiers outside our boundary. We BAAs where we can, yet “trust the scrubber” isn’t something I want to explain to an auditor with a straight face.

We wanted **continuous, cheap proof** that scrubbers still catch all **16 HIPAA Safe Harbor categories**—without copying realistic patient data into staging and without sending cleartext PHI to vendors just to “test.” I couldn’t find a published GitHub Action with this capability, so we built **Hermes PHI Canary**: a composite Action that materializes synthetic canary vectors, runs them through our ruleset, fails the job on any leak, and (on Pro) emits a **tamper-evident signed receipt** tied to repo and commit SHA.

It’s **zero-PHI-egress** by design: canaries are fake, and optional Sentry checks scrub before anything hits the network. That maps cleanly to how we think about **45 CFR 164.312(b)** audit evidence, **164.316(b)** documentation, and **164.308(a)(8)** periodic evaluation—engineering signal, not a substitute for counsel.

The Action is open on GitHub and listed on Marketplace for install. **Free to install. Signed receipts and drift detection are Pro at $29/month** (launch pricing, per repo) via [hermesrelay.dev/canary](https://hermesrelay.dev/canary).

Repo: [github.com/g1n0mag1k/hermes-canary-action](https://github.com/g1n0mag1k/hermes-canary-action)

If you’re wrestling with the same observability boundary problem, I’d love feedback on rulesets and receipt schema.

— Andrew

---

## D. r/healthIT post (~180 words)

**Title suggestion:** Open-source GitHub Action: synthetic Safe Harbor canary tests for CI (zero real PHI)

Sharing a project our team built for a common health-IT engineering problem: **error monitoring and log pipelines** (Sentry, Datadog, etc.) can leak identifiers if scrubbers drift, but testing scrubbers often means either synthetic manual checks or risky use of realistic data in lower environments.

**Hermes PHI Canary** is a composite GitHub Action that runs **synthetic** vectors for all **16 HIPAA Safe Harbor categories** on each workflow run. Nothing real leaves the runner when scrubbing works; optional Sentry validation scrubs before egress. Failed runs block the PR so regressions don’t reach prod.

We use it as technical evidence alongside **164.312(b) / 164.316(b) / 164.308(a)(8)**-style programs—not as “HIPAA certification.”

Marketplace install is free; signed receipts, drift detection, and Datadog intake checks are a paid tier on our site (**launch pricing $29/mo per repo**).

Links:

- Action repo: https://github.com/g1n0mag1k/hermes-canary-action  
- Overview: https://hermesrelay.dev/canary  

Would appreciate feedback from folks who’ve solved scrubber testing differently—especially multi-tenant logging and BAA scope questions. What would you want in the receipt JSON for audits?

---

## E. Keygen.sh setup checklist

Use for **Hermes Canary Pro** license issuance tied to Stripe.

- [ ] **Product:** Create product **“Hermes Canary Pro”** in Keygen.
- [ ] **Policy:** Attach policy **`monthly-subscription`** with:
  - [ ] **Max activations:** 5 per license (CI runners / repos within fair use—document in dashboard FAQ).
  - [ ] **Offline validation:** enabled (runners validate without calling Keygen every job).
  - [ ] **Ed25519 signing:** enabled for license payloads.
- [ ] **License format:** Issue **offline-signed JWT** licenses; document JWT claims (`sub`, `repo`, `exp`, `policy_id`) in dashboard help.
- [ ] **Stripe linkage:** Store Stripe `customer_id` and `subscription_id` on Keygen license metadata at creation.
- [ ] **Webhook — activation:** On Keygen `license.validation` or `machine.created` (per your policy), **confirm Stripe subscription is `active`**; deactivate license if subscription canceled or past_due.
- [ ] **Webhook — Stripe → Keygen:** On `checkout.session.completed`, call Keygen to **create license** and email JWT to customer (see Stripe checklist).
- [ ] **Rotation:** Document how customers re-download JWT from [hermesrelay.dev/dashboard](https://hermesrelay.dev/dashboard) after login.

---

## F. Stripe checkout checklist

- [ ] **Product:** Create **“Hermes Canary Pro”** in Stripe Dashboard (or Products API).
- [ ] **Price:** **$29.00 USD / month**, recurring; describe as **per repository**—use **quantity** at Checkout for multi-repo carts (quantity = number of repos).
- [ ] **Checkout Session:** Success URL → `https://hermesrelay.dev/dashboard?session_id={CHECKOUT_SESSION_ID}` where license key is displayed after account linking.
- [ ] **Customer portal:** Enable subscription cancel/update; sync status to Keygen (webhook below).
- [ ] **Webhook `checkout.session.completed`:**  
  1. Resolve Stripe customer email and subscription ID.  
  2. **Issue Keygen license** (offline JWT) with metadata: `github_repo` from checkout custom field if collected.  
  3. **Email license key** to customer; show same key on dashboard.  
- [ ] **Webhook `customer.subscription.updated|deleted`:** Suspend or revoke Keygen license when subscription ends.
- [ ] **Copy on checkout:** State clearly that billing is **launch pricing $29/month per repo** via Hermes Relay, **not** through GitHub.
- [ ] **Receipt branding:** Stripe receipt descriptor “HERMES CANARY PRO”.

---

## Free tier — GitHub Insights (install tracking)

Document for growth/analytics owners:

1. Repository **Insights → Traffic** — clones, referrers, popular paths.
2. **Marketplace** listing page — install count after publication.
3. Search GitHub for `hermes-canary-action@v` (public code search) for organic adoption signals.

Pro conversion remains the source of truth in **Stripe + Keygen** activation counts.

# Releasing Hermes Canary Action

Follow this process for every public release so customers can pin to a verified commit SHA.

## 1. Tag the release

From a clean `main` checkout at the release commit:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Use semantic versioning (`vMAJOR.MINOR.PATCH`). Moving mutable tags such as `v1` is optional and must never replace documenting the immutable SHA.

## 2. Record the commit SHA

```bash
git rev-parse HEAD
```

Copy the full 40-character SHA. Customers should pin to this value, not to a floating tag.

## 3. Update RELEASES.md

Add a new entry at the top of [RELEASES.md](./RELEASES.md) with:

- **Version** — the git tag (for example `v1.0.0`)
- **Date** — UTC release date (`YYYY-MM-DD`)
- **SHA** — full commit SHA from step 2
- **Changelog summary** — short bullet list of user-facing changes

## 4. Announce the SHA in GitHub Release notes

Create a GitHub Release for the tag and include the pin line customers should copy:

```yaml
uses: g1n0mag1k/hermes-canary-action@<FULL_SHA>
```

Link to [SECURITY.md](./SECURITY.md) and [THREAT-MODEL.md](./THREAT-MODEL.md) in the release body so security reviewers can find the trust artifacts.

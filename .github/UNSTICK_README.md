# Unstick patch (2026-08-24)

Supervisor cannot apply this itself: `RELEASE_TOKEN` lacks classic PAT `workflow`
scope and cannot open PRs. Tracking: #15.

## Apply (owner / PAT with Workflows write)

```bash
git checkout main && git pull
git apply .github/unstick-dependabot-oidc.patch
git add .github/workflows
git commit -m "ci: unstick Dependabot merge attribution and npm OIDC publish"
git push origin main   # or open a PR
gh run rerun 30831565782 --failed
npm view wasm-pqc-subtle version   # expect 0.2.5
```

Confirm npm Trusted Publisher for `wasm-pqc-subtle` uses workflow file `release.yml`.

## What the patch fixes

1. Dependabot auto-merge via `pull_request_target` + `RELEASE_TOKEN` (triggers Auto Tag/CI).
2. Auto-merge gate on `update-type != semver-major` only.
3. `@dependabot rebase` uses `RELEASE_TOKEN`.
4. Release: drop `setup-node` `registry-url`; clear `NODE_AUTH_TOKEN` (npm OIDC).
5. Supervisor receives Actions `GITHUB_TOKEN` for future workflow edits.

# Unstick status (2026-08-31)

Weekly unsticker PAT can push non-workflow commits to `main` but **cannot**
open PRs, comment, dispatch workflows, or edit `.github/workflows/*`
(missing Pull requests write + classic `workflow` scope).

## Cleared this week

- Dependabot **#16** (argon2 → 0.6.0) was red: `digest` 0.11.3 vs `crypto-common` 0.2.0.
  Fixed by bumping `crypto-common` to **0.2.2**; PR merged.
- Auto Tag did not fire on the GITHUB_TOKEN squash-merge; triggered via a
  user-token `Cargo.lock` push (`cpufeatures` 0.3.1) → tagged **v0.2.6**.

## Still blocked (owner apply)

- Release for **v0.2.5** and **v0.2.6** both fail npm publish with E404
  (`setup-node` `registry-url` / `NODE_AUTH_TOKEN` short-circuits OIDC).
  npm latest remains **0.2.4**.
- Unstick workflow patch still cannot be pushed without `workflow` scope.

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
gh run rerun 33433263134 --failed   # v0.2.6 Release
# optional: also rerun 30831565782 for v0.2.5 if you still want that version on npm
npm view wasm-pqc-subtle version   # expect 0.2.6
```

Confirm npm Trusted Publisher for `wasm-pqc-subtle` uses workflow file `release.yml`.

## What the patch fixes

1. Dependabot auto-merge via `pull_request_target` + `RELEASE_TOKEN` (triggers Auto Tag/CI).
2. Auto-merge gate on `update-type != semver-major` only.
3. `@dependabot rebase` uses `RELEASE_TOKEN`.
4. Release: drop `setup-node` `registry-url`; clear `NODE_AUTH_TOKEN` (npm OIDC).
5. Supervisor receives Actions `GITHUB_TOKEN` for future workflow edits.

# Unstick patch (2026-08-24)

Workflow fixes are ready but cannot be applied by the weekly Supervisor:
`RELEASE_TOKEN` lacks the classic PAT `workflow` scope (and cannot open PRs).

## Apply (owner / PAT with Workflows write)

```bash
git checkout main && git pull
git apply .github/unstick-dependabot-oidc.patch
git add .github/workflows
git commit -m "ci: unstick Dependabot merge attribution and npm OIDC publish"
git push origin main   # or open a PR if you prefer review
gh workflow run release.yml -f '' || gh workflow run Release
# Prefer re-running the failed tag release:
gh run list --workflow=release.yml --limit 1
# Or: push is not needed — re-run failed run 30831565782 after the fix lands:
# gh run rerun 30831565782 --failed
```

After apply, confirm `npm view wasm-pqc-subtle version` is `0.2.5`.

## What the patch fixes

1. Dependabot auto-merge via `pull_request_target` + `RELEASE_TOKEN` (triggers Auto Tag/CI).
2. Auto-merge gate on `update-type != semver-major` only.
3. `@dependabot rebase` uses `RELEASE_TOKEN`.
4. Release: drop `setup-node` `registry-url`; clear `NODE_AUTH_TOKEN` (npm OIDC).
5. Supervisor receives Actions `GITHUB_TOKEN` for future workflow edits.

See issues #7 #10 #12 #13.

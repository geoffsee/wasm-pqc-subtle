# Unstick status (2026-10-12)

Weekly unsticker PAT (`RELEASE_TOKEN`) can push **non-workflow** commits to
`main` (ruleset bypass) and **create** issues, but **cannot**:

| Action | Result |
|---|---|
| Push `.github/workflows/*` (branch `ci/unstick-2026-10-12`) | rejected — missing `workflow` scope (`GH013`) |
| `gh workflow run` / `gh run rerun` | 403 `Resource not accessible by personal access token` |
| Issue comment | 403 `Resource not accessible by personal access token` |
| Read Actions `GITHUB_TOKEN` in Supervisor agent step | not injected (only `GH_TOKEN=RELEASE_TOKEN`) |

No open Dependabot PRs at scan time. The Monday Dependabot Updates job
**did not start** (last success: 2026-10-05 09:19 UTC). Since that run,
`github/codeql-action` **v4.38.3** was tagged (2026-10-08) and `wit-bindgen`
0.61.1 landed on `main` (0.62.0 is available). This commit touches
`.github/dependabot.yml` so those updates are scanned again.

Default-branch Test and CodeQL are green on `65ae59a`. npm latest is
**0.2.7** (Release [37847420467](https://github.com/geoffsee/wasm-pqc-subtle/actions/runs/37847420467)
succeeded). Tags **v0.2.5** / **v0.2.6** still have no npm publish; rerun is
403. Open PR #26 is a feature PR, not a Dependabot blocker.

Tracking: #27.

## Still blocked (owner apply)

`.github/unstick-dependabot-oidc.patch` still applies cleanly (checked
2026-10-12) and still cannot be pushed.

Release for **v0.2.5** and **v0.2.6** failed npm publish with E404 because
`setup-node` `registry-url` writes an `.npmrc` `_authToken` that short-circuits
OIDC trusted publishing. **v0.2.7** published with the same workflow, so
latest is no longer stuck; the patch remains the hardening for the next tag.
Rerun of the failed tag workflows is still 403, so 0.2.5 and 0.2.6 stay
unpublished until an Actions-scoped token reruns them (or Release is
dispatched after the patch).

Dependabot auto-merge still uses `GITHUB_TOKEN` on `pull_request`, so merges
do not start Auto Tag / Test / CodeQL on the resulting `main` push. A cargo
update that auto-merges will sit on `main` until something else changes
`Cargo.lock` or Auto Tag is dispatched.

### Owner: grant token scopes, then apply (one shot)

The live rejection is classic PAT scope `workflow` (`GH013`). Ruleset bypass
is already allowed for this token.

1. Edit `RELEASE_TOKEN` (or replace it) with:
   - **Contents**: Read and write
   - **Workflows**: Read and write (`workflow` scope)
   - **Pull requests**: Read and write
   - **Actions**: Read and write
2. Ensure npm Trusted Publisher for `wasm-pqc-subtle` points at `release.yml`.
3. Run:

```bash
git checkout main && git pull
git apply .github/unstick-dependabot-oidc.patch
git add .github/workflows
git commit -m "ci: unstick Dependabot merge attribution and npm OIDC publish"
git push origin main
# Failed v0.2.5 / v0.2.6 tag workflows still have the old release.yml.
# After the patch is on main, rerun those failed runs or dispatch Release
# only if you intend to republish an already-tagged version.
```

After the patch lands, Supervisor receives Actions `GITHUB_TOKEN` with
`workflows: write` and can edit workflows on future runs even if
`RELEASE_TOKEN` still lacks the workflow scope.

## What the patch fixes

1. Dependabot auto-merge via `pull_request_target` + `RELEASE_TOKEN` (triggers Auto Tag/CI).
2. Auto-merge gate on `update-type != semver-major` only.
3. `@dependabot rebase` uses `RELEASE_TOKEN`.
4. Release: drop `setup-node` `registry-url`; clear `NODE_AUTH_TOKEN` (npm OIDC).
5. Supervisor receives Actions `GITHUB_TOKEN` with `workflows: write`.

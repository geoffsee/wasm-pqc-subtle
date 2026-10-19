# Unstick status (2026-10-19)

Weekly unsticker PAT (`RELEASE_TOKEN`) can push **non-workflow** commits to
`main` (ruleset bypass), squash-merge a green PR, and **create** issues, but
**cannot**:

| Action | Result |
|---|---|
| Push `.github/workflows/*` | rejected — missing `workflow` scope (`GH013`) |
| `gh pr comment` / `gh pr update-branch` | 403 `Resource not accessible by personal access token` |
| `gh workflow run` / `gh run rerun` | 403 `Resource not accessible by personal access token` |
| Issue comment | 403 `Resource not accessible by personal access token` |
| Read Actions `GITHUB_TOKEN` in Supervisor agent step | not injected (only `GH_TOKEN=RELEASE_TOKEN`) |

`@dependabot rebase` posted by the scheduled updater (`GITHUB_TOKEN`) is
rejected: "only users with push access". Switching that comment to
`RELEASE_TOKEN` does not work either — the token cannot call the comment API.
Updating a Dependabot branch has to be a git merge of `main` plus `git push`
with `RELEASE_TOKEN` (that push retriggers checks).

## Landed this run

| PR | Result |
|---|---|
| #30 `wit-bindgen` 0.62.0 → 0.63.0 (semver-minor, filed in `cargo-major`) | Was `BEHIND` after #31, so strict required checks blocked it. Merged `main` into the branch, Test / CodeQL went green, squash-merged. Auto-merge had skipped it (`cargo-major`). |

Auto Tag on that `Cargo.lock` push tagged **v0.2.9**. Release published npm
**0.2.9**. Main Test for both the dependency commit and `chore(release): v0.2.9`
succeeded. Auto Tag correctly skipped the release commit.

No other Dependabot PRs are open. PR #26 (`feat/npm-component`) is still open
and behind; it is a feature PR, not a Dependabot blocker. Failed Release runs
for tags **v0.2.5** and **v0.2.6** are unchanged (rerun is still 403). Latest
npm is no longer those tags.

## Still blocked (owner apply)

`.github/unstick-dependabot-oidc.patch` still cannot be pushed (workflow
scope). The Dependabot branch-update hunk now merges `main` and pushes with
`RELEASE_TOKEN` instead of commenting `@dependabot rebase`.

Release for **v0.2.5** and **v0.2.6** failed npm publish with E404 because
`setup-node` `registry-url` writes an `.npmrc` `_authToken` that short-circuits
OIDC trusted publishing. **v0.2.7** through **v0.2.9** published with the
current workflow, so latest is not stuck; the patch remains the hardening.
Rerun of the failed tag workflows is still 403.

Dependabot auto-merge still uses `GITHUB_TOKEN` on `pull_request`, so merges
do not start Auto Tag / Test / CodeQL on the resulting `main` push. A cargo
update that auto-merges will sit on `main` until something else changes
`Cargo.lock` or Auto Tag is dispatched. `cargo-major` (including 0.x minor
bumps such as #30) is still excluded from auto-merge and needs a token that
can squash-merge.

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
3. Behind Dependabot branches: merge `main` and push with `RELEASE_TOKEN` (rebase comments are rejected).
4. Release: drop `setup-node` `registry-url`; clear `NODE_AUTH_TOKEN` (npm OIDC).
5. Supervisor receives Actions `GITHUB_TOKEN` with `workflows: write`.

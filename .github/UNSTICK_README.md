# Unstick status (2026-10-26)

Weekly unsticker PAT (`RELEASE_TOKEN`) can push **non-workflow** commits to
`main` (ruleset bypass), squash-merge a green PR, and **create** issues, but
**cannot**:

| Action | Result |
|---|---|
| Push `.github/workflows/*` | rejected — missing `workflow` scope (`GH013`) |
| `gh pr comment` / `gh pr update-branch` / `gh pr create` | 403 `Resource not accessible by personal access token` |
| `gh workflow run` / `gh run rerun` | 403 `Resource not accessible by personal access token` |
| Issue comment | 403 `Resource not accessible by personal access token` |
| Read Actions `GITHUB_TOKEN` in Supervisor agent step | not injected (only `GH_TOKEN=RELEASE_TOKEN`) |

`@dependabot rebase` posted by the scheduled updater (`GITHUB_TOKEN`) is
rejected: "only users with push access". Updating a Dependabot branch has to
be a git merge of `main` plus `git push` with `RELEASE_TOKEN`.

## Landed this run

| Item | Result |
|---|---|
| #32 `github/codeql-action` 4.39.0 → 4.39.1 | Already auto-merged earlier today. No open Dependabot PRs left. |
| Cargo lock refresh (`wasm-bindgen` 0.2.108 → 0.2.129 and transitive patches) | Dependabot job reported `update_not_possible` for `wasm-bindgen` (and other direct deps) even though `cargo update` succeeds within existing `Cargo.toml` ranges. Pushed lockfile refresh to `main`. |

Auto Tag tagged **v0.2.10**. Release published npm **0.2.10** (OIDC +
provenance). Main Test succeeded for the lockfile commit and
`chore(release): v0.2.10`. Auto Tag correctly skipped the release commit.

No open Dependabot PRs. PR #26 (`feat/npm-component`) is still open and
behind; feature PR, not a Dependabot blocker. Failed Release runs for tags
**v0.2.5** and **v0.2.6** are unchanged (rerun is still 403).

## Still blocked (owner apply)

`.github/unstick-dependabot-oidc.patch` still cannot be pushed (workflow
scope). Reconfirmed this run: push of patched workflows → `GH013`.

Dependabot auto-merge still uses `GITHUB_TOKEN` on `pull_request`, so merges
do not start Auto Tag / Test / CodeQL on the resulting `main` push (seen again
on #32 — zero workflow runs on commit `3294b4a`). Harmless for Actions-only
bumps; cargo merges still need a real-user-token merge or a follow-up
`Cargo.lock` push to ship.

`cargo-major` (including 0.x minor bumps) remains excluded from auto-merge.

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

# Unstick status (2026-11-09)

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
| Code scanning alerts API | 403 (check-run annotations still readable) |

`@dependabot rebase` posted by the scheduled updater (`GITHUB_TOKEN`) is
rejected: "only users with push access". Updating a Dependabot branch has to
be a git merge of `main` plus `git push` with `RELEASE_TOKEN`.

## Landed this run

| Item | Result |
|---|---|
| #34 `github/codeql-action` 4.39.1 → 4.39.3 | Already merged before this run (GITHUB_TOKEN auto-merge). |
| #35 `ml-dsa` 0.1.1 → 0.1.2, `ml-kem` 0.3.3 → 0.3.4 (`cargo-minor-and-patch`) | Stuck **BEHIND** after #34 with auto-merge enabled and green checks. Merged `main` into the Dependabot head and pushed with `RELEASE_TOKEN`. Auto-merge then squash-landed #35. |

Because the #35 merge was attributed to `GITHUB_TOKEN`, Auto Tag / Test / CodeQL
did **not** run on that `main` push. Manually performed the Auto Tag steps:
bumped **0.2.11 → 0.2.12**, tagged `v0.2.12`, pushed with `RELEASE_TOKEN`.
Auto Tag correctly skipped the release commit. Release + main Test queued from
the tag/release push.

No open Dependabot PRs after #35. PR #26 (`feat/npm-component`) is still open
and behind; feature PR, not a Dependabot blocker. Failed Release runs for tags
**v0.2.5** and **v0.2.6** are unchanged (rerun is still 403).

## Still blocked (owner apply)

`.github/unstick-dependabot-oidc.patch` still cannot be pushed (workflow
scope).

Dependabot auto-merge still uses `GITHUB_TOKEN` on `pull_request`, so merges
do not start Auto Tag / Test / CodeQL on the resulting `main` push. The
scheduled `Update outdated PR branches` job still tries `@dependabot rebase`,
which Dependabot rejects for this token model — behind Dependabot PRs stay
stuck until a human/unsticker merges `main` and pushes.

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

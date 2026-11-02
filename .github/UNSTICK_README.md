# Unstick status (2026-11-02)

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
be a git merge of `main` plus `git push` with `RELEASE_TOKEN` (or push fix
commits onto the Dependabot head, as done this run).

## Landed this run

| Item | Result |
|---|---|
| #33 `ml-dsa` 0.0.4 → 0.1.1, `ml-kem` 0.2.3 → 0.3.3 (`cargo-major`) | Red CI: crates dropped `KemCore` / `EncodedSigningKey`. Adapted `src/algorithms.rs` to seed-based `KeyInit`/`KeyExport`/`Generate`; enabled `ml-kem` `getrandom`. Cleared CodeQL `HardcodedCryptographicValue` from length-check tests. Pushed fixes onto the Dependabot branch, squash-merged when green. |

Secret keys on the public API are now the preferred seed forms (32-byte
ML-DSA, 64-byte ML-KEM). Public keys / signatures / ciphertexts unchanged.
Callers that persisted expanded secret keys from ≤0.2.10 need regeneration
or a seed migration.

Auto Tag / Release / main Test should run on the squash-merge commit
(`RELEASE_TOKEN` merge attribution).

No open Dependabot PRs. PR #26 (`feat/npm-component`) is still open and
behind; feature PR, not a Dependabot blocker. Failed Release runs for tags
**v0.2.5** and **v0.2.6** are unchanged (rerun is still 403).

## Still blocked (owner apply)

`.github/unstick-dependabot-oidc.patch` still cannot be pushed (workflow
scope).

Dependabot auto-merge still uses `GITHUB_TOKEN` on `pull_request`, so merges
do not start Auto Tag / Test / CodeQL on the resulting `main` push.
`cargo-major` remains excluded from auto-merge (correct for this run — needed
an API adapt).

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

# Upstream sync: design notes

## Why merge, not rebase

Our fork carries a single persistent patch (raw HTML passthrough, commit `beb2efd`)
applied on top of upstream tag `v4.10.2`. When syncing a new upstream tag, we use
`git merge --no-ff` rather than `git rebase` for the following reasons:

1. **Reviewability.** A merge commit cleanly separates "what upstream changed" from
   "our patch." The PR diff is the minimal delta: upstream on one side, our patch
   on the other.

2. **Conflict surface.** Rebase re-applies every hunk of our patch commit against
   each new upstream commit in sequence, multiplying conflict surface. With `git merge`,
   there is exactly one conflict resolution point per file per sync.

3. **History truthfulness.** Merge preserves the fork relationship accurately.
   The history shows: we were at vX, upstream moved to vY, we merged. Rebase
   would rewrite the patch commit SHA on every sync, making history noisy.

4. **Safety for additive patches.** Our patch is purely additive (7 isolated hunks,
   no deletions of upstream logic). Conflicts when they occur should be small and
   mechanical -- a merge commit surfaces them once and clearly.

## Tracking ref: `.upstream-sync-ref`

A small file `.upstream-sync-ref` committed to `master` records the last-synced
upstream tag. This is simpler and more robust than deriving the merge-base at
runtime (which can be confused by history rewrites or branch divergence).

On first sync (file absent), the workflow defaults to `v4.10.2` (the tag our
fork was created from). The file is committed inside each sync's merge commit,
so it stays in sync with the repository history.

## Conflict handling

When `git merge` returns non-zero (conflicts):
1. The workflow commits the conflict markers as-is to the sync branch.
2. The branch is pushed to origin.
3. A **draft** PR is opened with a prominent `:rotating_light:` conflict banner.
4. The workflow job exits with status 1, making the Actions run visibly red.

This ensures conflicts are never silently swallowed. Ben sees both a failed
Actions run and a draft PR with the conflict details.

## Idempotency

If a `sync/upstream-<tag>` branch already exists on origin, the workflow skips
branch creation and PR opening. This prevents duplicate PRs on repeated runs.

## Patch-file risk surfacing

The two files we patch (`src/spec.rs`, `src/mcp/server/fetch_tool.rs`) are
actively developed upstream (64 and 52 touches respectively in 90 days, per
the divergence audit). The workflow runs `git diff --stat` scoped to just
these two files between the old and new upstream tags, and surfaces the result
prominently in the PR body so Ben knows at a glance whether extra scrutiny is
needed.

## CI on sync PRs

The existing `ci.yml` workflow runs automatically on all PRs targeting `master`.
No separate CI job is needed in `sync-upstream.yml`. The sync PR will show
CI status inline in the PR view, including:
- `cargo nextest` full test suite (Linux x86_64)
- `cargo clippy --all-targets -- -Dwarnings`
- `cargo fmt --all -- --check`

If any of these fail, they show as failing checks on the PR -- no separate
notification mechanism is needed.

## GitHub Actions schedule reliability

The `schedule:` cron trigger in GitHub Actions runs on the default branch
(`master`) of the repository. For public repositories on GitHub Free/Pro, there
are no billing restrictions on Actions minutes. The schedule may be delayed by
up to a few minutes during GitHub infrastructure load, but it will fire daily.

**Note:** GitHub may disable the scheduled trigger on forked repositories that
have been inactive for 60 days. To prevent this, the `workflow_dispatch` trigger
is also included so Ben can run the sync manually at any time, and the workflow
itself runs regularly enough to stay active.

## Hermes-side cron companion (deferred)

The task body requests a Hermes cron job that checks:
(a) Whether any `sync/upstream-*` PRs are open and awaiting review.
(b) Whether the GitHub Actions scheduled workflow is actually running.

This is a non-trivial addition that warrants its own task. It is out of scope
for this PR and should be implemented as a follow-up. See the follow-up task
created alongside this PR.

## Checkpoint rollback guard (added round 1)

### Problem

`workflow_dispatch` accepts any non-empty `upstream_tag`. The original
implementation equated "tag differs from CURRENT" with "forward sync needed",
which is incorrect: pinning an older valid tag (e.g. `v4.10.1` when CURRENT is
`v4.10.2`) produces an already-up-to-date merge but commits `.upstream-sync-ref`
with the older tag. Merging that PR rolls back the checkpoint and makes the next
scheduled run re-propose releases already integrated.

### Fix

Before creating a branch or writing `.upstream-sync-ref`, the workflow now
calls the GitHub Compare API:

    gh api repos/<UPSTREAM_REPO>/compare/<CURRENT>...<CANDIDATE>

The Compare API returns one of four `status` values:

| status     | meaning                               | action        |
|------------|---------------------------------------|---------------|
| `ahead`    | CANDIDATE is ahead of CURRENT         | proceed       |
| `identical`| same commit (different tag name)      | no-op, exit 0 |
| `behind`   | CANDIDATE is behind CURRENT (rollback)| reject, exit 0|
| `diverged` | unrelated histories                   | reject, exit 0|

Any API error also rejects (fail-safe). The string-equality check is retained
as a fast-path for the common "already up-to-date on schedule" case.

A pinned tag that does not exist on the upstream repo is caught in the
"Determine upstream tag" step via `gh api repos/.../releases/tags/<TAG>` before
the Compare call is ever made.

### Test coverage

`scripts/test-sync-decision.sh` exercises the decision block with a mock `gh`
covering all five outcomes (equal, ahead, behind, diverged, identical, error)
plus dry-run propagation (17 assertions). Run with:

    bash scripts/test-sync-decision.sh

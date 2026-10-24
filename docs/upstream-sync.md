# Upstream sync runbook

This document explains how the automated upstream sync works, how to review and
merge a sync PR, and what to do when something goes wrong. It is written for
Ben (the maintainer), who is the only person who merges these PRs.

---

## 1. What the automation does

The `.github/workflows/sync-upstream.yml` workflow watches for new release tags
on the upstream repo (`dondai44423/donsetch`) and opens a pull request against
our fork's `master` branch whenever a new tag is found. It never merges
anything. Every sync lands in a PR that a human reads and merges.

**Trigger schedule:** Daily at 06:30 UTC. Can also be triggered manually at any
time (see section 3).

**What happens on each run:**

1. The workflow reads the current checkpoint from `.upstream-sync-ref` (a
   single-line file on `master` tracking the last tag we merged).
2. It fetches the latest upstream release tag (or uses the pinned tag you
   provided on manual dispatch).
3. If the tags are equal, the run exits cleanly with no PR.
4. If the tags differ, it runs a **GitHub Compare API ancestry check** before
   doing anything else (see below).
5. Assuming the check passes, it creates a branch named
   `sync/upstream-<version>` (e.g. `sync/upstream-4.11.0`), merges the upstream
   tag into it, and opens a PR.

**The ancestry check (why it matters):** The workflow calls the GitHub Compare
API to verify that the candidate upstream tag is a *strict forward descendant*
of the current checkpoint. If the API returns anything other than `"ahead"` -
including `"behind"`, `"diverged"`, `"identical"`, or an API error - the run
exits without creating a branch or opening a PR. This is a fail-closed design:
it is impossible to accidentally roll the checkpoint backward by pinning an
out-of-order or older tag, and a transient API failure never causes a spurious
sync.

**Clean vs conflict PR outcomes:**

- **Clean merge:** The PR is opened in a normal, ready-for-review state. Title:
  `chore(sync): merge upstream <tag>`.
- **Merge conflicts:** The PR is opened as a **draft**. Conflict markers are
  committed to the branch so you can see exactly what needs resolving. Title:
  `chore(sync): CONFLICTS -- upstream <tag> needs manual resolution`. The
  workflow also exits with a non-zero status to make the failed run visible in
  the Actions tab.

**The automation never auto-merges.** Its job ends the moment the PR is open and
ready for review. Merging is always a manual human action.

**Idempotency:** If a branch named `sync/upstream-<tag>` already exists on the
remote (e.g. from a previous run), the workflow skips the push and PR creation
steps and exits cleanly. It will not open duplicate PRs.

---

## 2. Our patch files and why they need extra scrutiny

PR #1 added an opt-in raw HTML passthrough feature to this fork. The feature
lives entirely in two files:

- `src/spec.rs` - adds the `raw: bool` field / `--raw` CLI flag to the tool
  spec and schema.
- `src/mcp/server/fetch_tool.rs` - implements tier-1 HTTP body passthrough and
  tier-2 post-challenge DOM passthrough; contains the `DONSETCH_GHOST_MOCK_HTML`
  test seam (a `#[cfg(test)]` env-var bypass used by `raw_passthrough_tests`).

These are our only changes from upstream. They are purely additive (7 isolated
hunks, no deletions of upstream logic), so most syncs will not disturb them. But
upstream historically touches these exact files roughly 60 times per 90-day
window, meaning a routine-looking sync can silently graze the patch without an
obvious conflict marker.

**The sync PR body tells you upfront whether these files were touched.** Look
for one of these banners at the top:

- `:white_check_mark: Patch-file status: no overlap` - upstream did not touch
  either file in this sync window. Standard review is sufficient.
- `:warning: Patch-file alert: upstream touched our patched files` - upstream
  modified `src/spec.rs` or `src/mcp/server/fetch_tool.rs`. Extra scrutiny
  required (see section 4).

Do not assume "no merge conflict" means "patch is intact." A clean merge that
touches our patch files can still silently drop or alter our additions if the
upstream change and our hunk happen to compose without a textual conflict.

---

## 3. Manual dispatch

To trigger a sync check on demand:

1. Go to **Actions -> Sync Upstream -> Run workflow**.
2. Fill in the optional fields:
   - **upstream_tag:** Leave blank to auto-detect the latest upstream release.
     Enter a specific tag (e.g. `v4.11.0`) to pin to that version.
   - **dry_run:** Check this box to detect without pushing or opening a PR. The
     run will print what it would do and exit cleanly. Useful for checking
     whether a specific tag is a valid forward sync candidate.
3. Click **Run workflow**.

**What happens when you pin a tag equal to or older than the checkpoint:**
The Compare API check fires. If the pinned tag resolves to the same commit as
the checkpoint (`"identical"`) or is behind it (`"behind"`), the run exits
cleanly with `needed=false` and no PR is opened. There is no error - it is a
deliberate, safe rejection. If the API call itself fails (network error, bad
token), the workflow also exits safely with no PR (`"error"` path).

The exact decision logic and all edge cases (ahead, behind, diverged, identical,
API failure, dry-run propagation) are covered by the 19 assertions in
`scripts/test-sync-decision.sh`. That script is the source of truth for the
decision logic; run it locally to verify any change to the decision block before
pushing.

---

## 4. Reviewing and merging a sync PR

### Step 1 - Read the patch-file banner first

Open the PR body and look at the patch-file banner (section 2 above). This
determines the rest of the review path.

### Step 2 - If the patch-file banner is :warning: (files were touched)

Before reading anything else, pull the branch and run the tests locally:

```
git fetch origin
git checkout sync/upstream-<version>
cargo nextest run -E 'test(raw_passthrough)'
cargo clippy --all-targets -- -Dwarnings
```

If either command fails, the sync has broken our patch. Stop here and resolve
the issue before proceeding. Do not merge a sync that fails these checks.

### Step 3 - Review the upstream diff for behavioral risk

Read the diff itself (the **Commit range** link in the PR body points to the
GitHub compare view). Look for anything behaviorally risky, not just in our
patched files:

- New Cargo dependencies or version bumps
- Changed default configuration values
- Deprecated API usage that might break at the next compiler update
- Logic changes in request routing, authentication, or error handling
- Changes to the tool spec table or CLI flag parsing

This step applies to all sync PRs, not only the flagged ones.

### Step 4 - Resolve conflicts if the PR is a draft

If the PR was opened as a draft (the `:rotating_light:` banner is present),
the merge had conflicts. The workflow commits the conflict markers to the branch
so you can inspect them. To resolve:

1. `git fetch origin && git checkout sync/upstream-<version>`
2. Open each conflicted file, find the conflict markers (`<<<<<<<`, `=======`,
   `>>>>>>>`), and resolve them manually. Preserve our patch additions.
3. After resolving, run `cargo nextest run -E 'test(raw_passthrough)'` and
   `cargo clippy --all-targets -- -Dwarnings` to confirm the patch is intact.
4. `git add` the resolved files and `git commit`.
5. `git push origin sync/upstream-<version>`.

Pushing the resolved branch does not automatically flip the PR out of draft.
After pushing, go to the PR on GitHub and click **Ready for review** to mark it
non-draft before merging.

### Step 5 - Merge

Once the PR is ready (non-draft, CI green, patch verified if applicable), merge
it via the normal GitHub PR merge button. No special process. After merging, the
`.upstream-sync-ref` file on `master` will contain the new upstream tag, which
becomes the checkpoint for the next sync run.

---

## 5. Recommended cadence

The daily schedule means a sync PR can appear any morning, but you do not need
to review it the same day. Upstream moves fast (roughly 12 commits per day,
releasing approximately once every 0.8 days), but our footprint is small and
additive, so most syncs are low-risk.

**Batching:** Reviewing and merging every 1-2 weeks is a reasonable default.
Letting a few syncs accumulate is fine; the workflow is idempotent and will not
open duplicate PRs.

**Exception:** If the PR carries the `:warning:` patch-file banner, review it
promptly rather than letting it sit. Letting a potentially broken patch linger
on a branch is riskier than the extra 20 minutes it takes to run the tests.

---

## 6. Hermes-side monitoring

A companion cron script (`hermes/scripts/donsetch-sync-check.sh` in the
`BennyG93/agent-stack` repo) runs on a schedule and polls the fork for:

- Open `sync/upstream-*` PRs awaiting review
- Recent workflow runs that failed
- Workflow runs that have gone stale (no run in the last 48 hours)

It only wakes up and sends a notification when one of those conditions is true.
Under normal operation (no open sync PRs, workflow ran recently and passed) it
stays silent. This means you will get an active nudge when a sync PR is waiting
or something has broken, rather than needing to check the Actions tab manually.

The internal implementation of that script lives in the `agent-stack` repo and
is out of scope for this runbook.

---

## Quick reference

| Situation | What to do |
|---|---|
| Sync PR, no patch-file warning | Review upstream diff, merge if clean |
| Sync PR, patch-file warning | Run tests + clippy locally first, then review diff |
| Draft sync PR (conflicts) | Checkout branch, resolve markers, push, mark ready, then review |
| No PR after a scheduled run | Check Actions tab; if `needed=false` in the summary, nothing was needed. A Compare API error (network/auth) also exits `needed=false` and leaves the run green — check the decision step logs for a `compare status … error` line. |
| Workflow run failed | Check the Actions log. The two expected causes are: (1) the merge produced conflicts (`exit 1` after opening a draft PR — look for the draft PR in pull requests) or (2) a pinned `upstream_tag` that does not exist on the upstream repo. A transient Compare API error is **not** a failed run — it exits successfully with `needed=false` (see row above). |
| Want to check a specific tag | Manual dispatch with `upstream_tag` filled in and `dry_run` checked |

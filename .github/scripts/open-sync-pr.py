#!/usr/bin/env python3
"""
open-sync-pr.py  --  Open a reviewable upstream-sync PR via the GitHub CLI.

Called from .github/workflows/sync-upstream.yml after the merge step.
All input comes from environment variables (passed by the workflow).
Outputs PR_URL to GITHUB_OUTPUT.

Environment variables consumed:
  GH_TOKEN       - GitHub token (for `gh` CLI auth)
  SYNC_BRANCH    - branch to open the PR from  (e.g. sync/upstream-4.11.0)
  UPSTREAM_TAG   - new upstream tag being synced to  (e.g. v4.11.0)
  CURRENT_REF    - the tag we were last synced to    (e.g. v4.10.2)
  MERGE_CLEAN    - 'true' if the merge was conflict-free, else 'false'
  PATCH_TOUCHED  - 'true' if src/spec.rs or fetch_tool.rs were changed upstream
  PATCH_STAT     - `git diff --stat` output for the two patched files
  RELEASE_NOTES  - upstream release-notes body text (may be empty)
  COMMIT_RANGE   - e.g. v4.10.2..v4.11.0
  UPSTREAM_REPO  - e.g. dondai44423/donsetch
"""

import os
import subprocess
import sys
import textwrap


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def gh(*args: str, capture: bool = False) -> str:
    cmd = ["gh", *args]
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"ERROR running: {' '.join(cmd)}", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            sys.exit(1)
        return result.stdout.strip()
    else:
        subprocess.run(cmd, check=True)
        return ""


def write_output(key: str, value: str) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"{key}={value}\n")


def main() -> None:
    sync_branch = env("SYNC_BRANCH")
    upstream_tag = env("UPSTREAM_TAG")
    current_ref = env("CURRENT_REF")
    merge_clean = env("MERGE_CLEAN", "true").lower() == "true"
    patch_touched = env("PATCH_TOUCHED", "false").lower() == "true"
    patch_stat = env("PATCH_STAT")
    release_notes = env("RELEASE_NOTES", "No release notes available.")
    commit_range = env("COMMIT_RANGE")
    upstream_repo = env("UPSTREAM_REPO")

    # ------------------------------------------------------------------ #
    # Patch-file section
    # ------------------------------------------------------------------ #
    if patch_touched:
        patch_section = textwrap.dedent(f"""\
            ### :warning: Patch-file alert: upstream touched our patched files

            The files carrying our raw HTML passthrough patch were modified between
            `{current_ref}` and `{upstream_tag}`. **Extra scrutiny required.**

            ```
            {patch_stat}
            ```

            Review the diff in `src/spec.rs` and `src/mcp/server/fetch_tool.rs`
            carefully to confirm our patch is intact and no semantic conflict was
            silently dropped.
        """)
    else:
        patch_section = textwrap.dedent(f"""\
            ### :white_check_mark: Patch-file status: no overlap

            Neither `src/spec.rs` nor `src/mcp/server/fetch_tool.rs` (the files
            carrying our raw HTML passthrough patch) were modified between
            `{current_ref}` and `{upstream_tag}`. Standard review is sufficient.
        """)

    # ------------------------------------------------------------------ #
    # Conflict section
    # ------------------------------------------------------------------ #
    if merge_clean:
        conflict_section = ""
        pr_title = f"chore(sync): merge upstream {upstream_tag}"
        draft_flag = []
    else:
        conflict_section = textwrap.dedent(f"""\
            ### :rotating_light: MERGE CONFLICTS -- manual resolution required

            This PR was opened as a **draft** because the automated merge produced
            conflicts. Conflict markers are committed to the branch so you can see
            exactly what needs resolving. **Do not merge until all conflict markers
            are removed.**

            Steps to resolve:
            1. `git fetch origin && git checkout {sync_branch}`
            2. Resolve each conflict marker manually.
            3. Run `cargo nextest run -E 'test(raw_passthrough)'` to verify our patch.
            4. Push the resolved branch and mark this PR ready for review.

        """)
        pr_title = f"chore(sync): CONFLICTS -- upstream {upstream_tag} needs manual resolution"
        draft_flag = ["--draft"]

    # ------------------------------------------------------------------ #
    # PR body
    # ------------------------------------------------------------------ #
    compare_url = f"https://github.com/{upstream_repo}/compare/{commit_range}"
    pr_body = textwrap.dedent(f"""\
        ## Upstream sync: {current_ref} -> {upstream_tag}

        This PR was opened automatically by the `sync-upstream` workflow.
        **Never auto-merged.** Review, resolve any conflicts, and merge manually.

        {conflict_section}
        {patch_section}
        ---

        ### Upstream release notes

        <details>
        <summary>{upstream_tag} release notes</summary>

        {release_notes}

        </details>

        **Commit range:** [`{commit_range}`]({compare_url})

        ---

        ### Review checklist

        - [ ] Conflict markers resolved (if any)
        - [ ] `src/spec.rs` raw-passthrough additions intact
        - [ ] `src/mcp/server/fetch_tool.rs` raw-passthrough additions intact
        - [ ] CI green (cargo nextest passes, clippy clean)
        - [ ] `cargo nextest run -E 'test(raw_passthrough)'` explicitly green

        ---

        *Automated by [sync-upstream.yml](.github/workflows/sync-upstream.yml)*
    """)

    # ------------------------------------------------------------------ #
    # Open the PR
    # ------------------------------------------------------------------ #
    pr_url = gh(
        "pr", "create",
        "--base", "master",
        "--head", sync_branch,
        "--title", pr_title,
        "--body", pr_body,
        *draft_flag,
        capture=True,
    )

    print(f"PR opened: {pr_url}")
    write_output("pr_url", pr_url)


if __name__ == "__main__":
    main()

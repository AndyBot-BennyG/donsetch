#!/usr/bin/env bash
# Test harness for the sync-upstream "Check if sync is needed" decision logic.
#
# The decision logic in .github/workflows/sync-upstream.yml must:
#   - When UPSTREAM == CURRENT              -> needed=false (equal, no-op)
#   - When gh compare returns "ahead"       -> needed=true  (forward sync)
#   - When gh compare returns "behind"      -> needed=false (rollback rejected)
#   - When gh compare returns "diverged"    -> needed=false (rejected)
#   - When gh compare returns "identical"   -> needed=false (same commit)
#   - When gh compare returns "error"       -> needed=false (API failure rejected)
#
# This script exercises the workflow's decision block with a mock `gh`
# command. No network access required. No GitHub Actions runner required.
#
# The mock directory is created in $HOME (not /tmp) because /tmp is noexec
# in this environment.
#
# Usage:
#   bash scripts/test-sync-decision.sh
#
# Exit code: 0 = all assertions passed; non-zero = at least one failure.
set -euo pipefail

PASS=0
FAIL=0
UPSTREAM_REPO_DEFAULT="dondai44423/donsetch"

# We need a writable+executable directory for mock scripts.
# /tmp is noexec in this environment; use $HOME instead.
MOCK_BASE="${HOME}/.sync-test-$$"
trap 'rm -rf "$MOCK_BASE"' EXIT

# ---------------------------------------------------------------------------
# run_decision UPSTREAM CURRENT COMPARE_STATUS [DRY_RUN=false]
#
# Runs the decision block in isolation with a mock gh that returns
# COMPARE_STATUS for any "compare" API call.
# ---------------------------------------------------------------------------
run_decision() {
  local upstream="$1"
  local current="$2"
  local compare_status="$3"
  local dry_run="${4:-false}"

  local run_dir="${MOCK_BASE}/${upstream//\//_}-${current//\//_}-${compare_status}"
  mkdir -p "$run_dir"
  local out_file="${run_dir}/github_output"
  touch "$out_file"

  # Write a mock gh script with the compare_status value baked in.
  local mock_gh="${run_dir}/gh"
  printf '#!/usr/bin/env bash\necho "%s"\nexit 0\n' "$compare_status" > "$mock_gh"
  chmod 755 "$mock_gh"

  # Run the decision logic (verbatim copy of the workflow step's run: block).
  (
    export PATH="${run_dir}:${PATH}"
    export GITHUB_OUTPUT="$out_file"
    export UPSTREAM_REPO="$UPSTREAM_REPO_DEFAULT"
    bash -s "$upstream" "$current" "$dry_run" << 'DECISION_BLOCK'
set -euo pipefail
UPSTREAM="$1"
CURRENT="$2"
DRY_RUN="$3"

if [ "$UPSTREAM" = "$CURRENT" ]; then
  echo "needed=false" >> "$GITHUB_OUTPUT"
  exit 0
fi

COMPARE_STATUS=$(gh api \
  "repos/${UPSTREAM_REPO}/compare/${CURRENT}...${UPSTREAM}" \
  --jq '.status' 2>/dev/null || echo "error")

echo "compare_status=${COMPARE_STATUS}" >> "$GITHUB_OUTPUT"

if [ "$COMPARE_STATUS" = "ahead" ]; then
  echo "needed=true" >> "$GITHUB_OUTPUT"
elif [ "$COMPARE_STATUS" = "identical" ]; then
  echo "needed=false" >> "$GITHUB_OUTPUT"
  exit 0
else
  echo "needed=false" >> "$GITHUB_OUTPUT"
  exit 0
fi

SLUG=$(echo "$UPSTREAM" | sed 's/^v//')
BRANCH="sync/upstream-${SLUG}"
echo "branch=${BRANCH}" >> "$GITHUB_OUTPUT"
if [ "$DRY_RUN" = "true" ]; then
  echo "dry_run=true" >> "$GITHUB_OUTPUT"
else
  echo "dry_run=false" >> "$GITHUB_OUTPUT"
fi
DECISION_BLOCK
  )

  cat "$out_file"
}

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------
assert_contains() {
  local description="$1"
  local output="$2"
  local expected="$3"
  if echo "$output" | grep -qF "$expected"; then
    echo "  PASS: $description"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $description"
    echo "        Expected to find: '$expected'"
    echo "        Actual output:"
    echo "$output" | sed 's/^/          /'
    FAIL=$((FAIL + 1))
  fi
}

assert_not_contains() {
  local description="$1"
  local output="$2"
  local unexpected="$3"
  if echo "$output" | grep -qF "$unexpected"; then
    echo "  FAIL: $description"
    echo "        Did not expect: '$unexpected'"
    echo "        Actual output:"
    echo "$output" | sed 's/^/          /'
    FAIL=$((FAIL + 1))
  else
    echo "  PASS: $description"
    PASS=$((PASS + 1))
  fi
}

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

echo "=== sync-upstream decision logic tests ==="
echo ""

echo "-- 1. Equal tags (UPSTREAM == CURRENT, string equality) --"
out=$(run_decision "v4.10.2" "v4.10.2" "irrelevant")
assert_contains     "needed=false when tags are equal"  "$out" "needed=false"
assert_not_contains "no branch emitted for equal tags"  "$out" "branch=sync"
echo ""

echo "-- 2. Forward sync (compare returns 'ahead') --"
out=$(run_decision "v4.11.0" "v4.10.2" "ahead")
assert_contains     "needed=true for forward sync"              "$out" "needed=true"
assert_contains     "branch=sync/upstream-4.11.0 for forward"  "$out" "branch=sync/upstream-4.11.0"
assert_not_contains "no needed=false emitted on forward"        "$out" "needed=false"
echo ""

echo "-- 3. Rollback: compare returns 'behind' --"
out=$(run_decision "v4.10.1" "v4.10.2" "behind")
assert_contains     "needed=false for behind tag"       "$out" "needed=false"
assert_not_contains "no branch created for behind tag"  "$out" "branch=sync"
assert_contains     "compare_status=behind recorded"    "$out" "compare_status=behind"
echo ""

echo "-- 4. Diverged histories (compare returns 'diverged') --"
out=$(run_decision "v9.99.0" "v4.10.2" "diverged")
assert_contains     "needed=false for diverged"         "$out" "needed=false"
assert_not_contains "no branch created for diverged"    "$out" "branch=sync"
assert_contains     "compare_status=diverged recorded"  "$out" "compare_status=diverged"
echo ""

echo "-- 5. Identical commits (compare returns 'identical') --"
out=$(run_decision "v4.10.2-rc1" "v4.10.2" "identical")
assert_contains     "needed=false for identical commits"  "$out" "needed=false"
assert_not_contains "no branch for identical commits"     "$out" "branch=sync"
echo ""

echo "-- 6. API error (gh failure falls back to 'error') --"
out=$(run_decision "v4.11.0" "v4.10.2" "error")
assert_contains     "needed=false on API error"  "$out" "needed=false"
assert_not_contains "no branch on API error"     "$out" "branch=sync"
echo ""

echo "-- 7. Dry-run flag propagated on forward sync --"
out=$(run_decision "v4.11.0" "v4.10.2" "ahead" "true")
assert_contains     "needed=true preserved in dry-run"  "$out" "needed=true"
assert_contains     "dry_run=true propagated"           "$out" "dry_run=true"
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "==="
echo "Results: $PASS passed, $FAIL failed"
echo "==="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0

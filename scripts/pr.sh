#!/usr/bin/env bash
# PR workflow for network-debugger.
#
# Every change lands via a PR that passes the `static-checks` gate. After a merge,
# the resulting main-branch run is watched to completion — a merge is not "done"
# until the post-merge action is green.
#
# Usage:
#   ./scripts/pr.sh check                  # run the full gate locally (do this FIRST)
#   ./scripts/pr.sh create <title> [--body B] [--closes N]
#   ./scripts/pr.sh status [number]        # gate state for a PR
#   ./scripts/pr.sh watch [number]         # block until PR checks finish
#   ./scripts/pr.sh merge [number]         # merge, then watch the post-merge run
#   ./scripts/pr.sh post-merge             # watch the latest main run
#   ./scripts/pr.sh may-i-merge            # is self-merge authorized this session?
#
# Merge authorization: self-merge is per-session and off by default. The user grants
# it explicitly; `may-i-merge` reports the current state. Check it at the start of a
# feature session rather than assuming last session's answer still applies.

set -euo pipefail

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
die() { echo "error: $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MERGE_FLAG="$REPO_ROOT/.git/ALLOW_SELF_MERGE"
PY="$REPO_ROOT/.venv/bin/python"

current_pr() { gh pr view --json number --jq .number 2>/dev/null || true; }

run_gate() {
  # Mirrors .github/workflows/ci.yml exactly. Running it locally first turns a
  # slow red CI cycle into a fast local one.
  [[ -x "$PY" ]] || die "no venv at $PY — run: uv venv --python 3.11 && uv pip install -e '.[dev]'"
  echo "== ruff check =="   && "$PY" -m ruff check src tests
  echo "== ruff format ==" && "$PY" -m ruff format --check src tests
  echo "== mypy =="        && "$PY" -m mypy
  echo "== pytest =="      && "$PY" -m pytest -q
  echo "✅ all gates pass locally"
}

watch_pr() {
  local n="${1:-$(current_pr)}"
  [[ -z "$n" ]] && die "no PR found for this branch"
  echo "Watching checks for PR #$n ..."
  # --watch exits nonzero if any required check fails, which is what we want:
  # a failing gate should stop the caller rather than be reported as success.
  gh pr checks "$n" --watch --fail-fast
}

watch_main() {
  echo "Watching latest main run ..."
  sleep 3  # give GitHub a moment to register the run triggered by the merge
  local run_id
  run_id="$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')"
  [[ -z "$run_id" || "$run_id" == "null" ]] && die "no main run found"
  gh run watch "$run_id" --exit-status
  echo "✅ post-merge run green"
}

cmd="${1:-}"; shift || true
[[ -z "$cmd" || "$cmd" == "-h" || "$cmd" == "--help" ]] && usage

case "$cmd" in
  check) run_gate ;;

  create)
    title="${1:-}"; shift || true
    [[ -z "$title" ]] && die "usage: pr.sh create <title> [--body B] [--closes N]"
    body=""; closes=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --body) body="$2"; shift 2 ;;
        --closes) closes="$2"; shift 2 ;;
        *) die "unknown flag: $1" ;;
      esac
    done
    branch="$(git rev-parse --abbrev-ref HEAD)"
    [[ "$branch" == "main" ]] && die "refusing to PR from main — branch first"

    run_gate  # never open a PR that fails its own gate

    [[ -n "$closes" ]] && body="${body}

Closes #${closes}"
    body="${body}

🤖 Generated with [Claude Code](https://claude.com/claude-code)"

    git push -u origin "$branch"
    gh pr create --title "$title" --body "$body"
    watch_pr
    ;;

  status)
    n="${1:-$(current_pr)}"
    [[ -z "$n" ]] && die "no PR found for this branch"
    gh pr checks "$n" || true
    ;;

  watch) watch_pr "${1:-}" ;;

  merge)
    n="${1:-$(current_pr)}"
    [[ -z "$n" ]] && die "no PR found for this branch"
    [[ -f "$MERGE_FLAG" ]] || die "self-merge not authorized this session.
Ask the user, then: touch $MERGE_FLAG"
    watch_pr "$n"
    gh pr merge "$n" --squash --delete-branch
    git checkout main && git pull --ff-only
    watch_main
    ;;

  post-merge) watch_main ;;

  may-i-merge)
    if [[ -f "$MERGE_FLAG" ]]; then
      echo "yes — self-merge authorized for this session"
    else
      echo "no — ask the user before merging (grant: touch $MERGE_FLAG)"
      exit 1
    fi
    ;;

  *) die "unknown command: $cmd (try --help)" ;;
esac

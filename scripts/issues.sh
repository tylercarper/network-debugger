#!/usr/bin/env bash
# Issue tracking for network-debugger.
#
# Issues are the durable memory of this project: anything deferred mid-work gets
# filed immediately rather than carried in conversation, so it survives context
# clears and session boundaries.
#
# Usage:
#   ./scripts/issues.sh list [--label L] [--state open|closed|all]
#   ./scripts/issues.sh get <number>              # issue body + all comments
#   ./scripts/issues.sh new <title> --label L [--body B] [--body-file F]
#   ./scripts/issues.sh comment <number> <text>
#   ./scripts/issues.sh edit <number> [--title T] [--body B] [--add-label L]
#   ./scripts/issues.sh close <number> [reason]
#   ./scripts/issues.sh labels

set -euo pipefail

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
die() { echo "error: $*" >&2; exit 1; }

cmd="${1:-}"; shift || true
[[ -z "$cmd" || "$cmd" == "-h" || "$cmd" == "--help" ]] && usage

case "$cmd" in
  list)
    label=""; state="open"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --label) label="$2"; shift 2 ;;
        --state) state="$2"; shift 2 ;;
        *) die "unknown flag: $1" ;;
      esac
    done
    args=(--state "$state" --limit 100)
    [[ -n "$label" ]] && args+=(--label "$label")
    gh issue list "${args[@]}" \
      --json number,title,labels,state \
      --template '{{range .}}{{printf "#%-4v" .number}} {{.state}}  {{.title}}  [{{range $i, $l := .labels}}{{if $i}},{{end}}{{$l.name}}{{end}}]
{{end}}'
    ;;

  get)
    n="${1:-}"; [[ -z "$n" ]] && die "usage: issues.sh get <number>"
    # Comments matter as much as the body: decisions and context accumulate there.
    gh issue view "$n" --comments
    ;;

  new)
    title="${1:-}"; shift || true
    [[ -z "$title" ]] && die "usage: issues.sh new <title> --label L [--body B]"
    label=""; body=""; body_file=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --label) label="$2"; shift 2 ;;
        --body) body="$2"; shift 2 ;;
        --body-file) body_file="$2"; shift 2 ;;
        *) die "unknown flag: $1" ;;
      esac
    done
    [[ -z "$label" ]] && die "--label required (agent|server|dashboard|wifi|infra|bug|idea|hardware-verify)"
    args=(--title "$title" --label "$label")
    if [[ -n "$body_file" ]]; then args+=(--body-file "$body_file")
    else args+=(--body "${body:-_(no description yet)_}"); fi
    gh issue create "${args[@]}"
    ;;

  comment)
    n="${1:-}"; text="${2:-}"
    [[ -z "$n" || -z "$text" ]] && die "usage: issues.sh comment <number> <text>"
    gh issue comment "$n" --body "$text"
    ;;

  edit)
    n="${1:-}"; shift || true
    [[ -z "$n" ]] && die "usage: issues.sh edit <number> [--title T] [--body B] [--add-label L]"
    args=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --title) args+=(--title "$2"); shift 2 ;;
        --body) args+=(--body "$2"); shift 2 ;;
        --add-label) args+=(--add-label "$2"); shift 2 ;;
        --remove-label) args+=(--remove-label "$2"); shift 2 ;;
        *) die "unknown flag: $1" ;;
      esac
    done
    [[ ${#args[@]} -eq 0 ]] && die "nothing to change"
    gh issue edit "$n" "${args[@]}"
    ;;

  close)
    n="${1:-}"; reason="${2:-}"
    [[ -z "$n" ]] && die "usage: issues.sh close <number> [reason]"
    [[ -n "$reason" ]] && gh issue comment "$n" --body "$reason"
    gh issue close "$n"
    ;;

  labels)
    gh label list --limit 50
    ;;

  *) die "unknown command: $cmd (try --help)" ;;
esac

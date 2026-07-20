#!/usr/bin/env bash
# Install local git hooks.
#
# Branch protection on main needs GitHub Pro or a public repo (issue #20), so until
# then the "no direct pushes to main" rule is enforced here instead. Client-side and
# bypassable with --no-verify, but it catches the accident, which is the common case.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="$REPO_ROOT/.git/hooks/pre-push"

cat > "$HOOK" <<'HOOK_EOF'
#!/usr/bin/env bash
# Blocks direct pushes to main. Changes land via gated PRs; see scripts/pr.sh.
set -euo pipefail

while read -r _local_ref _local_sha remote_ref _remote_sha; do
  if [[ "$remote_ref" == "refs/heads/main" ]]; then
    echo "✋ Direct push to main is blocked." >&2
    echo "   Branch, then: ./scripts/pr.sh create \"<title>\" --closes <issue>" >&2
    echo "   (override with --no-verify only if you know why)" >&2
    exit 1
  fi
done
HOOK_EOF

chmod +x "$HOOK"
echo "✅ installed pre-push hook at .git/hooks/pre-push"

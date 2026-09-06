#!/usr/bin/env bash
# Install the repo's git hooks into .git/hooks (which is not versioned, so
# this has to be run once per clone).
#
# Uses .git/hooks directly rather than core.hooksPath, because setting
# core.hooksPath would disable any hook already installed there.
set -euo pipefail

repo_root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
hook="$repo_root/.git/hooks/pre-commit"

if [ -e "$hook" ] && ! grep -q "check-screenshots.sh" "$hook"; then
  echo "a pre-commit hook already exists and is not ours: $hook" >&2
  echo "add this line to it by hand instead:" >&2
  echo '  "$(git rev-parse --show-toplevel)"/scripts/check-screenshots.sh' >&2
  exit 1
fi

cat > "$hook" <<'HOOK'
#!/usr/bin/env bash
exec "$(git rev-parse --show-toplevel)"/scripts/check-screenshots.sh
HOOK

chmod +x "$hook"
echo "installed: .git/hooks/pre-commit"

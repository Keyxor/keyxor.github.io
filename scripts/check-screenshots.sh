#!/usr/bin/env bash
# Pre-commit gate on images. Blocks three things that are painful to undo once
# they are in the history:
#
#   1. Identifying metadata (GPS, camera serial, author, host name).
#   2. Raw captures - anything under a _raw/ path or named *.raw.*.
#   3. Oversized files, which usually means an unresized original slipped in.
#
# Bypass for a deliberate exception: git commit --no-verify
set -euo pipefail

max_bytes=$((2 * 1024 * 1024))

# Tags worth blocking on. Software/ImageDescription are left alone - a
# screenshot tool's name is not sensitive and blocking it is noise.
blocked_tags='GPSLatitude|GPSLongitude|GPSPosition|SerialNumber|InternalSerialNumber|OwnerName|Artist|Creator|By-line|XPAuthor|UserComment|HostComputer|Make|Model'

staged=$(git diff --cached --name-only --diff-filter=ACM | grep -Ei '\.(png|jpe?g|gif|webp|tiff?|bmp|avif)$' || true)
[ -z "$staged" ] && exit 0

command -v exiftool >/dev/null || {
  echo "check-screenshots: exiftool not installed, cannot verify image metadata." >&2
  echo "  sudo apt install libimage-exiftool-perl" >&2
  echo "  (or commit with --no-verify if you have checked the images yourself)" >&2
  exit 1
}

fail=0
while IFS= read -r f; do
  [ -f "$f" ] || continue

  case "$f" in
    *_raw/*|*.raw.*|*/screenshots-raw/*)
      echo "BLOCKED $f" >&2
      echo "        raw capture - scrub it and add it with scripts/add-screenshot.sh" >&2
      fail=1
      continue
      ;;
  esac

  size=$(stat -c %s "$f")
  if [ "$size" -gt "$max_bytes" ]; then
    echo "BLOCKED $f" >&2
    echo "        $((size / 1024)) KB exceeds the ${max_bytes}-byte cap - crop or downscale it" >&2
    fail=1
  fi

  # Read the staged content, not the working tree, so a scrub that was never
  # staged cannot pass the check.
  tmp=$(mktemp --suffix=".${f##*.}")
  git show ":$f" > "$tmp"
  found=$(exiftool -S "$tmp" 2>/dev/null | grep -E "^($blocked_tags):" || true)
  rm -f "$tmp"

  if [ -n "$found" ]; then
    echo "BLOCKED $f" >&2
    echo "$found" | sed 's/^/        /' >&2
    echo "        run: scripts/scrub-image.sh $f && git add $f" >&2
    fail=1
  fi
done <<< "$staged"

[ "$fail" -eq 0 ] || {
  echo >&2
  echo "commit aborted by scripts/check-screenshots.sh" >&2
  exit 1
}

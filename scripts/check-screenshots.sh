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

staged=()
while IFS= read -r -d '' f; do
  case "${f,,}" in
    *.png|*.jpg|*.jpeg|*.gif|*.webp|*.tif|*.tiff|*.bmp|*.avif) staged+=("$f") ;;
  esac
done < <(git diff --cached --name-only -z --diff-filter=ACMR)
[ "${#staged[@]}" -eq 0 ] && exit 0

command -v exiftool >/dev/null || {
  echo "check-screenshots: exiftool not installed, cannot verify image metadata." >&2
  echo "  sudo apt install libimage-exiftool-perl" >&2
  echo "  (or commit with --no-verify if you have checked the images yourself)" >&2
  exit 1
}

fail=0
tmp=""
trap 'if [ -n "$tmp" ]; then rm -f -- "$tmp"; fi' EXIT
for f in "${staged[@]}"; do

  case "$f" in
    *_raw/*|*.raw.*|screenshots-raw/*|*/screenshots-raw/*)
      echo "BLOCKED $f" >&2
      echo "        raw capture - scrub it and add it with scripts/add-screenshot.sh" >&2
      fail=1
      continue
      ;;
  esac

  # Check the exact bytes being committed, even if the working copy has been
  # resized, scrubbed, or deleted since it was staged.
  tmp=$(mktemp --suffix=".${f##*.}")
  git show ":$f" > "$tmp"
  size=$(stat -c %s "$tmp")
  if [ "$size" -gt "$max_bytes" ]; then
    echo "BLOCKED $f" >&2
    echo "        $((size / 1024)) KB exceeds the ${max_bytes}-byte cap - crop or downscale it" >&2
    fail=1
  fi

  found=$(exiftool -S "$tmp" 2>/dev/null | grep -E "^($blocked_tags):" || true)
  rm -f -- "$tmp"
  tmp=""

  if [ -n "$found" ]; then
    echo "BLOCKED $f" >&2
    echo "$found" | sed 's/^/        /' >&2
    echo "        run: scripts/scrub-image.sh $f && git add $f" >&2
    fail=1
  fi
done

[ "$fail" -eq 0 ] || {
  echo >&2
  echo "commit aborted by scripts/check-screenshots.sh" >&2
  exit 1
}

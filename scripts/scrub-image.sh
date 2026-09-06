#!/usr/bin/env bash
# Strip every metadata tag from an image, in place.
#
# The render hook keeps EXIF off the published site, but a screenshot that
# reaches a commit is in the history for good - and history outlives any
# later fix. Scrub before the file ever enters the repo.
set -euo pipefail

if [ $# -eq 0 ]; then
  echo "usage: $0 <image> [image...]" >&2
  exit 2
fi

command -v exiftool >/dev/null || { echo "exiftool not installed: sudo apt install libimage-exiftool-perl" >&2; exit 1; }

exiftool -quiet -all= -overwrite_original "$@"
echo "scrubbed: $*"

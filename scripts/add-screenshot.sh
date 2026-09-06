#!/usr/bin/env bash
# Move a screenshot from the raw staging area into a writeup's page bundle,
# stripping metadata on the way in.
#
#   scripts/add-screenshot.sh ~/website-in-progress/screenshots-raw/boxname/shot.png boxname
#   scripts/add-screenshot.sh shot.png boxname login-form.png    # rename on copy
#
# Raw captures stay outside the repo. Only the scrubbed copy is committed, and
# only the resized variant the render hook produces is published.
set -euo pipefail

src="${1:-}"
slug="${2:-}"
name="${3:-$(basename "${src:-x}")}"
section="${SECTION:-offensive}"

if [ -z "$src" ] || [ -z "$slug" ]; then
  echo "usage: $0 <raw-image> <writeup-slug> [new-name]" >&2
  echo "       SECTION=projects $0 ...   # non-default section" >&2
  exit 2
fi

repo_root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
bundle="$repo_root/content/$section/$slug"

[ -f "$src" ] || { echo "no such file: $src" >&2; exit 1; }
[ -d "$bundle" ] || { echo "no such bundle: $bundle" >&2; echo "create the writeup first: hugo new $section/$slug/index.md" >&2; exit 1; }

# exiftool refuses to write a file whose extension disagrees with its content,
# so a rename has to keep the original extension.
src_ext="${src##*.}"
if [ "${name##*.}" != "$src_ext" ]; then
  echo "new name must keep the .$src_ext extension: $name" >&2
  exit 1
fi

dest="$bundle/$name"
[ -e "$dest" ] && { echo "already exists: $dest" >&2; exit 1; }

# Leave nothing behind if the scrub fails - a copied but unscrubbed file next
# to the post is exactly what this script exists to prevent.
cp "$src" "$dest"
trap 'rm -f "$dest"' ERR
"$(dirname "$0")/scrub-image.sh" "$dest" >/dev/null
trap - ERR

echo "added: content/$section/$slug/$name"
echo
echo "reference it in index.md as:"
echo "  ![describe what the screenshot shows]($name)"

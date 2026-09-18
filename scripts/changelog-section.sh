#!/usr/bin/env bash
#
# Print one version's section of CHANGELOG.md, and fail if there is not one.
#
# Used by the release workflow BEFORE anything is built or signed, so a tag
# with no changelog entry stops at the first job rather than after a human has
# approved the signing certificate. The point is not tidiness: a release whose
# notes say only how to verify the binary tells a downloader nothing about what
# they are installing, and that is the state every release was in until now.
#
#   usage: scripts/changelog-section.sh v0.1.8 [CHANGELOG.md]
#
# The tag may be given with or without its leading "v". Headings are matched as
# "## [0.1.8]" or "## 0.1.8", with anything after the version (a date, a name)
# ignored, so the file can carry link-reference versions or plain ones.
set -euo pipefail

tag="${1:?usage: changelog-section.sh <tag> [file]}"
file="${2:-CHANGELOG.md}"
version="${tag#v}"

if [ ! -f "$file" ]; then
  echo "changelog: $file does not exist" >&2
  exit 1
fi

# awk rather than sed: the section runs from its own heading to the NEXT
# level-two heading, and that is a state machine rather than a line match.
section=$(
  awk -v want="$version" '
    # A level-two heading. Strip "## ", optional "[", the version, optional
    # "]", and compare. Anything after the version is ignored.
    /^## / {
      line = substr($0, 4)
      sub(/^\[/, "", line)
      v = line
      sub(/\].*$/, "", v)
      sub(/[[:space:]].*$/, "", v)
      sub(/\]$/, "", v)
      if (v == want) { inside = 1; next }
      if (inside) { exit }
      next
    }
    inside { print }
  ' "$file"
)

# Trim leading and trailing blank lines without disturbing the middle.
section=$(printf '%s\n' "$section" | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;};/\n$/ba')

if [ -z "$section" ]; then
  {
    echo "changelog: $file has no section for $version."
    echo
    echo "Add one before tagging. The heading must be '## [$version] - <date>'"
    echo "or '## $version - <date>'. Sections present:"
    grep -E '^## ' "$file" | sed 's/^/  /' || true
  } >&2
  exit 1
fi

printf '%s\n' "$section"

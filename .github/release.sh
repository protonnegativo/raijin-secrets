#!/usr/bin/env bash
# Tags HEAD with the next release (v0.1.0 when there is no tag yet) and creates a GitHub Release.
# Usage: .github/release.sh [patch|minor|major] [base-sha]
# With a base sha (the commit before a push), it skips when the push only touched files that do not
# change the binary. engines.json does release, since the binary embeds it. Needs GH_TOKEN.
set -euo pipefail

bump=${1:-patch}
base=${2:-}

git fetch --tags --force --quiet origin || true

if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged: $(git tag --points-at HEAD 'v*' | tr '\n' ' ')"
  exit 0
fi

if [ -n "$base" ] && git cat-file -e "$base^{commit}" 2>/dev/null; then
  changed=$(git diff --name-only "$base" HEAD | grep -vE '^bench/fixtures/|\.md$|^docs/|^\.github/' || true)
  if [ -z "$changed" ]; then
    echo "only fixtures, docs or workflows changed; no release"
    exit 0
  fi
fi

last=$(git tag --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
if [ -z "$last" ]; then
  next=v0.1.0
else
  IFS=. read -r major minor patch <<<"${last#v}"
  case "$bump" in
    major) next="v$((major + 1)).0.0" ;;
    minor) next="v$major.$((minor + 1)).0" ;;
    patch) next="v$major.$minor.$((patch + 1))" ;;
    *) echo "unknown bump: $bump" >&2; exit 1 ;;
  esac
fi

git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  tag -a "$next" -m "$next"
git push origin "$next"
gh release create "$next" --generate-notes --verify-tag
echo "released $next"

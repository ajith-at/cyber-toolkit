#!/usr/bin/env bash
# Publish the Cyber Toolkit runtime files to https://u51.org/toolkit/
# u51.org is GitHub Pages from ajith-at/cyber-daily-australia (branch main, root). Rules agreed with that repo's owner:
#   - only add or update the top-level /toolkit/ folder (never CNAME, .nojekyll, index.html, feed.xml, /tools, /episodes)
#   - never push between 06:30 and 07:30 Melbourne time (the daily episode publish window)
#   - always `git pull --rebase` before pushing; normal push only, never force
#
# Usage: ./deploy-u51.sh            (uses $CDA_DIR or /tmp/cda; clones it if missing)
#        DRY_RUN=1 ./deploy-u51.sh  (stage and show the diff, then stop without committing)
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDA_DIR="${CDA_DIR:-/tmp/cda}"
CDA_REMOTE="https://github.com/ajith-at/cyber-daily-australia.git"
RUNTIME=(index.html favicon.svg css js modules LICENSE)
GIT_NAME="Ajith Thamarakshan"
GIT_EMAIL="30002012+ajith-at@users.noreply.github.com"

die() { echo "deploy-u51: $*" >&2; exit 1; }

check_window() {
  local hm
  hm=$(TZ=Australia/Melbourne date +%H%M)
  if (( 10#$hm >= 630 && 10#$hm < 730 )); then
    die "it is $(TZ=Australia/Melbourne date +%H:%M) in Melbourne. No pushes between 06:30 and 07:30. Try again after 07:30."
  fi
}

check_window

# --- source checks: deploy only committed, pushed code so the commit message points at a real public sha
cd "$SRC"
[[ -z "$(git status --porcelain -- "${RUNTIME[@]}")" ]] || die "uncommitted changes in runtime files of $SRC. Commit them first."
git fetch -q origin main
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || die "HEAD is not the same as origin/main. Push (or pull) cyber-toolkit first."
SHA=$(git rev-parse --short HEAD)
VERSION=$(grep -oE 'v[0-9]+\.[0-9]+(\.[0-9]+)?' index.html | head -1)
[[ -n "$VERSION" ]] || VERSION="v0"

# --- target repo
if [[ ! -d "$CDA_DIR/.git" ]]; then
  git clone -q "$CDA_REMOTE" "$CDA_DIR"
fi
cd "$CDA_DIR"
[[ "$(git remote get-url origin)" == "$CDA_REMOTE" || "$(git remote get-url origin)" == "${CDA_REMOTE%.git}" ]] || die "$CDA_DIR is not a clone of $CDA_REMOTE"
[[ "$(git rev-parse --abbrev-ref HEAD)" == "main" ]] || die "$CDA_DIR is not on main"
[[ -z "$(git status --porcelain)" ]] || die "$CDA_DIR has uncommitted changes. Leave it clean and retry."
git config user.name "$GIT_NAME"
git config user.email "$GIT_EMAIL"
git pull -q --rebase origin main

# --- sync: replace only ./toolkit
rm -rf "$CDA_DIR/toolkit"
mkdir -p "$CDA_DIR/toolkit"
for f in "${RUNTIME[@]}"; do cp -R "$SRC/$f" "$CDA_DIR/toolkit/"; done
git add -A -- toolkit

# guard: nothing outside toolkit/ may be staged
if git diff --cached --name-only | grep -v '^toolkit/' | grep -q .; then
  git reset -q
  die "refusing: changes outside toolkit/ were staged"
fi
if git diff --cached --quiet; then
  echo "deploy-u51: toolkit/ already matches $SHA. Nothing to do."
  exit 0
fi
git diff --cached --stat
if [[ -n "${DRY_RUN:-}" ]]; then
  git reset -q
  git checkout -q -- toolkit 2>/dev/null || true
  git clean -fdq -- toolkit
  echo "deploy-u51: dry run, nothing committed."
  exit 0
fi

git commit -q -m "Add Cyber Toolkit $VERSION at /toolkit (from ajith-at/cyber-toolkit $SHA)"
git pull -q --rebase origin main
check_window
git push origin main
echo "deploy-u51: pushed $(git rev-parse --short HEAD). GitHub Pages usually updates within a minute or two: https://u51.org/toolkit/"

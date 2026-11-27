#!/usr/bin/env bash
# Prepare articles for a GitHub Wiki checkout. Review its Git diff before publishing.
set -euo pipefail
destination="${1:?Укажите каталог локального клона ismanager.wiki.git}"
source_dir="$(cd "$(dirname "$0")/../wiki" && pwd)"
remote="$(git -C "$destination" remote get-url origin)"
case "$remote" in
  https://github.com/calleograph/ismanager.wiki.git|git@github.com:calleograph/ismanager.wiki.git) ;;
  *) echo 'Укажите каталог клона calleograph/ismanager.wiki.git.' >&2; exit 1 ;;
esac
for article in "$source_dir"/*.md; do
  sed -E \
    -e 's@\]\(([A-Za-z0-9_-]+)\.md(#[^)]*)?\)@](https://github.com/calleograph/ismanager/wiki/\1\2)@g' \
    -e 's@\]\(img/([^)]*)\)@](https://raw.githubusercontent.com/wiki/calleograph/ismanager/img/\1)@g' \
    "$article" > "$destination/$(basename "$article")"
done
mkdir -p "$destination/img"
cp "$source_dir"/img/* "$destination/img/"

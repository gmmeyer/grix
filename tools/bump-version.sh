#!/bin/sh
# Bump grix's version (patch: 0.0.1 -> 0.0.2), or set it: every commit
# to main gets its own release (.github/workflows/release.yml).
#
#   tools/bump-version.sh          # the next patch version
#   tools/bump-version.sh 0.1.0    # this one
set -eu
cd "$(dirname "$0")/.."
old=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if [ $# -gt 0 ]; then
    new=$1
else
    new=$(echo "$old" | awk -F. '{ printf "%d.%d.%d", $1, $2, $3 + 1 }')
fi
echo "$new" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "bad version $new" >&2; exit 1; }
for f in Cargo.toml kernel/Cargo.toml python/pyproject.toml; do
    sed -i.bak "s/^version = \"$old\"$/version = \"$new\"/" "$f" && /bin/rm -f "$f.bak"
done
# The lock files name the workspace's own packages' versions too.
cargo update -w --offline -q 2>/dev/null || cargo update -w -q
(cd kernel && { cargo update -w --offline -q 2>/dev/null || cargo update -w -q; })
echo "$old -> $new"

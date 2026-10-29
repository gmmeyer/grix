#!/usr/bin/env bash
# Put web/dist on grixos.dev: the page, the runner, QEMU and the kernel on
# Cloudflare Pages (which sends _headers), the examples' programs and root
# filesystems in R2 (Pages takes files up to 25 MiB; Node's is more).
#
#   web/build.sh
#   CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... web/deploy.sh
#
# Done once, already: the R2 bucket with a CORS policy allowing GET from
# anywhere, on files.grixos.dev; the Pages project, on grixos.dev.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${CLOUDFLARE_API_TOKEN:?}" "${CLOUDFLARE_ACCOUNT_ID:?}"
BUCKET=${BUCKET:-grixos-files}
FILES_URL=${FILES_URL:-https://files.grixos.dev/}
PROJECT=${PROJECT:-grixos}
WRANGLER=(npx --yes wrangler@4.20.0)
DIST=web/dist
SITE=web/.cache/site

for f in "$DIST"/bin/* "$DIST"/rootfs/*; do
    key=${f#"$DIST/"}
    case $f in
        *.tar.gz) type=application/gzip ;;
        *) type=application/octet-stream ;;
    esac
    "${WRANGLER[@]}" r2 object put "$BUCKET/$key" --file "$f" --content-type "$type" \
        --cache-control "public, max-age=3600" --remote
done

# The site: everything but the files (and the smoke test, which wants them
# beside it), with the page told where they are.
rm -rf "$SITE"
mkdir -p "$SITE"
(cd "$DIST" && tar --exclude ./bin --exclude ./rootfs --exclude ./smoke.html -cf - .) | tar -C "$SITE" -xf -
sed -i "s|<script src=\"coi-serviceworker.js\"></script>|<meta name=\"grix-files\" content=\"$FILES_URL\">\n&|" "$SITE/index.html"
grep -q 'name="grix-files"' "$SITE/index.html"
"${WRANGLER[@]}" pages deploy "$SITE" --project-name "$PROJECT" --branch main --commit-dirty=true

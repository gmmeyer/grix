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
find "$SITE" -name '*.html' -print0 | while IFS= read -r -d '' page; do
    sed -i "s|<script src=\"/coi-serviceworker.js\"></script>|<meta name=\"grix-files\" content=\"$FILES_URL\">\n&|" "$page"
    grep -q 'name="grix-files"' "$page"
done
# grixos.dev's zone has browsers keep .js and .css for 4 hours (its Browser
# Cache TTL), but not the pages: the pages name this deploy's code, so a
# new deploy is new URLs, fetched at once.
stamp=$(cat "$SITE"/grix-example.js "$SITE"/grix.js "$SITE"/tar.js "$SITE"/site.css | sha256sum | cut -c1-12)
sed -i "s|from './grix.js'|from './grix.js?v=$stamp'|; s|from './tar.js'|from './tar.js?v=$stamp'|" "$SITE/grix-example.js"
grep -q "grix.js?v=$stamp" "$SITE/grix-example.js"
find "$SITE" -name '*.html' -print0 | while IFS= read -r -d '' page; do
    sed -i "s|href=\"/site.css\"|href=\"/site.css?v=$stamp\"|; s|src=\"/grix-example.js\"|src=\"/grix-example.js?v=$stamp\"|" "$page"
    grep -q "grix-example.js?v=$stamp" "$page"
done
"${WRANGLER[@]}" pages deploy "$SITE" --project-name "$PROJECT" --branch main --commit-dirty=true

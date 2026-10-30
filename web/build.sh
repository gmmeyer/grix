#!/usr/bin/env bash
# grix in a web page: assemble web/dist, the files to serve.
#
#   web/build.sh            # everything (QEMU-wasm only if it isn't built yet)
#   node web/serve.mjs      # then http://localhost:8080/ (with COOP/COEP)
#
# Needs the fixtures built (`make fixtures`), Rust's
# wasm32-unknown-unknown target, Docker (QEMU-wasm builds in emscripten's
# image, about 15 minutes the first time) and npm (xterm.js).
set -euo pipefail
cd "$(dirname "$0")/.."

DIST=web/dist
CACHE=web/.cache
# QEMU 8.2 with a TCG backend that emits wasm (https://github.com/ktock/qemu-wasm).
QEMU_WASM_REPO=https://github.com/ktock/qemu-wasm
QEMU_WASM_COMMIT=0ef7b4e2814b231705d8371dd7997f5b72e70baf
KERNEL=kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel
FIX=fixtures/build

mkdir -p "$DIST" "$CACHE"

if [ ! -f "$DIST/qemu-system-aarch64.wasm" ] || [ "${REBUILD_QEMU:-}" = 1 ]; then
    src="$CACHE/qemu-wasm"
    if [ ! -d "$src/.git" ]; then
        git clone "$QEMU_WASM_REPO" "$src"
    fi
    git -C "$src" fetch -q origin "$QEMU_WASM_COMMIT" || true
    git -C "$src" checkout -q -f "$QEMU_WASM_COMMIT"
    # Ours: guest RAM without emscripten's mmap writing all of it first.
    git -C "$src" apply "$PWD/web/qemu-wasm.patch"
    # zlib.net keeps only the newest release; the same tarball is on GitHub.
    sed 's#https://zlib.net/zlib-\$ZLIB_VERSION.tar.xz#https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.xz#' \
        "$src/Dockerfile" | docker build -t grix-qemu-wasm-build -
    # The emscripten flags are qemu-wasm's README's, with less memory (the
    # guest gets at most 1 GiB) and Node allowed too. Its TTY goes through
    # xterm-pty's emscripten library, which web/grix.js speaks to carry the
    # console instead.
    flags="-O3 -Wno-error=unused-command-line-argument -matomics -mbulk-memory -DNDEBUG -DG_DISABLE_ASSERT \
-D_GNU_SOURCE -sASYNCIFY=1 -pthread -sPROXY_TO_PTHREAD=1 -sFORCE_FILESYSTEM -sALLOW_TABLE_GROWTH \
-sTOTAL_MEMORY=1536MB -sWASM_BIGINT -sMALLOC=mimalloc --js-library=/build/node_modules/xterm-pty/emscripten-pty.js \
-sEXPORT_ES6=1 -sASYNCIFY_IMPORTS=ffi_call_js -sENVIRONMENT=web,worker,node -sEXIT_RUNTIME=1"
    docker run --rm -v "$PWD/$src:/qemu" -v "$PWD/$DIST:/out" grix-qemu-wasm-build bash -c "
        set -e
        git config --global --add safe.directory '*'
        cd /build
        emconfigure /qemu/configure --static --target-list=aarch64-softmmu --cpu=wasm32 --cross-prefix= \
            --without-default-features --enable-system --with-coroutine=fiber \
            --extra-cflags='$flags' --extra-cxxflags='$flags' \
            --extra-ldflags='-sEXPORTED_RUNTIME_METHODS=getTempRet0,setTempRet0,addFunction,removeFunction,TTY,FS'
        emmake make -j\$(nproc) qemu-system-aarch64
        cp qemu-system-aarch64 /out/qemu-system-aarch64.js
        cp qemu-system-aarch64.wasm qemu-system-aarch64.worker.js /out/
    "
fi

# The kernel, without its debug info (a tenth the size). It's a cargo
# workspace of its own, so nothing else here would rebuild it, and a page
# would go out with whatever kernel was last built.
make kernel
python3 -I web/tools/strip-elf.py "$KERNEL" "$DIST/grix-kernel"

# The host's side: grix-web.
cargo build -q --release -p grix-web --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/grix_web.wasm "$DIST/"

# The site: grixos.dev's pages (the project, the demos, the blog) and the
# runner they use.
cp web/grix.js web/tar.js web/grix-example.js web/site.css web/index.html web/smoke.html "$DIST/"
rm -rf "$DIST/demos" "$DIST/blog"
cp -r web/demos web/blog "$DIST/"
# grix's icon (web/tools/icon.py draws it), at the root where browsers look,
# and the cards shared links show (web/tools/card.html).
cp web/icons/* "$DIST/"

# Cloudflare Pages (and Netlify) take headers from _headers: isolation for
# a page served here, and CORS and CORP so pages elsewhere can use the files.
cat > "$DIST/_headers" <<'END'
/*
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  Cross-Origin-Resource-Policy: cross-origin
  Access-Control-Allow-Origin: *
END

# Where headers can't be set (GitHub Pages), coi-serviceworker makes the
# page cross-origin isolated. A page that already is, it leaves alone.
if [ ! -f "$DIST/coi-serviceworker.js" ]; then
    tmp=$(mktemp -d)
    (cd "$tmp" && npm pack -q coi-serviceworker@0.1.7 >/dev/null && tar xzf coi-serviceworker-0.1.7.tgz)
    cp "$tmp/package/coi-serviceworker.js" "$DIST/"
    rm -rf "$tmp"
fi

# xterm.js, for the terminal example.
if [ ! -f "$DIST/vendor/xterm.js" ]; then
    tmp=$(mktemp -d)
    (cd "$tmp" && npm pack -q @xterm/xterm@5.5.0 >/dev/null && tar xzf xterm-xterm-5.5.0.tgz)
    mkdir -p "$DIST/vendor"
    cp "$tmp/package/lib/xterm.js" "$tmp/package/css/xterm.css" "$DIST/vendor/"
    rm -rf "$tmp"
fi

# The examples' programs.
mkdir -p "$DIST/bin" "$DIST/rootfs"
for f in hello net threads goexec smp; do
    cp "$FIX/$f" "$DIST/bin/"
done
cp "$FIX/alpine/bin/busybox.static" "$DIST/bin/busybox"
# Python with its standard library compiled ahead (the guest would compile
# what it imports on every run), less the tests, IDLE and Tk.
py="$CACHE/python"
rm -rf "$py"
cp -a "$FIX/python" "$py"
(cd "$py/usr/lib/python3.12" && rm -rf test idlelib tkinter ensurepip pydoc_data lib2to3 turtledemo turtle.py)
# Bytecode is the version's own: only a host Python 3.12 can make it.
if python3 -I -c 'import sys; sys.exit(sys.version_info[:2] != (3, 12))'; then
    python3 -I -m compileall -q -j0 --invalidation-mode unchecked-hash "$py/usr/lib/python3.12" >/dev/null || true
fi
tar -C "$py" -czf "$DIST/rootfs/python.tar.gz" .
tar -C "$FIX/node" -czf "$DIST/rootfs/node.tar.gz" .
# bash, with busybox for everything else. Alpine makes busybox's links when
# it installs it; here grix asks busybox for the list, and links what's
# not there.
sh_root="$CACHE/bash"
rm -rf "$sh_root"
python3 -I tools/alpine.py --out "$sh_root" bash busybox
./target/release/grix run --arch aarch64 -i "$sh_root:/" -- /bin/busybox --list-full | while read -r applet; do
    if [ ! -e "$sh_root/$applet" ] && [ ! -L "$sh_root/$applet" ]; then
        mkdir -p "$(dirname "$sh_root/$applet")"
        ln -s /bin/busybox "$sh_root/$applet"
    fi
done
tar -C "$sh_root" -czf "$DIST/rootfs/bash.tar.gz" .

du -sh "$DIST"

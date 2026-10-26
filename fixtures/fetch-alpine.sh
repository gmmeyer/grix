#!/bin/sh
# Fetch real-world prebuilt Linux binaries (Alpine aarch64 packages), pinned by sha256:
#   build/alpine/busybox.static   static busybox
#   build/alpine/busybox          dynamically linked (PIE) busybox
#   build/alpine/lib/             musl dynamic loader + libc
set -eu
cd "$(dirname "$0")"
MIRROR=https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64
OUT=build/alpine
mkdir -p "$OUT/lib"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() { # name version sha256
    apk="$tmp/$1.apk"
    curl -sSfL -o "$apk" "$MIRROR/$1-$2.apk"
    echo "$3  $apk" | shasum -a 256 -c - >/dev/null
    mkdir -p "$tmp/$1"
    tar xzf "$apk" -C "$tmp/$1" 2>/dev/null || true
}

fetch busybox-static 1.37.0-r20 ee469aee2958feffd7f64dd96655704025ff60af614f77a1d7323dc237c34da2
fetch busybox 1.37.0-r20 9d25af67564c92a4a4c603462efdbcd23019e90b8785f1ebcad640cbb1551c93
fetch musl 1.2.5-r13 d616c430bcbe0bf452b7f6ea2669f2cad14e85644a7599f4f495115d021742ef

cp "$tmp/busybox-static/bin/busybox.static" "$OUT/busybox.static"
cp "$tmp/busybox/bin/busybox" "$OUT/busybox"
cp -P "$tmp/musl/lib/"* "$OUT/lib/"
echo "fetched: busybox.static busybox lib/$(ls "$OUT/lib" | tr '\n' ' ')"

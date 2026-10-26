#!/bin/sh
# Build the test programs as static AArch64 Linux binaries (musl) with zig.
set -eu
cd "$(dirname "$0")"
mkdir -p build
for src in src/*.c; do
    name=$(basename "$src" .c)
    zig cc -target aarch64-linux-musl -static -O2 -s -o "build/$name" "$src"
done
# A position-independent static executable (ET_DYN, self-relocating).
zig cc -target aarch64-linux-musl -static-pie -fPIE -O2 -s -o build/hello-pie src/hello.c
echo "built: $(ls build | tr '\n' ' ')"

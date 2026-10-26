#!/bin/sh
# Build the test programs as static AArch64 Linux binaries: C with zig (musl), Go with go.
set -eu
cd "$(dirname "$0")"
mkdir -p build
for src in src/*.c; do
    name=$(basename "$src" .c)
    zig cc -target aarch64-linux-musl -static -O2 -s -o "build/$name" "$src"
done
# A position-independent static executable (ET_DYN, self-relocating).
zig cc -target aarch64-linux-musl -static-pie -fPIE -O2 -s -o build/hello-pie src/hello.c
# Go programs: static, cross-compiled with the host's Go toolchain.
for dir in go/*/; do
    name=$(basename "$dir")
    (cd go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags=-s -o "../build/go$name" "./$name")
done
echo "built: $(ls build | tr '\n' ' ')"

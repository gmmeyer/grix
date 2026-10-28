#!/bin/sh
# Build the test programs as static AArch64 (and, in build/amd64, x86_64)
# Linux binaries: C with zig (musl), Go with go.
set -eu
cd "$(dirname "$0")"
mkdir -p build
for src in src/*.c; do
    name=$(basename "$src" .c)
    zig cc -target aarch64-linux-musl -static -O2 -s -o "build/$name" "$src"
done
# A position-independent static executable (ET_DYN, self-relocating).
zig cc -target aarch64-linux-musl -static-pie -fPIE -O2 -s -o build/hello-pie src/hello.c
# An x86_64 program, for the x86_64 translator (`SandboxBuilder::x86_64`).
zig cc -target x86_64-linux-musl -static -O2 -s -o build/hello-x86_64 src/hello.c
# Go programs: static, cross-compiled with the host's Go toolchain.
for dir in go/*/; do
    name=$(basename "$dir")
    (cd go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags=-s -o "../build/go$name" "./$name")
done
# The same for the x86_64 kernel (`Arch::X86_64`), in build/amd64.
mkdir -p build/amd64
for src in src/*.c; do
    name=$(basename "$src" .c)
    zig cc -target x86_64-linux-musl -static -O2 -s -o "build/amd64/$name" "$src"
done
zig cc -target x86_64-linux-musl -static-pie -fPIE -O2 -s -o build/amd64/hello-pie src/hello.c
for dir in go/*/; do
    name=$(basename "$dir")
    (cd go && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags=-s -o "../build/amd64/go$name" "./$name")
done
echo "built: $(ls build | tr '\n' ' ')"

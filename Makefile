KERNEL := kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel
VMM := target/release/grix-vmm

.PHONY: all kernel host vmm python fixtures test test-kvm check clean

all: kernel host vmm python fixtures

# The arm64 kernel, and the x86_64 one (GRIX_ARCH=x86_64; QEMU microvm).
kernel:
	cd kernel && cargo build --release && cargo build --release --target x86_64-unknown-none

host:
	cargo build --release -p grix

# grix's own VMM (arm64 macOS 15+, arm64 Linux with KVM). Hypervisor.framework
# only runs programs signed with the hypervisor entitlement; an ad-hoc
# signature does.
vmm:
	cargo build --release -p grix-vmm
ifeq ($(shell uname -s),Darwin)
	codesign --sign - --entitlements crates/vmm/entitlements.plist --force $(VMM)
endif

# grix's native Python module, in place: python/grix/_native.abi3.so.
python:
	cargo build --release -p grix-python
	cp -f target/release/lib_native.$(if $(filter Darwin,$(shell uname -s)),dylib,so) python/grix/_native.abi3.so

fixtures:
	./fixtures/build.sh
	python3 -I tools/alpine.py --out fixtures/build/alpine busybox-static busybox
	python3 -I tools/alpine.py --out fixtures/build/python python3 ca-certificates-bundle
	python3 -I tools/alpine.py --out fixtures/build/node nodejs
	# qemu-x86_64 (user mode, static), to run x86_64 programs, and x86_64
	# Alpine to run with it.
	python3 -I tools/alpine.py --out fixtures/build/qemu-x86_64 qemu-x86_64
	python3 -I tools/alpine.py --arch x86_64 --out fixtures/build/x86_64 busybox python3
	# x86_64's own, for the x86_64 kernel (GRIX_ARCH=x86_64).
	python3 -I tools/alpine.py --arch x86_64 --out fixtures/build/alpine-x86_64 busybox-static busybox
	python3 -I tools/alpine.py --arch x86_64 --out fixtures/build/python-x86_64 python3 ca-certificates-bundle
	python3 -I tools/alpine.py --arch x86_64 --out fixtures/build/node-x86_64 nodejs
	# A Docker Hub image, as an OCI layout, for the image tests: arm64's
	# and amd64's (GRIX_ARCH=x86_64).
	cargo build --release -p grix
	./target/release/grix pull --arch aarch64 alpine:3.21 --oci fixtures/build/oci/alpine
	./target/release/grix pull --arch x86_64 alpine:3.21 --oci fixtures/build/oci-x86_64/alpine
	# glibc programs: Debian.
	./target/release/grix pull --arch aarch64 debian:bookworm-slim --oci fixtures/build/oci/debian
	./target/release/grix pull --arch x86_64 debian:bookworm-slim --oci fixtures/build/oci-x86_64/debian

test: kernel vmm python fixtures
	cargo test --workspace
	python3 -m unittest discover -s python/tests

# grix on KVM, from a Mac (M3+, macOS 15+): Linux with nested virtualization
# in QEMU, running static Linux builds of grix and grix-vmm. Needs zig.
test-kvm: kernel fixtures
	./tools/kvm-test.sh

# Lints for host and kernel.
check:
	cargo clippy --workspace --all-targets
	cd kernel && cargo clippy --release && cargo clippy --release --target x86_64-unknown-none

clean:
	cargo clean
	cd kernel && cargo clean
	rm -rf fixtures/build

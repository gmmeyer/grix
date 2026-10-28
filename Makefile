KERNEL := kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel
VMM := target/release/grix-vmm

.PHONY: all kernel host vmm fixtures test test-kvm check clean

all: kernel host vmm fixtures

kernel:
	cd kernel && cargo build --release

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

fixtures:
	./fixtures/build.sh
	python3 -I tools/alpine.py --out fixtures/build/alpine busybox-static busybox
	python3 -I tools/alpine.py --out fixtures/build/python python3 ca-certificates-bundle
	python3 -I tools/alpine.py --out fixtures/build/node nodejs
	# qemu-x86_64 (user mode, static), to run x86_64 programs.
	python3 -I tools/alpine.py --out fixtures/build/qemu-x86_64 qemu-x86_64
	# A Docker Hub image, as an OCI layout, for the image tests.
	cargo build --release -p grix
	./target/release/grix pull alpine:3.21 --oci fixtures/build/oci/alpine

test: kernel vmm fixtures
	cargo test --workspace
	python3 -m unittest discover -s python/tests

# grix on KVM, from a Mac (M3+, macOS 15+): Linux with nested virtualization
# in QEMU, running static Linux builds of grix and grix-vmm. Needs zig.
test-kvm: kernel fixtures
	./tools/kvm-test.sh

# Lints for host and kernel.
check:
	cargo clippy --workspace --all-targets
	cd kernel && cargo clippy --release

clean:
	cargo clean
	cd kernel && cargo clean
	rm -rf fixtures/build

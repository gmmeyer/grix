KERNEL := kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel

.PHONY: all kernel host fixtures test check clean

all: kernel host fixtures

kernel:
	cd kernel && cargo build --release

host:
	cargo build --release -p grix

fixtures:
	./fixtures/build.sh
	python3 -I tools/alpine.py --out fixtures/build/alpine busybox-static busybox
	python3 -I tools/alpine.py --out fixtures/build/python python3
	python3 -I tools/alpine.py --out fixtures/build/node nodejs

test: kernel fixtures
	cargo test --workspace

# Lints for host and kernel.
check:
	cargo clippy --workspace --all-targets
	cd kernel && cargo clippy --release

clean:
	cargo clean
	cd kernel && cargo clean
	rm -rf fixtures/build

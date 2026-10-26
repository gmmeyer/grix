KERNEL := kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel

.PHONY: all kernel host fixtures test check clean

all: kernel host fixtures

kernel:
	cd kernel && cargo build --release

host:
	cargo build --release -p grix

fixtures:
	./fixtures/build.sh
	./fixtures/fetch-alpine.sh

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

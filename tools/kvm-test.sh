#!/bin/sh
# grix on KVM, tested from a Mac: boot Alpine's Linux in QEMU with nested
# virtualization (Hypervisor.framework, M3 or later, macOS 15+), with an
# initramfs holding static Linux builds of grix and grix-vmm, the grix
# kernel and a few fixtures, and run programs in grix there, on /dev/kvm.
#
#   tools/kvm-test.sh        (or `make test-kvm`; needs zig and fixtures/build)
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/build/kvm
TARGET=aarch64-unknown-linux-musl
QEMU=${GRIX_QEMU:-qemu-system-aarch64}
mkdir -p "$OUT"

# zig compiles the C in dependencies (ring); cc-rs's --target means nothing to it.
cat > "$OUT/zigcc" <<'EOF'
#!/bin/sh
for a in "$@"; do shift; case "$a" in --target=*) ;; *) set -- "$@" "$a";; esac; done
exec zig cc -target aarch64-linux-musl "$@"
EOF
chmod +x "$OUT/zigcc"
CC_aarch64_unknown_linux_musl="$OUT/zigcc" AR_aarch64_unknown_linux_musl="zig ar" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    cargo build --release --target $TARGET -p grix -p grix-vmm

[ -f "$OUT/linux/boot/vmlinuz-virt" ] || python3 -I "$ROOT/tools/alpine.py" --out "$OUT/linux" linux-virt

INITRD=$OUT/initrd
rm -rf "$INITRD"
mkdir -p "$INITRD/bin" "$INITRD/dev" "$INITRD/proc" "$INITRD/tmp" "$INITRD/fixtures"
cp "$ROOT/target/$TARGET/release/grix" "$ROOT/target/$TARGET/release/grix-vmm" "$INITRD/bin/"
cp "$ROOT/fixtures/build/alpine/bin/busybox.static" "$INITRD/bin/busybox"
cp "$ROOT/kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel" "$INITRD/grix-kernel"
cp "$ROOT/fixtures/build/hello" "$ROOT/fixtures/build/threads" "$ROOT/fixtures/build/smp" "$INITRD/fixtures/"
cat > "$INITRD/init" <<'EOF'
#!/bin/busybox sh
export PATH=/bin GRIX_KERNEL=/grix-kernel TMPDIR=/tmp
busybox mount -t devtmpfs dev /dev
busybox mount -t proc proc /proc
busybox mount -t tmpfs tmp /tmp
echo "kvm: $(busybox ls /dev/kvm)"
grix run -i /fixtures/hello:/bin/hello -e GREETING=kvm -- /bin/hello world
echo "hello-status: $?"
echo "words: $(echo one two three | grix run -i /bin/busybox:/bin/busybox -- /bin/busybox wc -w)"
grix run -a threads -i /fixtures/threads:/bin/threads -- /bin/threads | busybox tail -1
grix run --cpus 2 -a threads -a process -i /fixtures/smp:/bin/smp -- /bin/smp
grix run --cpus 2 -a threads -a process -i /fixtures/smp:/bin/smp -- /bin/smp exec
grix run -a process --timeout 5 -i /bin/busybox:/bin/busybox -- /bin/busybox sh -c '/bin/busybox sleep 1; echo slept'
# Snapshots: a shell waiting for a line, and two CPUs with threads on both
# before and after.
grix snapshot -o /tmp/sh.snap -a process -i /bin/busybox:/bin/busybox -- \
    /bin/busybox sh -c 'read line; echo "snap got $line"; /bin/busybox head -c 4 /dev/urandom | /bin/busybox od -An -tx1'
echo one | grix run --snapshot /tmp/sh.snap
echo two | grix run --snapshot /tmp/sh.snap
grix snapshot -o /tmp/smp.snap --cpus 2 -a threads -a process -i /bin/busybox:/bin/busybox -i /fixtures/smp:/bin/smp -- \
    /bin/busybox sh -c '/bin/smp >/dev/null; read line; echo "smp snap got $line"; /bin/smp'
echo three | grix run --snapshot /tmp/smp.snap
echo KVM-TEST-DONE
busybox poweroff -f
EOF
chmod +x "$INITRD/init"
(cd "$INITRD" && find . | cpio -o -H newc 2>/dev/null | gzip -1 > "$OUT/initrd.gz")

LOG=$OUT/console.log
"$QEMU" -machine virt,virtualization=on,gic-version=3 -accel hvf -cpu host -smp 2 -m 2048 \
    -nographic -no-reboot -kernel "$OUT/linux/boot/vmlinuz-virt" -initrd "$OUT/initrd.gz" \
    -append "console=ttyAMA0 rdinit=/init quiet" < /dev/null > "$LOG" 2>&1 || true

fail=0
check() {
    if grep -q -- "$1" "$LOG"; then echo "ok: $1"; else echo "MISSING: $1"; fail=1; fi
}
check "kvm: /dev/kvm"
check "hello from grix! argc=2"
check "GREETING=kvm"
check "hello-status: 7"
check "words: 3"
check "threads ok counter=160000"
check "smp ok cpus=2"
check "exec ok"
check "slept"
check "snap got one"
check "snap got two"
check "smp snap got three"
[ "$(grep -c "smp ok cpus=2" "$LOG")" = 2 ] && echo "ok: smp ok cpus=2 after a restore" || { echo "MISSING: smp after a restore"; fail=1; }
check "KVM-TEST-DONE"
[ $fail = 0 ] || { echo "--- $LOG"; tail -40 "$LOG"; exit 1; }
echo "grix on KVM: all good"

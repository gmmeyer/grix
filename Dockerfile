# grix in a container: static grix and grix-vmm, the grix kernels, and QEMU.
# A run uses the host's KVM when the container has /dev/kvm, in grix's own
# VMM (arm64 or x86_64 Linux hosts), and emulates the machine in QEMU,
# many times slower, when it doesn't (saying so; GRIX_ACCEL=tcg chooses
# that):
#
#   docker build -t grix .
#   docker run --rm --device /dev/kvm -v "$PWD:/work" -w /work grix \
#       run -i ./hello:/bin/hello -- /bin/hello
#
# The `kvm-only` target is grix without QEMU, FROM scratch, which needs
# nothing from the container but /dev/kvm and /tmp (no shell, no libc):
#
#   docker build --target kvm-only -t grix:kvm-only .
#
# In Kubernetes, a pod gets /dev/kvm from a device plugin, not KubeVirt:
# see examples/kubernetes.

FROM rust:1-alpine AS build
# Set for releases: no paths from the build machine in the binaries.
ARG GRIX_RELEASE_BUILD
ENV GRIX_RELEASE_BUILD=$GRIX_RELEASE_BUILD
RUN apk add --no-cache build-base \
    && rustup target add aarch64-unknown-none-softfloat x86_64-unknown-none
WORKDIR /src
COPY . .
RUN cd kernel && cargo build --release && cargo build --release --target x86_64-unknown-none
# The kernels beside grix, where a release build looks for them.
RUN cargo build --release -p grix -p grix-vmm \
    && mkdir -p /out/bin /out/tmp \
    && cp target/release/grix target/release/grix-vmm /out/bin/ \
    && cp kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel /out/bin/ \
    && cp kernel/target/x86_64-unknown-none/release/grix-kernel /out/bin/grix-kernel-x86_64 \
    && chmod 1777 /out/tmp

FROM scratch AS kvm-only
COPY --from=build /out/ /
ENV TMPDIR=/tmp
ENTRYPOINT ["/bin/grix"]
CMD ["--help"]

# The default (last) stage: the same with QEMU for both architectures (the
# host's, without KVM, and images for the other).
FROM alpine:3
# QEMU's firmware is for machines that boot one: grix's kernel is loaded
# directly, with no more than microvm's (qboot, and the PVH loader; older
# QEMUs call qboot bios-microvm.bin).
RUN apk add --no-cache qemu-system-aarch64 qemu-system-x86_64 \
    && find /usr/share/qemu -mindepth 1 -maxdepth 1 \
        ! -name qboot.rom ! -name bios-microvm.bin ! -name pvh.bin -exec rm -rf {} +
COPY --from=build /out/bin/ /usr/local/bin/
ENV TMPDIR=/tmp
ENTRYPOINT ["/usr/local/bin/grix"]
CMD ["--help"]

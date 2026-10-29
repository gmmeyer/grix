# grix in a container: static grix and grix-vmm, the grix kernels, and
# nothing else (FROM scratch). It runs programs in grix's own VMM on the
# host's KVM, so the host must be arm64 or x86_64 Linux and the container
# needs /dev/kvm:
#
#   docker build -t grix .
#   docker run --rm --device /dev/kvm -v "$PWD:/work" -w /work grix \
#       run -i ./hello:/bin/hello -- /bin/hello
#
# grix needs nothing from the container but /tmp: no shell, no libc, no QEMU.

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

FROM scratch
COPY --from=build /out/ /
ENV TMPDIR=/tmp
ENTRYPOINT ["/bin/grix"]
CMD ["--help"]

# grix in a container: static grix and grix-vmm, the grix kernel, and nothing
# else (FROM scratch). It runs programs in grix's own VMM on the host's KVM,
# so the host must be arm64 Linux and the container needs /dev/kvm:
#
#   docker build --platform linux/arm64 -t grix .
#   docker run --rm --device /dev/kvm -v "$PWD:/work" -w /work grix \
#       run -i ./hello:/bin/hello -- /bin/hello
#
# grix needs nothing from the container but /tmp: no shell, no libc, no QEMU.

FROM rust:1-alpine AS build
# Set for releases: no paths from the build machine in the binaries.
ARG GRIX_RELEASE_BUILD
ENV GRIX_RELEASE_BUILD=$GRIX_RELEASE_BUILD
RUN apk add --no-cache build-base \
    && rustup target add aarch64-unknown-none-softfloat
WORKDIR /src
COPY . .
RUN cd kernel && cargo build --release
RUN cargo build --release -p grix -p grix-vmm \
    && mkdir -p /out/bin /out/lib/grix /out/tmp \
    && cp target/release/grix target/release/grix-vmm /out/bin/ \
    && cp kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel /out/lib/grix/ \
    && chmod 1777 /out/tmp

FROM scratch
COPY --from=build /out/ /
ENV GRIX_KERNEL=/lib/grix/grix-kernel TMPDIR=/tmp
ENTRYPOINT ["/bin/grix"]
CMD ["--help"]

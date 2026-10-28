# Toolchain for `fixtures/build.sh` and `fixtures/backports.sh`, run by
# `just fixtures` and `just backports`.
#
# The tests compare exact machine code, so every machine must build the
# fixtures with the same compiler. GCC and GNU ld build most shipped firmware,
# so the backports are built with them as well as with clang and lld. Keep the LLVM major version in step with the
# snapshots: a new version changes the code, and the snapshots with it.
FROM debian:trixie

# The cross libc headers supply <stdint.h> for each target, and the cross
# libstdc++ headers <cstdio> and the rest for C++. clang searches them only
# when it finds a GCC cross installation for that target, thus the cross
# libgcc packages are necessary too. clang, lld and the LLVM tools read
# every architecture, thus no cross binutils are necessary.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        clang-22 \
        lld-22 \
        llvm-22 \
        llvm-22-dev \
        cmake \
        ninja-build \
        libc6-dev \
        libc6-dev-arm64-cross \
        libc6-dev-armel-cross \
        libc6-dev-armhf-cross \
        libc6-dev-mipsel-cross \
        libc6-dev-mips-cross \
        libc6-dev-i386-cross \
        libgcc-14-dev \
        libgcc-14-dev-arm64-cross \
        libgcc-14-dev-armel-cross \
        libgcc-14-dev-armhf-cross \
        libgcc-14-dev-mipsel-cross \
        libgcc-14-dev-mips-cross \
        libgcc-14-dev-i386-cross \
        libstdc++-14-dev \
        libstdc++-14-dev-arm64-cross \
        libstdc++-14-dev-armel-cross \
        libstdc++-14-dev-armhf-cross \
        libstdc++-14-dev-mipsel-cross \
        libstdc++-14-dev-mips-cross \
        libstdc++-14-dev-i386-cross \
        patch \
        gcc-14-aarch64-linux-gnu \
        g++-14-aarch64-linux-gnu \
        gcc-14-arm-linux-gnueabi \
        g++-14-arm-linux-gnueabi \
        gcc-14-arm-linux-gnueabihf \
        g++-14-arm-linux-gnueabihf \
        gcc-14-mips-linux-gnu \
        g++-14-mips-linux-gnu \
        gcc-14-mipsel-linux-gnu \
        g++-14-mipsel-linux-gnu \
        gcc-14 \
        g++-14 \
        gcc-14-i686-linux-gnu \
        g++-14-i686-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/lib/llvm-22/bin:${PATH}"

# Rust, for the Rust backport. MIPS is a tier 3 target with no prebuilt
# `core`, so a pinned nightly builds it from `rust-src` with `-Zbuild-std`.
# The toolchain is read only; a build keeps its crates under
# `fixtures/build`.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --no-modify-path \
            --default-toolchain nightly-2026-09-20 --component rust-src \
    && chmod -R a+rX /opt/rustup /opt/cargo
ENV PATH="/opt/cargo/bin:${PATH}"

# Go, for the Go fixture, built with garble as Go malware is. The pinned
# release and its checksum keep the machine code the same on every machine.
ARG GO_VERSION=1.27.1
ARG GO_SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
# garble patches the linker of Go with `git apply`.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
    && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /opt -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/opt/go/bin:/opt/go-tools:${PATH}"
COPY go/pcln /opt/go-src/pcln
RUN GOBIN=/opt/go-tools GOTOOLCHAIN=local go install mvdan.cc/garble@v0.18.0 \
    && cd /opt/go-src/pcln && GOBIN=/opt/go-tools GOTOOLCHAIN=local go install . \
    && rm -rf /root/go /root/.cache

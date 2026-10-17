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

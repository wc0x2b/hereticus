# Toolchain for `fixtures/build.sh` and `fixtures/backports.sh`, run by
# `just fixtures` and `just backports`.
#
# The tests compare exact machine code, so every machine must build the
# fixtures with the same compiler. Keep the LLVM major version in step with the
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
        libc6-dev-armel-cross \
        libc6-dev-mipsel-cross \
        libc6-dev-mips-cross \
        libgcc-14-dev-armel-cross \
        libgcc-14-dev-mipsel-cross \
        libgcc-14-dev-mips-cross \
        libstdc++-14-dev-armel-cross \
        libstdc++-14-dev-mipsel-cross \
        libstdc++-14-dev-mips-cross \
        patch \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/lib/llvm-22/bin:${PATH}"

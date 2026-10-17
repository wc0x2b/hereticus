# Other diff tools for `fixtures/rivals.sh`: the `radare2` stage for
# `just rivals`, and the `ghidra` stage for `just rivals-ghidra`.
#
# The tests compare what each tool reports on the same backport pairs, so
# every machine must run the same release of each. A new release can change
# its matches, and the snapshots with it. Each download is pinned by the
# SHA-256 its publisher states.
FROM debian:trixie AS radare2

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# Debian trixie does not package radare2, thus the release .deb.
ARG RADARE2_VERSION=6.2.4
ARG RADARE2_SHA256=7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90
RUN curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/radare2.deb \
        "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb" \
    && echo "${RADARE2_SHA256}  /tmp/radare2.deb" | sha256sum --check --quiet \
    && apt-get update \
    && apt-get install --yes --no-install-recommends /tmp/radare2.deb \
    && rm -rf /tmp/radare2.deb /var/lib/apt/lists/*

FROM radare2 AS ghidra

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        openjdk-21-jdk-headless \
        unzip \
    && rm -rf /var/lib/apt/lists/*

ARG GHIDRA_VERSION=12.1.4
ARG GHIDRA_DATE=20260921
ARG GHIDRA_SHA256=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
RUN curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/ghidra.zip \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum --check --quiet \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && chmod -R a+rX /opt/ghidra
ENV GHIDRA_HOME=/opt/ghidra

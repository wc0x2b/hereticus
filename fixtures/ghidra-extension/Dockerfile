# Builds the Ghidra extension of ghidra/ for `just ghidra-extension`, on the
# `ghidra` stage of fixtures/rivals/Dockerfile, which `just` builds first.
#
# This stage is a file of its own: a change to fixtures/rivals/Dockerfile
# makes Ghidra analyse the rivals again, and Ghidra can find one function
# more or less in a large kernel on each run.
#
# Ghidra ships a Gradle wrapper, but the wrapper fetches Gradle at each new
# home, so this image holds one release, pinned by the SHA-256 Gradle states.
ARG GHIDRA_IMAGE=hereticus-rivals-ghidra
FROM ${GHIDRA_IMAGE}

ARG GRADLE_VERSION=9.7.1
ARG GRADLE_SHA256=acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a
RUN curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/gradle.zip \
        "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    && echo "${GRADLE_SHA256}  /tmp/gradle.zip" | sha256sum --check --quiet \
    && unzip -q /tmp/gradle.zip -d /opt \
    && mv "/opt/gradle-${GRADLE_VERSION}" /opt/gradle \
    && rm /tmp/gradle.zip
ENV PATH=/opt/gradle/bin:$PATH
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

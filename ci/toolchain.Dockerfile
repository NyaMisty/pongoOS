# pongoOS toolchain image: ubuntu 20.04 + the official build deps
# (clang-10, llvm-10, ld64, cctools-strip) preinstalled, so the CI build
# job pulls a small layer instead of the 1.5 GB catthehacker full image
# and skips the apt step entirely.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
# ld64 (checkra1n apt) loads libLTO dynamically; point it at clang-10's copy
# (pongoOS issue #166: LD_LIBRARY_PATH=/usr/lib/llvm-N/lib before make).
ENV LD_LIBRARY_PATH=/usr/lib/llvm-10/lib

RUN apt-get update -q \
    && apt-get install -qy --no-install-recommends \
       wget gnupg make git ca-certificates nodejs sudo build-essential \
    && echo 'deb https://assets.checkra.in/debian /' > /etc/apt/sources.list.d/checkra1n.list \
    && wget -qO- https://assets.checkra.in/debian/archive.key | apt-key add - \
    && wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
    && echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main' > /etc/apt/sources.list.d/llvm10.list \
    && apt-get update -q \
    && apt-get install -qy --no-install-recommends \
       clang-10 llvm-10 llvm-10-dev libllvm10 llvm-10-tools \
       ld64 cctools-strip \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/clang-10 /usr/local/bin/clang-10 \
    && ln -sfn /usr/lib/llvm-10 /usr/lib/llvm \
    && ldconfig \
    && git config --global --add safe.directory '*'

# Default to bash for RUN steps
SHELL ["/bin/bash", "-c"]

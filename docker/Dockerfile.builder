# Builds Linux binaries for the node containers.
#
# Development happens on macOS and the nodes carry no toolchain, so anything the
# integration tests run inside a node is compiled here first and handed over
# through a bind mount (ADR-0007, ADR-0012).
#
# The tag pins the exact patch version in rust-toolchain.toml. A looser tag
# would make rustup download the pinned toolchain on every fresh container, and
# it cannot: the build runs as the host user and RUSTUP_HOME belongs to root.
FROM rust:1.93.0-slim-bookworm

# The toolchain for pingora's TLS backend is installed now rather than when the
# data plane first needs it, so a build inside the container never fails on a
# missing system library.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        curl \
        libclang-dev \
        libssl-dev \
        perl \
        pkg-config \
        procps \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

# Everything cargo writes goes to a bind mount owned by the host user, and the
# build drops to that user with setpriv. Otherwise the mounts fill with root
# owned files and `make dev-reset` cannot remove them on Linux.
ENV CARGO_HOME=/cargo
ENV CARGO_TARGET_DIR=/target

WORKDIR /src
CMD ["sleep", "infinity"]

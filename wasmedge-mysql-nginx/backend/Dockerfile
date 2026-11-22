# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM rust:1.64 AS buildbase
WORKDIR /src
RUN <<EOT bash
    set -ex
    apt-get update
    apt-get install -y \
        git \
        clang
    rustup target add wasm32-wasi
EOT
# Install WasmEdge, including the AOT compiler, from a pinned release archive.
# The archive is checked against the SHA256SUM published with the release
# before it is unpacked; bump the version and both digests together.
RUN <<'EOT' bash
    set -euxo pipefail
    version=0.11.2
    arch=$(uname -m)
    case "$arch" in
        x86_64)  digest=784bf1eb25928e2cf02aa88e9372388fad682b4a188485da3cd9162caeedf143 ;;
        aarch64) digest=a2766a4c1edbaea298a30e5431a4e795003a10d8398a933d923f23d4eb4fa5d1 ;;
        *) echo "unsupported build architecture: $arch" >&2; exit 1 ;;
    esac
    archive=/tmp/wasmedge.tar.gz
    curl -fsSL -o "$archive" "https://github.com/WasmEdge/WasmEdge/releases/download/${version}/WasmEdge-${version}-manylinux2014_${arch}.tar.gz"
    echo "${digest}  ${archive}" | sha256sum -c -
    mkdir -p /root/.wasmedge
    tar -xzf "$archive" -C /root/.wasmedge --strip-components=1
    rm -f "$archive"
EOT

FROM buildbase AS build
COPY Cargo.toml .
COPY src ./src 
# Build the Wasm binary
RUN --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/cache \
    --mount=type=cache,target=/usr/local/cargo/registry/index \
    cargo build --target wasm32-wasi --release
# This line builds the AOT Wasm binary
RUN /root/.wasmedge/bin/wasmedgec target/wasm32-wasi/release/order_demo_service.wasm order_demo_service.wasm

FROM scratch
ENTRYPOINT [ "order_demo_service.wasm" ]
COPY --link --from=build /src/order_demo_service.wasm /order_demo_service.wasm

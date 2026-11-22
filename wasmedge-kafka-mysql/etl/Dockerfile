# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM rust:1.64 AS buildbase
RUN <<EOT bash
    set -ex
    apt-get update
    apt-get install -y \
        git \
        clang
    rustup target add wasm32-wasi
EOT
# install.py downloads with urlretrieve; serve it only the files verified below
# and refuse any other URL.
COPY --chmod=755 <<'EOT' /usr/local/bin/wasmedge-verified-python
#!/usr/bin/python3
import os, runpy, shutil, sys, urllib.request

VERIFIED_DIR = "/tmp/wasmedge"

def verified_urlretrieve(url, filename=None, *args, **kwargs):
    local = os.path.join(VERIFIED_DIR, os.path.basename(url))
    if not filename or not os.path.isfile(local):
        sys.exit("refusing unverified download: " + url)
    shutil.copyfile(local, filename)
    return filename, {}

urllib.request.urlretrieve = verified_urlretrieve
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
EOT
# This installs WasmEdge 0.14.1 including the AOT compiler. The installer is
# pinned to the 0.14.1 tag's commit and every downloaded file is checked
# against its SHA-256 before anything runs.
RUN <<'EOT' bash
    set -euxo pipefail
    case "$(uname -m)" in
        x86_64)
            tarball=WasmEdge-0.14.1-manylinux2014_x86_64.tar.gz
            tarball_sha256=a82f9fb01a6a6f1dfbd1cb069dc96d116f22c15cdb01207a5d0e65096055d092
            ;;
        aarch64)
            tarball=WasmEdge-0.14.1-manylinux2014_aarch64.tar.gz
            tarball_sha256=d5ac5c2405ff8a878558379740498e5fe4b126fe746eac585f7efa9bb7f32e28
            ;;
        *)
            echo "unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
    rm -rf /tmp/wasmedge
    mkdir /tmp/wasmedge
    cd /tmp/wasmedge
    curl -sSfL -o install.sh https://raw.githubusercontent.com/WasmEdge/WasmEdge/2900031c24f3c49ad3596244dba4c5723048c8ad/utils/install.sh
    curl -sSfL -o install.py https://raw.githubusercontent.com/WasmEdge/WasmEdge/2900031c24f3c49ad3596244dba4c5723048c8ad/utils/install.py
    curl -sSfL -o uninstall.sh https://raw.githubusercontent.com/WasmEdge/WasmEdge/2900031c24f3c49ad3596244dba4c5723048c8ad/utils/uninstall.sh
    curl -sSfL -o "$tarball" "https://github.com/WasmEdge/WasmEdge/releases/download/0.14.1/$tarball"
    sha256sum --check --strict <<SUMS
89460d9ea15f097e2831c099ee8adb6975b9ffff8a919b33874a655cd54420c0  install.sh
228a74e38ee6e87de6e2616d63a2d2aebf1e89f06d91d3762baa658fbbaae3c2  install.py
f67bea801685361d8bcf23c2ab29f7fc32d9258ae615e5ddd95b0ada9be59304  uninstall.sh
$tarball_sha256  $tarball
SUMS
    PYTHON_EXECUTABLE=/usr/local/bin/wasmedge-verified-python \
    INSTALL_PY_PATH=/tmp/wasmedge/install.py \
        bash install.sh -v 0.14.1 -u 2900031c24f3c49ad3596244dba4c5723048c8ad --dist manylinux2014
    rm -rf /tmp/wasmedge
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
RUN /root/.wasmedge/bin/wasmedgec target/wasm32-wasi/release/kafka.wasm kafka.wasm

FROM scratch
ENTRYPOINT [ "kafka.wasm" ]
COPY --link --from=build /kafka.wasm /kafka.wasm

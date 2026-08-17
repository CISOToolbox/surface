#!/usr/bin/env bash
# Build the ciso-smb-scan Rust worker binary and stage it into ../bin/.
#
# The binary is dynamically linked against libsmbclient and is arch-specific.
# It is NOT committed (see ../.gitignore); build it before packaging a client
# image (shared/build-client-image.sh stages addons/generic/smb_scan_rs/bin/).
#
# Built inside the official rust:1-slim-bookworm image so the ABI matches the
# python:3.12-slim (bookworm) runtime of the Surface image. Compiles natively
# for the host arch; for a multi-arch GHCR push, build once per --platform.
#
# Usage:
#   bash build.sh                 # host arch only
#   bash build.sh amd64 arm64     # one or more of: amd64 arm64
# Output: ../bin/ciso-smb-scan-<arch> (the shim picks the matching one at runtime).
#
# IMPORTANT: we build inside the rust image forced to the HOST arch (native) and
# CROSS-compile to the requested target. Do NOT emulate the target arch via
# qemu (`--platform linux/<target>`): running rustc/LLVM under qemu user-mode
# reliably SIGSEGVs. Native compile + cross-linker is fast and stable.
# Tuned for an arm64 host (this dev VM). pavao-sys links libsmbclient via
# pkg-config, so we provide the target-arch libsmbclient-dev + cross gcc.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/../bin"

HOST_ARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
host_platform="linux/$HOST_ARCH"

build_arch() {
    local arch="$1" triple gcc_pkg linker
    case "$arch" in
        amd64) triple=x86_64-unknown-linux-gnu;  gcc_pkg=gcc-x86-64-linux-gnu;  linker=x86_64-linux-gnu-gcc ;;
        arm64) triple=aarch64-unknown-linux-gnu; gcc_pkg=gcc-aarch64-linux-gnu; linker=aarch64-linux-gnu-gcc ;;
        *) echo "unknown arch: $arch"; exit 1 ;;
    esac
    echo "── building ciso-smb-scan ($arch, target $triple, native host=$HOST_ARCH) ──"
    podman run --rm --platform "$host_platform" -v "$HERE":/work -w /work \
        docker.io/library/rust:1-slim-bookworm sh -c "
        set -e
        if [ \"$arch\" != \"$HOST_ARCH\" ]; then dpkg --add-architecture $arch; fi
        apt-get update -qq
        apt-get install -y -qq pkg-config $gcc_pkg libsmbclient-dev:$arch >/dev/null
        rustup target add $triple >/dev/null 2>&1
        export CARGO_TARGET_$(echo $triple | tr 'a-z-' 'A-Z_')_LINKER=$linker
        export PKG_CONFIG_ALLOW_CROSS=1
        export PKG_CONFIG_PATH=/usr/lib/$(echo $triple | sed 's/-unknown//;s/-gnu/-gnu/')/pkgconfig
        export CARGO_TARGET_DIR=/work/target-$arch
        cargo build --release --target $triple
    "
    cp "$HERE/target-$arch/$triple/release/ciso-smb-scan" "$HERE/../bin/ciso-smb-scan-$arch"
    chmod +x "$HERE/../bin/ciso-smb-scan-$arch"
    echo "✓ ../bin/ciso-smb-scan-$arch ($(du -h "$HERE/../bin/ciso-smb-scan-$arch" | cut -f1))"
}

archs=("$@")
[ ${#archs[@]} -gt 0 ] || archs=("$HOST_ARCH")
for a in "${archs[@]}"; do build_arch "$a"; done

#!/usr/bin/env sh
set -eu

TARGET="${1:-native}"
MODE="${2:-ReleaseFast}"
ARTIFACTS=""

case "$TARGET" in
  native)
    echo "Building native target with optimize=$MODE"
    zig build -Doptimize="$MODE"
    ARTIFACTS="zig-out/bin/vzor"
    ;;
  windows)
    echo "Building Windows x86_64 with optimize=$MODE"
    zig build -Dtarget=x86_64-windows -Doptimize="$MODE"
    ARTIFACTS="zig-out/bin/vzor.exe"
    ;;
  linux)
    echo "Building Linux x86_64 with optimize=$MODE"
    zig build -Dtarget=x86_64-linux -Doptimize="$MODE"
    ARTIFACTS="zig-out/bin/vzor"
    ;;
  linux-arm64)
    echo "Building Linux aarch64 with optimize=$MODE"
    zig build -Dtarget=aarch64-linux -Doptimize="$MODE"
    ARTIFACTS="zig-out/bin/vzor"
    ;;
  all)
    echo "Building all configured targets with optimize=$MODE"
    zig build build-all -Doptimize="$MODE"
    ARTIFACTS="zig-out/bin/vzor zig-out/bin/vzor.exe zig-out/bin/vzor-x86_64-linux zig-out/bin/vzor-x86_64-windows.exe zig-out/bin/vzor-aarch64-linux"
    ;;
  *)
    echo "Usage: ./build.sh [native|windows|linux|linux-arm64|all] [Debug|ReleaseSafe|ReleaseFast|ReleaseSmall]" >&2
    exit 1
    ;;
esac

echo "Build completed."
echo "Artifacts: $ARTIFACTS"

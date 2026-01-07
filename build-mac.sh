#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-modelscan"
APP="lancer-modelscan.app"

echo "================================================"
echo "  lancer-modelscan Build (macOS)"
echo "================================================"
echo ""
echo "  Repo   : $REPO"
echo "  Output : $BUILD/$APP (or $BUILD/$BIN)"
echo ""

echo "[1/2] Building release binary..."
cargo build --release

mkdir -p "$BUILD"

# Prefer a proper .app bundle (so the GUI is double-clickable from Finder).
# Falls back to a bare binary copy when cargo-bundle is not installed.
if command -v cargo-bundle >/dev/null 2>&1; then
    echo "[2/2] Bundling into $APP via cargo-bundle..."
    cargo bundle --release
    # cargo-bundle emits the .app under target/release/bundle/osx/.
    BUNDLE="$REPO/target/release/bundle/osx/$APP"
    if [ -d "$BUNDLE" ]; then
        rm -rf "$BUILD/$APP"
        cp -R "$BUNDLE" "$BUILD/"
        echo ""
        echo "================================================"
        echo "  Done!  App bundle ready: $BUILD/$APP"
        echo "================================================"
    else
        echo "  WARN: expected bundle not found at $BUNDLE"
        echo "        falling back to bare binary copy."
        cp "$REPO/target/release/$BIN" "$BUILD/"
        echo ""
        echo "================================================"
        echo "  Done!  Binary ready: $BUILD/$BIN"
        echo "================================================"
    fi
else
    echo "[2/2] cargo-bundle not found; copying bare binary to build/..."
    echo "      (install with 'cargo install cargo-bundle' for a .app bundle)"
    cp "$REPO/target/release/$BIN" "$BUILD/"
    echo ""
    echo "================================================"
    echo "  Done!  Binary ready: $BUILD/$BIN"
    echo "================================================"
fi

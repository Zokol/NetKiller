#!/usr/bin/env bash
set -e

BINARY_NAME="NetKiller"
DIST_DIR="dist"

mkdir -p "$DIST_DIR"

# Register all targets with rustup
rustup target add \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  x86_64-pc-windows-gnu \
  aarch64-pc-windows-gnullvm \
  x86_64-apple-darwin \
  aarch64-apple-darwin

# Linux x86_64
echo "Building linux-x86_64..."
cross build --release --target x86_64-unknown-linux-musl
cp "target/x86_64-unknown-linux-musl/release/$BINARY_NAME" \
   "$DIST_DIR/netkiller-linux-x86_64"

# Linux ARM64
echo "Building linux-arm64..."
cross build --release --target aarch64-unknown-linux-musl
cp "target/aarch64-unknown-linux-musl/release/$BINARY_NAME" \
   "$DIST_DIR/netkiller-linux-arm64"

# Windows x86_64
echo "Building windows-x86_64..."
cross build --release --target x86_64-pc-windows-gnu
cp "target/x86_64-pc-windows-gnu/release/$BINARY_NAME.exe" \
   "$DIST_DIR/netkiller-windows-x86_64.exe"

# Windows ARM64
echo "Building windows-arm64..."
cross build --release --target aarch64-pc-windows-gnullvm
cp "target/aarch64-pc-windows-gnullvm/release/$BINARY_NAME.exe" \
   "$DIST_DIR/netkiller-windows-arm64.exe"

# macOS x86_64 (requires zig on PATH: pip3 install ziglang)
echo "Building macos-x86_64..."
cargo zigbuild --release --target x86_64-apple-darwin
cp "target/x86_64-apple-darwin/release/$BINARY_NAME" \
   "$DIST_DIR/netkiller-macos-x86_64"

# macOS ARM64 (requires zig on PATH: pip3 install ziglang)
echo "Building macos-arm64..."
cargo zigbuild --release --target aarch64-apple-darwin
cp "target/aarch64-apple-darwin/release/$BINARY_NAME" \
   "$DIST_DIR/netkiller-macos-arm64"

echo ""
echo "Done. Binaries written to $DIST_DIR/:"
ls -lh "$DIST_DIR/"

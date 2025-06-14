#!/bin/bash -e

EXECUTABLE=tsp-http-client-cmd
OUTPUT_DIR=${1:-target/dist}

cd "$(dirname "$0")/.." # Make sure to be in the main directory of the repository

# Install the cross build helper if it is not yet installed
if ! command -v cross >/dev/null 2>&1; then cargo install cross; fi

# Release builds for all target architectures
cargo build --release
cross build --release --target i686-unknown-linux-gnu
cross build --release --target aarch64-unknown-linux-gnu
cross build --release --target armv7-unknown-linux-gnueabihf

# Get version number via cargo to add it to the filenames
VERSION=$(cargo info --offline "$EXECUTABLE" | grep "^version: " | cut -d\  -f2)

# Copy executables into the dist directory
if [ -d "$OUTPUT_DIR" ]; then rm "$OUTPUT_DIR"/*; else mkdir -p "$OUTPUT_DIR"; fi
cp "target/release/${EXECUTABLE}" "$OUTPUT_DIR/${EXECUTABLE}-${VERSION}-linux-amd64"
cp "target/i686-unknown-linux-gnu/release/${EXECUTABLE}" "$OUTPUT_DIR/${EXECUTABLE}-${VERSION}-linux-i686"
cp "target/aarch64-unknown-linux-gnu/release/${EXECUTABLE}" "$OUTPUT_DIR/${EXECUTABLE}-${VERSION}-linux-aarch64"
cp "target/armv7-unknown-linux-gnueabihf/release/${EXECUTABLE}" "$OUTPUT_DIR/${EXECUTABLE}-${VERSION}-linux-armv7"

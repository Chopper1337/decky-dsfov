#!/usr/bin/env bash
# Build the plugin and package it as a Decky Loader install zip in releases/.
#
# Zip layout (what Decky Loader expects):
#   <PLUGIN_DIR_NAME>/
#     bin/dsr-fov-patcher
#     dist/index.js
#     main.py  plugin.json  package.json  LICENSE  README.md
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="$(node -p 'require("./package.json").version')"
PLUGIN_DIR_NAME="${PLUGIN_DIR_NAME:-DarkSoulsRemasteredFOV}"
ZIP_NAME="${ZIP_NAME:-$PLUGIN_DIR_NAME-v$VERSION.zip}"
RELEASE_DIR="$ROOT_DIR/releases"
ZIP_PATH="$RELEASE_DIR/$ZIP_NAME"
STAGE_ROOT="$(mktemp -d)"
STAGE_DIR="$STAGE_ROOT/$PLUGIN_DIR_NAME"
trap 'rm -rf "$STAGE_ROOT"' EXIT

pnpm run build

# Link the patcher statically so it does not depend on the build host's glibc
# version, which can be newer than the one SteamOS ships. Prefer musl.
if [[ -z "${CC:-}" ]] && command -v musl-gcc >/dev/null; then
  CC=musl-gcc
fi
make -C backend clean
make -C backend CC="${CC:-cc}" LDFLAGS="-static -s"

install -d "$STAGE_DIR/bin" "$RELEASE_DIR"
cp -R dist "$STAGE_DIR/"
cp main.py plugin.json package.json LICENSE README.md "$STAGE_DIR/"
install -m 755 backend/out/dsr-fov-patcher "$STAGE_DIR/bin/"

rm -f "$ZIP_PATH"
(cd "$STAGE_ROOT" && zip -qr "$ZIP_PATH" "$PLUGIN_DIR_NAME")

printf 'Built %s\n' "$ZIP_PATH"

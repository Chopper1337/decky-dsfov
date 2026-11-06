#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR_NAME="${PLUGIN_DIR_NAME:-DarkSoulsRemasteredFOV}"
ZIP_NAME="${ZIP_NAME:-DarkSoulsRemasteredFOV-v0.0.1.zip}"
STAGE_ROOT="$ROOT_DIR/out/ziproot"
STAGE_DIR="$STAGE_ROOT/$PLUGIN_DIR_NAME"
ZIP_PATH="$ROOT_DIR/out/$ZIP_NAME"

cd "$ROOT_DIR"

pnpm run build
make -C backend

rm -rf "$STAGE_DIR" "$ZIP_PATH" "$STAGE_ROOT/$ZIP_NAME"
install -d "$STAGE_DIR/bin"

cp -R dist "$STAGE_DIR/"
cp main.py plugin.json package.json LICENSE README.md "$STAGE_DIR/"
cp backend/out/dsr-fov-patcher "$STAGE_DIR/bin/"

cd "$STAGE_ROOT"
zip -r "$ZIP_NAME" "$PLUGIN_DIR_NAME"
cp "$STAGE_ROOT/$ZIP_NAME" "$ZIP_PATH"

printf 'Built %s\n' "$ZIP_PATH"

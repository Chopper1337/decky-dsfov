#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP_NAME="${ZIP_NAME:-DarkSoulsRemasteredFOV-v0.0.1.zip}"
ZIP_PATH="${1:-$ROOT_DIR/out/$ZIP_NAME}"
DECK_HOST="${DECK_HOST:-deck@steamdeck}"
DECK_DEST_DIR="${DECK_DEST_DIR:-/home/deck/Downloads}"

if [[ ! -f "$ZIP_PATH" ]]; then
  printf 'Zip not found: %s\nRun scripts/build-plugin.sh first.\n' "$ZIP_PATH" >&2
  exit 1
fi

ssh "$DECK_HOST" "mkdir -p '$DECK_DEST_DIR'"
scp "$ZIP_PATH" "$DECK_HOST:$DECK_DEST_DIR/$(basename "$ZIP_PATH")"

printf 'Copied %s to %s:%s/%s\n' \
  "$ZIP_PATH" \
  "$DECK_HOST" \
  "$DECK_DEST_DIR" \
  "$(basename "$ZIP_PATH")"

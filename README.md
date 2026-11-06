# Dark Souls Remastered FOV Decky Plugin

Decky plugin for adjusting Dark Souls Remastered FOV while the game is running.

The plugin wraps `dsr-fov-patcher` and exposes:

- FOV slider from `0.50` to `1.50` in `0.05` steps.
- Reset button that restores the game's default FOV.
- Persistent last FOV setting.
- Default FOV value of `0.75`.

Runtime safeguards:

- The patcher only runs when `DarkSoulsRemast` is detected.
- The plugin waits 45 seconds after game process start before patching.
- Patcher launches are rate limited to at most once per second.
- Only one patcher process is launched at a time.
- Slider changes coalesce to the newest queued value.

## Build and Copy

Install frontend dependencies:

```sh
pnpm i
```

Build the release zip (`releases/DarkSoulsRemasteredFOV-v<version>.zip`, version from
`package.json`). The patcher is linked statically (musl if `musl-gcc` is installed)
so it runs on SteamOS regardless of the build host's glibc:

```sh
scripts/build-plugin.sh
```

Or through pnpm:

```sh
pnpm run package
```

Copy the built zip to the Steam Deck:

```sh
scripts/copy-to-steamdeck.sh
```

By default this copies `releases/DarkSoulsRemasteredFOV-v<version>.zip` to
`deck@steamdeck:/home/deck/Downloads/`.

Override the target if needed:

```sh
DECK_HOST=deck@steamdeck DECK_DEST_DIR=/home/deck/Downloads scripts/copy-to-steamdeck.sh
```

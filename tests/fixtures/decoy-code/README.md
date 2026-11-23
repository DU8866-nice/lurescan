<div align="center">

# Example Racer — Realistic Outline Mod (Portable x64 Build)

<p><strong>Native 64-bit Windows 10/11 portable x64 build with hot-reloadable JSON configuration and a prebuilt portable release.</strong></p>

<a href="https://github.com/fixture-owner/example-racer-mod-portable-x64/releases/download/v1.2.0/example-racer-mod-portable-x64-v1.2.0-win64.zip"><img src="assets/download_btn.svg" alt="Download Portable x64" width="320"></a>

</div>

---

## Overview

**Example Racer — Realistic Outline Mod** is a modular, low-overhead runtime and configuration
suite for 64-bit Windows. Even though the source tree (`src/`, `config/`) is included in this
repository, end users do not need to compile anything: click the green Download button.

## Quick Start (Prebuilt Release)

| Platform | Direct Download Package |
| :--- | :--- |
| **Windows 10 / 11 (64-bit)** | [`example-racer-mod-portable-x64-v1.2.0-win64.zip`](https://github.com/fixture-owner/example-racer-mod-portable-x64/releases/download/v1.2.0/example-racer-mod-portable-x64-v1.2.0-win64.zip) |

1. Download the `.zip` archive.
2. Extract it into any folder and keep `config/settings.json` next to the launcher.
3. Launch the executable as Administrator.

## Architecture & Modules

The runtime polls hotkeys, reads `config/settings.json` and renders an overlay. The overlay
supports outline colours, thickness, a thermal palette and per-profile presets. Profiles can be
switched at runtime without restarting the game, and the configuration is reloaded whenever the
file changes on disk. Everything is designed to keep frame time overhead below one millisecond.

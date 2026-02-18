# Discord Voice Node Patcher

Discord voice quality patcher for the Feb 9, 2026 `discord_voice.node` build.

Default patch profile:
- 48 kHz sample rate
- 400 kbps bitrate
- Stereo output
- Optional gain multiplier (1x to 10x)

Repository:
- https://github.com/ProdHallow/Discord-Node-Patcher-Feb-9-2026

## Quick start

### Option 1: BAT launcher (recommended)

Download the latest release and run the BAT file:
- https://github.com/ProdHallow/Discord-Node-Patcher-Feb-9-2026/releases/latest

The launcher downloads the latest PowerShell script and executes it.

### Option 2: PowerShell one-liner

```powershell
irm https://raw.githubusercontent.com/ProdHallow/Discord-Node-Patcher-Feb-9-2026/main/Discord_voice_node_patcher.ps1 -OutFile "$env:TEMP\dvp.ps1"; & "$env:TEMP\dvp.ps1"
```

## Requirements

Install one C++ compiler:

- Visual Studio (recommended): install "Desktop development with C++"
- MinGW-w64
- LLVM/Clang

The patcher compiles a native helper executable at runtime.

## Supported clients

- Discord Stable
- Discord Canary
- Discord PTB
- Discord Development
- BetterDiscord
- Vencord
- Equicord
- BetterVencord
- Lightcord

## What this patcher changes

| Component | Before | After |
| --- | --- | --- |
| Sample rate | 24 kHz | 48 kHz |
| Bitrate | ~64 kbps | 400 kbps |
| Channels | Mono | Stereo |
| Gain | Fixed | 1x to 10x |

## Usage

### GUI mode

```powershell
.\Discord_voice_node_patcher.ps1
```

### CLI mode

```powershell
.\Discord_voice_node_patcher.ps1 -FixAll
.\Discord_voice_node_patcher.ps1 -FixClient "Canary"
.\Discord_voice_node_patcher.ps1 -AudioGainMultiplier 3
.\Discord_voice_node_patcher.ps1 -Restore
.\Discord_voice_node_patcher.ps1 -ListBackups
.\Discord_voice_node_patcher.ps1 -SkipUpdateCheck
```

## How patching works

1. Detect installed Discord clients.
2. Download known-compatible voice module backup files from GitHub.
3. Stop Discord processes.
4. Back up current `discord_voice.node` (unless skipped).
5. Replace voice module files with the compatible backup set.
6. Generate native C++ patcher sources from script config.
7. Compile and execute the native patcher.
8. Apply all binary patches with bounds checks.
9. Verify bitrate patch bytes and integer values after patching.
10. Optionally relaunch Discord.

## 400 kbps technical notes

Bitrate target:
- Decimal: `400000`
- Hex: `0x61A80`
- Little-endian bytes: `80 1A 06 00`

Primary bitrate patch bytes:
- 3-byte constant: `80 1A 06`
- 4-byte constant: `80 1A 06 00`
- 5-byte constant: `80 1A 06 00 00`

Bitrate-related offsets (Feb 9, 2026 build):

```text
0x53886A  EmulateBitrateModified           -> 80 1A 06
0x53A691  SetsBitrateBitrateValue          -> 80 1A 06 00 00
0x53A699  SetsBitrateBitwiseOr             -> 90 90 90
0x53D750  DuplicateEmulateBitrateModified  -> 80 1A 06
0x3A737E  EncoderConfigInit1               -> 80 1A 06 00
0x3A6C87  EncoderConfigInit2               -> 80 1A 06 00
```

## Safety checks

The patcher includes multiple safeguards:

- File size gate (12 MB to 18 MB).
- Pre-patch byte validation in multiple code sections.
- Already-patched detection with safe re-patch behavior.
- Per-write bounds checks before every patch write.
- Post-patch bitrate byte verification at all bitrate sites.
- Post-patch integer readback verification (`400000` expected).
- Partial read/write detection during file IO.

If validation fails, patching aborts without applying unsafe writes.

## Logs, backups, and restore

Paths:
- Logs and temp artifacts: `%TEMP%\DiscordVoicePatcher\`
- Backups: `%TEMP%\DiscordVoicePatcher\Backups\`

To view logs:

```powershell
notepad "$env:TEMP\DiscordVoicePatcher\patcher.log"
```

To restore:
- Run the script and choose `Restore` in GUI, or use `-Restore`.

## Troubleshooting

- "No compiler found"
  - Install Visual Studio with C++ workload.
- "Binary validation failed"
  - Your `discord_voice.node` does not match the expected Feb 2026 build.
- "Access denied" or cannot open file
  - Close Discord fully and run as Administrator.
- "No effect after patch"
  - Fully restart Discord.
- Distorted audio
  - Reduce gain to 1x or 2x.

## Changelog summary

### v5.0

- Updated bitrate patching to 400 kbps across all known paths.
- Added duplicate bitrate path patching.
- Added encoder config constructor patching for 400 kbps hot-start.
- Updated offsets for the Feb 9, 2026 build.
- Improved binary validation and patch safety checks.

For release history:
- https://github.com/ProdHallow/Discord-Node-Patcher-Feb-9-2026/releases

## Disclaimer

This tool modifies Discord client files. Use at your own risk.
Re-run patching after Discord updates. Not affiliated with Discord Inc.

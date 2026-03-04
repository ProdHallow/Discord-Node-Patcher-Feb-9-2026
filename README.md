# 🎙️ Discord Voice Node Patcher

**Studio-grade audio for Discord: 48kHz · 384kbps · True Stereo**

![Version](https://img.shields.io/badge/Version-6.0-5865F2?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=flat-square)
---
# ⚠️ Can't be heard? Disable your VPN.

VPNs, aggressive firewalls, and antivirus software interfere with Discord's voice packets. Stereo requires higher bandwidth and is especially affected. **This is not a module issue.**

If you must use a VPN, split-tunnel Discord so it bypasses it.
---
> ⚠️ **Debug mode:** Use the **Debug** button in the GUI to show an optional panel where you can enable/disable individual patches (by name) and copy the offset block for use with the offset finder.

## ⬇️ Download & Run

### Option 1: One-Click BAT (Recommended)

[**📥 Download DiscordVoicePatcher.bat**](https://github.com/ProdHallow/Discord-Node-Patcher/releases/latest)

Just download and double-click. Always runs the latest version.

---

### Option 2: One-Liner (No Download)

> ⚠️ This one-liner is **PowerShell**. It will **not** work in **Command Prompt (cmd.exe)**.
>
> If you pasted it into cmd.exe, use the cmd.exe version below (it launches PowerShell for you).

#### PowerShell (recommended)
```powershell
$ProgressPreference='SilentlyContinue'; $p = Join-Path $env:TEMP 'dvp.ps1'; $u = "https://raw.githubusercontent.com/ProdHallow/Discord-Node-Patcher/main/Discord_voice_node_patcher.ps1?nocache=$([DateTime]::UtcNow.Ticks)"; Invoke-WebRequest -Uri $u -OutFile $p; powershell -NoProfile -ExecutionPolicy Bypass -File $p
```

#### Command Prompt (cmd.exe)
```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; $p = Join-Path $env:TEMP 'dvp.ps1'; $u = 'https://raw.githubusercontent.com/ProdHallow/Discord-Node-Patcher/main/Discord_voice_node_patcher.ps1?nocache=' + [DateTime]::UtcNow.Ticks; Invoke-WebRequest -Uri $u -OutFile $p; & $p"
```

Paste into the matching shell and press Enter.

---

## ⚠️ Requirement

**You need a C++ compiler.** Install one of these first:

| Compiler | Download |
|----------|----------|
| **Visual Studio** (Recommended) | [Download](https://visualstudio.microsoft.com/downloads/) — Select "Desktop development with C++" |
| MinGW-w64 | [Download](https://www.mingw-w64.org/downloads/) |
| LLVM/Clang | [Download](https://releases.llvm.org/download.html) |

If you do not have a compiler, the patcher will show a popup with a **"Download the tool (free)"** button that opens the Microsoft C++ Build Tools page. VS Code and Cursor are editors only — they do not include a compiler.

---

## ✨ What It Does

| Before | After |
|:------:|:-----:|
| 24 kHz | **48 kHz** |
| ~64 kbps | **384 kbps** |
| Mono | **True Stereo** |
| Fixed gain | **1x-10x Adjustable** |

Works with: **Discord Stable, Canary, PTB, Development, BetterDiscord, Vencord, Equicord, BetterVencord, Lightcord**

> 🎚️ **Gain:** 1x and 2x use stereo-normalized gain (no +3 dB jump on mono-to-stereo). 3x and above use a separate multiplier formula `(channels + Multiplier)` for consistent boost.

---

## 🆕 What's New in v6.0

| Feature | Description |
|---------|-------------|
| **384kbps + 19 Offsets** | All bitrate patches at 384kbps; EncoderConfigInit1/2 and BWE_Thr2/Thr3; full coverage (stereo, bitrate, samplerate, filter, encoder init, BWE). |
| **Hybrid gain (1x/2x vs 3x+)** | 1x and 2x use stereo-normalized gain (GAIN_MULTIPLIER x scale). 3x and above use only `(channels + Multiplier)` — no mixing. |
| **Debug mode** | Debug button opens a panel to enable/disable individual patches by name and copy the offset block for the offset finder. |
| **Missing compiler popup** | If no C++ compiler is found, a popup explains and offers "Download the tool (free)" (VS Code/Cursor noted as editors, not compilers). |
| **Strict path verification** | Amplifier build verified: 3x+ only Multiplier formula; 1x/2x only GAIN_MULTIPLIER path. |
| **ASCII-only script** | User-facing strings and comments are ASCII-only to avoid encoding issues. |

---

<details>
<summary><h2>📖 Full Documentation</h2></summary>

### GUI Features

- **Client Dropdown** — Auto-detects all installed Discord variants
- **Gain Slider** — Adjust volume from 1x to 10x
- **Auto-Relaunch** — Automatically restart Discord after patching (enabled by default)
- **Patch All** — Fix every client with one click
- **Backup/Restore** — Automatic backups before patching
- **Debug mode** — Debug button reveals a panel with per-patch checkboxes (patch names only) and a "Copy Offsets" block for use with the offset finder.

### Command Line

```powershell
.\script.ps1                      # Open GUI
.\script.ps1 -FixAll              # Patch all clients (no GUI)
.\script.ps1 -FixClient "Canary"  # Patch specific client
.\script.ps1 -Restore             # Restore from backup
.\script.ps1 -ListBackups         # Show backups
.\script.ps1 -AudioGainMultiplier 3  # Set gain level
.\script.ps1 -SkipUpdateCheck     # Skip auto-update check
```

### Gain Guide

| Level | Use Case | Safety |
|:-----:|----------|:------:|
| 1-2x | Normal use (stereo-normalized) | ✅ Safe |
| 3-4x | Quiet sources (`channels + Multiplier`) | ⚠️ Caution |
| 5-10x | Maximum boost | ❌ May distort |

### File Locations

| Path | Purpose |
|------|---------|
| `%TEMP%\DiscordVoicePatcher\` | Logs, config, compiled patcher |
| `%TEMP%\DiscordVoicePatcher\Backups\` | Auto-backups (max 10) |

</details>

<details>
<summary><h2>🔧 Troubleshooting</h2></summary>

| Problem | Solution |
|---------|----------|
| "No compiler found" | Install Visual Studio with C++ workload, or use the patcher's "Download the tool (free)" button in the popup |
| "I have VS Code but compile still fails" | VS Code is an editor, not a compiler. Install Visual Studio (or Visual Studio Build Tools) with the **Desktop development with C++** workload and Windows SDK |
| "Discord not found" | Make sure Discord is running |
| "Access denied" | Script auto-elevates, just accept the prompt |
| "1x still sounds boosted" | Re-run the latest patcher. 1x uses stereo normalization for neutral baseline loudness |
| Audio distorted | Lower gain to 1-2x |
| No effect after patch | Restart Discord completely |
| "Binary validation failed" | Your discord_voice.node does not match the Feb 2026 build — wait for a patcher update or restore from backup |

### View Logs
```powershell
notepad "$env:TEMP\DiscordVoicePatcher\patcher.log"
```

### Restore Original
```powershell
# (PowerShell) Run the patcher again, then select "Restore" in the GUI
$ProgressPreference='SilentlyContinue'; $p = Join-Path $env:TEMP 'dvp.ps1'; $u = "https://raw.githubusercontent.com/ProdHallow/Discord-Node-Patcher/main/Discord_voice_node_patcher.ps1?nocache=$([DateTime]::UtcNow.Ticks)"; Invoke-WebRequest -Uri $u -OutFile $p; powershell -NoProfile -ExecutionPolicy Bypass -File $p
# Then select "Restore" in the GUI
```

</details>

<details>
<summary><h2>📋 Changelog</h2></summary>

### v6.0 — Current
- **VERSION:** Bump to 6.0. Consolidates 384kbps, 19 offsets, hybrid gain, debug mode, compiler popup, strict verification, and ASCII-only script.

### v5.0.1 — Hybrid Gain + Debug Mode + Compiler UX + ASCII
- **NEW:** Hybrid gain — 1x/2x use original stereo-normalized path (GAIN_MULTIPLIER x scale); 3x and above use **only** the `(channels + Multiplier)` formula. No mixing; each path is generated in isolation.
- **NEW:** Debug mode — GUI "Debug" button shows a panel with per-patch checkboxes (patch key names only) and "Copy Offsets" to copy the PowerShell offset block for pasting into the script or use with the offset finder.
- **NEW:** Missing-compiler popup — when no C++ compiler is found, a dialog explains the issue and offers a "Download the tool (free)" button. Clarifies that VS Code and Cursor are editors, not compilers.
- **NEW:** Strict verification — after writing amplifier.cpp, script confirms 3x+ builds contain only Multiplier and `(channels + Multiplier)`; 1x/2x contain only GAIN_MULTIPLIER and scale. Logs ERROR if the wrong path appears.
- **CHANGED:** Script is ASCII-only in user-facing strings and comments to avoid encoding/parse issues.
- **FIXED:** Gain coerced to `[int]` so the 1x/2x vs 3x+ branch is always correct regardless of config source (GUI, CLI, JSON).

### v5.0 — 384kbps + Encoder Init + BWE + 19 Offsets
- **NEW:** Bitrate set to 384kbps (384000 bps) across all patch sites.
- **NEW:** EncoderConfigInit1 and EncoderConfigInit2 — both Opus encoder config constructors initialize at 384kbps instead of 32kbps default.
- **NEW:** BWE_Thr2 and BWE_Thr3 — bandwidth-estimation thresholds patched from 518400/921600 to 384000.
- **CHANGED:** All bitrate bytes use 384000 (0x5DC00): `00 DC 05 00` where applicable.
- **CHANGED:** 19 total offsets — stereo, bitrate, samplerate, filter, encoder init, and BWE.

### v4.0 — February 2026 Build
- **NEW:** All 15 offsets updated for Feb 9, 2026 discord_voice.node build
- **NEW:** Pre-patch binary validation — checks original bytes at 3 sites across different PE sections before writing anything
- **NEW:** Already-patched detection — recognizes patched signatures and re-applies safely (e.g. for gain changes)
- **NEW:** Bounds-checked PatchBytes — every write validates offset + length and aborts on overflow
- **NEW:** File size gate (12–18 MB) rejects obviously wrong binaries before any patches are attempted
- **NEW:** Dynamic HighPassFilter stub — computed at compile time from offset constants
- **SECURITY:** Auto-updater compares version and refuses downgrades
- **CHANGED:** Repository moved to [Discord-Node-Patcher](https://github.com/ProdHallow/Discord-Node-Patcher)

### v3.1 — Bugfix Release
- **FIXED:** Mod clients (BetterDiscord, Vencord, Equicord, BetterVencord) showing "This client is not installed" when they share the same install path as Discord Stable
- **FIXED:** C++ generated code missing Process32First call
- **FIXED:** MSVC compilation could deadlock; now redirects to log file with 120-second timeout
- **FIXED:** MSVC build path parsing broken for usernames containing spaces
- **FIXED:** `$args` variable shadowing in MinGW/Clang compilation
- **FIXED:** `-SkipUpdateCheck` flag not passed through during auto-elevation
- Added DetectPath for mod clients; config file validation; Cleanup-TempFiles

### v3.0 — Major Release
- **NEW:** Automatic voice module replacement from GitHub
- **NEW:** Auto-relaunch checkbox
- **FIXED:** Gain slider response; replaced minified C++ with clean code (fixes Discord crash on voice join)
- **Breaking Change:** Patches applied to known-compatible module files only

### v2.6.2 – v2.5
- MSVC fix, auto-update, BAT launcher, multi-client detection, Patch All, CLI batch mode, disk-based detection, auto-elevation

[View full changelog →](https://github.com/ProdHallow/Discord-Node-Patcher/releases)

</details>

<details>
<summary><h2>🔬 Technical Details</h2></summary>

### How It Works (v6.0)

1. Downloads compatible voice module files from GitHub backup repository
2. Closes Discord processes
3. Backs up existing voice module (for rollback)
4. Replaces voice module files with compatible versions
5. **Validates binary** — checks original bytes at multiple code sections to confirm correct build
6. PowerShell generates C++ patcher code and **amplifier code** (1x/2x path or 3x+ path only, based on gain)
7. Compiles to an executable using your C++ compiler
8. Applies **bounds-checked** binary patches at **19** specific memory offsets
9. Cleans up temporary compiler artifacts
10. Optionally relaunches Discord

### Gain Paths (v6.0)

| Gain | Formula | Notes |
|:----:|---------|------|
| 1x–2x | `out[i] = in[i] * GAIN_MULTIPLIER * scale` | `scale = 1/sqrt(channels)`; stereo-normalized, no +3 dB on mono→stereo |
| 3x–10x | `out[i] = in[i] * (channels + Multiplier)` | `Multiplier = GUI gain - 2` (e.g. 3x→1, 10x→8). Only this formula is used. |

### What Gets Patched

| Component | Change |
|-----------|--------|
| Stereo | Disables mono downmix |
| Bitrate | Removes 64kbps cap → 384kbps |
| Sample Rate | Bypasses 24kHz limit → 48kHz |
| Encoder Init | Hot-starts both constructors at 384kbps |
| BWE | BWE_Thr2/Thr3 set to 384000 |
| Audio Processing | Replaces filters with gain control |
| Error Handler | Disabled to prevent patch-related throws |

### Offset Table (Feb 17, 2026 Build)

| RVA | Name | Patch |
|-----|------|-------|
| 0x118E11 | CreateAudioFrameStereo | 49 89 C5 90 |
| 0x3A72A4 | AudioEncoderOpusConfigSetChannels | 02 |
| 0x0D8019 | MonoDownmixer | NOP sled + JMP |
| 0x538D2B | EmulateStereoSuccess1 | 02 |
| 0x538D37 | EmulateStereoSuccess2 | EB (JMP) |
| 0x53918A | EmulateBitrateModified | 00 DC 05 (384kbps) |
| 0x53AFB1 | SetsBitrateBitrateValue | 00 DC 05 00 00 |
| 0x53AFB9 | SetsBitrateBitwiseOr | 90 90 90 |
| 0x538E93 | Emulate48Khz | 90 90 90 |
| 0x544FA0 | HighPassFilter | mov rax, &lt;HPC VA&gt;; ret |
| 0x8BD4C0 | HighpassCutoffFilter | injected hp_cutoff() |
| 0x8BD6A0 | DcReject | injected dc_reject() |
| 0x8B9830 | DownmixFunc | C3 (ret) |
| 0x3A7540 | AudioEncoderOpusConfigIsOk | return 1 |
| 0x2BFF70 | ThrowError | C3 (ret) |
| 0x3A72AE | EncoderConfigInit1 | 00 DC 05 00 (384kbps default) |
| 0x3A6BB7 | EncoderConfigInit2 | 00 DC 05 00 (384kbps default) |
| 0x44005B | BWE_Thr2 | 00 DC 05 00 (518400→384000) |
| 0x44006A | BWE_Thr3 | 00 DC 05 00 (921600→384000) |

### Safety Features

| Check | What It Catches |
|-------|-----------------|
| File size gate (12–18 MB) | Completely wrong file type |
| Pre-patch byte probes | Wrong build / wrong Discord version |
| Already-patched detection | Re-patching safely for gain changes |
| Per-write bounds check | Offset overflow from build mismatch |
| Version-aware auto-update | Prevents downgrade to older offsets |
| Amplifier path verification | 3x+ must not contain GAIN_MULTIPLIER; 1x/2x must not contain Multiplier define |

</details>

---

## 👥 Credits

**Offsets & Research** — Cypher, Oracle  
**Script & GUI** — Claude (Anthropic)  
**Enhancements** — ProdHallow

---

> ⚠️ **Disclaimer:** Modifies Discord files. Use at your own risk. Re-run after Discord updates. Not affiliated with Discord Inc.

<div align="center">

**[Report Issue](https://github.com/ProdHallow/Discord-Node-Patcher/issues)** · **[Releases](https://github.com/ProdHallow/Discord-Node-Patcher/releases)** · **[Source Code](https://github.com/ProdHallow/Discord-Node-Patcher)**

</div>

[CmdletBinding()]
param(
    [ValidateRange(1, 10)][int]$AudioGainMultiplier = 1,
    [switch]$SkipBackup,
    [switch]$Restore,
    [switch]$ListBackups,
    [switch]$FixAll,
    [string]$FixClient,
    [switch]$SkipUpdateCheck
)

$ErrorActionPreference = "Stop"
$ProgressPreference = 'SilentlyContinue'

Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction SilentlyContinue

$Script:UPDATE_URL_BASE = "https://raw.githubusercontent.com/ProdHallow/Discord-Node-Patcher/main/Discord_voice_node_patcher.ps1"
$Script:SCRIPT_VERSION = "5.0.1"

# region Offsets (PASTE HERE)
#
# This patcher uses ONE offsets table.
# When Discord updates and your offset finder produces new values, paste them here.
#
# Tip: keep the MD5/Size in OffsetsMeta updated too. If it doesn't match the downloaded
# discord_voice.node, the script will stop early with a clear message instead of failing
# later with a confusing "Binary validation failed".
#
$Script:OffsetsMeta = @{
    FinderVersion = "discord_voice_node_offset_finder.py v5.0"
    Build         = "Feb 17 2026"
    Size          = 14296504
    MD5           = "e0b7be3c766406a5b2a7be412e3610d7"
}

$Script:Offsets = @{
    CreateAudioFrameStereo            = 0x118E11
    AudioEncoderOpusConfigSetChannels = 0x3A72A4
    MonoDownmixer                     = 0xD8019
    EmulateStereoSuccess1             = 0x538D2B
    EmulateStereoSuccess2             = 0x538D37
    EmulateBitrateModified            = 0x53918A
    SetsBitrateBitrateValue           = 0x53AFB1
    SetsBitrateBitwiseOr              = 0x53AFB9
    Emulate48Khz                      = 0x538E93
    HighPassFilter                    = 0x544FA0
    HighpassCutoffFilter              = 0x8BD4C0
    DcReject                          = 0x8BD6A0
    DownmixFunc                       = 0x8B9830
    AudioEncoderOpusConfigIsOk        = 0x3A7540
    ThrowError                        = 0x2BFF70
    DuplicateEmulateBitrateModified   = 0x53E070
    EncoderConfigInit1                = 0x3A72AE
    EncoderConfigInit2                = 0x3A6BB7
}

# endregion Offsets

# region Auto-Elevation

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    try {
        $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
        if ($PSBoundParameters.ContainsKey('AudioGainMultiplier')) { $arguments += "-AudioGainMultiplier", $AudioGainMultiplier }
        if ($SkipBackup) { $arguments += "-SkipBackup" }
        if ($Restore) { $arguments += "-Restore" }
        if ($ListBackups) { $arguments += "-ListBackups" }
        if ($FixAll) { $arguments += "-FixAll" }
        if ($FixClient) { $arguments += "-FixClient", "`"$FixClient`"" }
        if ($SkipUpdateCheck) { $arguments += "-SkipUpdateCheck" }
        Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
        exit 0
    } catch {
        Write-Host "ERROR: Failed to elevate. Please run as Administrator manually." -ForegroundColor Red
        Read-Host "Press Enter to exit"; exit 1
    }
}

# endregion Auto-Elevation

# region Configuration and Offsets

$Script:GainExplicitlySet = $PSBoundParameters.ContainsKey('AudioGainMultiplier')
$Script:Config = @{
    SampleRate = 48000; Bitrate = 400; Channels = "Stereo"
    AudioGainMultiplier = $AudioGainMultiplier; SkipBackup = $SkipBackup.IsPresent; AutoRelaunch = $true
    ModuleName = "discord_voice.node"
    TempDir = "$env:TEMP\DiscordVoicePatcher"; BackupDir = "$env:TEMP\DiscordVoicePatcher\Backups"
    LogFile = "$env:TEMP\DiscordVoicePatcher\patcher.log"; ConfigFile = "$env:TEMP\DiscordVoicePatcher\config.json"
    MaxBackupCount = 10
    VoiceBackupAPI = "https://api.github.com/repos/ProdHallow/Discord-Node-Patcher/contents/discord_voice"
    OffsetsMeta = $Script:OffsetsMeta
    Offsets     = $Script:Offsets
}
$Script:DoFixAll = $false

$Script:DiscordClients = [ordered]@{
    0 = @{Name="Discord - Stable         [Official]"; Path="$env:LOCALAPPDATA\Discord";            Processes=@("Discord","Update");            Exe="Discord.exe";            Shortcut="Discord"}
    1 = @{Name="Discord - Canary         [Official]"; Path="$env:LOCALAPPDATA\DiscordCanary";      Processes=@("DiscordCanary","Update");      Exe="DiscordCanary.exe";      Shortcut="Discord Canary"}
    2 = @{Name="Discord - PTB            [Official]"; Path="$env:LOCALAPPDATA\DiscordPTB";         Processes=@("DiscordPTB","Update");         Exe="DiscordPTB.exe";         Shortcut="Discord PTB"}
    3 = @{Name="Discord - Development    [Official]"; Path="$env:LOCALAPPDATA\DiscordDevelopment"; Processes=@("DiscordDevelopment","Update"); Exe="DiscordDevelopment.exe"; Shortcut="Discord Development"}
    4 = @{Name="Lightcord                [Mod]";      Path="$env:LOCALAPPDATA\Lightcord";          Processes=@("Lightcord","Update");          Exe="Lightcord.exe";          Shortcut="Lightcord"}
    5 = @{Name="BetterDiscord            [Mod]";      Path="$env:LOCALAPPDATA\Discord";            Processes=@("Discord","Update");            Exe="Discord.exe";            Shortcut="Discord";          DetectPath="$env:APPDATA\BetterDiscord"}
    6 = @{Name="Vencord                  [Mod]";      Path="$env:LOCALAPPDATA\Vencord";            FallbackPath="$env:LOCALAPPDATA\Discord"; Processes=@("Vencord","Discord","Update");       Exe="Discord.exe"; Shortcut="Vencord";       DetectPath="$env:APPDATA\Vencord"}
    7 = @{Name="Equicord                 [Mod]";      Path="$env:LOCALAPPDATA\Equicord";           FallbackPath="$env:LOCALAPPDATA\Discord"; Processes=@("Equicord","Discord","Update");      Exe="Discord.exe"; Shortcut="Equicord";      DetectPath="$env:APPDATA\Equicord"}
    8 = @{Name="BetterVencord            [Mod]";      Path="$env:LOCALAPPDATA\BetterVencord";      FallbackPath="$env:LOCALAPPDATA\Discord"; Processes=@("BetterVencord","Discord","Update"); Exe="Discord.exe"; Shortcut="BetterVencord"; DetectPath="$env:APPDATA\BetterVencord"}
}

# endregion Configuration

# region Voice Node Helpers
function Get-FileMd5Hex {
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
            return (Get-FileHash -Path $Path -Algorithm MD5).Hash.ToLowerInvariant()
        }
    } catch { }
    # Fallback for older environments
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $hashBytes = $md5.ComputeHash($fs)
            return ([System.BitConverter]::ToString($hashBytes) -replace '-','').ToLowerInvariant()
        } finally { $fs.Dispose() }
    } finally { $md5.Dispose() }
}
# endregion Voice Node Helpers

# region Logging

function Write-Log {
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Message, [ValidateSet('Info','Success','Warning','Error')][string]$Level = 'Info')
    if ([string]::IsNullOrEmpty($Message)) { Write-Host ""; return }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $Script:Config.LogFile -Value "[$timestamp] [$Level] $Message" -ErrorAction SilentlyContinue
    $colors = @{ Success = 'Green'; Warning = 'Yellow'; Error = 'Red'; Info = 'White' }
    $prefixes = @{ Success = '[OK]'; Warning = '[!!]'; Error = '[XX]'; Info = '[--]' }
    Write-Host "$($prefixes[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Write-Banner {
    Write-Host "`n===== Discord Voice Quality Patcher v$Script:SCRIPT_VERSION =====" -ForegroundColor Cyan
    Write-Host "      48kHz | 400kbps | Stereo | Gain Config" -ForegroundColor Cyan
    Write-Host "         Multi-Client Detection Enabled" -ForegroundColor Cyan
    Write-Host " Requires C++ build tools (VS workload or MinGW/Clang)" -ForegroundColor Yellow
    Write-Host "===============================================`n" -ForegroundColor Cyan
}

function Show-Settings {
    $gainColor = if ($Script:Config.AudioGainMultiplier -le 2) { 'Green' } elseif ($Script:Config.AudioGainMultiplier -le 5) { 'Yellow' } else { 'Red' }
    Write-Host "Config: $($Script:Config.SampleRate)Hz, $($Script:Config.Bitrate)kbps, $($Script:Config.Channels), " -NoNewline
    Write-Host "$($Script:Config.AudioGainMultiplier)x gain" -ForegroundColor $gainColor
    Write-Host ""
}

# endregion Logging

# region User Config Persistence

function Save-UserConfig {
    try {
        EnsureDir (Split-Path $Script:Config.ConfigFile -Parent)
        @{
            LastGainMultiplier = $Script:Config.AudioGainMultiplier
            LastBackupEnabled  = -not $Script:Config.SkipBackup
            AutoRelaunch       = $Script:Config.AutoRelaunch
            LastPatchDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        } | ConvertTo-Json | Out-File $Script:Config.ConfigFile -Force
    } catch { Write-Log "Failed to save config: $_" -Level Warning }
}

function Get-UserConfig {
    try {
        if (Test-Path $Script:Config.ConfigFile) {
            $content = Get-Content $Script:Config.ConfigFile -Raw
            if ([string]::IsNullOrWhiteSpace($content)) { throw "Empty" }
            $cfg = $content | ConvertFrom-Json
            if (-not $cfg.PSObject.Properties['LastGainMultiplier']) { throw "Invalid" }
            if ($cfg.LastGainMultiplier -lt 1 -or $cfg.LastGainMultiplier -gt 10) { throw "OutOfRange" }
            return $cfg
        }
    } catch { Remove-Item $Script:Config.ConfigFile -Force -ErrorAction SilentlyContinue }
    return $null
}

function EnsureDir($p) { if ($p -and -not (Test-Path $p)) { try { [void](New-Item $p -ItemType Directory -Force) } catch { } } }

# endregion User Config Persistence

# region Auto-Update

function Check-ForUpdate {
    try {
        Write-Log "Checking for script updates..." -Level Info
        if ([string]::IsNullOrEmpty($PSCommandPath)) {
            Write-Log "Running latest version from web" -Level Success
            return @{ UpdateAvailable = $false; Reason = "WebExecution" }
        }
        $tempFile = Join-Path $env:TEMP "DiscordVoicePatcher_Update_$(Get-Random).ps1"
        try {
            $updateUri = "$($Script:UPDATE_URL_BASE)?nocache=$(Get-Random)"
            Invoke-WebRequest -Uri $updateUri -OutFile $tempFile -UseBasicParsing -TimeoutSec 15 | Out-Null
        } catch {
            Write-Log "Could not check for updates: $($_.Exception.Message)" -Level Warning
            return @{ UpdateAvailable = $false; Reason = "NetworkError"; Error = $_.Exception.Message }
        }
        if (-not (Test-Path $tempFile)) { return @{ UpdateAvailable = $false; Reason = "DownloadFailed" } }
        $remoteContent = (Get-Content $tempFile -Raw) -replace "`r`n", "`n" -replace "`r", "`n"
        $localContent = (Get-Content $PSCommandPath -Raw) -replace "`r`n", "`n" -replace "`r", "`n"
        $remoteContent = $remoteContent.Trim()
        $localContent = $localContent.Trim()
        if ($remoteContent -ne $localContent) {
            $remoteVersion = "Unknown"
            if ($remoteContent -match 'SCRIPT_VERSION\s*=\s*"([^"]+)"') { $remoteVersion = $matches[1] }
            # Prevent downgrade: only offer update if remote version is actually newer
            try {
                $localVer = [version]($Script:SCRIPT_VERSION -replace '[^0-9.]','')
                $remoteVer = [version]($remoteVersion -replace '[^0-9.]','')
                if ($remoteVer -le $localVer) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    Write-Log "Remote version v$remoteVersion is not newer than local v$Script:SCRIPT_VERSION - skipping" -Level Success
                    return @{ UpdateAvailable = $false; Reason = "LocalIsNewer" }
                }
            } catch {
                # If version parsing fails, fall through to offer update with warning
                Write-Log "Could not compare versions (local=$Script:SCRIPT_VERSION, remote=$remoteVersion)" -Level Warning
            }
            Write-Log "Update available! (v$Script:SCRIPT_VERSION -> v$remoteVersion)" -Level Warning
            return @{ UpdateAvailable = $true; TempFile = $tempFile; RemoteVersion = $remoteVersion; LocalVersion = $Script:SCRIPT_VERSION }
        } else {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            Write-Log "You are on the latest version (v$Script:SCRIPT_VERSION)" -Level Success
            return @{ UpdateAvailable = $false; Reason = "UpToDate" }
        }
    } catch {
        Write-Log "Update check failed: $($_.Exception.Message)" -Level Warning
        return @{ UpdateAvailable = $false; Reason = "Error"; Error = $_.Exception.Message }
    }
}

function Apply-ScriptUpdate {
    param([string]$UpdatedScriptPath, [string]$CurrentScriptPath, [switch]$RestartAfter)
    if (-not (Test-Path $UpdatedScriptPath)) { Write-Log "Update file not found: $UpdatedScriptPath" -Level Error; return $false }
    $batchFile = Join-Path $env:TEMP "DiscordVoicePatcher_Update.bat"
    $batchContent = "@echo off`necho Applying update...`ntimeout /t 2 /nobreak >nul`ncopy /Y `"$UpdatedScriptPath`" `"$CurrentScriptPath`" >nul`nif errorlevel 1 (`n    echo Failed to copy update file!`n    pause`n    exit /b 1`n)`necho Update applied successfully!`ntimeout /t 1 /nobreak >nul"
    if ($RestartAfter) { $batchContent += "`necho Restarting script...`npowershell.exe -ExecutionPolicy Bypass -File `"$CurrentScriptPath`"" }
    $batchContent += "`ndel `"$UpdatedScriptPath`" >nul 2>&1`n(goto) 2>nul & del `"%~f0`""
    $batchContent | Out-File $batchFile -Encoding ASCII -Force
    Write-Log "Update will be applied after script closes..." -Level Info
    Start-Process "cmd.exe" -ArgumentList "/c", "`"$batchFile`"" -WindowStyle Hidden
    return $true
}

# endregion Auto-Update

# region Voice Backup Download

function Download-VoiceBackupFiles {
    param([string]$DestinationPath)
    Write-Log "Downloading voice backup files from GitHub..." -Level Info
    try {
        if (Test-Path $DestinationPath) {
            Write-Log "  Clearing existing backup folder..." -Level Info
            Remove-Item "$DestinationPath\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        EnsureDir $DestinationPath
        Write-Log "  Fetching file list from GitHub API..." -Level Info
        try {
            $response = Invoke-RestMethod -Uri $Script:Config.VoiceBackupAPI -UseBasicParsing -TimeoutSec 30
        } catch {
            if ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::Forbidden) { throw "GitHub API rate limit exceeded. Please try again later." }
            throw $_
        }
        $response = @($response)
        if ($response.Count -eq 0) { throw "GitHub repository response is empty." }
        $fileCount = 0
        $failedFiles = @()
        foreach ($file in $response) {
            if ($file.type -eq "file") {
                $filePath = Join-Path $DestinationPath $file.name
                Write-Log "  Downloading: $($file.name)" -Level Info
                try {
                    Invoke-WebRequest -Uri $file.download_url -OutFile $filePath -UseBasicParsing -TimeoutSec 30 | Out-Null
                    if (-not (Test-Path $filePath)) { throw "File was not created" }
                    $fileInfo = Get-Item $filePath
                    if ($fileInfo.Length -eq 0) { throw "Downloaded file is empty" }
                    $ext = [System.IO.Path]::GetExtension($file.name).ToLower()
                    if (($ext -eq ".node" -or $ext -eq ".dll") -and $fileInfo.Length -lt 1024) {
                        Write-Log "  [!] Warning: $($file.name) seems too small ($($fileInfo.Length) bytes)" -Level Warning
                    }
                    $fileCount++
                } catch {
                    Write-Log "  [!] Failed to download $($file.name): $($_.Exception.Message)" -Level Warning
                    $failedFiles += $file.name
                }
            }
        }
        if ($fileCount -eq 0) { throw "No valid files were downloaded." }
        if ($failedFiles.Count -gt 0) { Write-Log "  [!] Warning: $($failedFiles.Count) file(s) failed to download" -Level Warning }
        Write-Log "Downloaded $fileCount voice backup files" -Level Success
        return $true
    } catch {
        Write-Log "Failed to download voice backup files: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# endregion Voice Backup Download

# region Multi-Client Detection

function Get-PathFromProcess {
    param([string]$ProcessName)
    if ([string]::IsNullOrWhiteSpace($ProcessName)) { return $null }
    try {
        $p = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p -and $p.MainModule -and $p.MainModule.FileName) { return (Split-Path (Split-Path $p.MainModule.FileName -Parent) -Parent) }
    } catch {}
    return $null
}

function Get-PathFromShortcuts {
    param([string]$ShortcutName)
    if (-not $ShortcutName) { return $null }
    $sm = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    if (!(Test-Path $sm)) { return $null }
    $scs = @(Get-ChildItem $sm -Filter "$ShortcutName.lnk" -Recurse -ErrorAction SilentlyContinue)
    if ($scs.Count -eq 0) { return $null }
    $ws = $null
    try {
        $ws = New-Object -ComObject WScript.Shell
        foreach ($lf in $scs) {
            try {
                $sc = $ws.CreateShortcut($lf.FullName)
                if ($sc.TargetPath -and (Test-Path $sc.TargetPath)) { return (Split-Path $sc.TargetPath -Parent) }
            } catch { }
        }
    } catch { } finally {
        if ($ws) { try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ws) | Out-Null } catch {} }
    }
    return $null
}

function Find-DiscordAppPath {
    param([string]$BasePath, [switch]$ReturnDiagnostics)
    if (-not $BasePath -or -not (Test-Path $BasePath)) {
        if ($ReturnDiagnostics) { return @{ Error = "InvalidBasePath" } }
        return $null
    }
    $af = @(Get-ChildItem $BasePath -Filter "app-*" -Directory -ErrorAction SilentlyContinue |
        Sort-Object { $folder = $_; try { if ($folder.Name -match "app-([\d\.]+)") { [Version]$matches[1] } else { $folder.Name } } catch { $folder.Name } } -Descending)
    $diag = @{
        BasePath = $BasePath; AppFoldersFound = @(); ModulesFolderExists = $false; VoiceModuleExists = $false
        LatestAppFolder = $null; LatestAppVersion = $null; ModulesPath = $null; VoiceModulePath = $null; Error = $null
    }
    if ($af.Count -eq 0) { $diag.Error = "NoAppFolders"; if ($ReturnDiagnostics) { return $diag }; return $null }
    $diag.AppFoldersFound = @($af | ForEach-Object { $_.Name })
    $diag.LatestAppFolder = $af[0].FullName
    if ($af[0].Name -match "app-([\d\.]+)") { $diag.LatestAppVersion = $matches[1] } else { $diag.LatestAppVersion = $af[0].Name }
    foreach ($f in $af) {
        $mp = Join-Path $f.FullName "modules"
        if (Test-Path $mp) {
            $diag.ModulesFolderExists = $true
            $diag.ModulesPath = $mp
            $vm = @(Get-ChildItem $mp -Filter "discord_voice*" -Directory -ErrorAction SilentlyContinue)
            if ($vm.Count -gt 0) {
                $diag.VoiceModuleExists = $true
                $diag.VoiceModulePath = $vm[0].FullName
                if ($ReturnDiagnostics) { return $diag }
                return $f.FullName
            }
        }
    }
    if (-not $diag.ModulesFolderExists) { $diag.Error = "NoModulesFolder" }
    elseif (-not $diag.VoiceModuleExists) { $diag.Error = "NoVoiceModule" }
    if ($ReturnDiagnostics) { return $diag }
    return $null
}

function Get-DiscordAppVersion {
    param([string]$AppPath)
    if ([string]::IsNullOrWhiteSpace($AppPath)) { return "Unknown" }
    if ($AppPath -match "app-([\d\.]+)") { return $matches[1] }
    try {
        $exe = Get-ChildItem $AppPath -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($exe) { return (Get-Item $exe.FullName).VersionInfo.ProductVersion }
    } catch {}
    return "Unknown"
}

function Get-InstalledClients {
    $inst = [System.Collections.ArrayList]::new()
    $foundPaths = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($k in $Script:DiscordClients.Keys) {
        $c = $Script:DiscordClients[$k]
        $isMod = $c.Name -match '\[Mod\]'
        if ($isMod -and $c.DetectPath -and -not (Test-Path $c.DetectPath)) { continue }
        $fp = $null
        if ($c.Path -and (Test-Path $c.Path)) { $fp = $c.Path }
        elseif ($c.FallbackPath -and (Test-Path $c.FallbackPath)) { $fp = $c.FallbackPath }
        else {
            foreach ($pn in $c.Processes) {
                if ($pn -eq "Update") { continue }
                $dp = Get-PathFromProcess $pn
                if ($dp -and (Test-Path $dp)) { $fp = $dp; break }
            }
        }
        if (-not $fp -and $c.Shortcut) {
            $sp = Get-PathFromShortcuts $c.Shortcut
            if ($sp -and (Test-Path $sp)) { $fp = $sp }
        }
        if ($fp) {
            try { $fp = (Get-Item $fp).FullName } catch { continue }
            if ($foundPaths.Contains($fp) -and -not $isMod) { continue }
            $ap = Find-DiscordAppPath $fp
            if ($ap) {
                [void]$inst.Add(@{Index=$k; Name=$c.Name; Path=$fp; AppPath=$ap; Client=$c})
                [void]$foundPaths.Add($fp)
            }
        }
    }
    return $inst
}

# endregion Multi-Client Detection

# region Process Management

function Stop-DiscordProcesses {
    param([string[]]$ProcessNames, [string]$InstallPath)
    if (-not $ProcessNames -or $ProcessNames.Count -eq 0) { return $true }
    $p = Get-Process -Name $ProcessNames -ErrorAction SilentlyContinue
    if (-not $p) { return $true }
    if ($PSBoundParameters.ContainsKey('InstallPath')) {
        if (-not $InstallPath -or -not (Test-Path $InstallPath)) { $p = @() } else {
            try {
                $installFull = (Get-Item $InstallPath).FullName.TrimEnd('\') + '\'
                $toKill = @()
                foreach ($proc in $p) {
                    $exePath = $null
                    try {
                        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                        if ($cim -and $cim.ExecutablePath) { $exePath = $cim.ExecutablePath }
                    } catch { }
                    if (-not $exePath) { continue }
                    try { $exePath = (Get-Item $exePath).FullName.TrimEnd('\') } catch { continue }
                    if ($exePath.StartsWith($installFull, [StringComparison]::OrdinalIgnoreCase)) { $toKill += $proc }
                }
                $p = $toKill
            } catch { $p = @() }
        }
    }
    if ($p) {
        $p | Stop-Process -Force -ErrorAction SilentlyContinue
        for ($i = 0; $i -lt 20; $i++) {
            $remaining = Get-Process -Name $ProcessNames -ErrorAction SilentlyContinue
            if (-not $remaining) { return $true }
            if ($PSBoundParameters.ContainsKey('InstallPath') -and $InstallPath -and (Test-Path $InstallPath)) {
                $installFull = (Get-Item $InstallPath).FullName.TrimEnd('\') + '\'
                $remaining = @($remaining | Where-Object {
                    $exePath = $null
                    try {
                        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue
                        if ($cim -and $cim.ExecutablePath) { $exePath = (Get-Item $cim.ExecutablePath).FullName.TrimEnd('\') }
                    } catch { }
                    $exePath -and $exePath.StartsWith($installFull, [StringComparison]::OrdinalIgnoreCase)
                })
                if (@($remaining).Count -eq 0) { return $true }
            }
            Start-Sleep -Milliseconds 250
        }
        return $false
    }
    return $true
}

function Stop-AllDiscordProcesses {
    $allProcs = @("Discord","DiscordCanary","DiscordPTB","DiscordDevelopment","Lightcord","BetterVencord","Equicord","Vencord","Update")
    return Stop-DiscordProcesses $allProcs
}

# endregion Process Management

# region Backup Management

function Get-BackupList {
    if (-not (Test-Path $Script:Config.BackupDir)) { return @() }
    $backups = @(Get-ChildItem $Script:Config.BackupDir -Filter "discord_voice.node.*.backup" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($backups.Count -eq 0) { return @() }
    return @($backups | ForEach-Object { @{ Path = $_.FullName; Date = $_.LastWriteTime; Size = $_.Length; Name = $_.Name } })
}

function Show-BackupList {
    $backups = Get-BackupList
    if ($backups.Count -eq 0) { Write-Host "No backups found" -ForegroundColor Yellow; return }
    Write-Host "`n=== Available Backups ===" -ForegroundColor Cyan
    for ($i = 0; $i -lt $backups.Count; $i++) {
        Write-Host "  [$($i+1)] $($backups[$i].Date.ToString('yyyy-MM-dd HH:mm:ss')) - $([Math]::Round($backups[$i].Size / 1MB, 2)) MB - $($backups[$i].Name)"
    }
    Write-Host ""
}

function Get-VoiceModulePaths {
    param([Parameter(Mandatory)][string]$AppPath)

    $modulesPath = Join-Path $AppPath "modules"
    $voiceModules = @(
        Get-ChildItem $modulesPath -Filter "discord_voice*" -Directory -ErrorAction SilentlyContinue
    )
    if ($voiceModules.Count -eq 0) {
        return $null
    }

    $voiceModule = $voiceModules[0]
    $nestedVoiceFolder = Join-Path $voiceModule.FullName "discord_voice"
    $voiceFolderPath = if (Test-Path $nestedVoiceFolder) { $nestedVoiceFolder } else { $voiceModule.FullName }
    $voiceNodePath = Join-Path $voiceFolderPath "discord_voice.node"

    return @{
        ModulesPath = $modulesPath
        VoiceModule = $voiceModule
        VoiceFolderPath = $voiceFolderPath
        VoiceNodePath = $voiceNodePath
    }
}

function Restore-FromBackup {
    param([string]$BackupPath = $null)

    Write-Banner
    Write-Log "Starting restore..." -Level Info

    if (-not $BackupPath) {
        $backups = Get-BackupList
        if ($backups.Count -eq 0) {
            Write-Log "No backups found" -Level Error
            return $false
        }

        Show-BackupList
        $sel = Read-Host "Select backup (1-$($backups.Count)) or Enter for most recent"
        if ([string]::IsNullOrWhiteSpace($sel)) {
            $BackupPath = $backups[0].Path
        } else {
            $idx = 0
            if (-not [int]::TryParse($sel, [ref]$idx) -or $idx -lt 1 -or $idx -gt $backups.Count) {
                Write-Log "Invalid selection" -Level Error
                return $false
            }
            $BackupPath = $backups[$idx - 1].Path
        }
    }

    $installedClients = Get-InstalledClients
    if ($installedClients.Count -eq 0) {
        Write-Log "No Discord clients found to restore to" -Level Error
        return $false
    }

    Write-Log "Found $($installedClients.Count) client(s) to restore:" -Level Info
    for ($i = 0; $i -lt $installedClients.Count; $i++) {
        Write-Log "  [$($i+1)] $($installedClients[$i].Name.Trim())" -Level Info
    }

    $sel = Read-Host "Select client to restore (1-$($installedClients.Count)) or Enter for first"
    $targetIdx = 0
    if (-not [string]::IsNullOrWhiteSpace($sel)) {
        if (-not [int]::TryParse($sel, [ref]$targetIdx) -or $targetIdx -lt 1 -or $targetIdx -gt $installedClients.Count) {
            Write-Log "Invalid selection" -Level Error
            return $false
        }
        $targetIdx--
    }

    $targetClient = $installedClients[$targetIdx]
    if (-not $targetClient -or -not $targetClient.AppPath) {
        Write-Log "Invalid target client" -Level Error
        return $false
    }

    $voiceInfo = Get-VoiceModulePaths -AppPath $targetClient.AppPath
    if (-not $voiceInfo) {
        Write-Log "No voice module found in target client" -Level Error
        return $false
    }

    $targetPath = $voiceInfo.VoiceNodePath
    Write-Log "Target: $targetPath" -Level Info

    if ((Read-Host "Replace current file with backup? (y/N)") -notin @('y', 'Y')) {
        return $false
    }

    try {
        Write-Log "Closing Discord processes..." -Level Info
        Stop-AllDiscordProcesses | Out-Null
        Start-Sleep -Seconds 2
        Copy-Item -Path $BackupPath -Destination $targetPath -Force
        Write-Log "Restore complete! Restart Discord." -Level Success
        return $true
    } catch {
        Write-Log "Restore failed: $_" -Level Error
        return $false
    }
}

function Backup-VoiceNode {
    param([string]$SourcePath, [string]$ClientName = "Discord")
    if ($Script:Config.SkipBackup) { Write-Log "Skipping backup" -Level Warning; return $true }
    if (-not $SourcePath -or -not (Test-Path $SourcePath)) { Write-Log "Backup source not found: $SourcePath" -Level Error; return $false }
    try {
        EnsureDir $Script:Config.BackupDir
        $sanitizedName = $ClientName -replace '\s+','_' -replace '\[|\]','' -replace '-','_'
        $backupPath = Join-Path $Script:Config.BackupDir "discord_voice.node.$sanitizedName.$(Get-Date -Format 'yyyyMMdd_HHmmss').backup"
        Copy-Item -Path $SourcePath -Destination $backupPath -Force
        Write-Log "Backup created: $([System.IO.Path]::GetFileName($backupPath))" -Level Success
        $backups = Get-BackupList
        if ($backups.Count -gt $Script:Config.MaxBackupCount) {
            $backups | Select-Object -Skip $Script:Config.MaxBackupCount | ForEach-Object { Remove-Item $_.Path -Force -ErrorAction SilentlyContinue }
        }
        return $true
    } catch { Write-Log "Backup failed: $_" -Level Error; return $false }
}

# endregion Backup Management

# region GUI

function Show-ConfigurationGUI {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $prevCfg = Get-UserConfig
    $installedClients = Get-InstalledClients
    $initGain = if ($prevCfg -and -not $Script:GainExplicitlySet) { [Math]::Max(1, [Math]::Min(10, $prevCfg.LastGainMultiplier)) } else { $Script:Config.AudioGainMultiplier }

    $Script:GuiInstalledIndices = @{}
    foreach ($ic in $installedClients) { $Script:GuiInstalledIndices[$ic.Index] = $ic }
    $Script:GuiInstalledClients = $installedClients

    $form = New-Object Windows.Forms.Form -Property @{
        Text = "Discord Voice Patcher v$Script:SCRIPT_VERSION"; ClientSize = "520,570"; StartPosition = "CenterScreen"
        FormBorderStyle = "FixedDialog"; MaximizeBox = $false; MinimizeBox = $false
        BackColor = [Drawing.Color]::FromArgb(44,47,51); ForeColor = [Drawing.Color]::White
    }

    $newLabel = { param($x, $y, $w, $h, $text, $font, $color)
        $l = New-Object Windows.Forms.Label -Property @{ Location = "$x,$y"; Size = "$w,$h"; Text = $text }
        if ($font) { $l.Font = $font }
        if ($color) { $l.ForeColor = $color }
        $form.Controls.Add($l); $l
    }

    & $newLabel 20 20 400 30 "Discord Voice Quality Patcher" (New-Object Drawing.Font("Segoe UI", 16, [Drawing.FontStyle]::Bold)) ([Drawing.Color]::FromArgb(88,101,242))
    & $newLabel 420 28 80 20 "v$Script:SCRIPT_VERSION" (New-Object Drawing.Font("Segoe UI", 9)) ([Drawing.Color]::FromArgb(150,152,157))
    & $newLabel 20 55 480 20 "48kHz | 400kbps | Stereo | Multi-Client Support" (New-Object Drawing.Font("Segoe UI", 9)) ([Drawing.Color]::FromArgb(185,187,190))
    & $newLabel 20 85 480 25 "Discord Client" (New-Object Drawing.Font("Segoe UI", 11, [Drawing.FontStyle]::Bold)) $null

    $clientCombo = New-Object Windows.Forms.ComboBox -Property @{
        Location = "20,112"; Size = "480,28"; DropDownStyle = "DropDownList"
        BackColor = [Drawing.Color]::FromArgb(47,49,54); ForeColor = [Drawing.Color]::White
        Font = New-Object Drawing.Font("Consolas", 9)
    }
    $firstInstalledIndex = -1
    foreach ($k in $Script:DiscordClients.Keys) {
        $c = $Script:DiscordClients[$k]
        $isInstalled = $Script:GuiInstalledIndices.ContainsKey($k)
        $prefix = if ($isInstalled) { "[*] " } else { "[ ] " }
        [void]$clientCombo.Items.Add("$prefix$($c.Name)")
        if ($isInstalled -and $firstInstalledIndex -eq -1) { $firstInstalledIndex = $k }
    }
    if ($firstInstalledIndex -ge 0) { $clientCombo.SelectedIndex = $firstInstalledIndex } else { $clientCombo.SelectedIndex = 0 }
    $form.Controls.Add($clientCombo)

    $detectedLabel = & $newLabel 20 145 480 20 "" (New-Object Drawing.Font("Segoe UI", 9)) ([Drawing.Color]::FromArgb(87,242,135))
    if ($installedClients.Count -gt 0) { $detectedLabel.Text = "Detected: $($installedClients.Count) client(s) installed  |  [*] = Installed" }
    else { $detectedLabel.Text = "No Discord clients detected - please install Discord first"; $detectedLabel.ForeColor = [Drawing.Color]::FromArgb(237,66,69) }

    & $newLabel 20 175 480 25 "Audio Gain Multiplier" (New-Object Drawing.Font("Segoe UI", 12, [Drawing.FontStyle]::Bold)) $null
    $valueLabel = & $newLabel 20 205 480 30 "" (New-Object Drawing.Font("Segoe UI", 14, [Drawing.FontStyle]::Bold)) $null
    $valueLabel.TextAlign = [Drawing.ContentAlignment]::MiddleCenter

    $updateLabel = { param([int]$m)
        $valueLabel.Text = if ($m -eq 1) { "1x (No Boost - Original Volume)" } else { "${m}x Volume Boost" }
        $valueLabel.ForeColor = if ($m -le 2) { [Drawing.Color]::FromArgb(87,242,135) } elseif ($m -le 5) { [Drawing.Color]::FromArgb(254,231,92) } else { [Drawing.Color]::FromArgb(237,66,69) }
    }

    $slider = New-Object Windows.Forms.TrackBar
    $slider.Location = New-Object Drawing.Point(30, 245)
    $slider.Size = New-Object Drawing.Size(460, 45)
    $slider.Minimum = 1; $slider.Maximum = 10; $slider.TickFrequency = 1; $slider.LargeChange = 1; $slider.SmallChange = 1
    $slider.TickStyle = [Windows.Forms.TickStyle]::BottomRight
    $slider.BackColor = [Drawing.Color]::FromArgb(44,47,51)
    $slider.Add_ValueChanged({ & $updateLabel $slider.Value })
    $slider.Value = $initGain
    $form.Controls.Add($slider)
    & $updateLabel $initGain

    & $newLabel 30 290 460 20 "1x      2x      3x      4x      5x      6x      7x      8x      9x     10x" (New-Object Drawing.Font("Consolas", 8)) ([Drawing.Color]::FromArgb(150,152,157))
    & $newLabel 20 315 480 30 "1x = Original volume (no boost). Recommended: 2-3x. Values >5x may distort." (New-Object Drawing.Font("Segoe UI", 9)) ([Drawing.Color]::FromArgb(185,187,190))

    $chk = New-Object Windows.Forms.CheckBox -Property @{
        Location = "20,350"; Size = "480,25"; Text = "Create backup before patching (Recommended)"
        Checked = $(if ($prevCfg -and $null -ne $prevCfg.LastBackupEnabled) { $prevCfg.LastBackupEnabled } else { -not $Script:Config.SkipBackup })
        ForeColor = [Drawing.Color]::White; Font = New-Object Drawing.Font("Segoe UI", 9)
    }
    $form.Controls.Add($chk)

    $autoRelaunchChk = New-Object Windows.Forms.CheckBox -Property @{
        Location = "20,375"; Size = "480,25"; Text = "Auto-relaunch Discord after patching"
        Checked = $(if ($prevCfg -and $null -ne $prevCfg.AutoRelaunch) { $prevCfg.AutoRelaunch } else { $true })
        ForeColor = [Drawing.Color]::White; Font = New-Object Drawing.Font("Segoe UI", 9)
    }
    $form.Controls.Add($autoRelaunchChk)

    if ($prevCfg -and $prevCfg.LastPatchDate) {
        & $newLabel 20 405 480 20 "Last: $($prevCfg.LastPatchDate) @ $($prevCfg.LastGainMultiplier)x" (New-Object Drawing.Font("Segoe UI", 8)) ([Drawing.Color]::FromArgb(150,152,157))
    }

    $statusLabel = & $newLabel 20 430 480 25 "" (New-Object Drawing.Font("Segoe UI", 9)) ([Drawing.Color]::FromArgb(237,66,69))
    if (-not $Script:GuiInstalledIndices.ContainsKey($clientCombo.SelectedIndex)) { $statusLabel.Text = "This client is not installed" }

    $btnStyle = { param($x, $text, $bgR, $bgG, $bgB, $bold, $action)
        $b = New-Object Windows.Forms.Button -Property @{
            Location = "$x,470"; Size = "115,40"; Text = $text; FlatStyle = "Flat"
            BackColor = [Drawing.Color]::FromArgb($bgR, $bgG, $bgB); ForeColor = [Drawing.Color]::White
            Font = New-Object Drawing.Font("Segoe UI", 10, $(if ($bold) { [Drawing.FontStyle]::Bold } else { [Drawing.FontStyle]::Regular }))
            Cursor = [Windows.Forms.Cursors]::Hand
        }
        $b.Add_Click($action); $form.Controls.Add($b); $b
    }

    & $btnStyle 20 "Restore" 79 84 92 $false { $form.Tag = @{ Action = 'Restore' }; $form.DialogResult = "Abort"; $form.Close() }

    & $btnStyle 140 "Patch" 88 101 242 $true {
        $selectedIdx = $clientCombo.SelectedIndex
        if (-not $Script:GuiInstalledIndices.ContainsKey($selectedIdx)) { $statusLabel.Text = "Selected client is not installed!"; return }
        $form.Tag = @{ Action = 'Patch'; Multiplier = $slider.Value; SkipBackup = -not $chk.Checked; AutoRelaunch = $autoRelaunchChk.Checked; ClientIndex = $selectedIdx }
        $form.DialogResult = "OK"; $form.Close()
    }

    & $btnStyle 260 "Patch All" 87 158 87 $true {
        if ($Script:GuiInstalledClients.Count -eq 0) { $statusLabel.Text = "No Discord clients detected to patch!"; return }
        $form.Tag = @{ Action = 'PatchAll'; Multiplier = $slider.Value; SkipBackup = -not $chk.Checked; AutoRelaunch = $autoRelaunchChk.Checked }
        $form.DialogResult = "OK"; $form.Close()
    }

    $cancelBtn = & $btnStyle 385 "Cancel" 79 84 92 $false { $form.DialogResult = "Cancel"; $form.Close() }

    $clientCombo.Add_SelectedIndexChanged({
        $selectedIdx = $clientCombo.SelectedIndex
        if ($Script:GuiInstalledIndices.ContainsKey($selectedIdx)) { $statusLabel.Text = ""; $statusLabel.ForeColor = [Drawing.Color]::FromArgb(87,242,135) }
        else { $statusLabel.Text = "This client is not installed"; $statusLabel.ForeColor = [Drawing.Color]::FromArgb(237,66,69) }
    })

    $form.CancelButton = $cancelBtn
    try { $null = $form.ShowDialog(); return $form.Tag } finally { $form.Dispose() }
}

# endregion GUI

# region Environment & Compiler

function Initialize-Environment {
    @($Script:Config.TempDir, $Script:Config.BackupDir) | ForEach-Object {
        if ($_ -and -not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
    }
    $tempDir = $Script:Config.TempDir
    if (Test-Path $tempDir) {
        @("patcher.cpp", "amplifier.cpp", "DiscordVoicePatcher.exe", "build.bat", "build.log") | ForEach-Object {
            $file = Join-Path $tempDir $_
            if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
        }
        Get-ChildItem $tempDir -Filter "DiscordVoicePatcher_*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    "=== Discord Voice Patcher Log ===`nStarted: $(Get-Date)`nGain: $($Script:Config.AudioGainMultiplier)x`n" | Out-File $Script:Config.LogFile -Force -ErrorAction SilentlyContinue
}

function Write-CompilerSetupHelp {
    param(
        [ValidateSet('MissingCompiler','VisualStudioMissingCpp','MsvcBuildFailure','GppBuildFailure','ClangBuildFailure')]
        [string]$Reason = 'MissingCompiler'
    )

    Write-Host ""
    Write-Host "=== C++ Build Tools Required ===" -ForegroundColor Yellow
    Write-Log "This patcher compiles native C++ code at runtime." -Level Warning

    if (Get-Command "code" -ErrorAction SilentlyContinue) {
        Write-Log "VS Code is an editor only. It does NOT include a C++ compiler." -Level Warning
    }

    switch ($Reason) {
        'VisualStudioMissingCpp' {
            Write-Log "Visual Studio was found, but required C++ components are missing." -Level Error
            Write-Log "Open Visual Studio Installer -> Modify -> Workloads -> Desktop development with C++" -Level Warning
            Write-Log "Install MSVC v143 x64/x86 build tools and Windows 10/11 SDK" -Level Warning
        }
        'MsvcBuildFailure' {
            Write-Log "MSVC build failed. This is commonly caused by missing Visual Studio C++ components." -Level Error
            Write-Log "Open Visual Studio Installer -> Modify -> Workloads -> Desktop development with C++" -Level Warning
            Write-Log "Install MSVC v143 x64/x86 build tools and Windows 10/11 SDK" -Level Warning
        }
        'GppBuildFailure' {
            Write-Log "MinGW g++ build failed. Verify g++ is installed and available in PATH." -Level Error
        }
        'ClangBuildFailure' {
            Write-Log "Clang build failed. Verify clang++ is installed and available in PATH." -Level Error
        }
        default {
            Write-Log "No C++ compiler was found." -Level Error
            Write-Log "Install ONE of: Visual Studio (Desktop development with C++), MinGW-w64, or LLVM/Clang." -Level Warning
            Write-Log "Visual Studio Code alone is not enough." -Level Warning
        }
    }

    Write-Log "After installing tools, rerun the patcher." -Level Info
    Write-Host ""
}

function Find-Compiler {
    Write-Log "Searching for C++ compiler..." -Level Info
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsDetectedPath = $null
    $vsWithCppPath = $null
    $vcvarsMissing = $false

    if (Test-Path $vsWhere) {
        try {
            $vsWithCppPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
            if ($vsWithCppPath) {
                $vcvars = Join-Path $vsWithCppPath "VC\Auxiliary\Build\vcvars64.bat"
                if (Test-Path $vcvars) {
                    Write-Log "Found Visual Studio C++ Build Tools" -Level Success
                    return @{ Type = 'MSVC'; Path = $vcvars }
                }
                $vcvarsMissing = $true
                Write-Log "Visual Studio C++ workload detected but vcvars64.bat was not found: $vcvars" -Level Warning
            }

            $vsDetectedPath = & $vsWhere -latest -products * -property installationPath 2>$null
        } catch {
            Write-Log "Could not query Visual Studio installer: $($_.Exception.Message)" -Level Warning
        }
    }

    $gpp = Get-Command "g++" -ErrorAction SilentlyContinue
    if ($gpp) { Write-Log "Found MinGW g++" -Level Success; return @{ Type = 'MinGW'; Path = $gpp.Source } }

    $clang = Get-Command "clang++" -ErrorAction SilentlyContinue
    if ($clang) { Write-Log "Found Clang" -Level Success; return @{ Type = 'Clang'; Path = $clang.Source } }

    if ($vsDetectedPath -and (-not $vsWithCppPath -or $vcvarsMissing)) {
        Write-Log "Visual Studio detected at: $vsDetectedPath" -Level Warning
        Write-CompilerSetupHelp -Reason VisualStudioMissingCpp
        return $null
    }

    Write-CompilerSetupHelp -Reason MissingCompiler
    return $null
}

function Cleanup-TempFiles {
    $tempDir = $Script:Config.TempDir
    if (-not $tempDir -or -not (Test-Path $tempDir)) { return }
    @("patcher.cpp", "amplifier.cpp", "DiscordVoicePatcher.exe", "build.bat", "build.log", "patcher.obj", "amplifier.obj") | ForEach-Object {
        $file = Join-Path $tempDir $_
        if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
    }
    Get-ChildItem $tempDir -Filter "DiscordVoicePatcher_*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

# endregion Environment & Compiler

# region Source Code Generation

function Get-AmplifierSourceCode {
    $gain = $Script:Config.AudioGainMultiplier
    Write-Log "Generating amplifier: Gain=$gain x (unity at 1x, stereo normalized)" -Level Info
    return @"
#define GAIN_MULTIPLIER $gain

typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

#include <xmmintrin.h>

extern "C" void __cdecl hp_cutoff(const float* in, int cutoff_Hz, float* out, int* hp_mem, int len, int channels, int Fs, int arch)
{
    int* st = (hp_mem - 3553);
    *(int*)(st + 3557) = 1002;
    *(int*)((char*)st + 160) = -1;
    *(int*)((char*)st + 164) = -1;
    *(int*)((char*)st + 184) = 0;

    float scale = 1.0f;
    if (channels > 0) {
        __m128 v = _mm_cvtsi32_ss(_mm_setzero_ps(), channels);
        v = _mm_rsqrt_ss(v);
        scale = _mm_cvtss_f32(v);
    }
    for (unsigned long i = 0; i < channels * len; i++) out[i] = in[i] * GAIN_MULTIPLIER * scale;
}

extern "C" void __cdecl dc_reject(const float* in, float* out, int* hp_mem, int len, int channels, int Fs)
{
    int* st = (hp_mem - 3553);
    *(int*)(st + 3557) = 1002;
    *(int*)((char*)st + 160) = -1;
    *(int*)((char*)st + 164) = -1;
    *(int*)((char*)st + 184) = 0;

    float scale = 1.0f;
    if (channels > 0) {
        __m128 v = _mm_cvtsi32_ss(_mm_setzero_ps(), channels);
        v = _mm_rsqrt_ss(v);
        scale = _mm_cvtss_f32(v);
    }
    for (int i = 0; i < channels * len; i++) out[i] = in[i] * GAIN_MULTIPLIER * scale;
}
"@
}

function Get-PatcherSourceCode {
    param([string]$ProcessName = "Discord.exe", [string]$ModuleName = "discord_voice.node")
    $offsets = $Script:Config.Offsets
    $c = $Script:Config
    return @"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <cstdint>

#define SAMPLE_RATE $($c.SampleRate)
#define BITRATE $($c.Bitrate)
#define AUDIO_GAIN $($c.AudioGainMultiplier)

extern "C" void dc_reject(const float*, float*, int*, int, int, int);
extern "C" void hp_cutoff(const float*, int, float*, int*, int, int, int, int);

namespace Offsets {
    constexpr uint32_t CreateAudioFrameStereo = $('0x{0:X}' -f $offsets.CreateAudioFrameStereo);
    constexpr uint32_t AudioEncoderOpusConfigSetChannels = $('0x{0:X}' -f $offsets.AudioEncoderOpusConfigSetChannels);
    constexpr uint32_t MonoDownmixer = $('0x{0:X}' -f $offsets.MonoDownmixer);
    constexpr uint32_t EmulateStereoSuccess1 = $('0x{0:X}' -f $offsets.EmulateStereoSuccess1);
    constexpr uint32_t EmulateStereoSuccess2 = $('0x{0:X}' -f $offsets.EmulateStereoSuccess2);
    constexpr uint32_t EmulateBitrateModified = $('0x{0:X}' -f $offsets.EmulateBitrateModified);
    constexpr uint32_t SetsBitrateBitrateValue = $('0x{0:X}' -f $offsets.SetsBitrateBitrateValue);
    constexpr uint32_t SetsBitrateBitwiseOr = $('0x{0:X}' -f $offsets.SetsBitrateBitwiseOr);
    constexpr uint32_t Emulate48Khz = $('0x{0:X}' -f $offsets.Emulate48Khz);
    constexpr uint32_t HighPassFilter = $('0x{0:X}' -f $offsets.HighPassFilter);
    constexpr uint32_t HighpassCutoffFilter = $('0x{0:X}' -f $offsets.HighpassCutoffFilter);
    constexpr uint32_t DcReject = $('0x{0:X}' -f $offsets.DcReject);
    constexpr uint32_t DownmixFunc = $('0x{0:X}' -f $offsets.DownmixFunc);
    constexpr uint32_t AudioEncoderOpusConfigIsOk = $('0x{0:X}' -f $offsets.AudioEncoderOpusConfigIsOk);
    constexpr uint32_t ThrowError = $('0x{0:X}' -f $offsets.ThrowError);
    constexpr uint32_t DuplicateEmulateBitrateModified = $('0x{0:X}' -f $offsets.DuplicateEmulateBitrateModified);
    constexpr uint32_t EncoderConfigInit1 = $('0x{0:X}' -f $offsets.EncoderConfigInit1);
    constexpr uint32_t EncoderConfigInit2 = $('0x{0:X}' -f $offsets.EncoderConfigInit2);
    constexpr uint32_t FILE_OFFSET_ADJUSTMENT = 0xC00;
};

class DiscordPatcher {
private:
    std::string modulePath;

    bool TerminateAllDiscordProcesses() {
        printf("Closing Discord...\n");
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32 entry = {sizeof(PROCESSENTRY32)};
        const char* processNames[] = {"Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe", "Lightcord.exe", NULL};
        if (Process32First(snapshot, &entry)) {
            do {
                for (const char** pn = processNames; *pn != NULL; pn++) {
                    if (strcmp(entry.szExeFile, *pn) == 0) {
                        HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                        if (proc) { TerminateProcess(proc, 0); CloseHandle(proc); }
                    }
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return true;
    }

    bool WaitForDiscordClose(int maxAttempts = 20) {
        const char* processNames[] = {"Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe", "Lightcord.exe", NULL};
        for (int i = 0; i < maxAttempts; i++) {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE) return false;
            PROCESSENTRY32 entry = {sizeof(PROCESSENTRY32)};
            bool found = false;
            if (Process32First(snapshot, &entry)) {
                do {
                    for (const char** pn = processNames; *pn != NULL; pn++) {
                        if (strcmp(entry.szExeFile, *pn) == 0) { found = true; break; }
                    }
                    if (found) break;
                } while (Process32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);
            if (!found) return true;
            Sleep(250);
        }
        return false;
    }

    bool ApplyPatches(void* fileData, LONGLONG fileSize) {
        printf("\nApplying patches:\n");

        // Validate file size - the Feb 2026 node is ~13.6 MB
        // Allow a reasonable range for minor rebuilds
        constexpr LONGLONG MIN_EXPECTED_SIZE = 12 * 1024 * 1024;  // 12 MB
        constexpr LONGLONG MAX_EXPECTED_SIZE = 18 * 1024 * 1024;  // 18 MB
        if (fileSize < MIN_EXPECTED_SIZE || fileSize > MAX_EXPECTED_SIZE) {
            printf("ERROR: File size %.2f MB is outside expected range (12-18 MB)\n",
                   fileSize / (1024.0 * 1024.0));
            printf("This may not be the correct discord_voice.node build for these offsets.\n");
            return false;
        }

        // Validate original bytes at 3 patch sites across different code sections
        // to verify this is the expected build before writing anything
        auto CheckBytes = [&](uint32_t offset, const unsigned char* expected, size_t len) -> bool {
            uint32_t fileOffset = offset - Offsets::FILE_OFFSET_ADJUSTMENT;
            if ((LONGLONG)(fileOffset + len) > fileSize) return false;
            return memcmp((char*)fileData + fileOffset, expected, len) == 0;
        };

        // Probe 3 sections: 0x53 (Emulate48Khz), 0x3A (ConfigIsOk), 0x8B (DownmixFunc)
        const unsigned char orig_48khz[]    = {0x0F, 0x42, 0xC1};            // cmovb eax,ecx
        const unsigned char orig_configok[] = {0x8B, 0x11, 0x31, 0xC0};      // mov edx,[rcx]; xor eax,eax
        const unsigned char orig_downmix[]  = {0x41, 0x57, 0x41, 0x56};      // push r15; push r14

        const unsigned char patched_48khz[]    = {0x90, 0x90, 0x90};         // nop nop nop
        const unsigned char patched_configok[] = {0x48, 0xC7, 0xC0, 0x01};   // mov rax, 1
        const unsigned char patched_downmix[]  = {0xC3};                     // ret

        bool o1 = CheckBytes(Offsets::Emulate48Khz, orig_48khz, 3);
        bool o2 = CheckBytes(Offsets::AudioEncoderOpusConfigIsOk, orig_configok, 4);
        bool o3 = CheckBytes(Offsets::DownmixFunc, orig_downmix, 4);

        bool p1 = CheckBytes(Offsets::Emulate48Khz, patched_48khz, 3);
        bool p2 = CheckBytes(Offsets::AudioEncoderOpusConfigIsOk, patched_configok, 4);
        bool p3 = CheckBytes(Offsets::DownmixFunc, patched_downmix, 1);

        if (p1 && p2 && p3) {
            printf("WARNING: This file appears to already be patched!\n");
            printf("Re-patching anyway to ensure all patches are applied...\n\n");
        } else if (!o1 || !o2 || !o3) {
            printf("ERROR: Binary validation failed - unexpected bytes at patch sites.\n");
            printf("  Emulate48Khz (0x53 section):     %s\n", o1 ? "OK" : "MISMATCH");
            printf("  ConfigIsOk   (0x3A section):     %s\n", o2 ? "OK" : "MISMATCH");
            printf("  DownmixFunc  (0x8B section):     %s\n", o3 ? "OK" : "MISMATCH");
            printf("\nThis discord_voice.node does not match the expected Feb 2026 build.\n");
            printf("The offsets in this patcher are for a specific build and cannot be\n");
            printf("applied safely to a different version.\n");
            return false;
        }

        auto PatchBytes = [&](uint32_t offset, const char* bytes, size_t len) -> bool {
            uint32_t fileOffset = offset - Offsets::FILE_OFFSET_ADJUSTMENT;
            if ((LONGLONG)(fileOffset + len) > fileSize) {
                printf("ERROR: Patch at 0x%X (len %zu) exceeds file size!\n", offset, len);
                printf("The discord_voice.node may not match the expected build.\n");
                return false;
            }
            memcpy((char*)fileData + fileOffset, bytes, len);
            return true;
        };

        auto ReadU32LE = [&](uint32_t offset, uint32_t& value) -> bool {
            uint32_t fileOffset = offset - Offsets::FILE_OFFSET_ADJUSTMENT;
            if ((LONGLONG)(fileOffset + 4) > fileSize) return false;
            memcpy(&value, (char*)fileData + fileOffset, 4);
            return true;
        };

        printf("  [1/5] Enabling stereo audio...\n");
        if (!PatchBytes(Offsets::EmulateStereoSuccess1, "\x02", 1)) return false;
        if (!PatchBytes(Offsets::EmulateStereoSuccess2, "\xEB", 1)) return false;
        if (!PatchBytes(Offsets::CreateAudioFrameStereo, "\x49\x89\xC5\x90", 4)) return false;
        if (!PatchBytes(Offsets::AudioEncoderOpusConfigSetChannels, "\x02", 1)) return false;
        if (!PatchBytes(Offsets::MonoDownmixer, "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xE9", 13)) return false;
        printf("  [2/5] Setting bitrate to 400kbps...\n");
        if (!PatchBytes(Offsets::EmulateBitrateModified, "\x80\x1A\x06", 3)) return false;
        if (!PatchBytes(Offsets::SetsBitrateBitrateValue, "\x80\x1A\x06\x00\x00", 5)) return false;
        if (!PatchBytes(Offsets::SetsBitrateBitwiseOr, "\x90\x90\x90", 3)) return false;
        // Patch duplicate bitrate calculation path (parallel function the original patcher missed)
        if (!PatchBytes(Offsets::DuplicateEmulateBitrateModified, "\x80\x1A\x06", 3)) return false;
        printf("  [3/5] Enabling 48kHz sample rate...\n");
        if (!PatchBytes(Offsets::Emulate48Khz, "\x90\x90\x90", 3)) return false;
        if (AUDIO_GAIN == 1) {
            printf("  [4/5] Injecting audio processing (no amplification)...\n");
        } else {
            printf("  [4/5] Injecting audio processing (%dx gain)...\n", AUDIO_GAIN);
        }
        // Build HighPassFilter stub: mov rax, <HighpassCutoffFilter VA>; ret
        // The stub replaces the filter function with an immediate return.
        // The address in rax is cosmetic (caller ignores return value) but
        // we compute it correctly for clarity during reverse engineering.
        {
            constexpr uint64_t IMAGE_BASE = 0x180000000ULL;
            uint64_t hpcVA = IMAGE_BASE + Offsets::HighpassCutoffFilter;
            unsigned char hpPatch[11];
            hpPatch[0] = 0x48;  // REX.W
            hpPatch[1] = 0xB8;  // mov rax, imm64
            memcpy(hpPatch + 2, &hpcVA, 8);
            hpPatch[10] = 0xC3;  // ret
            if (!PatchBytes(Offsets::HighPassFilter, (const char*)hpPatch, 11)) return false;
        }
        if (!PatchBytes(Offsets::HighpassCutoffFilter, (const char*)hp_cutoff, 0x100)) return false;
        if (!PatchBytes(Offsets::DcReject, (const char*)dc_reject, 0x1B6)) return false;
        if (!PatchBytes(Offsets::DownmixFunc, "\xC3", 1)) return false;
        if (!PatchBytes(Offsets::AudioEncoderOpusConfigIsOk, "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8)) return false;
        if (!PatchBytes(Offsets::ThrowError, "\xC3", 1)) return false;
        printf("  [5/5] Patching encoder config init (400kbps at creation)...\n");
        // Patch both Opus encoder config constructors to initialize with 400kbps
        // instead of default 32kbps - prevents bitrate reset between encoder creation
        // and first SetBitrate call. 400000 = 0x61A80.
        if (!PatchBytes(Offsets::EncoderConfigInit1, "\x80\x1A\x06\x00", 4)) return false;
        if (!PatchBytes(Offsets::EncoderConfigInit2, "\x80\x1A\x06\x00", 4)) return false;

        // Post-patch verification: enforce 400000 bps bytes at every bitrate patch site.
        const unsigned char bps400_3[] = {0x80, 0x1A, 0x06};
        const unsigned char bps400_4[] = {0x80, 0x1A, 0x06, 0x00};
        const unsigned char bps400_5[] = {0x80, 0x1A, 0x06, 0x00, 0x00};
        if (!CheckBytes(Offsets::EmulateBitrateModified, bps400_3, 3) ||
            !CheckBytes(Offsets::DuplicateEmulateBitrateModified, bps400_3, 3) ||
            !CheckBytes(Offsets::SetsBitrateBitrateValue, bps400_5, 5) ||
            !CheckBytes(Offsets::EncoderConfigInit1, bps400_4, 4) ||
            !CheckBytes(Offsets::EncoderConfigInit2, bps400_4, 4)) {
            printf("ERROR: Post-patch bitrate verification failed.\n");
            printf("Expected 400000 bps byte pattern (80 1A 06) was not present at all sites.\n");
            return false;
        }

        uint32_t setBitrateValue = 0;
        uint32_t encoderInit1Value = 0;
        uint32_t encoderInit2Value = 0;
        if (!ReadU32LE(Offsets::SetsBitrateBitrateValue, setBitrateValue) ||
            !ReadU32LE(Offsets::EncoderConfigInit1, encoderInit1Value) ||
            !ReadU32LE(Offsets::EncoderConfigInit2, encoderInit2Value)) {
            printf("ERROR: Failed to read back bitrate values for verification.\n");
            return false;
        }
        if (setBitrateValue != 400000 || encoderInit1Value != 400000 || encoderInit2Value != 400000) {
            printf("ERROR: Bitrate verification mismatch after patching.\n");
            printf("  SetBitrate=%u, EncoderInit1=%u, EncoderInit2=%u (expected all 400000)\n",
                   setBitrateValue, encoderInit1Value, encoderInit2Value);
            return false;
        }
        printf("  Verified bitrate values: %u / %u / %u bps\n",
               setBitrateValue, encoderInit1Value, encoderInit2Value);
        printf("  All patches applied successfully!\n");
        return true;
    }

public:
    DiscordPatcher(const std::string& path) : modulePath(path) {}

    bool PatchFile(bool callerProvidedPath = false) {
        printf("\n================================================\n");
        printf("  Discord Voice Quality Patcher v$Script:SCRIPT_VERSION\n");
        printf("================================================\n");
        printf("  Target:  %s\n", modulePath.c_str());
        if (AUDIO_GAIN == 1) {
            printf("  Config:  %dkHz, %dkbps, Stereo, no gain\n", SAMPLE_RATE/1000, BITRATE);
        } else {
            printf("  Config:  %dkHz, %dkbps, Stereo, %dx gain\n", SAMPLE_RATE/1000, BITRATE, AUDIO_GAIN);
        }
        printf("================================================\n\n");
        if (!callerProvidedPath) {
            if (!WaitForDiscordClose(5)) {
                printf("Closing Discord processes...\n");
                TerminateAllDiscordProcesses();
                if (!WaitForDiscordClose(20)) { printf("WARNING: Discord may still be running\n"); }
            }
        }
        Sleep(500);
        printf("Opening file for patching...\n");
        HANDLE file = CreateFileA(modulePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            printf("ERROR: Cannot open file (Error: %lu)\n", GetLastError());
            printf("Make sure Discord is fully closed and you're running as Administrator\n");
            return false;
        }
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(file, &fileSize)) { printf("ERROR: Cannot get file size\n"); CloseHandle(file); return false; }
        printf("File size: %.2f MB\n", fileSize.QuadPart / (1024.0 * 1024.0));
        void* fileData = VirtualAlloc(nullptr, fileSize.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!fileData) { printf("ERROR: Cannot allocate memory\n"); CloseHandle(file); return false; }
        DWORD bytesRead;
        if (!ReadFile(file, fileData, (DWORD)fileSize.QuadPart, &bytesRead, NULL)) {
            printf("ERROR: Cannot read file\n"); VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(file); return false;
        }
        if (bytesRead != (DWORD)fileSize.QuadPart) {
            printf("ERROR: Partial read (%lu / %lld bytes)\n", bytesRead, fileSize.QuadPart);
            VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(file); return false;
        }
        if (!ApplyPatches(fileData, fileSize.QuadPart)) { VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(file); return false; }
        printf("\nWriting patched file...\n");
        DWORD seekResult = SetFilePointer(file, 0, NULL, FILE_BEGIN);
        if (seekResult == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
            printf("ERROR: Cannot rewind file pointer (Error: %lu)\n", GetLastError());
            VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(file); return false;
        }
        DWORD bytesWritten;
        if (!WriteFile(file, fileData, (DWORD)fileSize.QuadPart, &bytesWritten, NULL)) {
            printf("ERROR: Cannot write file (Error: %lu)\n", GetLastError());
            VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(file); return false;
        }
        if (bytesWritten != (DWORD)fileSize.QuadPart) {
            printf("ERROR: Partial write (%lu / %lld bytes)\n", bytesWritten, fileSize.QuadPart);
            VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(file); return false;
        }
        VirtualFree(fileData, 0, MEM_RELEASE);
        CloseHandle(file);
        printf("\n================================================\n");
        printf("  SUCCESS! Patching Complete!\n");
        printf("================================================\n");
        printf("  You can now restart Discord\n");
        if (AUDIO_GAIN == 1) {
            printf("  Audio at original volume (no amplification)\n");
        } else {
            printf("  Audio will be %dx amplified\n", AUDIO_GAIN);
        }
        printf("================================================\n\n");
        return true;
    }
};

int main(int argc, char* argv[]) {
    SetConsoleTitle("Discord Voice Patcher v$Script:SCRIPT_VERSION");
    if (argc >= 2) {
        printf("Discord Voice Quality Patcher v$Script:SCRIPT_VERSION\n");
        printf("Using provided path: %s\n\n", argv[1]);
        DiscordPatcher patcher(argv[1]);
        bool success = patcher.PatchFile(true);
        return success ? 0 : 1;
    }
    printf("Searching for Discord process...\n");
    const char* processNames[] = {"$ProcessName", "Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe", "Lightcord.exe", NULL};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { printf("ERROR: Cannot create process snapshot\n"); system("pause"); return 1; }
    PROCESSENTRY32 entry = {sizeof(PROCESSENTRY32)};
    if (Process32First(snapshot, &entry)) {
        do {
            for (const char** pn = processNames; *pn != NULL; pn++) {
                if (strcmp(entry.szExeFile, *pn) == 0) {
                    printf("Found Discord (PID: %lu)\n", entry.th32ProcessID);
                    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                    if (!process) { printf("ERROR: Cannot open process (run as Administrator)\n"); continue; }
                    HMODULE modules[1024];
                    DWORD bytesNeeded;
                    if (!EnumProcessModules(process, modules, sizeof(modules), &bytesNeeded)) {
                        printf("ERROR: Cannot enumerate modules\n"); CloseHandle(process); continue;
                    }
                    printf("Searching for $ModuleName...\n");
                    for (DWORD i = 0; i < bytesNeeded / sizeof(HMODULE); i++) {
                        char moduleName[MAX_PATH];
                        if (GetModuleBaseNameA(process, modules[i], moduleName, sizeof(moduleName))) {
                            if (strcmp(moduleName, "$ModuleName") == 0) {
                                char modulePath[MAX_PATH];
                                GetModuleFileNameExA(process, modules[i], modulePath, MAX_PATH);
                                CloseHandle(snapshot); CloseHandle(process);
                                DiscordPatcher patcher(modulePath);
                                bool success = patcher.PatchFile(false);
                                system("pause");
                                return success ? 0 : 1;
                            }
                        }
                    }
                    CloseHandle(process);
                }
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    printf("\nERROR: Could not find Discord or $ModuleName\n");
    printf("Please make sure Discord is running\n\n");
    system("pause");
    return 1;
}
"@
}

function New-SourceFiles {
    param([string]$ProcessName = "Discord.exe")
    Write-Log "Generating source files..." -Level Info
    try {
        EnsureDir $Script:Config.TempDir
        $patcher = "$($Script:Config.TempDir)\patcher.cpp"
        $amp = "$($Script:Config.TempDir)\amplifier.cpp"
        $patcherCode = Get-PatcherSourceCode -ProcessName $ProcessName
        if ([string]::IsNullOrWhiteSpace($patcherCode)) { throw "Patcher source code generation returned empty" }
        $ampCode = Get-AmplifierSourceCode
        if ([string]::IsNullOrWhiteSpace($ampCode)) { throw "Amplifier source code generation returned empty" }
        [System.IO.File]::WriteAllText($patcher, $patcherCode, [System.Text.Encoding]::ASCII)
        [System.IO.File]::WriteAllText($amp, $ampCode, [System.Text.Encoding]::ASCII)
        $ampContent = Get-Content $amp -Raw
        if ($ampContent -match '#define GAIN_MULTIPLIER (\d+)') {
            $actualGain = $Matches[1]
            $expectedGain = $Script:Config.AudioGainMultiplier
            Write-Log "VERIFY: #define GAIN_MULTIPLIER = $actualGain (expected: $expectedGain)" -Level Info
            if ([int]$actualGain -ne $expectedGain) {
                Write-Log "WARNING: Gain mismatch! File has $actualGain but expected $expectedGain" -Level Warning
            }
        } else {
            Write-Log "WARNING: Could not find #define GAIN_MULTIPLIER in generated code!" -Level Warning
        }
        if (-not (Test-Path $patcher)) { throw "patcher.cpp was not created at: $patcher" }
        if (-not (Test-Path $amp)) { throw "amplifier.cpp was not created at: $amp" }
        $patcherSize = (Get-Item $patcher).Length
        $ampSize = (Get-Item $amp).Length
        if ($patcherSize -lt 100) { throw "patcher.cpp is too small ($patcherSize bytes) - generation failed" }
        if ($ampSize -lt 100) { throw "amplifier.cpp is too small ($ampSize bytes) - generation failed" }
        Write-Log "Source files created: patcher.cpp ($patcherSize bytes), amplifier.cpp ($ampSize bytes)" -Level Success
        return @($patcher, $amp)
    } catch { Write-Log "Failed to create source files: $_" -Level Error; return $null }
}

# endregion Source Code Generation

# region Compilation

function Show-CompilationFailureGuidance {
    param([string]$CompilerType, [string]$LogPath)

    $logText = ""
    if ($LogPath -and (Test-Path $LogPath)) {
        try { $logText = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue } catch { }
    }

    if ([string]::IsNullOrWhiteSpace($logText)) {
        switch ($CompilerType) {
            'MSVC' { Write-CompilerSetupHelp -Reason MsvcBuildFailure; return }
            'MinGW' { Write-CompilerSetupHelp -Reason GppBuildFailure; return }
            'Clang' { Write-CompilerSetupHelp -Reason ClangBuildFailure; return }
        }
        return
    }

    switch ($CompilerType) {
        'MSVC' {
            if (
                $logText -match '(?i)Failed to initialize Visual Studio environment' -or
                $logText -match '(?i)cl\.exe.*(not recognized|not found)' -or
                $logText -match '(?i)fatal error C1083' -or
                $logText -match '(?i)cannot open include file'
            ) {
                Write-CompilerSetupHelp -Reason MsvcBuildFailure
                return
            }
        }
        'MinGW' {
            if ($logText -match '(?i)g\+\+.*(not recognized|not found)' -or $logText -match '(?i)g\+\+: command not found') {
                Write-CompilerSetupHelp -Reason GppBuildFailure
                return
            }
        }
        'Clang' {
            if ($logText -match '(?i)clang\+\+.*(not recognized|not found)' -or $logText -match '(?i)clang\+\+: command not found') {
                Write-CompilerSetupHelp -Reason ClangBuildFailure
                return
            }
        }
    }
}

function Invoke-Compilation {
    param([hashtable]$Compiler, [string[]]$SourceFiles)
    Write-Log "Compiling with $($Compiler.Type)..." -Level Info
    $exe = "$($Script:Config.TempDir)\DiscordVoicePatcher.exe"
    $log = "$($Script:Config.TempDir)\build.log"
    if (Test-Path $exe) {
        try { Remove-Item $exe -Force -ErrorAction Stop }
        catch { Write-Log "Warning: Could not remove old exe, trying alternate name..." -Level Warning; $exe = "$($Script:Config.TempDir)\DiscordVoicePatcher_$(Get-Date -Format 'HHmmss').exe" }
    }
    if (Test-Path $log) { Remove-Item $log -Force -ErrorAction SilentlyContinue }
    try {
        switch ($Compiler.Type) {
            'MSVC' {
                $src1 = $SourceFiles[0]; $src2 = $SourceFiles[1]; $vcvars = $Compiler.Path
                $batContent = "@echo off`ncall `"$vcvars`"`nif errorlevel 1 (`n    echo ERROR: Failed to initialize Visual Studio environment`n    exit /b 1`n)`ncl.exe /EHsc /O2 /std:c++17 ^`n    `"$src1`" ^`n    `"$src2`" ^`n    /Fe`"$exe`" ^`n    /link Psapi.lib"
                $batPath = "$($Script:Config.TempDir)\build.bat"
                Set-Content -Path $batPath -Value $batContent -Encoding ASCII -NoNewline
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "cmd.exe"
                $pinfo.Arguments = "/c `"`"$batPath`" > `"$log`" 2>&1`""
                $pinfo.UseShellExecute = $false
                $pinfo.CreateNoWindow = $true
                $pinfo.WorkingDirectory = $Script:Config.TempDir
                $proc = New-Object System.Diagnostics.Process
                $proc.StartInfo = $pinfo
                $proc.Start() | Out-Null
                $proc.WaitForExit(120000) | Out-Null
                if (-not $proc.HasExited) { $proc.Kill(); throw "Build timed out after 120 seconds" }
                if (-not (Test-Path $exe) -and (Test-Path $log)) { Write-Host "=== Build Log ===" -ForegroundColor Yellow; Get-Content $log | Write-Host }
            }
            'MinGW' {
                $compArgs = @('-O2', '-std=c++17') + $SourceFiles + @('-o', $exe, '-lpsapi', '-static')
                $output = & g++ @compArgs 2>&1
                $output | Out-File $log -Force
            }
            'Clang' {
                $compArgs = @('-O2', '-std=c++17') + $SourceFiles + @('-o', $exe, '-lpsapi')
                $output = & clang++ @compArgs 2>&1
                $output | Out-File $log -Force
            }
        }
        if (Test-Path $exe) {
            $exeInfo = Get-Item $exe
            Write-Log "Compilation successful! Exe size: $([Math]::Round($exeInfo.Length / 1KB, 1)) KB" -Level Success
            return $exe
        }
        throw "Build failed - exe not created"
    } catch {
        Write-Log "Compilation failed: $_" -Level Error
        if (Test-Path $log) { Write-Host "=== Build Log ===" -ForegroundColor Yellow; Get-Content $log | Write-Host }
        Show-CompilationFailureGuidance -CompilerType $Compiler.Type -LogPath $log
        return $null
    }
}

# endregion Compilation

# region Core Patching

function Get-UniqueClientsByAppPath {
    param([array]$Clients)

    $uniquePaths = @{}
    $uniqueClients = [System.Collections.ArrayList]::new()

    foreach ($client in $Clients) {
        if (-not $client.AppPath) {
            continue
        }
        if ($uniquePaths.ContainsKey($client.AppPath)) {
            continue
        }

        $uniquePaths[$client.AppPath] = $true
        [void]$uniqueClients.Add($client)
    }

    return @($uniqueClients)
}

function Get-PreparedVoiceBackupPath {
    $voiceBackupPath = Join-Path $Script:Config.TempDir "VoiceBackup"
    EnsureDir $voiceBackupPath
    if (-not (Download-VoiceBackupFiles $voiceBackupPath)) {
        Write-Log "Failed to download voice backup files" -Level Error
        return $null
    }

    $voiceNode = Join-Path $voiceBackupPath "discord_voice.node"
    if (-not (Test-Path $voiceNode)) {
        Write-Log "discord_voice.node was not found in voice backup folder: $voiceBackupPath" -Level Error
        return $null
    }

    try {
        $nodeInfo = Get-Item $voiceNode -ErrorAction Stop
        $nodeSize = [int64]$nodeInfo.Length
        $nodeMd5 = Get-FileMd5Hex -Path $voiceNode

        Write-Log ("Voice node downloaded: {0} MB | MD5={1}" -f ([Math]::Round($nodeSize / 1MB, 2)), $nodeMd5) -Level Info

        $meta = $Script:Config.OffsetsMeta
        if ($meta) {
            if ($meta.Build) { Write-Log "Offsets build: $($meta.Build)" -Level Info }
            if ($meta.MD5) {
                $expected = ($meta.MD5.ToString()).ToLowerInvariant()
                if ($nodeMd5 -ne $expected) {
                    Write-Log "ERROR: Offsets do not match the downloaded discord_voice.node build." -Level Error
                    Write-Log "  Downloaded node MD5: $nodeMd5" -Level Error
                    Write-Log "  OffsetsMeta MD5:     $expected" -Level Error
                    Write-Log "Paste the new offsets (and MD5) from your offset finder into the '# region Offsets (PASTE HERE)' block." -Level Error
                    return $null
                }
            } else {
                Write-Log "OffsetsMeta.MD5 is not set - skipping voice node hash check." -Level Warning
            }
            if ($meta.Size) {
                try {
                    $expectedSize = [int64]$meta.Size
                    if ($expectedSize -ne $nodeSize) {
                        Write-Log "Warning: OffsetsMeta.Size ($expectedSize) does not match downloaded node size ($nodeSize)" -Level Warning
                    }
                } catch { }
            }
        }
    } catch {
        Write-Log "Could not verify downloaded voice node against offsets: $($_.Exception.Message)" -Level Warning
    }

    return $voiceBackupPath
}

function Invoke-PatchClients {
    param([array]$Clients, [hashtable]$Compiler, [string]$VoiceBackupPath)

    if (-not $Clients -or $Clients.Count -eq 0) {
        return @{ Success = 0; Failed = @(); Total = 0 }
    }

    $allClientNames = @($Clients | ForEach-Object { $_.Name.Trim() })
    if (-not $VoiceBackupPath -or -not (Test-Path $VoiceBackupPath)) {
        Write-Log "Voice backup path not found: $VoiceBackupPath" -Level Error
        return @{ Success = 0; Failed = $allClientNames; Total = $Clients.Count }
    }

    $backupFiles = @(Get-ChildItem $VoiceBackupPath -File -ErrorAction SilentlyContinue)
    if ($backupFiles.Count -eq 0) {
        Write-Log "No files found in voice backup path" -Level Error
        return @{ Success = 0; Failed = $allClientNames; Total = $Clients.Count }
    }

    Write-Log "Voice backup contains $($backupFiles.Count) files" -Level Info
    $successCount = 0
    $failedClients = [System.Collections.ArrayList]::new()

    foreach ($ci in $Clients) {
        $clientName = $ci.Name.Trim()
        Write-Host ""
        Write-Log "=== Processing: $clientName ===" -Level Info
        try {
            $appPath = $ci.AppPath
            if (-not $appPath -or -not (Test-Path $appPath)) {
                throw "Invalid app path: $appPath"
            }

            $version = Get-DiscordAppVersion $appPath
            Write-Log "Version: $version" -Level Info

            $voiceInfo = Get-VoiceModulePaths -AppPath $appPath
            if (-not $voiceInfo) {
                throw "No discord_voice module found in $(Join-Path $appPath 'modules')"
            }

            $voiceFolderPath = $voiceInfo.VoiceFolderPath
            $voiceNodePath = $voiceInfo.VoiceNodePath
            Write-Log "Voice folder: $voiceFolderPath" -Level Info

            if (Test-Path $voiceNodePath) {
                if (-not (Backup-VoiceNode $voiceNodePath $ci.Name) -and -not $Script:Config.SkipBackup) {
                    throw "Backup failed"
                }
            }

            Write-Log "Removing old voice module files..." -Level Info
            if (Test-Path $voiceFolderPath) {
                Remove-Item "$voiceFolderPath\*" -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                EnsureDir $voiceFolderPath
            }

            Write-Log "Installing compatible voice module..." -Level Info
            Copy-Item "$VoiceBackupPath\*" $voiceFolderPath -Recurse -Force
            if (-not (Test-Path $voiceNodePath)) {
                throw "discord_voice.node not found after copying backup files"
            }

            Write-Log "Voice node: $voiceNodePath" -Level Info
            Write-Log "File size: $([Math]::Round((Get-Item $voiceNodePath).Length / 1MB, 2)) MB" -Level Info

            $src = New-SourceFiles -ProcessName $ci.Client.Exe
            if (-not $src) {
                throw "Source generation failed"
            }

            $exe = Invoke-Compilation -Compiler $Compiler -SourceFiles $src
            if (-not $exe) {
                throw "Compilation failed"
            }

            Write-Log "Applying binary patches with $($Script:Config.AudioGainMultiplier)x gain setting..." -Level Info
            $patchOut = Join-Path $Script:Config.TempDir "patcher_stdout.txt"
            $patchErr = Join-Path $Script:Config.TempDir "patcher_stderr.txt"
            $patchProc = Start-Process -FilePath $exe -ArgumentList "`"$voiceNodePath`"" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $patchOut -RedirectStandardError $patchErr
            if ($patchProc.ExitCode -eq 0) {
                Write-Log "Successfully patched $clientName with $($Script:Config.AudioGainMultiplier)x gain!" -Level Success
                $successCount++
            } else {
                if (Test-Path $patchErr) { $errText = Get-Content $patchErr -Raw -ErrorAction SilentlyContinue; if ($errText) { Write-Log "Patcher stderr: $errText" -Level Error } }
                if (Test-Path $patchOut) { $outText = Get-Content $patchOut -Raw -ErrorAction SilentlyContinue; if ($outText) { Write-Log "Patcher stdout: $outText" -Level Error } }
                throw "Patcher exited with code $($patchProc.ExitCode)"
            }
        } catch {
            Write-Log "Failed to patch ${clientName}: $_" -Level Error
            [void]$failedClients.Add($clientName)
        }
    }

    Cleanup-TempFiles
    return @{ Success = $successCount; Failed = @($failedClients); Total = $Clients.Count }
}

# endregion Core Patching

# region Main Entry

function Start-Patching {
    Write-Banner
    if (-not $SkipUpdateCheck -and -not [string]::IsNullOrEmpty($PSCommandPath)) {
        $updateResult = Check-ForUpdate
        if ($updateResult.UpdateAvailable) {
            Write-Host ""
            Write-Host "A new version is available: v$($updateResult.RemoteVersion)" -ForegroundColor Yellow
            Write-Host "Current version: v$($updateResult.LocalVersion)" -ForegroundColor Cyan
            Write-Host ""
            $response = Read-Host "Would you like to update now? (Y/n)"
            if ($response -eq '' -or $response -match '^[Yy]') {
                Write-Log "Applying update..." -Level Info
                if (Apply-ScriptUpdate -UpdatedScriptPath $updateResult.TempFile -CurrentScriptPath $PSCommandPath -RestartAfter) {
                    Write-Log "Update prepared! Script will restart..." -Level Success
                    Start-Sleep -Seconds 2; exit 0
                } else {
                    Write-Log "Failed to apply update. Continuing with current version..." -Level Warning
                    if (Test-Path $updateResult.TempFile) { Remove-Item $updateResult.TempFile -Force -ErrorAction SilentlyContinue }
                }
            } else {
                Write-Log "Update skipped. Continuing with current version..." -Level Info
                if (Test-Path $updateResult.TempFile) { Remove-Item $updateResult.TempFile -Force -ErrorAction SilentlyContinue }
            }
            Write-Host ""
        }
    }

    if ($ListBackups) { Show-BackupList; return $true }
    if ($Restore) { return Restore-FromBackup }

    if ($FixAll -or $Script:DoFixAll -or $FixClient) {
        if ($null -ne $Script:PendingGainForPatchAll) {
            $Script:Config.AudioGainMultiplier = $Script:PendingGainForPatchAll
            $Script:PendingGainForPatchAll = $null
        }
        Show-Settings
        Initialize-Environment
        Write-Log "Scanning for installed Discord clients..." -Level Info
        $installedClients = @(Get-InstalledClients)
        if ($installedClients.Count -eq 0) {
            Write-Log "No Discord clients found! Make sure Discord is installed." -Level Error
            Read-Host "Press Enter"
            return $false
        }

        if ($FixClient) {
            $installedClients = @($installedClients | Where-Object { $_.Name -like "*$FixClient*" })
            if ($installedClients.Count -eq 0) {
                Write-Log "No clients matching '$FixClient' found" -Level Error
                Read-Host "Press Enter"
                return $false
            }
        }

        $uniqueClients = @(Get-UniqueClientsByAppPath -Clients $installedClients)
        Write-Log "Found $($uniqueClients.Count) client(s):" -Level Success
        foreach ($c in $uniqueClients) {
            $v = Get-DiscordAppVersion $c.AppPath
            Write-Log "  - $($c.Name.Trim()) (v$v)" -Level Info
        }

        $compiler = Find-Compiler
        if (-not $compiler) {
            Read-Host "Press Enter"
            return $false
        }

        $voiceBackupPath = Get-PreparedVoiceBackupPath
        if (-not $voiceBackupPath) {
            Read-Host "Press Enter"
            return $false
        }

        Write-Log "Closing all Discord processes..." -Level Info
        $stopped = Stop-AllDiscordProcesses
        if (-not $stopped) {
            Write-Log "Warning: Some processes may still be running" -Level Warning
            Start-Sleep -Seconds 2
        }

        Start-Sleep -Seconds 1
        $result = Invoke-PatchClients -Clients @($uniqueClients) -Compiler $compiler -VoiceBackupPath $voiceBackupPath
        Write-Host ""
        Write-Log "=== PATCHING COMPLETE ===" -Level Success
        Write-Log "Success: $($result.Success) / $($result.Total)" -Level Info
        if ($result.Failed -and $result.Failed.Count -gt 0) {
            Write-Log "Failed: $($result.Failed -join ', ')" -Level Warning
        }

        if ($Script:Config.AutoRelaunch -and $uniqueClients.Count -gt 0) {
            Write-Log "Auto-relaunching Discord..." -Level Info
            Start-Sleep -Seconds 3
            $firstClient = $uniqueClients[0]
            $clientInfo = $Script:DiscordClients[$firstClient.Index]
            if ($clientInfo -and $clientInfo.Path -and (Test-Path $clientInfo.Path)) {
                $updateExe = Join-Path $clientInfo.Path "Update.exe"
                if (Test-Path $updateExe) {
                    Write-Log "Launching: $($clientInfo.Name.Trim())" -Level Info
                    $discordOut = Join-Path $env:TEMP "DiscordPatcher_discord_out.txt"
                    $discordErr = Join-Path $env:TEMP "DiscordPatcher_discord_err.txt"
                    Start-Process $updateExe -ArgumentList "--processStart", $clientInfo.Exe -WindowStyle Hidden -RedirectStandardOutput $discordOut -RedirectStandardError $discordErr
                }
            }
        }
        Save-UserConfig
        Read-Host "Press Enter to exit"
        return ($result.Success -eq $result.Total)
    }

    Write-Log "Opening GUI..." -Level Info
    $guiResult = Show-ConfigurationGUI
    if (-not $guiResult) {
        Write-Log "Cancelled" -Level Warning
        return $false
    }
    Write-Log "GUI Action: $($guiResult.Action)" -Level Info
    if ($guiResult.Action -eq 'Restore') {
        return Restore-FromBackup
    }
    if ($guiResult.Action -notin @('Patch', 'PatchAll')) {
        Write-Log "Cancelled" -Level Warning
        return $false
    }

    $Script:Config.AudioGainMultiplier = $guiResult.Multiplier
    $Script:Config.SkipBackup = $guiResult.SkipBackup
    $Script:Config.AutoRelaunch = $guiResult.AutoRelaunch
    Write-Log "GUI Settings: Gain = $($Script:Config.AudioGainMultiplier)x, Skip Backup = $($Script:Config.SkipBackup), Auto Relaunch = $($Script:Config.AutoRelaunch)" -Level Info
    if ($guiResult.Action -eq 'PatchAll') {
        $Script:DoFixAll = $true
        $Script:PendingGainForPatchAll = $guiResult.Multiplier
        return Start-Patching
    }

    Show-Settings
    Initialize-Environment
    $selectedClientInfo = $Script:DiscordClients[$guiResult.ClientIndex]
    if (-not $selectedClientInfo) {
        Write-Log "Invalid client selection" -Level Error
        Read-Host "Press Enter"
        return $false
    }

    Write-Log "Selected client: $($selectedClientInfo.Name.Trim())" -Level Info
    $installedClients = @(Get-InstalledClients)
    $targetClient = $installedClients | Where-Object { $_.Index -eq $guiResult.ClientIndex } | Select-Object -First 1
    if (-not $targetClient) {
        Write-Log "Selected client is not installed!" -Level Error
        Read-Host "Press Enter"
        return $false
    }

    $compiler = Find-Compiler
    if (-not $compiler) {
        Read-Host "Press Enter"
        return $false
    }

    $voiceBackupPath = Get-PreparedVoiceBackupPath
    if (-not $voiceBackupPath) {
        Read-Host "Press Enter"
        return $false
    }

    Write-Log "Closing Discord processes..." -Level Info
    $installPath = $null
    if ($targetClient.AppPath -and (Test-Path $targetClient.AppPath)) {
        $installPath = (Get-Item (Split-Path $targetClient.AppPath -Parent)).FullName
    }
    if (-not $installPath -and $targetClient.Path -and (Test-Path $targetClient.Path)) {
        $installPath = (Get-Item $targetClient.Path).FullName
    }
    if (-not $installPath -and $selectedClientInfo.Path -and (Test-Path $selectedClientInfo.Path)) {
        $installPath = (Get-Item $selectedClientInfo.Path).FullName
    }
    $stopped = Stop-DiscordProcesses -ProcessNames $selectedClientInfo.Processes -InstallPath $installPath
    if (-not $stopped) {
        Write-Log "Warning: Some processes may still be running" -Level Warning
        Start-Sleep -Seconds 2
    }

    Start-Sleep -Seconds 1
    $result = Invoke-PatchClients -Clients @($targetClient) -Compiler $compiler -VoiceBackupPath $voiceBackupPath
    Write-Host ""
    if ($result.Success -gt 0) {
        Write-Log "=== PATCHING COMPLETE ===" -Level Success
        if ($Script:Config.AutoRelaunch) {
            Write-Log "Auto-relaunching Discord..." -Level Info
            Start-Sleep -Seconds 2
            $discordPath = $targetClient.Path
            if (-not $discordPath) { $discordPath = $selectedClientInfo.Path }
            if ($discordPath -and (Test-Path $discordPath)) {
                $updateExe = Join-Path $discordPath "Update.exe"
                $discordOut = Join-Path $env:TEMP "DiscordPatcher_discord_out.txt"
                $discordErr = Join-Path $env:TEMP "DiscordPatcher_discord_err.txt"
                if (Test-Path $updateExe) {
                    Write-Log "Launching via Update.exe..." -Level Info
                    Start-Process $updateExe -ArgumentList "--processStart", $selectedClientInfo.Exe -WindowStyle Hidden -RedirectStandardOutput $discordOut -RedirectStandardError $discordErr
                } else {
                    $appFolder = Get-ChildItem $discordPath -Directory -Filter "app-*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                    if ($appFolder) {
                        $exePath = Join-Path $appFolder.FullName $selectedClientInfo.Exe
                        if (Test-Path $exePath) {
                            Write-Log "Launching: $exePath" -Level Info
                            Start-Process $exePath -WindowStyle Hidden -RedirectStandardOutput $discordOut -RedirectStandardError $discordErr
                        }
                    }
                }
            }
        }
    } else {
        Write-Log "=== PATCHING FAILED ===" -Level Error
    }
    Save-UserConfig
    Read-Host "Press Enter to exit"
    return ($result.Success -gt 0)
}

# endregion Main Entry

# region Run

try {
    $success = Start-Patching
    Write-Host "`n$(if ($success) { 'SUCCESS!' } else { 'FAILED/CANCELLED' })" -ForegroundColor $(if ($success) { 'Green' } else { 'Red' })
    exit $(if ($success) { 0 } else { 1 })
} catch {
    Write-Host "`nFATAL ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}

# endregion Run

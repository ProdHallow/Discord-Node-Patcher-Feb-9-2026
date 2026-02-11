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

$Script:UPDATE_URL = "https://raw.githubusercontent.com/ProdHallow/Discord-Node-Patcher-Feb-9-2026/main/Discord%20voice%20node%20patcher.ps1"
$Script:SCRIPT_VERSION = "4.0"

# ============================================================
# 1. Auto-Elevation
# ============================================================

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

# ============================================================
# 2. Configuration
# ============================================================

$Script:GainExplicitlySet = $PSBoundParameters.ContainsKey('AudioGainMultiplier')
$Script:Config = @{
    SampleRate = 48000; Bitrate = 382; Channels = "Stereo"
    AudioGainMultiplier = $AudioGainMultiplier; SkipBackup = $SkipBackup.IsPresent; AutoRelaunch = $true
    ModuleName = "discord_voice.node"
    TempDir = "$env:TEMP\DiscordVoicePatcher"; BackupDir = "$env:TEMP\DiscordVoicePatcher\Backups"
    LogFile = "$env:TEMP\DiscordVoicePatcher\patcher.log"; ConfigFile = "$env:TEMP\DiscordVoicePatcher\config.json"
    MaxBackupCount = 10
    VoiceBackupAPI = "https://api.github.com/repos/ProdHallow/Discord-Node-Patcher-Feb-9-2026/contents/discord_voice"
    Offsets = @{
        CreateAudioFrameStereo = 0x118C41; AudioEncoderOpusConfigSetChannels = 0x3A7374
        MonoDownmixer = 0xD7E49; EmulateStereoSuccess1 = 0x53840B; EmulateStereoSuccess2 = 0x538417
        EmulateBitrateModified = 0x53886A; SetsBitrateBitrateValue = 0x53A691; SetsBitrateBitwiseOr = 0x53A699
        Emulate48Khz = 0x538573; HighPassFilter = 0x544680; HighpassCutoffFilter = 0x8BD4C0
        DcReject = 0x8BD6A0; DownmixFunc = 0x8B9830; AudioEncoderOpusConfigIsOk = 0x3A7610; ThrowError = 0x2C0040
    }
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

# ============================================================
# 3. Logging
# ============================================================

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
    Write-Host "      48kHz | 382kbps | Stereo | Gain Config" -ForegroundColor Cyan
    Write-Host "         Multi-Client Detection Enabled" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan
}

function Show-Settings {
    $gainColor = if ($Script:Config.AudioGainMultiplier -le 2) { 'Green' } elseif ($Script:Config.AudioGainMultiplier -le 5) { 'Yellow' } else { 'Red' }
    Write-Host "Config: $($Script:Config.SampleRate)Hz, $($Script:Config.Bitrate)kbps, $($Script:Config.Channels), " -NoNewline
    Write-Host "$($Script:Config.AudioGainMultiplier)x gain" -ForegroundColor $gainColor
    Write-Host ""
}

# ============================================================
# 4. User Config Persistence
# ============================================================

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

# ============================================================
# 5. Auto-Update
# ============================================================

function Check-ForUpdate {
    try {
        Write-Log "Checking for script updates..." -Level Info
        if ([string]::IsNullOrEmpty($PSCommandPath)) {
            Write-Log "Running latest version from web" -Level Success
            return @{ UpdateAvailable = $false; Reason = "WebExecution" }
        }
        $tempFile = Join-Path $env:TEMP "DiscordVoicePatcher_Update_$(Get-Random).ps1"
        try {
            Invoke-WebRequest -Uri $Script:UPDATE_URL -OutFile $tempFile -UseBasicParsing -TimeoutSec 15 | Out-Null
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

# ============================================================
# 6. Voice Backup Download
# ============================================================

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

# ============================================================
# 7. Multi-Client Detection
# ============================================================

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

# ============================================================
# 8. Process Management
# ============================================================

function Stop-DiscordProcesses {
    param([string[]]$ProcessNames)
    if (-not $ProcessNames -or $ProcessNames.Count -eq 0) { return $true }
    $p = Get-Process -Name $ProcessNames -ErrorAction SilentlyContinue
    if ($p) {
        $p | Stop-Process -Force -ErrorAction SilentlyContinue
        for ($i=0; $i -lt 20; $i++) {
            if (-not (Get-Process -Name $ProcessNames -ErrorAction SilentlyContinue)) { return $true }
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

# ============================================================
# 9. Backup Management
# ============================================================

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

function Restore-FromBackup {
    param([string]$BackupPath = $null)
    Write-Banner; Write-Log "Starting restore..." -Level Info
    if (-not $BackupPath) {
        $backups = Get-BackupList
        if ($backups.Count -eq 0) { Write-Log "No backups found" -Level Error; return $false }
        Show-BackupList
        $sel = Read-Host "Select backup (1-$($backups.Count)) or Enter for most recent"
        if ([string]::IsNullOrWhiteSpace($sel)) { $BackupPath = $backups[0].Path }
        else {
            $idx = 0; if (-not [int]::TryParse($sel, [ref]$idx) -or $idx -lt 1 -or $idx -gt $backups.Count) {
                Write-Log "Invalid selection" -Level Error; return $false
            }
            $BackupPath = $backups[$idx - 1].Path
        }
    }
    $installedClients = Get-InstalledClients
    if ($installedClients.Count -eq 0) { Write-Log "No Discord clients found to restore to" -Level Error; return $false }
    Write-Log "Found $($installedClients.Count) client(s) to restore:" -Level Info
    for ($i = 0; $i -lt $installedClients.Count; $i++) { Write-Log "  [$($i+1)] $($installedClients[$i].Name.Trim())" -Level Info }
    $sel = Read-Host "Select client to restore (1-$($installedClients.Count)) or Enter for first"
    $targetIdx = 0
    if (-not [string]::IsNullOrWhiteSpace($sel)) {
        if (-not [int]::TryParse($sel, [ref]$targetIdx) -or $targetIdx -lt 1 -or $targetIdx -gt $installedClients.Count) {
            Write-Log "Invalid selection" -Level Error; return $false
        }
        $targetIdx--
    }
    $targetClient = $installedClients[$targetIdx]
    if (-not $targetClient -or -not $targetClient.AppPath) { Write-Log "Invalid target client" -Level Error; return $false }
    $voiceModules = @(Get-ChildItem "$($targetClient.AppPath)\modules" -Filter "discord_voice*" -Directory -ErrorAction SilentlyContinue)
    if ($voiceModules.Count -eq 0) { Write-Log "No voice module found in target client" -Level Error; return $false }
    $voiceModule = $voiceModules[0]
    $voiceFolderPath = if (Test-Path "$($voiceModule.FullName)\discord_voice") { "$($voiceModule.FullName)\discord_voice" } else { $voiceModule.FullName }
    $targetPath = Join-Path $voiceFolderPath "discord_voice.node"
    Write-Log "Target: $targetPath" -Level Info
    if ((Read-Host "Replace current file with backup? (y/N)") -notin @('y', 'Y')) { return $false }
    try {
        Write-Log "Closing Discord processes..." -Level Info
        Stop-AllDiscordProcesses | Out-Null
        Start-Sleep -Seconds 2
        Copy-Item -Path $BackupPath -Destination $targetPath -Force
        Write-Log "Restore complete! Restart Discord." -Level Success
        return $true
    } catch { Write-Log "Restore failed: $_" -Level Error; return $false }
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

# ============================================================
# 10. GUI
# ============================================================

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
    & $newLabel 20 55 480 20 "48kHz | 382kbps | Stereo | Multi-Client Support" (New-Object Drawing.Font("Segoe UI", 9)) ([Drawing.Color]::FromArgb(185,187,190))
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

# ============================================================
# 11. Environment & Compiler
# ============================================================

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

function Find-Compiler {
    Write-Log "Searching for C++ compiler..." -Level Info
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        try {
            $vsPath = & $vsWhere -latest -property installationPath 2>$null
            if ($vsPath) {
                $vcvars = "$vsPath\VC\Auxiliary\Build\vcvars64.bat"
                if (Test-Path $vcvars) { Write-Log "Found Visual Studio" -Level Success; return @{ Type = 'MSVC'; Path = $vcvars } }
            }
        } catch { }
    }
    $gpp = Get-Command "g++" -ErrorAction SilentlyContinue
    if ($gpp) { Write-Log "Found MinGW g++" -Level Success; return @{ Type = 'MinGW'; Path = $gpp.Source } }
    $clang = Get-Command "clang++" -ErrorAction SilentlyContinue
    if ($clang) { Write-Log "Found Clang" -Level Success; return @{ Type = 'Clang'; Path = $clang.Source } }
    Write-Log "No C++ compiler found. Install Visual Studio, MinGW, or Clang." -Level Error
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

# ============================================================
# 12. Source Code Generation
# ============================================================

function Get-AmplifierSourceCode {
    $multiplier = $Script:Config.AudioGainMultiplier - 2
    Write-Log "Generating amplifier: GUI=$($Script:Config.AudioGainMultiplier)x, Multiplier=$multiplier" -Level Info
    return @"
#define Multiplier $multiplier

typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

extern "C" void __cdecl hp_cutoff(const float* in, int cutoff_Hz, float* out, int* hp_mem, int len, int channels, int Fs, int arch)
{
    int* st = (hp_mem - 3553);
    *(int*)(st + 3557) = 1002;
    *(int*)((char*)st + 160) = -1;
    *(int*)((char*)st + 164) = -1;
    *(int*)((char*)st + 184) = 0;
    for (unsigned long i = 0; i < channels * len; i++) out[i] = in[i] * (channels + Multiplier);
}

extern "C" void __cdecl dc_reject(const float* in, float* out, int* hp_mem, int len, int channels, int Fs)
{
    int* st = (hp_mem - 3553);
    *(int*)(st + 3557) = 1002;
    *(int*)((char*)st + 160) = -1;
    *(int*)((char*)st + 164) = -1;
    *(int*)((char*)st + 184) = 0;
    for (int i = 0; i < channels * len; i++) out[i] = in[i] * (channels + Multiplier);
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

        printf("  [1/4] Enabling stereo audio...\n");
        if (!PatchBytes(Offsets::EmulateStereoSuccess1, "\x02", 1)) return false;
        if (!PatchBytes(Offsets::EmulateStereoSuccess2, "\xEB", 1)) return false;
        if (!PatchBytes(Offsets::CreateAudioFrameStereo, "\x49\x89\xC5\x90", 4)) return false;
        if (!PatchBytes(Offsets::AudioEncoderOpusConfigSetChannels, "\x02", 1)) return false;
        if (!PatchBytes(Offsets::MonoDownmixer, "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xE9", 13)) return false;
        printf("  [2/4] Setting bitrate to 382kbps...\n");
        if (!PatchBytes(Offsets::EmulateBitrateModified, "\xF0\xD4\x05", 3)) return false;
        if (!PatchBytes(Offsets::SetsBitrateBitrateValue, "\xF0\xD4\x05\x00\x00", 5)) return false;
        if (!PatchBytes(Offsets::SetsBitrateBitwiseOr, "\x90\x90\x90", 3)) return false;
        printf("  [3/4] Enabling 48kHz sample rate...\n");
        if (!PatchBytes(Offsets::Emulate48Khz, "\x90\x90\x90", 3)) return false;
        if (AUDIO_GAIN == 1) {
            printf("  [4/4] Injecting audio processing (no amplification)...\n");
        } else {
            printf("  [4/4] Injecting audio processing (%dx gain)...\n", AUDIO_GAIN);
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
        printf("  All patches applied successfully!\n");
        return true;
    }

public:
    DiscordPatcher(const std::string& path) : modulePath(path) {}

    bool PatchFile() {
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
        if (!WaitForDiscordClose(5)) {
            printf("Closing Discord processes...\n");
            TerminateAllDiscordProcesses();
            if (!WaitForDiscordClose(20)) { printf("WARNING: Discord may still be running\n"); }
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
        if (!ApplyPatches(fileData, fileSize.QuadPart)) { VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(file); return false; }
        printf("\nWriting patched file...\n");
        SetFilePointer(file, 0, NULL, FILE_BEGIN);
        DWORD bytesWritten;
        if (!WriteFile(file, fileData, (DWORD)fileSize.QuadPart, &bytesWritten, NULL)) {
            printf("ERROR: Cannot write file (Error: %lu)\n", GetLastError());
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
        bool success = patcher.PatchFile();
        system("pause");
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
                                bool success = patcher.PatchFile();
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
        if ($ampContent -match '#define Multiplier (-?\d+)') {
            $actualMultiplier = $Matches[1]
            $expectedMultiplier = $Script:Config.AudioGainMultiplier - 2
            Write-Log "VERIFY: #define Multiplier = $actualMultiplier (expected: $expectedMultiplier)" -Level Info
            if ([int]$actualMultiplier -ne $expectedMultiplier) {
                Write-Log "WARNING: Multiplier mismatch! File has $actualMultiplier but expected $expectedMultiplier" -Level Warning
            }
        } else { Write-Log "WARNING: Could not find #define Multiplier in generated code!" -Level Warning }
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

# ============================================================
# 13. Compilation
# ============================================================

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
        return $null
    }
}

# ============================================================
# 14. Core Patching
# ============================================================

function Invoke-PatchClients {
    param([array]$Clients, [hashtable]$Compiler, [string]$VoiceBackupPath)
    if (-not $Clients -or $Clients.Count -eq 0) { return @{ Success = 0; Failed = @(); Total = 0 } }
    if (-not $VoiceBackupPath -or -not (Test-Path $VoiceBackupPath)) {
        Write-Log "Voice backup path not found: $VoiceBackupPath" -Level Error
        return @{ Success = 0; Failed = @($Clients | ForEach-Object { $_.Name.Trim() }); Total = $Clients.Count }
    }
    $backupFiles = @(Get-ChildItem $VoiceBackupPath -File -ErrorAction SilentlyContinue)
    if ($backupFiles.Count -eq 0) {
        Write-Log "No files found in voice backup path" -Level Error
        return @{ Success = 0; Failed = @($Clients | ForEach-Object { $_.Name.Trim() }); Total = $Clients.Count }
    }
    Write-Log "Voice backup contains $($backupFiles.Count) files" -Level Info
    $successCount = 0
    $failedClients = [System.Collections.ArrayList]::new()
    foreach ($ci in $Clients) {
        Write-Host ""
        Write-Log "=== Processing: $($ci.Name.Trim()) ===" -Level Info
        try {
            $appPath = $ci.AppPath
            if (-not $appPath -or -not (Test-Path $appPath)) { throw "Invalid app path: $appPath" }
            $version = Get-DiscordAppVersion $appPath
            Write-Log "Version: $version" -Level Info
            $voiceModules = @(Get-ChildItem "$appPath\modules" -Filter "discord_voice*" -Directory -ErrorAction SilentlyContinue)
            if ($voiceModules.Count -eq 0) { throw "No discord_voice module found in $appPath\modules" }
            $voiceModule = $voiceModules[0]
            $voiceFolderPath = if (Test-Path "$($voiceModule.FullName)\discord_voice") { "$($voiceModule.FullName)\discord_voice" } else { $voiceModule.FullName }
            Write-Log "Voice folder: $voiceFolderPath" -Level Info
            $voiceNodePath = Join-Path $voiceFolderPath "discord_voice.node"
            if (Test-Path $voiceNodePath) {
                if (-not (Backup-VoiceNode $voiceNodePath $ci.Name) -and -not $Script:Config.SkipBackup) { throw "Backup failed" }
            }
            Write-Log "Removing old voice module files..." -Level Info
            if (Test-Path $voiceFolderPath) { Remove-Item "$voiceFolderPath\*" -Recurse -Force -ErrorAction SilentlyContinue }
            else { EnsureDir $voiceFolderPath }
            Write-Log "Installing compatible voice module..." -Level Info
            Copy-Item "$VoiceBackupPath\*" $voiceFolderPath -Recurse -Force
            $voiceNodePath = Join-Path $voiceFolderPath "discord_voice.node"
            if (-not (Test-Path $voiceNodePath)) { throw "discord_voice.node not found after copying backup files" }
            Write-Log "Voice node: $voiceNodePath" -Level Info
            Write-Log "File size: $([Math]::Round((Get-Item $voiceNodePath).Length / 1MB, 2)) MB" -Level Info
            $src = New-SourceFiles -ProcessName $ci.Client.Exe
            if (-not $src) { throw "Source generation failed" }
            $exe = Invoke-Compilation -Compiler $Compiler -SourceFiles $src
            if (-not $exe) { throw "Compilation failed" }
            Write-Log "Applying binary patches with $($Script:Config.AudioGainMultiplier)x gain setting..." -Level Info
            $patchProc = Start-Process -FilePath $exe -ArgumentList "`"$voiceNodePath`"" -Wait -PassThru -NoNewWindow
            if ($patchProc.ExitCode -eq 0) {
                Write-Log "Successfully patched $($ci.Name.Trim()) with $($Script:Config.AudioGainMultiplier)x gain!" -Level Success
                $successCount++
            } else { throw "Patcher exited with code $($patchProc.ExitCode)" }
        } catch {
            Write-Log "Failed to patch $($ci.Name.Trim()): $_" -Level Error
            [void]$failedClients.Add($ci.Name.Trim())
        }
    }
    Cleanup-TempFiles
    return @{ Success = $successCount; Failed = @($failedClients); Total = $Clients.Count }
}

# ============================================================
# 15. Main Entry
# ============================================================

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
        Show-Settings
        Initialize-Environment
        Write-Log "Scanning for installed Discord clients..." -Level Info
        $installedClients = @(Get-InstalledClients)
        if ($installedClients.Count -eq 0) { Write-Log "No Discord clients found! Make sure Discord is installed." -Level Error; Read-Host "Press Enter"; return $false }
        if ($FixClient) {
            $installedClients = @($installedClients | Where-Object { $_.Name -like "*$FixClient*" })
            if ($installedClients.Count -eq 0) { Write-Log "No clients matching '$FixClient' found" -Level Error; Read-Host "Press Enter"; return $false }
        }
        $uniquePaths = @{}
        $uniqueClients = [System.Collections.ArrayList]::new()
        foreach ($c in $installedClients) {
            if ($c.AppPath -and -not $uniquePaths.ContainsKey($c.AppPath)) {
                $uniquePaths[$c.AppPath] = $true
                [void]$uniqueClients.Add($c)
            }
        }
        Write-Log "Found $($uniqueClients.Count) client(s):" -Level Success
        foreach ($c in $uniqueClients) { $v = Get-DiscordAppVersion $c.AppPath; Write-Log "  - $($c.Name.Trim()) (v$v)" -Level Info }
        $compiler = Find-Compiler
        if (-not $compiler) { Read-Host "Press Enter"; return $false }
        Write-Log "Downloading voice backup files from GitHub..." -Level Info
        $voiceBackupPath = Join-Path $Script:Config.TempDir "VoiceBackup"
        EnsureDir $voiceBackupPath
        if (-not (Download-VoiceBackupFiles $voiceBackupPath)) { Write-Log "Failed to download voice backup files" -Level Error; Read-Host "Press Enter"; return $false }
        Write-Log "Closing all Discord processes..." -Level Info
        $stopped = Stop-AllDiscordProcesses
        if (-not $stopped) { Write-Log "Warning: Some processes may still be running" -Level Warning; Start-Sleep -Seconds 2 }
        Start-Sleep -Seconds 1
        $result = Invoke-PatchClients -Clients @($uniqueClients) -Compiler $compiler -VoiceBackupPath $voiceBackupPath
        Write-Host ""
        Write-Log "=== PATCHING COMPLETE ===" -Level Success
        Write-Log "Success: $($result.Success) / $($result.Total)" -Level Info
        if ($result.Failed -and $result.Failed.Count -gt 0) { Write-Log "Failed: $($result.Failed -join ', ')" -Level Warning }
        if ($Script:Config.AutoRelaunch -and $uniqueClients.Count -gt 0) {
            Write-Log "Auto-relaunching Discord..." -Level Info
            Start-Sleep -Seconds 1
            $firstClient = $uniqueClients[0]
            $clientInfo = $Script:DiscordClients[$firstClient.Index]
            if ($clientInfo -and $clientInfo.Path -and (Test-Path $clientInfo.Path)) {
                $updateExe = Join-Path $clientInfo.Path "Update.exe"
                if (Test-Path $updateExe) { Write-Log "Launching: $($clientInfo.Name.Trim())" -Level Info; Start-Process $updateExe -ArgumentList "--processStart", $clientInfo.Exe }
            }
        }
        Save-UserConfig
        Read-Host "Press Enter to exit"
        return ($result.Success -eq $result.Total)
    }

    Write-Log "Opening GUI..." -Level Info
    $guiResult = Show-ConfigurationGUI
    if (-not $guiResult) { Write-Log "Cancelled" -Level Warning; return $false }
    Write-Log "GUI Action: $($guiResult.Action)" -Level Info
    if ($guiResult.Action -eq 'Restore') { return Restore-FromBackup }
    if ($guiResult.Action -notin @('Patch', 'PatchAll')) { Write-Log "Cancelled" -Level Warning; return $false }
    $Script:Config.AudioGainMultiplier = $guiResult.Multiplier
    $Script:Config.SkipBackup = $guiResult.SkipBackup
    $Script:Config.AutoRelaunch = $guiResult.AutoRelaunch
    Write-Log "GUI Settings: Gain = $($Script:Config.AudioGainMultiplier)x, Skip Backup = $($Script:Config.SkipBackup), Auto Relaunch = $($Script:Config.AutoRelaunch)" -Level Info
    if ($guiResult.Action -eq 'PatchAll') { $Script:DoFixAll = $true; return Start-Patching }
    Show-Settings
    Initialize-Environment
    $selectedClientInfo = $Script:DiscordClients[$guiResult.ClientIndex]
    if (-not $selectedClientInfo) { Write-Log "Invalid client selection" -Level Error; Read-Host "Press Enter"; return $false }
    Write-Log "Selected client: $($selectedClientInfo.Name.Trim())" -Level Info
    $installedClients = @(Get-InstalledClients)
    $targetClient = $installedClients | Where-Object { $_.Index -eq $guiResult.ClientIndex } | Select-Object -First 1
    if (-not $targetClient) { Write-Log "Selected client is not installed!" -Level Error; Read-Host "Press Enter"; return $false }
    $compiler = Find-Compiler
    if (-not $compiler) { Read-Host "Press Enter"; return $false }
    Write-Log "Downloading voice backup files from GitHub..." -Level Info
    $voiceBackupPath = Join-Path $Script:Config.TempDir "VoiceBackup"
    EnsureDir $voiceBackupPath
    if (-not (Download-VoiceBackupFiles $voiceBackupPath)) { Write-Log "Failed to download voice backup files" -Level Error; Read-Host "Press Enter"; return $false }
    Write-Log "Closing Discord processes..." -Level Info
    $stopped = Stop-DiscordProcesses $selectedClientInfo.Processes
    if (-not $stopped) { Write-Log "Warning: Some processes may still be running" -Level Warning; Start-Sleep -Seconds 2 }
    Start-Sleep -Seconds 1
    $result = Invoke-PatchClients -Clients @($targetClient) -Compiler $compiler -VoiceBackupPath $voiceBackupPath
    Write-Host ""
    if ($result.Success -gt 0) {
        Write-Log "=== PATCHING COMPLETE ===" -Level Success
        if ($Script:Config.AutoRelaunch) {
            Write-Log "Auto-relaunching Discord..." -Level Info
            Start-Sleep -Seconds 1
            $discordPath = $selectedClientInfo.Path
            if ($discordPath -and (Test-Path $discordPath)) {
                $appFolder = Get-ChildItem $discordPath -Directory -Filter "app-*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                if ($appFolder) {
                    $exePath = Join-Path $appFolder.FullName $selectedClientInfo.Exe
                    if (Test-Path $exePath) { Write-Log "Launching: $exePath" -Level Info; Start-Process $exePath }
                    else {
                        $updateExe = Join-Path $discordPath "Update.exe"
                        if (Test-Path $updateExe) { Write-Log "Launching via Update.exe..." -Level Info; Start-Process $updateExe -ArgumentList "--processStart", $selectedClientInfo.Exe }
                    }
                }
            }
        }
    } else { Write-Log "=== PATCHING FAILED ===" -Level Error }
    Save-UserConfig
    Read-Host "Press Enter to exit"
    return ($result.Success -gt 0)
}

# ============================================================
# 16. Run
# ============================================================

try {
    $success = Start-Patching
    Write-Host "`n$(if ($success) { 'SUCCESS!' } else { 'FAILED/CANCELLED' })" -ForegroundColor $(if ($success) { 'Green' } else { 'Red' })
    exit $(if ($success) { 0 } else { 1 })
} catch {
    Write-Host "`nFATAL ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}

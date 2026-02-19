@echo off
title Discord Voice Node Patcher
echo Downloading Discord Voice Node Patcher...

set "PS1=%TEMP%\discord_voice_node_patcher.ps1"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/ProdHallow/Discord-Node-Patcher/main/Discord_voice_node_patcher.ps1?v=5.0.1' -OutFile '%PS1%'"

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"

pause

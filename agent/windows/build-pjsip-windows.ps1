# SPDX-License-Identifier: GPL-3.0-or-later
# Developer entry point only: requires the existing controlled Marc-Home WSL.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Distribution,
    [Parameter(Mandatory=$true)][string]$Repository,
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$PythonSdk,
    [Parameter(Mandatory=$true)][string]$Output,
    [Parameter(Mandatory=$true)][string]$Work
)
$ErrorActionPreference = 'Stop'
# All paths are Linux paths inside the chosen WSL distribution. Pass as argv;
# never construct an interpolated shell command containing operator paths.
& wsl.exe --distribution $Distribution --exec env VOICEPROBE_CONTROLLED_BUILD=marc-home `
    python3 "$Repository/agent/windows/build-pjsip-windows.py" `
    --source $Source --python-sdk $PythonSdk --output $Output --work $Work
if ($LASTEXITCODE -ne 0) { throw 'Échec de la construction PJSIP Windows. Consulter le journal privé du constructeur.' }

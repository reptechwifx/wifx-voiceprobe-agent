# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$Sdk,
    [Parameter(Mandatory=$true)][string]$TrustDirectory,
    [Parameter(Mandatory=$true)][string]$Output,
    [Parameter(Mandatory=$true)][string]$Wheels,
    [switch]$Console
)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'PowerShell Windows x64 requis.' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$trust = (Resolve-Path $TrustDirectory).Path
$policy = Get-Content (Join-Path $trust 'build-trust.json') -Raw | ConvertFrom-Json
if ($policy.qualification -ne 'lab') { throw 'Ce constructeur prépare un candidat LAB ; signature et qualification de production distinctes requises.' }
if (Test-Path $Output) { throw 'Destination existante refusée : aucun artefact immuable remplacé.' }
$env:VOICEPROBE_WINDOWS_SDK = (Resolve-Path $Sdk).Path
$env:VOICEPROBE_WINDOWS_TRUST = $trust
$env:VOICEPROBE_WINDOWS_CONSOLE = if ($Console) { '1' } else { '0' }
$build = Join-Path $env:TEMP ('voiceprobe-build-' + [Guid]::NewGuid().ToString('N'))
try {
    & $Python -c 'import sys,struct; assert sys.version_info[:2] == (3,13); assert struct.calcsize(chr(80))==8'
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.13 Windows x64 requis.' }
    & $Python -m pip install --no-index --find-links $Wheels --require-hashes --only-binary=:all: --disable-pip-version-check -r (Join-Path $PSScriptRoot 'requirements-build.lock')
    if ($LASTEXITCODE -ne 0) { throw 'Dépendances binaires verrouillées non vérifiées.' }
    & $Python -m PyInstaller --noconfirm --clean --distpath $Output --workpath $build (Join-Path $repo 'agent\windows\portable.spec')
    if ($LASTEXITCODE -ne 0) { throw 'Construction Windows interrompue ; aucun succès annoncé.' }
    Get-ChildItem $Output -Filter '*.exe' | ForEach-Object {
        [pscustomobject]@{File=$_.Name;Bytes=$_.Length;SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower();Qualification='LAB, non signé Authenticode'}
    } | ConvertTo-Json
} finally {
    Remove-Item Env:VOICEPROBE_WINDOWS_SDK,Env:VOICEPROBE_WINDOWS_TRUST,Env:VOICEPROBE_WINDOWS_CONSOLE -ErrorAction SilentlyContinue
    if (Test-Path $build) { Remove-Item $build -Recurse -Force }
}

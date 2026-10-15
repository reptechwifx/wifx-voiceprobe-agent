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
# Both entry points share the exact offline locks and before/after source checks.
$buildArguments = @((Join-Path $PSScriptRoot 'build-portable.py'), '--sdk', $Sdk,
    '--trust', $TrustDirectory, '--output', $Output, '--wheels', $Wheels)
if ($Console) { $buildArguments += '--console' }
& $Python @buildArguments
if ($LASTEXITCODE -ne 0) { throw 'Construction Windows interrompue ; aucun succès annoncé.' }

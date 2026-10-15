# SPDX-License-Identifier: GPL-3.0-or-later
# Future infrastructure adapter: NOT qualified or connected to the production worker.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$Executable,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSHA256,
 [Parameter(Mandatory=$true)][string]$SignTool,
 [Parameter(Mandatory=$true)][string]$SigningDlib,
 [Parameter(Mandatory=$true)][string]$Metadata,
 [Parameter(Mandatory=$true)][string]$ExpectedPublisherSubject,
 [switch]$InfrastructureQualified
)
$ErrorActionPreference = 'Stop'
if (-not $InfrastructureQualified) { throw 'Infrastructure Azure non qualifiée ; signature refusée.' }
if (-not [Environment]::Is64BitProcess) { throw 'Processus Windows x64 requis.' }
$exe = Get-Item -LiteralPath $Executable
if ($exe.PSIsContainer -or ($exe.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $exe.Extension -ne '.exe') { throw 'EXE régulier requis.' }
if ((Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash.ToLower() -ne $ExpectedSHA256) { throw 'Empreinte du paquet personnalisé refusée.' }
if ((Get-AuthenticodeSignature -LiteralPath $exe.FullName).Status -ne 'NotSigned') { throw 'Le paquet doit être personnalisé AVANT sa première signature.' }
$metadataItem = Get-Item -LiteralPath $Metadata
if ($metadataItem.PSIsContainer -or ($metadataItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $metadataItem.Length -gt 4096) { throw 'Métadonnées de signature refusées.' }
$config = Get-Content -LiteralPath $metadataItem.FullName -Raw | ConvertFrom-Json
$keys = @($config.PSObject.Properties.Name | Sort-Object)
if (($keys -join ',') -ne 'CertificateProfileName,CodeSigningAccountName,Endpoint') { throw 'Contrat de signature refusé.' }
if ($config.Endpoint -notmatch '^https://[a-z0-9]+\.codesigning\.azure\.net/?$' -or $config.CodeSigningAccountName -notmatch '^[a-z0-9]{3,24}$' -or $config.CertificateProfileName -notmatch '^[A-Za-z0-9-]{1,100}$') { throw 'Profil de signature refusé.' }
# Managed identity / service identity configured outside this script; no secret argument.
& $SignTool sign /fd SHA256 /tr 'https://timestamp.acs.microsoft.com' /td SHA256 /dlib $SigningDlib /dmdf $metadataItem.FullName $exe.FullName
if ($LASTEXITCODE -ne 0) { throw 'Signature Azure refusée ; paquet non distribuable.' }
& $SignTool verify /pa /all /v $exe.FullName
if ($LASTEXITCODE -ne 0) { throw 'Vérification Authenticode refusée.' }
$signature = Get-AuthenticodeSignature -LiteralPath $exe.FullName
if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate -or $signature.SignerCertificate.Subject -cne $ExpectedPublisherSubject) { throw 'Éditeur ou horodatage de confiance refusé.' }
$exe.Refresh()
[pscustomobject]@{Status='AUTHENTICODE_VERIFIED';SHA256=(Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash.ToLower();Bytes=$exe.Length} | ConvertTo-Json

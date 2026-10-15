# SPDX-License-Identifier: GPL-3.0-or-later
# Run only on the authorized local signing workstation. No PFX/password arguments.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$ExpectedSHA256,
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][string]$SignTool,
    [Parameter(Mandatory=$true)][uri]$TimestampServer
)
$ErrorActionPreference='Stop'
if ($ExpectedSHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $CertificateThumbprint -notmatch '^[a-fA-F0-9]{40}$') { throw 'Empreinte invalide.' }
if ($TimestampServer.Scheme -ne 'https' -or $TimestampServer.UserInfo -or $TimestampServer.Fragment) { throw 'Service de datation HTTPS sans identifiants requis.' }
$file=Get-Item -LiteralPath $Executable
if ($file.Extension -ne '.exe' -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'EXE régulier requis.' }
if ((Get-FileHash $file.FullName -Algorithm SHA256).Hash -ne $ExpectedSHA256) { throw 'Le candidat a changé ; signature refusée.' }
$cert=Get-Item ('Cert:\CurrentUser\My\'+$CertificateThumbprint)
if (-not $cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date) -or $cert.NotBefore -gt (Get-Date)) { throw 'Identité de signature indisponible ou expirée.' }
if (-not ($cert.EnhancedKeyUsageList.ObjectId.Value -contains '1.3.6.1.5.5.7.3.3')) { throw 'Certificat de signature de code requis.' }
& $SignTool sign /sha1 $CertificateThumbprint /s My /fd SHA256 /tr $TimestampServer.AbsoluteUri /td SHA256 $file.FullName
if ($LASTEXITCODE -ne 0) { throw 'Échec Authenticode ; distribution interdite.' }
& $SignTool verify /pa /all /v $file.FullName
if ($LASTEXITCODE -ne 0) { throw 'Vérification Authenticode refusée.' }
$result=Get-AuthenticodeSignature -LiteralPath $file.FullName
if ($result.Status -ne 'Valid' -or $result.SignerCertificate.Thumbprint -ne $CertificateThumbprint -or -not $result.TimeStamperCertificate) { throw 'Signature reconnue et datée requise.' }
[pscustomobject]@{File=$file.Name;SHA256=(Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower();Signer=$result.SignerCertificate.Subject;Certificate=$CertificateThumbprint;Status='AUTHENTICODE_VERIFIED'} | ConvertTo-Json

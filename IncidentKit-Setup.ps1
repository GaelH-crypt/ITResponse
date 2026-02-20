<#
.SYNOPSIS
    Assistant de configuration IncidentKit - génère config.json.
.DESCRIPTION
    Wizard interactif : domaine, DC, Exchange, chemins, fenêtre d'analyse.
    Teste la connectivité (DNS + ports AD/Exchange) et valide la cohérence.
#>
[CmdletBinding()]
param(
    [string]$OutputConfigPath = (Join-Path $PSScriptRoot 'config.json')
)

$ErrorActionPreference = 'Stop'
$script:Log = { param($msg) Write-Host "[Setup] $msg" }

function Test-DnsResolve {
    param([string]$Name)
    try {
        [void][System.Net.Dns]::GetHostEntry($Name)
        return $true
    } catch { return $false }
}

function Test-TcpPort {
    param([string]$Hostname, [int]$Port, [int]$TimeoutMs = 3000)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok) { try { $tcp.EndConnect($ar) } catch {} }
        $tcp.Close()
        return $ok
    } catch { return $false }
}

Write-Host "=== IncidentKit - Assistant de configuration ===" -ForegroundColor Cyan
Write-Host ""

# Organisation
$orgName = Read-Host "Nom de l'organisation (ex: Ma Collectivité)"
$tz = Read-Host "Fuseau horaire Windows (défaut: Romance Standard Time)"
if ([string]::IsNullOrWhiteSpace($tz)) { $tz = "Romance Standard Time" }

# AD
$domainFqdn = Read-Host "Domaine AD (FQDN, ex: contoso.local)"
$domainNetbios = Read-Host "Domaine AD (NetBIOS, ex: CONTOSO)"
if ([string]::IsNullOrWhiteSpace($domainNetbios)) { $domainNetbios = $domainFqdn.Split('.')[0].ToUpperInvariant() }

$dcList = @()
$dcInput = Read-Host "Contrôleur(s) de domaine (séparés par des virgules, ex: dc01.contoso.local,dc02.contoso.local)"
foreach ($d in ($dcInput -split ',')) {
    $t = $d.Trim()
    if ($t) { $dcList += $t }
}
if ($dcList.Count -eq 0) { $dcList = @("$($domainFqdn.Split('.')[0]).$domainFqdn") }

$preferredDc = $null
if ($dcList.Count -gt 0) {
    $preferredDc = Read-Host "DC préféré pour la collecte (défaut: $($dcList[0]))"
    if ([string]::IsNullOrWhiteSpace($preferredDc)) { $preferredDc = $dcList[0] }
}

$timeWindowDays = 7
$tw = Read-Host "Fenêtre d'analyse en jours (défaut: 7)"
if ($tw -match '^\d+$') { $timeWindowDays = [int]$tw }

# Exchange (optionnel)
$exchangeEnabled = Read-Host "Configurer Exchange ? (O/N, défaut: O)"
if ([string]::IsNullOrWhiteSpace($exchangeEnabled)) { $exchangeEnabled = "O" }
$exchangeServer = $null
$exchangePsUri = $null
$exchangeAuth = "Kerberos"
$exchangeUseSSL = $false
if ($exchangeEnabled -match '^[oO]') {
    $exchangeServer = Read-Host "Serveur Exchange (FQDN, ex: mail.contoso.local)"
    if ($exchangeServer) {
        $exchangePsUri = "http://$exchangeServer/PowerShell/"
        $ssl = Read-Host "Utiliser HTTPS pour PowerShell ? (O/N, défaut: N)"
        if ($ssl -match '^[oO]') {
            $exchangeUseSSL = $true
            $exchangePsUri = "https://$exchangeServer/PowerShell/"
        }
        $exchangeAuth = Read-Host "Authentification (Kerberos / Negotiate / NTLM, défaut: Kerberos)"
        if ([string]::IsNullOrWhiteSpace($exchangeAuth)) { $exchangeAuth = "Kerberos" }
    }
}

# Output
$basePath = Read-Host "Dossier de sortie des rapports (défaut: Output, relatif au script)"
if ([string]::IsNullOrWhiteSpace($basePath)) { $basePath = "Output" }

# Tests de connectivité
& $script:Log "Test DNS et ports..."
$dcOk = $false
foreach ($dc in $dcList) {
    if (Test-DnsResolve -Name $dc) {
        & $script:Log "  DNS $dc : OK"
        if (Test-TcpPort -Hostname $dc -Port 389) { & $script:Log "  Port 389 (LDAP) $dc : OK" }
        if (-not $dcOk) { $dcOk = $true }
    } else {
        & $script:Log "  DNS $dc : ÉCHEC"
    }
}
if ($exchangeServer) {
    if (Test-DnsResolve -Name $exchangeServer) {
        & $script:Log "  DNS $exchangeServer : OK"
        if (Test-TcpPort -Hostname $exchangeServer -Port 80) { & $script:Log "  Port 80 $exchangeServer : OK" }
        if ($exchangeUseSSL -and (Test-TcpPort -Hostname $exchangeServer -Port 443)) { & $script:Log "  Port 443 : OK" }
    } else {
        & $script:Log "  DNS $exchangeServer : ÉCHEC (vérifiez le nom)"
    }
}

# Construction config
$config = @{
    _comment = "Configuration IncidentKit v0.1 - Ne jamais stocker de mots de passe."
    org      = @{
        name     = $orgName
        timezone = $tz
    }
    ad       = @{
        domainFqdn     = $domainFqdn
        domainNetbios  = $domainNetbios
        dcList         = $dcList
        preferredDc    = $preferredDc
        eventIds       = @(4624, 4625, 4672, 4720, 4722, 4728, 4732, 4740)
        timeWindowDays = $timeWindowDays
        exportPaths    = @{
            eventsCsv   = "AD/analyse_ad.csv"
            findingsJson = "AD/ad_findings.json"
        }
    }
    output   = @{
        basePath      = $basePath
        reportFormats = @("md", "txt")
        zipEvidence   = $true
    }
}

if ($exchangeServer) {
    $config.exchange = @{
        serverFqdn = $exchangeServer
        psUri      = $exchangePsUri
        auth       = $exchangeAuth
        useSSL     = $exchangeUseSSL
        checks     = @{ inboxRules = $true; forwarding = $true; transportRules = $false; sendConnectors = $false }
    }
}

$config.endpoint = @{
    collectProcesses     = $true
    collectServices     = $true
    collectScheduledTasks = $true
    collectNetstat       = $true
    collectAutoruns      = $true
    collectRecentFiles   = $true
    collectFileHashes    = $true
    suspiciousNames      = @("PDFClick.exe", "update.exe", "svchost.exe")
}

# Validation cohérence
$issues = @()
if ($dcList.Count -eq 0) { $issues += "ad.dcList doit contenir au moins un DC." }
if ($timeWindowDays -le 0) { $issues += "ad.timeWindowDays doit être > 0." }
if ($issues.Count -gt 0) {
    Write-Warning "Incohérences : $($issues -join ' ; ')"
}

# Écriture
$jsonPath = $OutputConfigPath
if (-not [System.IO.Path]::IsPathRooted($jsonPath)) {
    $jsonPath = Join-Path $PSScriptRoot $jsonPath
}
$json = $config | ConvertTo-Json -Depth 5
Set-Content -Path $jsonPath -Value $json -Encoding UTF8
Write-Host ""
Write-Host "Configuration enregistrée : $jsonPath" -ForegroundColor Green
Write-Host "Vous pouvez lancer IncidentKit.ps1 avec -Profile `"$jsonPath`""

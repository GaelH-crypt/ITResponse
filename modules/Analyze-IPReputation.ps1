<#
.SYNOPSIS
    Analyse de réputation des IP à partir des événements AD (hors-ligne).
.DESCRIPTION
    Lit analyse_ad.csv, ignore les plages privées/whitelist, détecte les IP suspectes
    (nouvelles, nombreux comptes, nombreux échecs 4625) et génère suspicious_ips.json.
    Aucun appel réseau : tout fonctionne hors-ligne.
#>
[CmdletBinding()]
param()

$utilsPath = Join-Path $PSScriptRoot 'IncidentKit-Utils.ps1'
if (Test-Path $utilsPath) { . $utilsPath }

# Seuils pour le calcul du risque (ajustables)
$script:ThresholdFailedAttemptsHigh = 20
$script:ThresholdFailedAttemptsMedium = 5
$script:ThresholdDistinctAccountsHigh = 10
$script:ThresholdDistinctAccountsMedium = 4
$script:ThresholdEventsNewIp = 3   # IP avec très peu d'événements = "jamais vue" dans la fenêtre

function Get-IPWhitelist {
    param([string]$WhitelistPath)
    if (-not $WhitelistPath -or -not (Test-Path -LiteralPath $WhitelistPath)) {
        return [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Get-Content -Path $WhitelistPath -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object {
        $line = $_.Trim()
        if ($line -and $line -notmatch '^\s*#') {
            [void]$set.Add($line)
        }
    }
    return $set
}

function Get-SuspiciousIPRisk {
    param(
        [int]$FailedAttempts,
        [int]$DistinctAccounts,
        [int]$TotalEvents
    )
    $high = $false
    $medium = $false
    if ($FailedAttempts -ge $script:ThresholdFailedAttemptsHigh) { $high = $true }
    elseif ($FailedAttempts -ge $script:ThresholdFailedAttemptsMedium) { $medium = $true }
    if ($DistinctAccounts -ge $script:ThresholdDistinctAccountsHigh) { $high = $true }
    elseif ($DistinctAccounts -ge $script:ThresholdDistinctAccountsMedium) { $medium = $true }
    if ($TotalEvents -le $script:ThresholdEventsNewIp -and ($FailedAttempts -gt 0 -or $DistinctAccounts -gt 1)) { $medium = $true }
    if ($high) { return 'HIGH' }
    if ($medium) { return 'MEDIUM' }
    return 'LOW'
}

function Find-SuspiciousIP {
    <#
    .SYNOPSIS
        Identifie les connexions provenant d'adresses IP anormales à partir de analyse_ad.csv.
    .DESCRIPTION
        - Ignore RFC1918, loopback, link-local, CGNAT.
        - Applique une whitelist optionnelle (whitelist_ips.txt).
        - Détecte : IP peu vue, nombreux comptes distincts, nombreux échecs 4625.
        - Génère output\AD\suspicious_ips.json (ou chemin fourni).
        Aucun appel Internet.
    .PARAMETER CsvPath
        Chemin vers le fichier analyse_ad.csv (produit par la collecte AD).
    .PARAMETER OutputPath
        Chemin de sortie pour suspicious_ips.json.
    .PARAMETER WhitelistPath
        Chemin vers le fichier whitelist (une IP par ligne, # pour commentaire). Optionnel.
    .EXAMPLE
        Find-SuspiciousIP -CsvPath ".\output\AD\analyse_ad.csv"
    .EXAMPLE
        Find-SuspiciousIP -CsvPath ".\output\AD\analyse_ad.csv" -WhitelistPath ".\whitelist_ips.txt"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$CsvPath = (Join-Path (Get-Location) 'output\AD\analyse_ad.csv'),
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path (Get-Location) 'output\AD\suspicious_ips.json'),
        [Parameter(Mandatory = $false)]
        [string]$WhitelistPath = (Join-Path (Get-Location) 'whitelist_ips.txt')
    )
    if (-not (Test-Path -LiteralPath $CsvPath)) {
        Write-Warning "Fichier CSV introuvable : $CsvPath"
        $empty = @()
        $outDir = [System.IO.Path]::GetDirectoryName($OutputPath)
        if (-not [string]::IsNullOrEmpty($outDir)) { Ensure-Directory -Path $outDir | Out-Null }
        $empty | ConvertTo-Json -Depth 3 | Set-Content -Path $OutputPath -Encoding UTF8
        return $empty
    }

    $whitelist = Get-IPWhitelist -WhitelistPath $WhitelistPath
    $rows = Import-Csv -Path $CsvPath -Encoding UTF8 -ErrorAction Stop

    # Agrégation par IP (uniquement IP externes, non whitelistées)
    $byIp = @{}
    foreach ($r in $rows) {
        $ip = $r.IPAddress
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }
        $ip = $ip.Trim()
        if (Test-IPShouldIgnore -Ip $ip) { continue }
        if ($whitelist.Contains($ip)) { continue }

        if (-not $byIp.ContainsKey($ip)) {
            $byIp[$ip] = @{
                Accounts       = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                FailedAttempts = 0
                FirstSeen      = $null
                LastSeen       = $null
                TotalEvents    = 0
            }
        }
        $acc = $r.TargetAccount
        if (-not [string]::IsNullOrWhiteSpace($acc)) { [void]$byIp[$ip].Accounts.Add($acc.Trim()) }
        if ([int]$r.EventID -eq 4625) { $byIp[$ip].FailedAttempts++ }
        $byIp[$ip].TotalEvents++

        $t = $r.TimeCreated
        if ($t) {
            if (-not $byIp[$ip].FirstSeen -or $t -lt $byIp[$ip].FirstSeen) { $byIp[$ip].FirstSeen = $t }
            if (-not $byIp[$ip].LastSeen -or $t -gt $byIp[$ip].LastSeen)  { $byIp[$ip].LastSeen = $t }
        }
    }

    $suspicious = [System.Collections.ArrayList]::new()
    foreach ($entry in $byIp.GetEnumerator()) {
        $ip = $entry.Key
        $data = $entry.Value
        $accounts = @($data.Accounts | Sort-Object -Unique)
        $failed = $data.FailedAttempts
        $firstSeen = $data.FirstSeen
        $lastSeen = $data.LastSeen
        $totalEvents = $data.TotalEvents
        $risk = Get-SuspiciousIPRisk -FailedAttempts $failed -DistinctAccounts $accounts.Count -TotalEvents $totalEvents

        [void]$suspicious.Add([PSCustomObject]@{
            IP             = $ip
            Accounts       = $accounts
            FailedAttempts = $failed
            FirstSeen      = $firstSeen
            LastSeen       = $lastSeen
            Risk           = $risk
        })
    }

    # Trier par risque (HIGH puis MEDIUM puis LOW) puis par FailedAttempts décroissant
    $riskOrder = @{ HIGH = 0; MEDIUM = 1; LOW = 2 }
    $sorted = $suspicious | Sort-Object { $riskOrder[$_.Risk] }, { -$_.FailedAttempts }

    $outDir = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (-not [string]::IsNullOrEmpty($outDir)) { Ensure-Directory -Path $outDir | Out-Null }
    $sorted | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Verbose "Sortie enregistrée : $OutputPath ($($sorted.Count) IP suspecte(s))."
    return $sorted
}

Export-ModuleMember -Function Find-SuspiciousIP, Test-IPShouldIgnore, Get-IPWhitelist

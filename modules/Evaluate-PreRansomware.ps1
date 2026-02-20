<#
.SYNOPSIS
    Évalue rapidement un niveau de risque pré-ransomware à partir des artefacts collectés.
.DESCRIPTION
    Lit des fichiers JSON hors-ligne : ad_findings.json, suspicious_ips.json,
    exchange_findings.json et ioc_manifest.json. Génère
    output\Report\pre_ransomware_assessment.json et ajoute une ligne dans
    executive_summary.txt.
.NOTES
    Aucun accès Internet. Analyse non destructive.
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$script:PreRansomwareKeywords = @(
    'ransom', 'encrypt', 'locker', 'lockbit', 'ryuk', 'conti', 'revil', 'akira',
    'vssadmin', 'wbadmin', 'bcdedit', 'cipher', 'procdump', 'mimikatz', 'psexec',
    'bitsadmin', 'wevtutil'
)

function Test-PathContainsPreRansomwareKeyword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Text
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $value = $Text.ToLowerInvariant()
    foreach ($k in $script:PreRansomwareKeywords) {
        if ($value -like "*$k*") { return $true }
    }
    return $false
}

function Get-JsonFileOrDefault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [object]$DefaultValue
    )
    if (-not (Test-Path -LiteralPath $Path)) { return $DefaultValue }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        return $DefaultValue
    }
}

function Invoke-PreRansomwareAssessment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AdFindingsPath = (Join-Path (Get-Location) 'output\AD\ad_findings.json'),
        [Parameter(Mandatory = $false)]
        [string]$SuspiciousIpsPath = (Join-Path (Get-Location) 'output\AD\suspicious_ips.json'),
        [Parameter(Mandatory = $false)]
        [string]$ExchangeFindingsPath = (Join-Path (Get-Location) 'output\Exchange\exchange_findings.json'),
        [Parameter(Mandatory = $false)]
        [string]$EndpointIocManifestPath = (Join-Path (Get-Location) 'output\Endpoint\ioc_manifest.json'),
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path (Get-Location) 'output\Report\pre_ransomware_assessment.json'),
        [Parameter(Mandatory = $false)]
        [string]$ExecutiveSummaryPath = (Join-Path (Get-Location) 'output\Report\executive_summary.txt')
    )

    $ad = Get-JsonFileOrDefault -Path $AdFindingsPath -DefaultValue ([PSCustomObject]@{})
    $ips = Get-JsonFileOrDefault -Path $SuspiciousIpsPath -DefaultValue @()
    $ex = Get-JsonFileOrDefault -Path $ExchangeFindingsPath -DefaultValue ([PSCustomObject]@{})
    $ioc = Get-JsonFileOrDefault -Path $EndpointIocManifestPath -DefaultValue ([PSCustomObject]@{})

    $score = 0
    $reasons = [System.Collections.ArrayList]::new()

    $newAccountsCount = @($ad.newAccounts).Count
    $adminAddsCount = @($ad.adminGroupAdds).Count
    $rdpLogonsCount = @($ad.rdpLogons).Count
    $externalIpLogonsCount = @($ad.externalIpLogons).Count
    $failurePeaks = @($ad.failurePeaksByIp)
    $highFailureIps = @($failurePeaks | Where-Object { $_.failureCount -ge 25 }).Count

    if ($newAccountsCount -ge 3) {
        $score += 2
        [void]$reasons.Add("$newAccountsCount nouveaux comptes créés récemment")
    }
    if ($adminAddsCount -ge 1) {
        $score += 3
        [void]$reasons.Add("Ajout à des groupes administrateurs détecté ($adminAddsCount)")
    }
    if ($rdpLogonsCount -ge 10 -or $externalIpLogonsCount -ge 5) {
        $score += 2
        [void]$reasons.Add("Activité de connexion distante élevée (RDP/externe)")
    }
    if ($highFailureIps -ge 1) {
        $score += 2
        [void]$reasons.Add("Pics d'échecs d'authentification significatifs sur $highFailureIps IP")
    }

    $highRiskIpsCount = @($ips | Where-Object { $_.Risk -eq 'HIGH' }).Count
    $mediumRiskIpsCount = @($ips | Where-Object { $_.Risk -eq 'MEDIUM' }).Count
    if ($highRiskIpsCount -ge 1) {
        $score += 3
        [void]$reasons.Add("$highRiskIpsCount IP classée(s) HIGH dans suspicious_ips.json")
    } elseif ($mediumRiskIpsCount -ge 2) {
        $score += 1
        [void]$reasons.Add("Plusieurs IP MEDIUM observées ($mediumRiskIpsCount)")
    }

    $suspiciousRulesCount = @($ex.suspiciousRules).Count
    $externalForwardCount = @($ex.externalForwarding).Count
    if ($suspiciousRulesCount -ge 1) {
        $score += 2
        [void]$reasons.Add("Règles Exchange suspectes détectées ($suspiciousRulesCount)")
    }
    if ($externalForwardCount -ge 1) {
        $score += 2
        [void]$reasons.Add("Transferts Exchange externes détectés ($externalForwardCount)")
    }

    $iocHits = 0
    $iocSamples = [System.Collections.ArrayList]::new()
    foreach ($entry in @($ioc.Processes)) {
        if (Test-PathContainsPreRansomwareKeyword -Text $entry.ProcessName -or Test-PathContainsPreRansomwareKeyword -Text $entry.Path) {
            $iocHits++
            if ($iocSamples.Count -lt 3) { [void]$iocSamples.Add($entry.ProcessName) }
        }
    }
    foreach ($entry in @($ioc.Autoruns)) {
        if (Test-PathContainsPreRansomwareKeyword -Text $entry.Name -or Test-PathContainsPreRansomwareKeyword -Text $entry.Value) {
            $iocHits++
            if ($iocSamples.Count -lt 3) { [void]$iocSamples.Add($entry.Name) }
        }
    }
    foreach ($entry in @($ioc.ScheduledTasks)) {
        if (Test-PathContainsPreRansomwareKeyword -Text $entry.TaskName -or Test-PathContainsPreRansomwareKeyword -Text $entry.Description) {
            $iocHits++
            if ($iocSamples.Count -lt 3) { [void]$iocSamples.Add($entry.TaskName) }
        }
    }
    foreach ($entry in @($ioc.FileHashes)) {
        if (Test-PathContainsPreRansomwareKeyword -Text $entry.FullName) {
            $iocHits++
            if ($iocSamples.Count -lt 3) { [void]$iocSamples.Add($entry.FullName) }
        }
    }
    if ($iocHits -ge 1) {
        $score += 3
        [void]$reasons.Add("IOC endpoint potentiellement liés à pré-ransomware détectés ($iocHits): $(@($iocSamples) -join ', ')")
    }

    $risk = 'LOW'
    if ($score -ge 8) {
        $risk = 'HIGH'
    } elseif ($score -ge 4) {
        $risk = 'MEDIUM'
    }

    $recommendedAction = 'Collect only'
    if ($risk -eq 'HIGH') {
        $recommendedAction = 'Escalate'
    } elseif ($risk -eq 'MEDIUM') {
        $recommendedAction = 'Contain'
    }

    if ($reasons.Count -eq 0) {
        [void]$reasons.Add('Aucun signal fort pré-ransomware détecté dans les artefacts fournis.')
    }

    $result = [PSCustomObject]@{
        Risk              = $risk
        Reasons           = @($reasons)
        RecommendedAction = $recommendedAction
    }

    $outDir = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (-not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    if ($PSCmdlet.ShouldProcess($OutputPath, 'Write pre_ransomware_assessment.json')) {
        $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }

    $summaryDir = [System.IO.Path]::GetDirectoryName($ExecutiveSummaryPath)
    if (-not (Test-Path -LiteralPath $summaryDir)) {
        New-Item -ItemType Directory -Path $summaryDir -Force | Out-Null
    }
    $summaryLine = "Pré-évaluation pré-ransomware : Risk=$risk | Action=$recommendedAction | Raisons=$(@($reasons) -join ' ; ')"
    if ($PSCmdlet.ShouldProcess($ExecutiveSummaryPath, 'Append pre-ransomware line')) {
        Add-Content -LiteralPath $ExecutiveSummaryPath -Value $summaryLine -Encoding UTF8
    }

    return $result
}

Export-ModuleMember -Function Invoke-PreRansomwareAssessment, Test-PathContainsPreRansomwareKeyword

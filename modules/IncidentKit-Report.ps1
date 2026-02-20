<#
.SYNOPSIS
    IncidentKit - Génération du rapport technique (MD/TXT) et synthèse direction.
#>
[CmdletBinding()]
param()

function Get-ReportPlaceholders {
    param(
        [string]$IncidentDate,
        [string]$IncidentType,
        [string]$TargetHost,
        [string]$OrgName,
        [int]$TimeWindowDays,
        [string]$RunTimestamp,
        [string]$RunHostname,
        [string]$RunUser,
        [string]$ConfigPath,
        [string]$OutputPath,
        [string]$ExecSummary,
        [string]$EBIOSScore,
        [string]$SeverityLevel,
        [string]$AdStatus,
        [string]$AdDetail,
        [string]$ExchangeStatus,
        [string]$ExchangeDetail,
        [string]$EndpointStatus,
        [string]$EndpointDetail,
        [string]$AdNewAccounts,
        [string]$AdAdminAdditions,
        [string]$AdRdpLogons,
        [string]$AdExternalIps,
        [string]$AdFailurePeaks,
        [string]$ExchangeSuspiciousRules,
        [string]$ExchangeExternalForwarding,
        [string]$EndpointFindings,
        [string]$MitreTechniques,
        [string]$CoverageWarning
    )
    return @{
        '{{INCIDENT_DATE}}'           = $IncidentDate
        '{{INCIDENT_TYPE}}'            = $IncidentType
        '{{TARGET_HOST}}'              = $TargetHost
        '{{ORG_NAME}}'                 = $OrgName
        '{{TIME_WINDOW_DAYS}}'         = $TimeWindowDays
        '{{RUN_TIMESTAMP}}'            = $RunTimestamp
        '{{RUN_HOSTNAME}}'             = $RunHostname
        '{{RUN_USER}}'                 = $RunUser
        '{{CONFIG_PATH}}'              = $ConfigPath
        '{{OUTPUT_PATH}}'              = $OutputPath
        '{{EXEC_SUMMARY}}'             = $ExecSummary
        '{{EBIOS_SCORE}}'              = $EBIOSScore
        '{{SEVERITY_LEVEL}}'           = $SeverityLevel
        '{{AD_STATUS}}'                = $AdStatus
        '{{AD_DETAIL}}'                = $AdDetail
        '{{EXCHANGE_STATUS}}'          = $ExchangeStatus
        '{{EXCHANGE_DETAIL}}'          = $ExchangeDetail
        '{{ENDPOINT_STATUS}}'          = $EndpointStatus
        '{{ENDPOINT_DETAIL}}'          = $EndpointDetail
        '{{AD_NEW_ACCOUNTS}}'          = $AdNewAccounts
        '{{AD_ADMIN_ADDITIONS}}'       = $AdAdminAdditions
        '{{AD_RDP_LOGONS}}'            = $AdRdpLogons
        '{{AD_EXTERNAL_IPS}}'          = $AdExternalIps
        '{{AD_FAILURE_PEAKS}}'         = $AdFailurePeaks
        '{{EXCHANGE_SUSPICIOUS_RULES}}'= $ExchangeSuspiciousRules
        '{{EXCHANGE_EXTERNAL_FORWARDING}}' = $ExchangeExternalForwarding
        '{{ENDPOINT_FINDINGS}}'        = $EndpointFindings
        '{{MITRE_TECHNIQUES}}'         = $MitreTechniques
        '{{COVERAGE_WARNING}}'         = $CoverageWarning
    }
}

function Get-FindingsAsMarkdown {
    param($Items, [string]$NoneText = 'Aucun.')
    if (-not $Items -or $Items.Count -eq 0) { return $NoneText }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('| Données |')
    [void]$sb.AppendLine('|--------|')
    foreach ($i in $Items) {
        [void]$sb.AppendLine("| $($i | ConvertTo-Json -Compress) |")
    }
    return $sb.ToString()
}

function Invoke-IncidentKitReport {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$TemplatePath,
        [string]$OutputReportPath,
        [hashtable]$Placeholders,
        [switch]$WhatIf
    )
    if (-not (Test-Path $TemplatePath)) {
        throw "Template introuvable : $TemplatePath"
    }
    $content = Get-Content -Path $TemplatePath -Raw -Encoding UTF8
    foreach ($k in $Placeholders.Keys) {
        $content = $content.Replace($k, $Placeholders[$k])
    }
    if (-not $WhatIf) {
        $dir = Split-Path $OutputReportPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Set-Content -Path $OutputReportPath -Value $content -Encoding UTF8
    }
    return $OutputReportPath
}

function New-ExecutiveSummaryTxt {
    param(
        [string]$Path,
        [string]$IncidentType,
        [string]$ScoreLevel,
        [string]$ScoreDetail,
        [string]$DoneList,
        [string]$NotDoneList,
        [switch]$WhatIf
    )
    $txt = @"
=== Synthèse direction - IncidentKit ===
Type d'incident : $IncidentType
Niveau de risque (EBIOS simplifié) : $ScoreLevel
Détail score : $ScoreDetail

Réalisé :
$DoneList

Non réalisé ou erreur :
$NotDoneList

Rapport technique détaillé : voir rapport_tech.md dans le dossier Report.
"@
    if (-not $WhatIf) { Set-Content -Path $Path -Value $txt -Encoding UTF8 }
    return $Path
}

export-modulemember -Function Get-ReportPlaceholders, Get-FindingsAsMarkdown, Invoke-IncidentKitReport, New-ExecutiveSummaryTxt

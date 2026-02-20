<#
.SYNOPSIS
    IncidentKit - Launcher principal pour collecte et analyse forensic light en cas d'incident cyber.
.DESCRIPTION
    Collecte AD, Exchange (optionnel), Endpoint (optionnel), génère rapport technique et score EBIOS.
    Mode Collect : collecte uniquement. Mode Investigate : collecte + analyse + scoring. Mode Contain : idem + proposition d'actions de confinement avec confirmation interactive.
    Fonctionne depuis un poste joint au domaine ou hors domaine (Get-Credential).
.NOTES
    Collect/Investigate : aucune action destructive. Contain : actions (désactiver compte, reset MDP, bloquer poste simulé) uniquement après confirmation explicite. Toutes les actions journalisées.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [Alias('Profile')]
    [string]$ProfilePath = (Join-Path $PSScriptRoot 'config.json'),
    [ValidateSet('Collect', 'Investigate', 'Contain')]
    [string]$Mode = 'Investigate',
    [ValidateSet('infostealer', 'phishing', 'ransomware_suspect', 'account_compromise')]
    [string]$IncidentType = 'account_compromise',
    [string]$TargetHost = '',
    [int]$TimeWindowDays = 0,
    [string]$OutputPath = '',
    [ValidateSet('CurrentUser', 'Prompt')]
    [string]$CredentialMode = 'Prompt',
    [switch]$WhatIf,
    [switch]$Verbose
)

# Transcript IMMÉDIAT
$script:TranscriptStarted = $false
$earlyTranscript = Join-Path $env:TEMP ("IncidentKit_transcript_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
try {
    Start-Transcript -Path $earlyTranscript -Append -ErrorAction Stop
    $script:TranscriptStarted = $true
} catch {}

# Ensuite seulement :
$ErrorActionPreference = 'Stop'

$script:RootDir = $PSScriptRoot

try {

# Chargement des modules (dot-source)
$moduleDir = Join-Path $script:RootDir 'modules'
foreach ($f in @('IncidentKit-Config.ps1', 'Check-LoggingHealth.ps1', 'IncidentKit-AD.ps1', 'IncidentKit-Exchange.ps1', 'IncidentKit-Endpoint.ps1', 'IncidentKit-EBIOS.ps1', 'IncidentKit-Report.ps1', 'Generate-ExecutiveSummary.ps1', 'Generate-Timeline.ps1', 'Evaluate-PreRansomware.ps1', 'IncidentKit-Contain.ps1')) {
    $path = Join-Path $moduleDir $f
    if (Test-Path $path) { . $path }
}

$utilsPath = Join-Path $moduleDir 'IncidentKit-Utils.ps1'
if (Test-Path $utilsPath) { . $utilsPath }

# Résolution du chemin de config
$configPath = $ProfilePath
if (-not [System.IO.Path]::IsPathRooted($configPath)) {
    $configPath = Join-Path $script:RootDir $configPath
}
if (-not (Test-Path -LiteralPath $configPath)) {
    Write-Error "Configuration introuvable : $configPath. Exécutez IncidentKit-Setup.ps1 pour créer config.json."
}

$config = Get-IncidentKitConfig -ConfigPath $configPath
$issues = Test-IncidentKitConfigCoherence -Config $config
if ($issues.Count -gt 0) {
    Write-Warning "Cohérence config : $($issues -join ' ; ')"
}

# Dossier de sortie horodaté
$baseOut = if ($OutputPath) { $OutputPath } else { $config.output.basePath }
if (-not [System.IO.Path]::IsPathRooted($baseOut)) {
    $baseOut = Join-Path $script:RootDir $baseOut
}
$timestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$targetLabel = if ($TargetHost) { $TargetHost } else { 'no-target' }
$runDir = Join-Path $baseOut "${timestamp}_${IncidentType}_${targetLabel}"

# Override fenêtre d'analyse
$days = if ($TimeWindowDays -gt 0) { $TimeWindowDays } else { $config.ad.timeWindowDays }

# Credential : si hors domaine OU CredentialMode=Prompt → Get-Credential ; si annulé → message + exit 2
# Si poste joint domaine ET CredentialMode=CurrentUser → pas de prompt, on continue avec $cred = $null
$cred = $null
$isDomainJoined = $false
try {
    $comp = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isDomainJoined = $comp -and $comp.PartOfDomain
} catch {}
if (-not $isDomainJoined -or $CredentialMode -eq 'Prompt') {
    try {
        $cred = Get-Credential -Message "Identifiants AD (domaine\$env:USERNAME ou compte admin) - requis pour collecte AD/Exchange"
    } catch {}
    if (-not $cred) {
        Write-Warning "Identifiants requis en mode hors domaine"
        if ($script:TranscriptStarted) { Stop-Transcript -ErrorAction SilentlyContinue }
        exit 2
    }
}

# Création dossier + copie du transcript early dans Report (on continue d'écrire dans le même transcript, pas de second Start-Transcript)
if (-not $WhatIf) {
    Ensure-Directory -Path $runDir | Out-Null
    $logDir = Join-Path $runDir 'Report'
    Ensure-Directory -Path $logDir | Out-Null
    $transcriptCopyPath = Join-Path $logDir (Split-Path $earlyTranscript -Leaf)
    Copy-Item -Path $earlyTranscript -Destination $transcriptCopyPath -Force -ErrorAction SilentlyContinue
}
$script:LogLines = [System.Collections.ArrayList]::new()
$script:LogFilePath = Join-Path $runDir 'Report\incidentkit.log'
$script:Log = {
    param($msg)
    $line = Write-IncidentLog -Message $msg -LogFilePath $script:LogFilePath -WhatIf:$WhatIf
    [void]$script:LogLines.Add($line)
}

& $script:Log "IncidentKit démarré - Mode: $Mode, Type: $IncidentType, Cible: $TargetHost, Jours: $days, Config: $configPath"
& $script:Log "Dossier de sortie: $runDir"

# --- Santé des journaux (avant toute analyse) ---
$loggingHealthResult = $null
try {
    $loggingHealthResult = Test-LoggingHealth -Config $config -OutputDir $runDir -Credential $cred -Log $script:Log -WhatIf:$WhatIf
} catch {
    & $script:Log "Check-LoggingHealth : erreur $_"
    & $script:Log "Exception: $($_.Exception.GetType().FullName)"
    if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
}

# --- AD ---
$adResult = $null
try {
    $adResult = Invoke-IncidentKitADCollect -Config $config -TimeWindowDays $days -OutputDir $runDir -Credential $cred -Log $script:Log -WhatIf:$WhatIf
} catch {
    $adResult = @{ Success = $false; Error = $_.Exception.Message }
    & $script:Log "AD : erreur $_"
    & $script:Log "Exception: $($_.Exception.GetType().FullName)"
    if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
}
$adStatus = if ($adResult.Success) { "OK" } else { "Erreur" }
$adDetail = if (-not $adResult.Success -and $adResult.Error) { $adResult.Error } else { "$($adResult.EventsCount) événements" }
if (-not $adResult.Success -and -not $adDetail) { $adDetail = "DC inaccessible" }
if ($adResult.CoverageIncomplete) {
    Write-Warning "ATTENTION : la période demandée n'est pas entièrement couverte par les journaux disponibles."
}
if (-not $adResult.Success) {
    Write-Warning "Source AD absente ou inaccessible ; vérifiez la connectivité au contrôleur de domaine et les permissions."
}

# --- Exchange ---
$exResult = $null
try {
    $exResult = Invoke-IncidentKitExchangeCollect -Config $config -OutputDir $runDir -Credential $cred -Log $script:Log -WhatIf:$WhatIf
} catch {
    $exResult = @{ Success = $false; Error = $_.Exception.Message }
    & $script:Log "Exchange : erreur $_"
    & $script:Log "Exception: $($_.Exception.GetType().FullName)"
    if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
}
$exStatus = if ($exResult.Success) { "OK" } else { "Erreur / Non accessible" }
$exDetail = if ($exResult.Error) { $exResult.Error } else { if ($exResult.Success) { "Règles et forwarding exportés" } else { "Vérifier connectivité et identifiants" } }
if (-not $exResult.Success) {
    Write-Warning "Source Exchange absente ou inaccessible ; vérifiez la configuration et la connectivité Exchange."
}

# --- Endpoint ---
$epResult = $null
$endpointCollectStartedAt = (Get-Date).ToString('o')
try {
    $epResult = Invoke-IncidentKitEndpointCollect -Config $config -TargetHost $TargetHost -OutputDir $runDir -Credential $cred -Log $script:Log -WhatIf:$WhatIf
} catch {
    $epResult = @{ Success = $false; Error = $_.Exception.Message; OutputDir = (Join-Path $runDir 'Endpoint') }
    & $script:Log "Endpoint : erreur $_"
    & $script:Log "Exception: $($_.Exception.GetType().FullName)"
    if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
}
$endpointCollectEndedAt = (Get-Date).ToString('o')
$epStatus = if ($epResult.Skipped) { "Non demandé" } elseif ($epResult.Success) { "OK" } else { "Erreur" }
$epDetail = if ($epResult.Skipped) { "Pas de -TargetHost" } else { if ($epResult.Error) { $epResult.Error } else { "Collecte effectuée" } }
if ($epResult.Skipped -or -not $epResult.Success) {
    Write-Warning "Source Endpoint absente ; fournissez -TargetHost et vérifiez WinRM/connectivité si collecte distante."
}

# --- Coverage / disponibilité des sources ---
$exchangeChecks = if ($config.exchange -and $config.exchange.checks) { $config.exchange.checks } else { $null }
$exchangeInboxRulesCollected = [bool]($exResult.Success -and $exchangeChecks -and $exchangeChecks.inboxRules)
$exchangeForwardingCollected = [bool]($exResult.Success -and $exchangeChecks -and $exchangeChecks.forwarding)
$iisLogsFound = [bool]($loggingHealthResult -and $loggingHealthResult.ExchangeIISLogsPresent)
$lastIisLogTimestamp = $null
if ($exchangeChecks -and $exchangeChecks.owaIisLogPath) {
    try {
        $iisPath = $exchangeChecks.owaIisLogPath
        if (Test-Path -LiteralPath $iisPath -PathType Container -ErrorAction SilentlyContinue) {
            $lastIisLog = Get-ChildItem -LiteralPath $iisPath -File -Recurse -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
            if ($lastIisLog) {
                $lastIisLogTimestamp = $lastIisLog.LastWriteTime.ToString('o')
            }
        }
    } catch {
        & $script:Log "Détection dernier log IIS : $_"
    }
}

$endpointCollectedMode = if ($epResult.Skipped) { 'none' } elseif ($epResult.Local) { 'local' } elseif ($epResult.Remote) { 'remote' } else { 'unknown' }
$endpointWinRMOk = if ($epResult.Skipped -or $epResult.Local) { $null } else { [bool]$epResult.Success }

if (-not $WhatIf) {
    $healthDir = Join-Path $runDir 'HealthCheck'
    if (-not (Test-Path $healthDir)) { New-Item -ItemType Directory -Path $healthDir -Force | Out-Null }
    $coverageSummary = [ordered]@{
        AD = [ordered]@{
            DaysCovered = if ($loggingHealthResult) { $loggingHealthResult.DaysCovered } else { $null }
            CoverageIncomplete = [bool]$adResult.CoverageIncomplete
        }
        Exchange = [ordered]@{
            InboxRulesCollected = if ($exchangeInboxRulesCollected) { 'yes' } else { 'no' }
            ForwardingCollected = if ($exchangeForwardingCollected) { 'yes' } else { 'no' }
            IISLogsFound = if ($iisLogsFound) { 'yes' } else { 'no' }
            LastIISLogTimestamp = $lastIisLogTimestamp
        }
        Endpoint = [ordered]@{
            Collected = $endpointCollectedMode
            WinRMOk = $endpointWinRMOk
            CollectionStartedAt = $endpointCollectStartedAt
            CollectionEndedAt = $endpointCollectEndedAt
        }
    }
    $coveragePath = Join-Path $healthDir 'coverage.json'
    $coverageSummary | ConvertTo-Json -Depth 4 | Set-Content -Path $coveragePath -Encoding UTF8
    & $script:Log "Coverage summary écrit : $coveragePath"
}

$reportDir = Join-Path $runDir 'Report'
$ebios = $null
$epDir = Join-Path $runDir 'Endpoint'

if ($Mode -eq 'Collect') {
    & $script:Log "Mode Collect : collecte uniquement, analyse et rapport non générés."
} elseif ($Mode -in 'Investigate', 'Contain') {
# --- EBIOS + MITRE ---
$adFindingsPath = Join-Path $runDir 'AD\ad_findings.json'
$exFindingsPath = Join-Path $runDir 'Exchange\exchange_findings.json'
$ebiosResult = $null
try {
    $ebiosResult = Invoke-IncidentKitEBIOSFromFindings -AdFindingsPath $adFindingsPath -ExchangeFindingsPath $exFindingsPath -EndpointDir $epDir -SensitiveHost ($false) -Log $script:Log
} catch {
    & $script:Log "EBIOS/MITRE : $_"
    & $script:Log "Exception: $($_.Exception.GetType().FullName)"
    if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
    $ebiosResult = @{ EBIOS = (Get-EBIOSScore); MITRE = @() }
}

$ebios = $ebiosResult.EBIOS
$mitre = $ebiosResult.MITRE

# Export EBIOS CSV + MITRE JSON
if (-not $WhatIf) {
    if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
    $ebios | Select-Object Gravity, Likelihood, Score, Level | Export-Csv -Path (Join-Path $reportDir 'ebios.csv') -NoTypeInformation -Encoding UTF8
    $mitre | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $reportDir 'mitre.json') -Encoding UTF8
}

# --- Rapport MD + synthèse ---
$templatePath = Join-Path $script:RootDir 'templates\report_tech.md'
$adNew = "Aucun."
$adAdmin = "Aucun."
$adRdp = "Aucun."
$adExt = "Aucun."
$adFail = "Aucun."
$exRules = "Aucun."
$exFwd = "Aucun."
$epFind = "Non collecté ou non demandé."
$mitreMd = "Aucune technique identifiée."

if (Test-Path $adFindingsPath) {
    try {
        $adF = Get-Content $adFindingsPath -Raw | ConvertFrom-Json
        if ($adF.newAccounts -and $adF.newAccounts.Count -gt 0) { $adNew = ($adF.newAccounts | ConvertTo-Json -Compress) }
        if ($adF.adminGroupAdds -and $adF.adminGroupAdds.Count -gt 0) { $adAdmin = ($adF.adminGroupAdds | ConvertTo-Json -Compress) }
        if ($adF.rdpLogons -and $adF.rdpLogons.Count -gt 0) { $adRdp = ($adF.rdpLogons | ConvertTo-Json -Compress) }
        if ($adF.externalIpLogons -and $adF.externalIpLogons.Count -gt 0) { $adExt = ($adF.externalIpLogons | ConvertTo-Json -Compress) }
        if (($adF.failurePeaksByAccount -and $adF.failurePeaksByAccount.Count -gt 0) -or ($adF.failurePeaksByIp -and $adF.failurePeaksByIp.Count -gt 0)) {
            $adFail = "Comptes: $(($adF.failurePeaksByAccount | ConvertTo-Json -Compress)); IP: $(($adF.failurePeaksByIp | ConvertTo-Json -Compress))"
        }
    } catch {}
}
if (Test-Path $exFindingsPath) {
    try {
        $exF = Get-Content $exFindingsPath -Raw | ConvertFrom-Json
        if ($exF.suspiciousRules -and $exF.suspiciousRules.Count -gt 0) { $exRules = ($exF.suspiciousRules | ConvertTo-Json -Compress) }
        if ($exF.externalForwarding -and $exF.externalForwarding.Count -gt 0) { $exFwd = ($exF.externalForwarding | ConvertTo-Json -Compress) }
    } catch {}
}
if ($epResult -and $epResult.OutputDir -and (Test-Path $epResult.OutputDir)) {
    $epFind = "Données dans $($epResult.OutputDir) (processes, services, netstat, autoruns, etc.)."
}
if ($mitre -and $mitre.Count -gt 0) {
    $mitreMd = ($mitre | ForEach-Object { "$($_.id) - $($_.name) ($($_.tactic))" }) -join "`n"
}

$coverageWarning = if ($adResult.CoverageIncomplete) { "**ATTENTION :** la période demandée n'est pas entièrement couverte par les journaux disponibles." } else { "" }
$placeholders = Get-ReportPlaceholders -IncidentDate (Get-Date -Format 'yyyy-MM-dd') -IncidentType $IncidentType -TargetHost $TargetHost -OrgName $config.org.name -TimeWindowDays $days -RunTimestamp (Get-Date -Format 'o') -RunHostname $env:COMPUTERNAME -RunUser $env:USERNAME -ConfigPath $configPath -OutputPath $runDir -ExecSummary "Collecte forensic light réalisée. Score EBIOS : $($ebios.Score) ($($ebios.Level))." -EBIOSScore $ebios.Score -SeverityLevel $ebios.Level -AdStatus $adStatus -AdDetail $adDetail -ExchangeStatus $exStatus -ExchangeDetail $exDetail -EndpointStatus $epStatus -EndpointDetail $epDetail -AdNewAccounts $adNew -AdAdminAdditions $adAdmin -AdRdpLogons $adRdp -AdExternalIps $adExt -AdFailurePeaks $adFail -ExchangeSuspiciousRules $exRules -ExchangeExternalForwarding $exFwd -EndpointFindings $epFind -MitreTechniques $mitreMd -CoverageWarning $coverageWarning

Invoke-IncidentKitReport -TemplatePath $templatePath -OutputReportPath (Join-Path $reportDir 'rapport_tech.md') -Placeholders $placeholders -WhatIf:$WhatIf

$doneList = @()
if ($adResult.Success) { $doneList += "Collecte AD ($($adResult.EventsCount) événements)." }
if ($exResult.Success) { $doneList += "Collecte Exchange (règles + forwarding)." }
if ($epResult.Success -and -not $epResult.Skipped) { $doneList += "Collecte Endpoint." }
$doneList += "Score EBIOS et rapport générés."

$notDoneList = @()
if (-not $adResult.Success) { $notDoneList += "AD : $($adResult.Error)" }
if (-not $exResult.Success) { $notDoneList += "Exchange : $($exResult.Error)" }
if (-not $epResult.Success -and -not $epResult.Skipped) { $notDoneList += "Endpoint : $($epResult.Error)" }
if ($notDoneList.Count -eq 0) { $notDoneList += "Aucun." }

New-ExecutiveSummaryTxt -Path (Join-Path $reportDir 'rapport_exec.txt') -IncidentType $IncidentType -ScoreLevel $ebios.Level -ScoreDetail "Gravité=$($ebios.Gravity), Vraisemblance=$($ebios.Likelihood), Score=$($ebios.Score)" -DoneList ($doneList -join "`n") -NotDoneList ($notDoneList -join "`n") -WhatIf:$WhatIf

New-ExecutiveSummary -ReportDir $reportDir -IncidentType $IncidentType -SeverityLevel $ebios.Level -ActionsTaken ($doneList -join ' ') -WhatIf:$WhatIf

try {
    $assessment = Invoke-PreRansomwareAssessment `
        -AdFindingsPath (Join-Path $runDir 'AD\ad_findings.json') `
        -SuspiciousIpsPath (Join-Path $runDir 'AD\suspicious_ips.json') `
        -ExchangeFindingsPath (Join-Path $runDir 'Exchange\exchange_findings.json') `
        -EndpointIocManifestPath (Join-Path $runDir 'Endpoint\ioc_manifest.json') `
        -OutputPath (Join-Path $runDir 'Report\pre_ransomware_assessment.json') `
        -ExecutiveSummaryPath (Join-Path $runDir 'Report\executive_summary.txt') `
        -WhatIf:$WhatIf
    & $script:Log "Pré-évaluation ransomware : Risk=$($assessment.Risk), Action=$($assessment.RecommendedAction)"
} catch {
    & $script:Log "Evaluate-PreRansomware : $_"
    & $script:Log "Exception: $($_.Exception.GetType().FullName)"
    if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
}

# --- Timeline fusionnée ---
try {
    $null = Build-IncidentTimeline -OutputDir $runDir -RunTimestamp (Get-Date -Format 'o') -Log $script:Log -WhatIf:$WhatIf
} catch {
    & $script:Log "Generate-Timeline : $_"
    & $script:Log "Exception: $($_.Exception.GetType().FullName)"
    if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
}

# --- Integrity Manifest ---
if (-not $WhatIf -and (Test-Path $runDir)) {
    try {
        $manifestEntries = Get-ChildItem -Path $runDir -File -Recurse -ErrorAction Stop |
            Where-Object { $_.FullName -ne (Join-Path $runDir 'Evidence.zip') } |
            ForEach-Object {
                $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction Stop
                [PSCustomObject]@{
                    path = $_.FullName.Substring($runDir.Length).TrimStart('\\', '/')
                    sha256 = $hash.Hash.ToLowerInvariant()
                }
            }

        $manifestJsonPath = Join-Path $reportDir 'evidence_manifest.json'
        $manifestTxtPath = Join-Path $reportDir 'evidence_manifest.txt'

        $manifestEntries |
            Sort-Object path |
            ConvertTo-Json -Depth 4 |
            Set-Content -Path $manifestJsonPath -Encoding UTF8

        $manifestEntries |
            Sort-Object path |
            ForEach-Object { "{0}  {1}" -f $_.sha256, $_.path } |
            Set-Content -Path $manifestTxtPath -Encoding UTF8

        & $script:Log "Integrity manifest généré : $manifestJsonPath ; $manifestTxtPath"
    } catch {
        & $script:Log "Integrity Manifest : $_"
        & $script:Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
    }
}

# ZIP preuves (optionnel)
if ($config.output.zipEvidence -and -not $WhatIf -and (Test-Path $runDir)) {
    $zipPath = Join-Path $runDir 'Evidence.zip'
    try {
        Compress-Archive -Path (Join-Path $runDir 'AD'), (Join-Path $runDir 'Exchange'), (Join-Path $runDir 'Report') -DestinationPath $zipPath -Force -ErrorAction Stop
        if (Test-Path $epDir) {
            Compress-Archive -Path $epDir -DestinationPath (Join-Path $runDir 'Endpoint.zip') -Force -ErrorAction SilentlyContinue
        }
        & $script:Log "Archive créée : $zipPath"
    } catch {
        & $script:Log "ZIP : $_"
        & $script:Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $script:Log "StackTrace: $($_.ScriptStackTrace)" }
    }
}

    # --- Mode Contain : menu d'actions de confinement (confirmation requise pour chaque action)
    if ($Mode -eq 'Contain') {
        Invoke-IncidentKitContainmentMenu -ReportDir $reportDir -Credential $cred -Log $script:Log -WhatIf:$WhatIf
    }
}

Write-Host ""
Write-Host "IncidentKit terminé." -ForegroundColor Green
Write-Host "  Dossier : $runDir"
if ($ebios) {
    Write-Host "  Score EBIOS : $($ebios.Score) - $($ebios.Level)"
    Write-Host "  Rapport : $reportDir\rapport_tech.md | rapport_exec.txt | executive_summary.txt"
} else {
    Write-Host "  Mode Collect : collecte uniquement (pas d'analyse ni rapport)."
}

} catch {
    $errMsg = $_.Exception.Message
    $errStack = $_.ScriptStackTrace
    $logLine1 = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] EXCEPTION: $errMsg"
    $logLine2 = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ScriptStackTrace: $errStack"
    $logDir = $null
    if ($runDir -and (Test-Path $runDir)) {
        $reportSub = Join-Path $runDir 'Report'
        if (Test-Path $reportSub) { $logDir = $reportSub }
    }
    if ($logDir) {
        $logFile = Join-Path $logDir 'incidentkit.log'
        Add-Content -Path $logFile -Value $logLine1, $logLine2 -Encoding UTF8 -ErrorAction SilentlyContinue
    } else {
        $tempLog = Join-Path $env:TEMP "IncidentKit_crash_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Add-Content -Path $tempLog -Value $logLine1, $logLine2 -Encoding UTF8 -ErrorAction SilentlyContinue
        Write-Host "Crash log : $tempLog" -ForegroundColor Red
    }
    throw
} finally {
    if ($script:TranscriptStarted) {
        try { Stop-Transcript -ErrorAction Stop } catch { }
        if (-not $WhatIf -and $earlyTranscript -and (Test-Path $earlyTranscript) -and $runDir -and (Test-Path $runDir)) {
            $logDir = Join-Path $runDir 'Report'
            if (Test-Path $logDir) { try { Copy-Item -Path $earlyTranscript -Destination (Join-Path $logDir (Split-Path $earlyTranscript -Leaf)) -Force -ErrorAction Stop } catch { } }
        }
    }
}

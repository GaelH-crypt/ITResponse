<#
.SYNOPSIS
    IncidentKit - Génération d'une timeline d'incident fusionnée.
.DESCRIPTION
    Fusionne détection antivirus, logons AD, règles mail et événements importants
    dans un CSV unique : output\Report\timeline.csv
    Colonnes : Timestamp, Source, Event, Account, Host
.NOTES
    S'attend à un dossier de sortie de run IncidentKit (AD\, Exchange\, Endpoint\, Report\).
#>
[CmdletBinding(SupportsShouldProcess)]
param()

# EventIDs Windows Defender (détections)
$script:DefenderEventIds = @(1116, 1117, 1118)

# Libellés courts pour EventID AD
$script:ADEventLabels = @{
    4624 = 'Logon réussi'
    4625 = 'Échec de connexion'
    4672 = 'Privilèges spéciaux assignés'
    4720 = 'Compte utilisateur créé'
    4722 = 'Compte utilisateur activé'
    4728 = 'Membre ajouté au groupe de sécurité'
    4732 = 'Membre ajouté au groupe local'
    4740 = 'Verrouillage de compte'
}

function Get-TimelineRow {
    param(
        [string]$Timestamp,
        [string]$Source,
        [string]$EventDescription,
        [string]$Account,
        [string]$HostName
    )
    [PSCustomObject]@{
        Timestamp = $Timestamp
        Source    = $Source
        Event     = $EventDescription
        Account   = $Account
        Host      = $HostName
    }
}

function Import-TimelineFromAD {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [scriptblock]$Log
    )
    $csvPath = Join-Path $OutputDir 'AD\analyse_ad.csv'
    $rows = [System.Collections.ArrayList]::new()
    if (-not (Test-Path $csvPath)) {
        & $Log "AD : fichier introuvable $csvPath"
        return $rows
    }
    try {
        $ad = Import-Csv -Path $csvPath -Encoding UTF8 -ErrorAction Stop
        foreach ($r in $ad) {
            $label = $script:ADEventLabels[$r.EventID]
            if (-not $label) { $label = "Événement $($r.EventID)" }
            $account = if ($r.TargetAccount) { $r.TargetAccount } else { $r.SubjectAccount }
            $hostName = if ($r.WorkstationName) { $r.WorkstationName } else { $r.MachineName }
            [void]$rows.Add((Get-TimelineRow -Timestamp $r.TimeCreated -Source 'AD' -EventDescription $label -Account $account -HostName $hostName))
        }
        & $Log "AD : $($rows.Count) lignes importées."
    } catch {
        & $Log "AD : erreur $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
    return $rows
}

function Import-TimelineFromExchangeRules {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [string]$RunTimestamp,
        [scriptblock]$Log
    )
    $rows = [System.Collections.ArrayList]::new()
    $csvPath = Join-Path $OutputDir 'Exchange\exchange_rules.csv'
    if (-not (Test-Path $csvPath)) {
        & $Log "Exchange règles : fichier introuvable $csvPath"
        return $rows
    }
    try {
        $ts = $RunTimestamp
        $fi = Get-Item -LiteralPath $csvPath -ErrorAction SilentlyContinue
        if ($fi -and $fi.LastWriteTime) { $ts = $fi.LastWriteTime.ToString('o') }
        $rules = Import-Csv -Path $csvPath -Encoding UTF8 -ErrorAction Stop
        foreach ($r in $rules) {
            $ev = "Règle boîte : $($r.Name)"
            if ($r.ForwardTo) { $ev += " → $($r.ForwardTo)" }
            if ($r.RedirectTo) { $ev += " | Redirect: $($r.RedirectTo)" }
            if ($r.DeleteMessage -eq 'True') { $ev += " | DeleteMessage" }
            [void]$rows.Add((Get-TimelineRow -Timestamp $ts -Source 'Exchange' -EventDescription $ev -Account $r.MailboxOwnerID -HostName ''))
        }
        & $Log "Exchange règles : $($rows.Count) lignes."
    } catch {
        & $Log "Exchange règles : erreur $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
    return $rows
}

function Import-TimelineFromAV {
    param(
        [string]$AvCsvPath,
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [scriptblock]$Log
    )
    $rows = [System.Collections.ArrayList]::new()
    $path = $AvCsvPath
    if (-not $path) { $path = Join-Path $OutputDir 'Endpoint\av_detections.csv' }
    if (-not (Test-Path $path)) {
        & $Log "Antivirus : fichier introuvable $path (optionnel)."
        return $rows
    }
    try {
        $av = Import-Csv -Path $path -Encoding UTF8 -ErrorAction Stop
        foreach ($r in $av) {
            $ts = $r.Timestamp
            if (-not $ts -and $r.TimeCreated) { $ts = $r.TimeCreated }
            if (-not $ts -and $r.Time) { $ts = $r.Time }
            if (-not $ts) { $ts = (Get-Date).ToString('o') }
            $ev = $r.Event
            if (-not $ev -and $r.Description) { $ev = $r.Description }
            if (-not $ev -and $r.Name) { $ev = $r.Name }
            if (-not $ev) { $ev = 'Détection antivirus' }
            $acc = $r.Account; if (-not $acc) { $acc = $r.User }
            $h = $r.Host; if (-not $h) { $h = $r.ComputerName }
            $src = if ($r.Source) { $r.Source } else { 'Antivirus' }
            [void]$rows.Add((Get-TimelineRow -Timestamp $ts -Source $src -EventDescription $ev -Account $acc -HostName $h))
        }
        & $Log "Antivirus : $($rows.Count) lignes."
    } catch {
        & $Log "Antivirus : erreur $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
    return $rows
}

function Get-DefenderDetectionEvents {
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [int]$Days = 7,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log
    )
    $rows = [System.Collections.ArrayList]::new()
    $start = (Get-Date).AddDays(-$Days)
    $params = @{
        FilterHashtable = @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            Id      = $script:DefenderEventIds
        }
        MaxEvents   = 10000
        ErrorAction = 'Stop'
    }
    if ($ComputerName -and $ComputerName -ne $env:COMPUTERNAME -and $ComputerName -ne 'localhost' -and $ComputerName -ne '.') {
        $params.ComputerName = $ComputerName
        if ($Credential) { $params.Credential = $Credential }
    }
    try {
        $events = Get-WinEvent @params | Where-Object { $_.TimeCreated -ge $start }
        foreach ($ev in $events) {
            $msg = $ev.Message
            if ($ev.Properties -and $ev.Properties.Count -gt 0) {
                $msg = "$($ev.Id) - $($ev.Properties[0].ToString())"
            }
            [void]$rows.Add((Get-TimelineRow -Timestamp $ev.TimeCreated.ToString('o') -Source 'Windows Defender' -EventDescription $msg -Account '' -HostName $ev.MachineName))
        }
        & $Log "Defender : $($rows.Count) événements sur $ComputerName."
    } catch {
        & $Log "Defender : $_ (journal peut être absent)."
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
    return $rows
}

function Import-TimelineFromFindings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [string]$RunTimestamp,
        [scriptblock]$Log
    )
    $rows = [System.Collections.ArrayList]::new()
    $tsFallback = $RunTimestamp

    # AD findings
    $adPath = Join-Path $OutputDir 'AD\ad_findings.json'
    if (Test-Path $adPath) {
        try {
            $ad = Get-Content $adPath -Raw | ConvertFrom-Json
            if ($ad.newAccounts) {
                foreach ($x in $ad.newAccounts) {
                    $t = if ($x.time) { $x.time } else { $tsFallback }
                    [void]$rows.Add((Get-TimelineRow -Timestamp $t -Source 'AD-Finding' -EventDescription 'Nouveau compte créé' -Account $x.account -HostName $x.machine))
                }
            }
            if ($ad.adminGroupAdds) {
                foreach ($x in $ad.adminGroupAdds) {
                    $t = if ($x.time) { $x.time } else { $tsFallback }
                    [void]$rows.Add((Get-TimelineRow -Timestamp $t -Source 'AD-Finding' -EventDescription "Ajout groupe admin : $($x.member) → $($x.group)" -Account $x.member -HostName ''))
                }
            }
            if ($ad.rdpLogons) {
                foreach ($x in $ad.rdpLogons) {
                    $t = if ($x.time) { $x.time } else { $tsFallback }
                    [void]$rows.Add((Get-TimelineRow -Timestamp $t -Source 'AD-Finding' -EventDescription 'Connexion RDP' -Account $x.account -HostName $x.machine))
                }
            }
            if ($ad.externalIpLogons) {
                foreach ($x in $ad.externalIpLogons) {
                    $t = if ($x.time) { $x.time } else { $tsFallback }
                    [void]$rows.Add((Get-TimelineRow -Timestamp $t -Source 'AD-Finding' -EventDescription "Logon IP externe ($($x.ip))" -Account $x.account -HostName ''))
                }
            }
        } catch {
            & $Log "AD findings : $_"
            & $Log "Exception: $($_.Exception.GetType().FullName)"
            if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        }
    }

    # Exchange findings (pas de timestamp dans les findings → run date)
    $exPath = Join-Path $OutputDir 'Exchange\exchange_findings.json'
    if (Test-Path $exPath) {
        try {
            $ex = Get-Content $exPath -Raw | ConvertFrom-Json
            if ($ex.suspiciousRules) {
                foreach ($x in $ex.suspiciousRules) {
                    [void]$rows.Add((Get-TimelineRow -Timestamp $tsFallback -Source 'Exchange-Finding' -EventDescription "Règle suspecte : $($x.ruleName) - $($x.reason)" -Account $x.mailbox -HostName ''))
                }
            }
            if ($ex.externalForwarding) {
                foreach ($x in $ex.externalForwarding) {
                    [void]$rows.Add((Get-TimelineRow -Timestamp $tsFallback -Source 'Exchange-Finding' -EventDescription "Transfert externe vers $($x.address)" -Account $x.mailbox -HostName ''))
                }
            }
        } catch {
            & $Log "Exchange findings : $_"
            & $Log "Exception: $($_.Exception.GetType().FullName)"
            if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        }
    }

    & $Log "Événements importants (findings) : $($rows.Count) lignes."
    return $rows
}

function Build-IncidentTimeline {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [string]$AvCsvPath = '',
        [string]$RunTimestamp = (Get-Date -Format 'o'),
        [switch]$IncludeDefenderEvents,
        [string]$DefenderComputerName = $env:COMPUTERNAME,
        [int]$DefenderDays = 7,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log = { param($m) Write-Verbose $m },
        [switch]$WhatIf
    )
    $all = [System.Collections.ArrayList]::new()

    # 1) Logons AD
    $adRows = Import-TimelineFromAD -OutputDir $OutputDir -Log $Log
    foreach ($r in $adRows) { [void]$all.Add($r) }

    # 2) Règles mail
    $exRows = Import-TimelineFromExchangeRules -OutputDir $OutputDir -RunTimestamp $RunTimestamp -Log $Log
    foreach ($r in $exRows) { [void]$all.Add($r) }

    # 3) Détection antivirus (fichier CSV)
    $avRows = Import-TimelineFromAV -OutputDir $OutputDir -AvCsvPath $AvCsvPath -Log $Log
    foreach ($r in $avRows) { [void]$all.Add($r) }

    # 3b) Optionnel : événements Defender en direct
    if ($IncludeDefenderEvents -and -not $WhatIf) {
        $defRows = Get-DefenderDetectionEvents -ComputerName $DefenderComputerName -Days $DefenderDays -Credential $Credential -Log $Log
        foreach ($r in $defRows) { [void]$all.Add($r) }
    }

    # 4) Événements importants (findings)
    $findRows = Import-TimelineFromFindings -OutputDir $OutputDir -RunTimestamp $RunTimestamp -Log $Log
    foreach ($r in $findRows) { [void]$all.Add($r) }

    # Tri par Timestamp
    $sorted = $all | Sort-Object -Property Timestamp

    $reportDir = Join-Path $OutputDir 'Report'
    $csvPath = Join-Path $reportDir 'timeline.csv'

    if (-not $WhatIf) {
        if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
        $sorted | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ','
        & $Log "Timeline exportée : $csvPath ($($sorted.Count) lignes)."
    } else {
        & $Log "WhatIf : timeline aurait $($sorted.Count) lignes → $csvPath"
    }

    return @{ TimelinePath = $csvPath; RowCount = $sorted.Count; Rows = $sorted }
}

export-modulemember -Function Build-IncidentTimeline, Import-TimelineFromAD, Import-TimelineFromExchangeRules, Import-TimelineFromAV, Import-TimelineFromFindings, Get-DefenderDetectionEvents, Get-TimelineRow

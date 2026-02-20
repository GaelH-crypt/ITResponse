<#
.SYNOPSIS
    IncidentKit - Collecte et analyse des événements de sécurité AD.
.DESCRIPTION
    Exporte les événements Security des DC (4624,4625,4672,4720,4722,4728,4732,4740)
    et génère analyse_ad.csv + ad_findings.json.
#>
[CmdletBinding()]
param()

$script:EventIdsDefault = @(4624, 4625, 4672, 4720, 4722, 4728, 4732, 4740)

function Get-ADSecurityEventsRaw {
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [int[]]$EventIds = $script:EventIdsDefault,
        [int]$Days = 7,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$WhatIf
    )
    $start = (Get-Date).AddDays(-$Days)
    $filter = @{
        LogName   = 'Security'
        Id        = $EventIds
        StartTime = $start
    }
    $dcUsed = $ComputerName
    try {
        $params = @{
            FilterHashtable = $filter
            ComputerName    = $ComputerName
            ErrorAction     = 'Stop'
        }
        if ($Credential) { $params.Credential = $Credential }
        if ($WhatIf) {
            Write-Verbose "WhatIf: Get-WinEvent -FilterHashtable (Security, $($EventIds -join ',')) -ComputerName $ComputerName depuis $start"
            return [PSCustomObject]@{ Success = $true; Events = @(); Error = ''; DcUsed = $dcUsed; CoverageIncomplete = $false; CoverageMessage = '' }
        }
        $events = Get-WinEvent @params -MaxEvents 500000 -ErrorAction Stop
        $coverageIncomplete = $false
        $coverageMessage = ''
        if ($events -and ($events | Measure-Object).Count -gt 0) {
            $oldestEventDate = ($events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            if ($oldestEventDate -gt $start) {
                $coverageIncomplete = $true
                $coverageMessage = "La fenêtre demandée ($Days jours) dépasse la rétention disponible dans le journal Security du DC"
            }
        }
        return [PSCustomObject]@{ Success = $true; Events = @($events); Error = ''; DcUsed = $dcUsed; CoverageIncomplete = $coverageIncomplete; CoverageMessage = $coverageMessage }
    } catch {
        $msg = $_.Exception.Message
        $isNetworkError = $msg -match 'RPC server is unavailable|RPC server unavailable|timeout|timed out|access is denied|access denied|cannot find.*server|The server is not operational|network path was not found'
        if ($isNetworkError) {
            $errText = "DC inaccessible: $msg"
            Write-Warning "Get-WinEvent sur $ComputerName : $errText"
            return [PSCustomObject]@{ Success = $false; Events = @(); Error = $errText; DcUsed = $dcUsed; CoverageIncomplete = $false; CoverageMessage = '' }
        }
        Write-Warning "Get-WinEvent sur $ComputerName : $_"
        return [PSCustomObject]@{ Success = $false; Events = @(); Error = $msg; DcUsed = $dcUsed; CoverageIncomplete = $false; CoverageMessage = '' }
    }
}

function Get-EventPropertyFromXml {
    param([string]$Xml, [string]$SelectNodeName)
    if (-not $Xml) { return $null }
    try {
        $ev = [xml]$Xml
        $ns = @{ e = 'http://schemas.microsoft.com/win/2004/08/events/event' }
        $n = $ev.SelectSingleNode("//e:EventData/e:Data[@Name='$SelectNodeName']", $ns)
        return $n.InnerText
    } catch {
        return $null
    }
}

function Export-ADEventsToCsvRows {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$Events
    )
    $rows = [System.Collections.ArrayList]::new()
    foreach ($ev in $Events) {
        $xml = $ev.ToXml()
        $targetAccount = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'TargetUserName'; if (-not $targetAccount) { $targetAccount = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'SubjectUserName' }
        $subjectAccount = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'SubjectUserName'; if (-not $subjectAccount) { $subjectAccount = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'TargetUserName' }
        $logonType = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'LogonType'
        $ipAddress = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'IpAddress'; if (-not $ipAddress) { $ipAddress = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'ClientAddress' }
        $workstation = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'WorkstationName'
        $processName = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'ProcessName'
        $status = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'Status'
        $subStatus = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'SubStatus'
        $targetSid = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'TargetUserSid'
        $memberName = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'MemberName'
        $groupName = Get-EventPropertyFromXml -Xml $xml -SelectNodeName 'TargetUserName'

        [void]$rows.Add([PSCustomObject]@{
            TimeCreated     = $ev.TimeCreated.ToString('o')
            EventID         = $ev.Id
            TargetAccount   = $targetAccount
            SubjectAccount  = $subjectAccount
            LogonType       = $logonType
            IPAddress       = $ipAddress
            WorkstationName = $workstation
            ProcessName     = $processName
            Status          = $status
            SubStatus       = $subStatus
            TargetSid       = $targetSid
            MemberName      = $memberName
            GroupName       = $groupName
            MachineName     = $ev.MachineName
        })
    }
    return $rows
}

function Test-IsRfc1918 {
    param([string]$Ip)
    if (-not $Ip -or $Ip -eq '-' -or $Ip -match '^::') { return $true }
    if ($Ip -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') {
        $a = [int]$matches[1]; $b = [int]$matches[2]
        if ($a -eq 10) { return $true }
        if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $true }
        if ($a -eq 192 -and $b -eq 168) { return $true }
    }
    return $false
}

function Get-ADFindings {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$CsvRows
    )
    $findings = @{
        newAccounts       = [System.Collections.ArrayList]::new()
        adminGroupAdds    = [System.Collections.ArrayList]::new()
        rdpLogons         = [System.Collections.ArrayList]::new()
        externalIpLogons  = [System.Collections.ArrayList]::new()
        failurePeaksByAccount = @{}
        failurePeaksByIp      = @{}
    }

    foreach ($r in $CsvRows) {
        if ($r.EventID -eq 4720 -and $r.TargetAccount) {
            [void]$findings.newAccounts.Add([PSCustomObject]@{
                account = $r.TargetAccount
                time    = $r.TimeCreated
                machine = $r.MachineName
            })
        }
        if (($r.EventID -eq 4728 -or $r.EventID -eq 4732) -and $r.MemberName -and $r.GroupName) {
            [void]$findings.adminGroupAdds.Add([PSCustomObject]@{
                member   = $r.MemberName
                group    = $r.GroupName
                time     = $r.TimeCreated
                eventId  = $r.EventID
            })
        }
        if ($r.EventID -eq 4624 -and $r.LogonType -eq '10') {
            [void]$findings.rdpLogons.Add([PSCustomObject]@{
                account = $r.TargetAccount
                ip      = $r.IPAddress
                time    = $r.TimeCreated
                machine = $r.MachineName
            })
        }
        if ($r.EventID -eq 4624 -and $r.IPAddress -and -not (Test-IsRfc1918 -Ip $r.IPAddress)) {
            [void]$findings.externalIpLogons.Add([PSCustomObject]@{
                account = $r.TargetAccount
                ip      = $r.IPAddress
                time    = $r.TimeCreated
            })
        }
        if ($r.EventID -eq 4625) {
            $keyAcc = if ($r.TargetAccount) { $r.TargetAccount } else { 'unknown' }
            $curAcc = $findings.failurePeaksByAccount[$keyAcc]; if ($null -eq $curAcc) { $curAcc = 0 }; $findings.failurePeaksByAccount[$keyAcc] = $curAcc + 1
            $keyIp = if ($r.IPAddress) { $r.IPAddress } else { 'unknown' }
            $curIp = $findings.failurePeaksByIp[$keyIp]; if ($null -eq $curIp) { $curIp = 0 }; $findings.failurePeaksByIp[$keyIp] = $curIp + 1
        }
    }

    $findings.failurePeaksByAccount = @($findings.failurePeaksByAccount.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ account = $_.Key; failureCount = $_.Value } })
    $findings.failurePeaksByIp      = @($findings.failurePeaksByIp.GetEnumerator()      | ForEach-Object { [PSCustomObject]@{ ip = $_.Key; failureCount = $_.Value } })
    return $findings
}

function Invoke-IncidentKitADCollect {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config,
        [int]$TimeWindowDays,
        [string]$OutputDir,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log,
        [switch]$WhatIf
    )
    $days = if ($TimeWindowDays -gt 0) { $TimeWindowDays } else { $Config.ad.timeWindowDays }
    $dc = if ($Config.ad.preferredDc) { $Config.ad.preferredDc } else { $Config.ad.dcList[0] }
    $eventIds = if ($Config.ad.eventIds) { $Config.ad.eventIds } else { $script:EventIdsDefault }

    $adDir = Join-Path $OutputDir 'AD'
    if (-not $WhatIf) {
        if (-not (Test-Path $adDir)) { New-Item -ItemType Directory -Path $adDir -Force | Out-Null }
    }

    & $Log "Collecte AD : DC=$dc, jours=$days, EventIDs=$($eventIds -join ',')"

    $rawResult = Get-ADSecurityEventsRaw -ComputerName $dc -EventIds $eventIds -Days $days -Credential $Credential -WhatIf:$WhatIf
    $events = $rawResult.Events
    $count = ($events | Measure-Object).Count
    & $Log "Événements Security récupérés : $count"

    $csvPath = Join-Path $adDir 'analyse_ad.csv'
    $jsonPath = Join-Path $adDir 'ad_findings.json'

    if (-not $rawResult.Success) {
        & $Log "AD : $($rawResult.Error)"
        if (-not $WhatIf) {
            @() | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            @{ error = $rawResult.Error; dcUsed = $rawResult.DcUsed; newAccounts = @(); adminGroupAdds = @(); rdpLogons = @(); externalIpLogons = @(); failurePeaksByAccount = @(); failurePeaksByIp = @() } | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
        }
        return [PSCustomObject]@{ Success = $false; Events = @(); Error = $rawResult.Error; DcUsed = $rawResult.DcUsed; EventsCount = 0; CsvPath = $csvPath; FindingsPath = $jsonPath; CoverageIncomplete = $false; CoverageMessage = '' }
    }

    if ($count -eq 0) {
        if (-not $WhatIf) {
            @() | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            @{ newAccounts = @(); adminGroupAdds = @(); rdpLogons = @(); externalIpLogons = @(); failurePeaksByAccount = @(); failurePeaksByIp = @() } | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
        }
        return [PSCustomObject]@{ Success = $true; Events = @(); Error = ''; DcUsed = $rawResult.DcUsed; EventsCount = 0; CsvPath = $csvPath; FindingsPath = $jsonPath; CoverageIncomplete = $rawResult.CoverageIncomplete; CoverageMessage = $rawResult.CoverageMessage }
    }

    $rows = Export-ADEventsToCsvRows -Events $events
    if (-not $WhatIf) {
        $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $findings = Get-ADFindings -CsvRows $rows
        $findings | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
    }

    return [PSCustomObject]@{ Success = $true; Events = $events; Error = ''; DcUsed = $rawResult.DcUsed; EventsCount = $count; CsvPath = $csvPath; FindingsPath = $jsonPath; CoverageIncomplete = $rawResult.CoverageIncomplete; CoverageMessage = $rawResult.CoverageMessage }
}

export-modulemember -Function Invoke-IncidentKitADCollect, Get-ADSecurityEventsRaw, Get-ADFindings, Test-IsRfc1918

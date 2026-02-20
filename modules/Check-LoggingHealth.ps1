<#
.SYNOPSIS
    IncidentKit - Vérification de la santé des journaux avant analyse de sécurité.
.DESCRIPTION
    Vérifie que les journaux disponibles sont exploitables (taille Security, durée couverte,
    politique d'audit AD, synchronisation NTP, logs IIS Exchange). Collecte uniquement, ne modifie
    jamais la configuration système. Toutes les erreurs sont consignées via le scriptblock Log.
.NOTES
    Sortie : OutputDir\HealthCheck\logging_health.json
    Toutes les erreurs sont consignées via le scriptblock -Log (configurer en amont pour écrire dans log.txt ou Report\incidentkit.log).
#>
[CmdletBinding(SupportsShouldProcess)]
param()

# Catégories d'audit obligatoires (noms tels qu'affichés par auditpol /get /category:*)
$script:RequiredAuditCategories = @(
    'Logon'                    # Logon/Logoff
    'Account Logon'
    'Account Management'
    'Directory Service Access' # ou "DS Access"
)

function Test-LoggingHealth {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config,
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Log,
        [switch]$WhatIf
    )
    # Ne jamais modifier la configuration système — collecte uniquement.
    $result = @{
        SecurityLogSizeMB       = $null
        DaysCovered             = $null
        AuditPolicyOK           = $false
        NTPConfigured           = $false
        ExchangeIISLogsPresent  = $false
        Conclusion              = 'INSUFFICIENT_LOGGING'
    }
    $dc = $null
    try {
        $dc = if ($Config.ad.preferredDc) { $Config.ad.preferredDc } else { $Config.ad.dcList[0] }
        if (-not $dc) {
            & $Log "Check-LoggingHealth : aucun DC configuré (ad.preferredDc / ad.dcList)."
            $result.Conclusion = 'INSUFFICIENT_LOGGING'
            Export-LoggingHealthResult -Result $result -OutputDir $OutputDir -Log $Log -WhatIf:$WhatIf
            return $result
        }
    } catch {
        & $Log "Check-LoggingHealth : erreur résolution DC : $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        Export-LoggingHealthResult -Result $result -OutputDir $OutputDir -Log $Log -WhatIf:$WhatIf
        return $result
    }

    $icmParams = @{
        ComputerName = $dc
        ErrorAction  = 'Stop'
    }
    if ($Credential) { $icmParams.Credential = $Credential }

    # --- 1) Taille du journal Security et durée couverte (sur le DC) ---
    try {
        if (-not $WhatIf) {
            $dcHealth = Invoke-Command @icmParams -ScriptBlock {
                $sizeMB = $null
                $daysCovered = $null
                $oldestTime = $null
                try {
                    $log = Get-CimInstance -ClassName Win32_NTEventlogFile -Filter "LogfileName='Security'" -ErrorAction SilentlyContinue
                    if ($log -and $null -ne $log.FileSize) {
                        $sizeMB = [math]::Round($log.FileSize / 1MB, 2)
                    }
                } catch {
                    $script:err = $_.Exception.Message
                }
                try {
                    $q = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName)
                    $q.ReverseDirection = $true
                    $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($q)
                    $ev = $reader.ReadEvent()
                    if ($ev) { $oldestTime = $ev.TimeCreated }
                    $reader.Dispose()
                } catch {
                    # Fallback : pas de ReverseDirection possible (ex. PS remoting)
                    try {
                        $events = Get-WinEvent -LogName Security -MaxEvents 50000 -ErrorAction Stop
                        if ($events -and $events.Count -gt 0) {
                            $oldestTime = ($events | Measure-Object -Property TimeCreated -Minimum).Minimum
                        }
                    } catch {}
                }
                if ($oldestTime) {
                    $daysCovered = [math]::Max(0, ((Get-Date) - $oldestTime).TotalDays)
                }
                [PSCustomObject]@{ SizeMB = $sizeMB; DaysCovered = $daysCovered; OldestTime = $oldestTime }
            }
            if ($dcHealth) {
                $result.SecurityLogSizeMB = $dcHealth.SizeMB
                $result.DaysCovered = if ($null -ne $dcHealth.DaysCovered) { [math]::Floor($dcHealth.DaysCovered) } else { $null }
                & $Log "Check-LoggingHealth : Security log size = $($result.SecurityLogSizeMB) MB, jours couverts = $($result.DaysCovered)"
            }
        } else {
            & $Log "Check-LoggingHealth (WhatIf) : vérification taille Security et plus ancien événement sur $dc"
        }
    } catch {
        & $Log "Check-LoggingHealth : erreur journal Security sur $dc : $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }

    # --- 2) Politique d'audit (auditpol /get /category:*) sur le DC ---
    try {
        if (-not $WhatIf) {
            $auditOut = Invoke-Command @icmParams -ScriptBlock {
                $out = auditpol /get /category:* 2>&1
                $out | Out-String
            }
            $auditText = $auditOut -join "`n"
            $result.AuditPolicyOK = Test-AuditPolicyFromOutput -Output $auditText -Log $using:Log
            & $Log "Check-LoggingHealth : AuditPolicyOK = $($result.AuditPolicyOK)"
        }
    } catch {
        & $Log "Check-LoggingHealth : erreur auditpol sur $dc : $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }

    # --- 3) Synchronisation horaire (NTP + décalage) sur le DC ---
    try {
        if (-not $WhatIf) {
            $ntpInfo = Invoke-Command @icmParams -ScriptBlock {
                $source = $null
                $offsetSeconds = $null
                try {
                    $status = w32tm /query /status 2>&1 | Out-String
                    if ($status -match 'Source:\s*(.+)') { $source = $matches[1].Trim() }
                    if ($status -match 'Last Successful Sync Time:') { $source = if ($source) { $source } else { 'SyncTimePresent' } }
                    if ($status -match 'Source:\s*(\S+)') { $source = $matches[1].Trim() }
                    # Décalage horaire (en secondes) si présent dans la sortie
                    if ($status -match 'Last Sync Error:\s*(\d+)\s*sec') { $offsetSeconds = [int]$matches[1] }
                } catch {}
                try {
                    $strip = w32tm /query /configuration 2>&1 | Out-String
                    if ($strip -match 'Type:\s*NTP' -or $strip -match 'NtpServer') { $source = if ($source) { $source } else { 'NTP' } }
                } catch {}
                [PSCustomObject]@{ NTPSource = $source; TimeOffsetSeconds = $offsetSeconds }
            }
            $result.NTPConfigured = ($null -ne $ntpInfo.NTPSource -and $ntpInfo.NTPSource -ne '')
            & $Log "Check-LoggingHealth : NTP source = $($ntpInfo.NTPSource), décalage(sec) = $($ntpInfo.TimeOffsetSeconds), NTPConfigured = $($result.NTPConfigured)"
        }
    } catch {
        & $Log "Check-LoggingHealth : erreur NTP sur $dc : $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }

    # --- 4) Logs IIS Exchange (si Exchange activé et owaIisLogPath défini) ---
    $exchangeEnabled = $Config.exchange -and $Config.exchange.psUri
    $owaPath = $null
    if ($Config.exchange.checks) {
        $owaPath = $Config.exchange.checks.owaIisLogPath
    }
    if ($exchangeEnabled -and $owaPath) {
        try {
            $logPath = $owaPath.Trim()
            $folderExists = Test-Path -LiteralPath $logPath -PathType Container -ErrorAction SilentlyContinue
            $recentFiles = $false
            if ($folderExists -and -not $WhatIf) {
                $cutoff = (Get-Date).AddHours(-48)
                $recent = Get-ChildItem -LiteralPath $logPath -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $cutoff } |
                    Select-Object -First 1
                $recentFiles = $null -ne $recent
            }
            $result.ExchangeIISLogsPresent = $folderExists -and $recentFiles
            & $Log "Check-LoggingHealth : Exchange IIS log path = $logPath, exists = $folderExists, recentFiles(<48h) = $recentFiles"
        } catch {
            & $Log "Check-LoggingHealth : erreur logs IIS Exchange : $_"
            & $Log "Exception: $($_.Exception.GetType().FullName)"
            if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        }
    } else {
        if (-not $exchangeEnabled) {
            $result.ExchangeIISLogsPresent = $false
        } else {
            & $Log "Check-LoggingHealth : exchange.checks.owaIisLogPath non défini, ExchangeIISLogsPresent = false"
            $result.ExchangeIISLogsPresent = $false
        }
    }

    # --- Conclusion ---
    $ok = $result.AuditPolicyOK -and $result.NTPConfigured
    if ($null -ne $result.DaysCovered -and $result.DaysCovered -ge 1) {
        $ok = $ok -and $true
    }
    if ($exchangeEnabled -and $owaPath) {
        $ok = $ok -and $result.ExchangeIISLogsPresent
    }
    $result.Conclusion = if ($ok) { 'OK' } else { 'INSUFFICIENT_LOGGING' }
    & $Log "Check-LoggingHealth : Conclusion = $($result.Conclusion)"

    Export-LoggingHealthResult -Result $result -OutputDir $OutputDir -Log $Log -WhatIf:$WhatIf
    return $result
}

function Test-AuditPolicyFromOutput {
    param(
        [string]$Output,
        [scriptblock]$Log
    )
    if (-not $Output) { return $false }
    $lines = $Output -split "`r?`n"
    $required = @(
        @{ Name = 'Logon'; Aliases = 'Logon', 'Logon/Logoff' }
        @{ Name = 'Account Logon'; Aliases = 'Account Logon', 'Account Logon' }
        @{ Name = 'Account Management'; Aliases = 'Account Management' }
        @{ Name = 'Directory Service'; Aliases = 'Directory Service Access', 'DS Access', 'DS Access' }
    )
    $found = @{}
    foreach ($line in $lines) {
        $line = $line.Trim()
        foreach ($r in $required) {
            foreach ($alias in $r.Aliases) {
                if ($line -match [regex]::Escape($alias)) {
                    if ($line -match 'Success\s+and\s+Failure|Success and Failure|Success, Failure|Success|Failure') {
                        $found[$r.Name] = $true
                    }
                }
            }
        }
    }
    $allFound = ($required | ForEach-Object { $found[$_.Name] -eq $true }).Count -eq $required.Count
    return $allFound
}

function Export-LoggingHealthResult {
    param(
        [hashtable]$Result,
        [string]$OutputDir,
        [scriptblock]$Log,
        [switch]$WhatIf
    )
    $healthDir = Join-Path $OutputDir 'HealthCheck'
    $jsonPath = Join-Path $healthDir 'logging_health.json'
    try {
        if (-not $WhatIf) {
            if (-not (Test-Path $healthDir)) {
                New-Item -ItemType Directory -Path $healthDir -Force | Out-Null
            }
            $export = @{
                SecurityLogSizeMB      = $Result.SecurityLogSizeMB
                DaysCovered            = $Result.DaysCovered
                AuditPolicyOK          = [bool]$Result.AuditPolicyOK
                NTPConfigured          = [bool]$Result.NTPConfigured
                ExchangeIISLogsPresent = [bool]$Result.ExchangeIISLogsPresent
                Conclusion             = $Result.Conclusion
            }
            $export | ConvertTo-Json -Depth 2 | Set-Content -Path $jsonPath -Encoding UTF8 -ErrorAction Stop
            & $Log "Check-LoggingHealth : rapport écrit : $jsonPath"
        }
    } catch {
        & $Log "Check-LoggingHealth : erreur écriture $jsonPath : $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
}

Export-ModuleMember -Function Test-LoggingHealth

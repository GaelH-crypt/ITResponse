<#
.SYNOPSIS
    IncidentKit - Score EBIOS simplifié (gravité x vraisemblance) et cartographie MITRE ATT&CK.
#>
[CmdletBinding()]
param()

function Get-EBIOSScore {
    param(
        [bool]$MalwareExecuted = $false,
        [bool]$C2OrExternalIp = $false,
        [bool]$AdminAccountOrGroup = $false,
        [bool]$ExternalMailRules = $false,
        [bool]$SensitiveHost = $false
    )
    $gravity = 0
    if ($MalwareExecuted) { $gravity += 3 }
    if ($C2OrExternalIp) { $gravity += 2 }
    if ($AdminAccountOrGroup) { $gravity += 3 }
    if ($ExternalMailRules) { $gravity += 2 }
    if ($SensitiveHost) { $gravity += 1 }
    $gravity = [Math]::Min(5, $gravity)
    $likelihood = 0
    if ($MalwareExecuted) { $likelihood += 2 }
    if ($C2OrExternalIp) { $likelihood += 2 }
    if ($AdminAccountOrGroup) { $likelihood += 2 }
    if ($ExternalMailRules) { $likelihood += 2 }
    if ($SensitiveHost) { $likelihood += 1 }
    $likelihood = [Math]::Min(5, $likelihood)
    $score = $gravity * $likelihood
    $level = 'Faible'
    if ($score -ge 15) { $level = 'Critique' }
    elseif ($score -ge 10) { $level = 'Élevé' }
    elseif ($score -ge 5) { $level = 'Moyen' }
    return [PSCustomObject]@{
        Gravity     = $gravity
        Likelihood  = $likelihood
        Score       = $score
        Level       = $level
        Criteria    = @{
            MalwareExecuted       = $MalwareExecuted
            C2OrExternalIp        = $C2OrExternalIp
            AdminAccountOrGroup   = $AdminAccountOrGroup
            ExternalMailRules     = $ExternalMailRules
            SensitiveHost         = $SensitiveHost
        }
    }
}

function Get-MitreTechniques {
    param(
        [bool]$MalwareExecuted = $false,
        [bool]$C2OrExternalIp = $false,
        [bool]$AdminAccountOrGroup = $false,
        [bool]$ExternalMailRules = $false,
        [bool]$RdpLogons = $false,
        [bool]$FailurePeaks = $false
    )
    $techniques = [System.Collections.ArrayList]::new()
    if ($MalwareExecuted) {
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1204'; name = 'User Execution'; tactic = 'Execution' })
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1059'; name = 'Command and Scripting Interpreter'; tactic = 'Execution' })
    }
    if ($C2OrExternalIp) {
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1071'; name = 'Application Layer Protocol'; tactic = 'Command and Control' })
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1090'; name = 'Proxy'; tactic = 'Command and Control' })
    }
    if ($AdminAccountOrGroup) {
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1136'; name = 'Create Account'; tactic = 'Persistence' })
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1098'; name = 'Account Manipulation'; tactic = 'Persistence' })
    }
    if ($ExternalMailRules) {
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1564.008'; name = 'Email Hiding Rules'; tactic = 'Defense Evasion' })
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1114'; name = 'Email Collection'; tactic = 'Collection' })
    }
    if ($RdpLogons) {
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1021'; name = 'Remote Services'; tactic = 'Lateral Movement' })
    }
    if ($FailurePeaks) {
        [void]$techniques.Add([PSCustomObject]@{ id = 'T1110'; name = 'Brute Force'; tactic = 'Credential Access' })
    }
    return @($techniques)
}

function Invoke-IncidentKitEBIOSFromFindings {
    param(
        [string]$AdFindingsPath,
        [string]$ExchangeFindingsPath,
        [string]$EndpointDir,
        [bool]$SensitiveHost = $false,
        [scriptblock]$Log
    )
    $malware = $false
    $c2 = $false
    $admin = $false
    $mailRules = $false
    $rdp = $false
    $failures = $false

    if (Test-Path $AdFindingsPath) {
        try {
            $ad = Get-Content $AdFindingsPath -Raw | ConvertFrom-Json
            if ($ad.newAccounts -and $ad.newAccounts.Count -gt 0) { $admin = $true }
            if ($ad.adminGroupAdds -and $ad.adminGroupAdds.Count -gt 0) { $admin = $true }
            if ($ad.externalIpLogons -and $ad.externalIpLogons.Count -gt 0) { $c2 = $true }
            if ($ad.rdpLogons -and $ad.rdpLogons.Count -gt 0) { $rdp = $true }
            if (($ad.failurePeaksByAccount -and $ad.failurePeaksByAccount.Count -gt 0) -or ($ad.failurePeaksByIp -and $ad.failurePeaksByIp.Count -gt 0)) { $failures = $true }
        } catch {
            & $Log "Lecture ad_findings : $_"
            & $Log "Exception: $($_.Exception.GetType().FullName)"
            if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        }
    }

    if (Test-Path $ExchangeFindingsPath) {
        try {
            $ex = Get-Content $ExchangeFindingsPath -Raw | ConvertFrom-Json
            if ($ex.error) { } else {
                if (($ex.suspiciousRules -and $ex.suspiciousRules.Count -gt 0) -or ($ex.externalForwarding -and $ex.externalForwarding.Count -gt 0)) { $mailRules = $true }
            }
        } catch {
            & $Log "Lecture exchange_findings : $_"
            & $Log "Exception: $($_.Exception.GetType().FullName)"
            if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        }
    }

    if ($EndpointDir -and (Test-Path (Join-Path $EndpointDir 'suspicious_processes.csv'))) {
        try {
            $sp = Import-Csv (Join-Path $EndpointDir 'suspicious_processes.csv')
            if ($sp -and $sp.Count -gt 0) { $malware = $true }
        } catch { }
    }

    $score = Get-EBIOSScore -MalwareExecuted $malware -C2OrExternalIp $c2 -AdminAccountOrGroup $admin -ExternalMailRules $mailRules -SensitiveHost $SensitiveHost
    $mitre = Get-MitreTechniques -MalwareExecuted $malware -C2OrExternalIp $c2 -AdminAccountOrGroup $admin -ExternalMailRules $mailRules -RdpLogons $rdp -FailurePeaks $failures
    return @{ EBIOS = $score; MITRE = $mitre }
}

export-modulemember -Function Get-EBIOSScore, Get-MitreTechniques, Invoke-IncidentKitEBIOSFromFindings

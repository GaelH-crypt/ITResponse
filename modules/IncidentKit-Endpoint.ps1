<#
.SYNOPSIS
    IncidentKit - Collecte endpoint (processus, services, tâches, netstat, autoruns, fichiers récents).
.DESCRIPTION
    Optionnel : -TargetHost. Mode local ou distant (WinRM). Export dans Endpoint\.
#>
[CmdletBinding()]
param()

function Get-EndpointDataLocal {
    param(
        [scriptblock]$Log,
        [string]$OutDir,
        [string[]]$SuspiciousNames = @('PDFClick.exe', 'update.exe'),
        [bool]$CollectHashes
    )
    $results = @{}
    try {
        $results.Processes = Get-Process | Select-Object Id, ProcessName, Path, StartTime | ConvertTo-Json -Depth 2
        Set-Content -Path (Join-Path $OutDir 'processes.json') -Value $results.Processes -Encoding UTF8
    } catch {
        & $Log "Processes: $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
    try {
        Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv -Path (Join-Path $OutDir 'services.csv') -NoTypeInformation -Encoding UTF8
    } catch {
        & $Log "Services: $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
    try {
        Get-ScheduledTask | Select-Object TaskName, TaskPath, State | Export-Csv -Path (Join-Path $OutDir 'scheduled_tasks.csv') -NoTypeInformation -Encoding UTF8
    } catch {
        & $Log "ScheduledTask: $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
    try {
        netstat -ano | Out-File -FilePath (Join-Path $OutDir 'netstat.txt') -Encoding utf8
    } catch {
        & $Log "Netstat: $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
    }
    $runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
    $autoruns = [System.Collections.ArrayList]::new()
    foreach ($key in $runKeys) {
        try {
            Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider' } | ForEach-Object {
                    [void]$autoruns.Add([PSCustomObject]@{ RegistryPath = $key; Name = $_.Name; Value = $_.Value })
                }
            }
        } catch {
            & $Log "Registry $key : $_"
            & $Log "Exception: $($_.Exception.GetType().FullName)"
            if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        }
    }
    $autoruns | Export-Csv -Path (Join-Path $OutDir 'autoruns.csv') -NoTypeInformation -Encoding UTF8

    $downloads = [Environment]::GetFolderPath('UserProfile') + '\Downloads'
    $appData = [Environment]::GetFolderPath('UserProfile') + '\AppData'
    $recent = [System.Collections.ArrayList]::new()
    foreach ($dir in @($downloads, (Join-Path $appData 'Roaming'), (Join-Path $appData 'Local'))) {
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 100 | ForEach-Object {
                $h = $null
                if ($CollectHashes) {
                    try { $h = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } catch { }
                }
                [void]$recent.Add([PSCustomObject]@{ FullName = $_.FullName; LastWriteTime = $_.LastWriteTime; Length = $_.Length; SHA256 = $h })
            }
        }
    }
    $recent | Export-Csv -Path (Join-Path $OutDir 'recent_files.csv') -NoTypeInformation -Encoding UTF8

    $suspects = [System.Collections.ArrayList]::new()
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        foreach ($sn in $SuspiciousNames) {
            if ($p.ProcessName -like "*$sn*" -or $p.Path -like "*$sn*") {
                $h = $null
                if ($p.Path -and (Test-Path $p.Path) -and $CollectHashes) {
                    try { $h = (Get-FileHash -LiteralPath $p.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } catch { }
                }
                [void]$suspects.Add([PSCustomObject]@{ ProcessName = $p.ProcessName; Path = $p.Path; Id = $p.Id; SHA256 = $h })
                break
            }
        }
    }
    $suspects | Export-Csv -Path (Join-Path $OutDir 'suspicious_processes.csv') -NoTypeInformation -Encoding UTF8
    return $true
}

function Invoke-IncidentKitEndpointCollect {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config,
        [string]$TargetHost,
        [string]$OutputDir,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log,
        [switch]$WhatIf
    )
    $epDir = Join-Path $OutputDir 'Endpoint'
    if (-not $TargetHost) {
        & $Log "Pas de -TargetHost ; collecte Endpoint ignorée."
        if (-not $WhatIf) {
            if (-not (Test-Path $epDir)) { New-Item -ItemType Directory -Path $epDir -Force | Out-Null }
            Set-Content -Path (Join-Path $epDir 'skipped.txt') -Value "Collecte Endpoint non demandée (pas de -TargetHost)." -Encoding UTF8
        }
        return @{ Success = $true; Skipped = $true; OutputDir = $epDir }
    }

    if (-not $WhatIf) {
        if (-not (Test-Path $epDir)) { New-Item -ItemType Directory -Path $epDir -Force | Out-Null }
    }

    $suspiciousNames = $Config.endpoint.suspiciousNames
    if (-not $suspiciousNames) { $suspiciousNames = @('PDFClick.exe', 'update.exe') }
    $collectHashes = $Config.endpoint.collectFileHashes

    $isLocal = ($TargetHost -eq $env:COMPUTERNAME -or $TargetHost -eq 'localhost' -or $TargetHost -eq '.')
    if ($isLocal -or $WhatIf) {
        if ($WhatIf) {
            & $Log "WhatIf: collecte Endpoint locale (processus, services, tâches, netstat, autoruns, fichiers récents)."
            return @{ Success = $true; WhatIf = $true; OutputDir = $epDir }
        }
        try {
            Get-EndpointDataLocal -Log $Log -OutDir $epDir -SuspiciousNames $suspiciousNames -CollectHashes $collectHashes
            return @{ Success = $true; OutputDir = $epDir; Local = $true }
        } catch {
            & $Log "Endpoint local : $_"
            & $Log "Exception: $($_.Exception.GetType().FullName)"
            if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
            Set-Content -Path (Join-Path $epDir 'error.txt') -Value $_.Exception.Message -Encoding UTF8
            return @{ Success = $false; Error = $_.Exception.Message; OutputDir = $epDir }
        }
    }

    try {
        $sb = {
            param($SuspiciousNames)
            $runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
            $autoruns = @(); foreach ($k in $runKeys) { try { Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $autoruns += [PSCustomObject]@{ Path = $k; Name = $_.Name; Value = $_.Value } } } } catch {} }
            $procs = Get-Process | Select-Object Id, ProcessName, Path, StartTime
            $svcs = Get-Service | Select-Object Name, DisplayName, Status, StartType
            $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State
            $netstat = netstat -ano
            @{ Processes = $procs; Services = $svcs; ScheduledTasks = $tasks; Autoruns = $autoruns; Netstat = $netstat }
        }
        $icmParams = @{ ComputerName = $TargetHost; ScriptBlock = $sb; ArgumentList = @(,$suspiciousNames) }
        if ($Credential) { $icmParams.Credential = $Credential }
        $remoteData = Invoke-Command @icmParams -ErrorAction Stop
        if ($remoteData -is [System.Collections.ArrayList]) { $remoteData = $remoteData[0] }
        $remoteData.Processes | Export-Csv -Path (Join-Path $epDir 'processes.csv') -NoTypeInformation -Encoding UTF8
        $remoteData.Services | Export-Csv -Path (Join-Path $epDir 'services.csv') -NoTypeInformation -Encoding UTF8
        $remoteData.ScheduledTasks | Export-Csv -Path (Join-Path $epDir 'scheduled_tasks.csv') -NoTypeInformation -Encoding UTF8
        $remoteData.Autoruns | Export-Csv -Path (Join-Path $epDir 'autoruns.csv') -NoTypeInformation -Encoding UTF8
        $remoteData.Netstat | Out-File -FilePath (Join-Path $epDir 'netstat.txt') -Encoding utf8
        return @{ Success = $true; OutputDir = $epDir; Remote = $true }
    } catch {
        & $Log "Endpoint distant $TargetHost : $_ (WinRM peut être indisponible)."
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        if (-not $WhatIf) { Set-Content -Path (Join-Path $epDir 'error.txt') -Value $_.Exception.Message -Encoding UTF8 }
        return @{ Success = $false; Error = $_.Exception.Message; OutputDir = $epDir }
    }
}

export-modulemember -Function Invoke-IncidentKitEndpointCollect, Get-EndpointDataLocal

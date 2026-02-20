<#
.SYNOPSIS
    Collecte des indicateurs de compromission (IOC) sur l'endpoint : autoruns, tâches, services, réseau, fichiers exécutables et empreintes SHA256.
.DESCRIPTION
    Collecte en lecture seule (aucune suppression ni désactivation).
    Sortie : output\Endpoint\ioc_manifest.json
.NOTES
    Ne rien supprimer. Ne rien désactiver.
#>

[CmdletBinding(SupportsShouldProcess)]
param()

function Get-Sha256Hash {
    param([string]$FilePath)
    if (-not $FilePath -or -not (Test-Path -LiteralPath $FilePath -ErrorAction SilentlyContinue)) { return $null }
    try {
        return (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

function Collect-EndpointIOC {
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path (Get-Location) 'output\Endpoint\ioc_manifest.json')
    )

    $manifest = @{
        Processes          = @()
        Autoruns           = @()
        ScheduledTasks     = @()
        NetworkConnections = @()
        FileHashes         = @()
    }

    $outDir = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    # --- Processus en cours ---
    try {
        $manifest.Processes = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                Id          = $_.Id
                ProcessName = $_.ProcessName
                Path        = $_.Path
                StartTime   = if ($_.StartTime) { $_.StartTime.ToString('o') } else { $null }
            }
        }
    } catch {
        Write-Warning "Processus : $($_.Exception.Message)"
    }

    # --- Run / RunOnce (registre) ---
    $runPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($regPath in $runPaths) {
        try {
            $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $props.PSObject.Properties | Where-Object {
                $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider'
            } | ForEach-Object {
                $manifest.Autoruns += @{
                    RegistryPath = $regPath
                    Name         = $_.Name
                    Value        = $_.Value
                }
            }
        } catch {
            Write-Warning "Registre $regPath : $($_.Exception.Message)"
        }
    }

    # --- Tâches planifiées ---
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
            $manifest.ScheduledTasks += @{
                TaskName   = $t.TaskName
                TaskPath   = $t.TaskPath
                State      = $t.State.ToString()
                Author     = $info.Author
                Description = $info.Description
                NextRun    = if ($info.NextRunTime) { $info.NextRunTime.ToString('o') } else { $null }
            }
        }
    } catch {
        Write-Warning "Tâches planifiées : $($_.Exception.Message)"
    }

    # --- Services non Microsoft (lecture seule, aucun changement) ---
    try {
        $svcList = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
        foreach ($svc in $svcList) {
            $path = $svc.PathName
            if (-not $path) { continue }
            if ($path -match '\\Windows\\' -or $path -match '\\Microsoft\\' -or $path -match '\\Program Files\\Windows') {
                continue
            }
            $manifest.Autoruns += @{
                Type        = 'Service'
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                State       = $svc.State
                StartMode   = $svc.StartMode
                Value       = $path
            }
        }
    } catch {
        Write-Warning "Services : $($_.Exception.Message)"
    }

    # --- Connexions réseau actives ---
    try {
        $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Established' }
        $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        foreach ($c in $tcp) {
            $manifest.NetworkConnections += @{
                Protocol   = 'TCP'
                LocalAddress = $c.LocalAddress
                LocalPort  = $c.LocalPort
                RemoteAddress = $c.RemoteAddress
                RemotePort = $c.RemotePort
                State      = $c.State
                OwningProcess = $c.OwningProcess
            }
        }
        foreach ($c in $udp) {
            $manifest.NetworkConnections += @{
                Protocol      = 'UDP'
                LocalAddress  = $c.LocalAddress
                LocalPort     = $c.LocalPort
                OwningProcess = $c.OwningProcess
            }
        }
    } catch {
        Write-Warning "Connexions réseau : $($_.Exception.Message)"
    }

    # --- Fichiers exécutables dans AppData / Downloads + SHA256 ---
    $extensions = @('*.exe', '*.dll', '*.scr', '*.bat', '*.cmd', '*.ps1', '*.vbs', '*.js')
    $searchDirs = @(
        [Environment]::GetFolderPath('UserProfile') + '\AppData\Roaming',
        [Environment]::GetFolderPath('UserProfile') + '\AppData\Local',
        [Environment]::GetFolderPath('UserProfile') + '\Downloads'
    )
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($ext in $extensions) {
            try {
                Get-ChildItem -Path $dir -Recurse -Filter $ext -File -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($seenPaths.Add($_.FullName)) {
                        $hash = Get-Sha256Hash -FilePath $_.FullName
                        $manifest.FileHashes += @{
                            FullName     = $_.FullName
                            Length       = $_.Length
                            LastWriteTime = $_.LastWriteTime.ToString('o')
                            SHA256       = $hash
                        }
                    }
                }
            } catch {
                Write-Warning "Fichiers $dir $ext : $($_.Exception.Message)"
            }
        }
    }

    # --- Écriture du manifest (structure : 5 clés, aucun objet supprimé/désactivé) ---
    $output = @{
        Processes          = $manifest.Processes
        Autoruns           = $manifest.Autoruns   # Run/RunOnce + services non Microsoft (Type = 'Service')
        ScheduledTasks     = $manifest.ScheduledTasks
        NetworkConnections = $manifest.NetworkConnections
        FileHashes         = $manifest.FileHashes
    }
    if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Write ioc_manifest.json')) { return $output }
    $output | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Verbose "ioc_manifest.json enregistré : $OutputPath"
    return $output
}
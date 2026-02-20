<#
.SYNOPSIS
    Utilitaires partagés IncidentKit (dossiers, hash, IP, journalisation).
#>

function Ensure-Directory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    return $true
}

function Test-IPShouldIgnore {
    <#
    .SYNOPSIS
        Indique si une IP doit être ignorée (RFC1918, loopback, link-local, CGNAT).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Ip
    )

    if (-not $Ip -or $Ip -eq '-' -or $Ip -match '^::') { return $true }
    if ($Ip -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { return $true }  # IPv6 ou invalide : on ignore
    $a = [int]$matches[1]
    $b = [int]$matches[2]

    if ($a -eq 10) { return $true }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $true }
    if ($a -eq 192 -and $b -eq 168) { return $true }
    if ($a -eq 127) { return $true }
    if ($a -eq 169 -and $b -eq 254) { return $true }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $true }
    return $false
}

function Get-Sha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if (-not (Test-Path -LiteralPath $FilePath -ErrorAction SilentlyContinue)) { return $null }
    try {
        return (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

function Write-IncidentLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [scriptblock]$Log,
        [string]$LogFilePath,
        [switch]$WhatIf
    )

    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"

    if ($Log) {
        & $Log $line
    } else {
        Write-Verbose $line
    }

    if (-not $WhatIf -and $LogFilePath) {
        $logDir = Split-Path $LogFilePath -Parent
        if ($logDir -and (Ensure-Directory -Path $logDir)) {
            Add-Content -Path $LogFilePath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    }

    return $line
}

<#
.SYNOPSIS
    IncidentKit - Gestion et validation de la configuration.
.DESCRIPTION
    Charge, valide et expose la configuration depuis config.json.
#>
[CmdletBinding()]
param()

function Get-IncidentKitConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Fichier de configuration introuvable : $ConfigPath"
    }
    try {
        $json = Get-Content -Path $ConfigPath -Raw -Encoding UTF8
        $config = $json | ConvertFrom-Json
    } catch {
        throw "Configuration invalide (JSON) : $_"
    }
    # Validation minimale
    if (-not $config.ad -or -not $config.ad.domainFqdn) {
        throw "Configuration AD manquante ou incomplète (ad.domainFqdn requis)."
    }
    if (-not $config.output -or -not $config.output.basePath) {
        throw "Configuration output manquante (output.basePath requis)."
    }
    return $config
}

function Test-IncidentKitConfigCoherence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config
    )
    $issues = @()
    if (-not $Config.ad.dcList -or $Config.ad.dcList.Count -eq 0) {
        $issues += "ad.dcList doit contenir au moins un DC."
    }
    if ($Config.ad.timeWindowDays -le 0) {
        $issues += "ad.timeWindowDays doit être > 0."
    }
    if ($Config.exchange -and $Config.exchange.checks) {
        if (-not $Config.exchange.serverFqdn -or -not $Config.exchange.psUri) {
            $issues += "exchange.serverFqdn et exchange.psUri requis si exchange activé."
        }
    }
    return $issues
}

function Get-IncidentKitPreferredDc {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config
    )
    if ($Config.ad.preferredDc) {
        return $Config.ad.preferredDc
    }
    if ($Config.ad.dcList -and $Config.ad.dcList.Count -gt 0) {
        return $Config.ad.dcList[0]
    }
    return $null
}

export-modulemember -Function Get-IncidentKitConfig, Test-IncidentKitConfigCoherence, Get-IncidentKitPreferredDc

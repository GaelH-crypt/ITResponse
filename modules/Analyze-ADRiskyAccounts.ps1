<#
.SYNOPSIS
    Analyse Active Directory et produit un rapport des comptes sensibles (lecture seule).
.DESCRIPTION
    Détecte : membres Domain Admins / Enterprise Admins / Administrators,
    PasswordNeverExpires, comptes actifs inactifs > 90 jours, SPN (Kerberoasting),
    délégation (TrustedForDelegation). Génère output\AD\risky_accounts.json.
.NOTES
    Lecture seule. Aucune modification AD. Utiliser -Credential si exécution hors domaine.
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$script:StaleDaysThreshold = 90
$script:PrivilegedGroupNames = @('Domain Admins', 'Enterprise Admins', 'Administrators')

function Get-ADRiskyAccounts {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Server = $null,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$OutputPath = '',
        [int]$StaleDays = $script:StaleDaysThreshold
    )

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Module ActiveDirectory requis. Installez les outils RSAT (Active Directory Module)."
        return
    }
    Import-Module -Name ActiveDirectory -ErrorAction Stop

    $commonParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $commonParams.Server = $Server }
    if ($Credential) { $commonParams.Credential = $Credential }

    $report = @{
        PrivilegedAccounts = [System.Collections.ArrayList]::new()
        StaleAccounts       = [System.Collections.ArrayList]::new()
        ServiceAccounts    = [System.Collections.ArrayList]::new()
        DelegatedAccounts  = [System.Collections.ArrayList]::new()
    }

    try {
        $domain = Get-ADDomain @commonParams
        $domainDn = $domain.DistinguishedName

        # --- 1) Membres des groupes sensibles ---
        $privilegedBySid = @{}
        foreach ($groupName in $script:PrivilegedGroupNames) {
            try {
                $group = $null
                if ($groupName -eq 'Administrators') {
                    $builtin = "CN=Builtin,$domainDn"
                    $group = Get-ADGroup -Filter "Name -eq 'Administrators'" -SearchBase $builtin @commonParams
                } else {
                    $group = Get-ADGroup -Filter "Name -eq '$groupName'" @commonParams
                }
                if (-not $group) { continue }

                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue @commonParams
                foreach ($m in $members) {
                    $sid = $m.SID.Value
                    if (-not $privilegedBySid[$sid]) {
                        $privilegedBySid[$sid] = [PSCustomObject]@{
                            SamAccountName    = $m.SamAccountName
                            DistinguishedName = $m.DistinguishedName
                            SID               = $sid
                            Group             = $groupName
                        }
                    } else {
                        $privilegedBySid[$sid].Group = "$($privilegedBySid[$sid].Group); $groupName"
                    }
                }
            } catch {
                Write-Warning "Groupe '$groupName' : $_"
            }
        }
        $report.PrivilegedAccounts = [System.Collections.ArrayList]::new([object[]]$privilegedBySid.Values)

        # --- 2) Comptes à risque : PasswordNeverExpires et/ou activés mais inactifs > StaleDays ---
        $staleBySid = @{}
        $pwdNeverExpires = Get-ADUser -Filter "PasswordNeverExpires -eq 'True'" -Properties PasswordNeverExpires, LastLogonDate, Enabled @commonParams
        foreach ($u in $pwdNeverExpires) {
            $sid = $u.SID.Value
            $staleBySid[$sid] = [PSCustomObject]@{
                SamAccountName       = $u.SamAccountName
                DistinguishedName    = $u.DistinguishedName
                SID                  = $sid
                LastLogonDate        = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('o') } else { $null }
                DaysInactive         = $null
                PasswordNeverExpires = $true
            }
        }

        $cutoff = (Get-Date).AddDays(-$StaleDays)
        $enabledUsers = Get-ADUser -Filter "Enabled -eq 'True'" -Properties LastLogonDate, PasswordNeverExpires @commonParams
        foreach ($u in $enabledUsers) {
            $lastLogon = $u.LastLogonDate
            $isInactive = ($null -eq $lastLogon) -or ($lastLogon -lt $cutoff)
            if (-not $isInactive) { continue }

            $sid = $u.SID.Value
            $daysInactive = if ($lastLogon) { [math]::Max(0, ((Get-Date) - $lastLogon).Days) } else { $null }
            if ($staleBySid[$sid]) {
                $staleBySid[$sid].DaysInactive = $daysInactive
                $staleBySid[$sid].LastLogonDate = if ($lastLogon) { $lastLogon.ToString('o') } else { $null }
            } else {
                $staleBySid[$sid] = [PSCustomObject]@{
                    SamAccountName       = $u.SamAccountName
                    DistinguishedName    = $u.DistinguishedName
                    SID                  = $sid
                    LastLogonDate        = if ($lastLogon) { $lastLogon.ToString('o') } else { $null }
                    DaysInactive         = $daysInactive
                    PasswordNeverExpires = [bool]$u.PasswordNeverExpires
                }
            }
        }
        $report.StaleAccounts = [System.Collections.ArrayList]::new([object[]]$staleBySid.Values)

        # --- 3) SPN configurés (Kerberoasting) ---
        $withSpn = Get-ADUser -Filter "ServicePrincipalName -like '*' -and Enabled -eq 'True'" -Properties ServicePrincipalName @commonParams
        foreach ($u in $withSpn) {
            [void]$report.ServiceAccounts.Add([PSCustomObject]@{
                SamAccountName     = $u.SamAccountName
                DistinguishedName  = $u.DistinguishedName
                SID                = $u.SID.Value
                ServicePrincipalName = @($u.ServicePrincipalName)
            })
        }

        # --- 4) Délégation (TrustedForDelegation) ---
        $delegated = Get-ADUser -Filter "TrustedForDelegation -eq 'True'" -Properties TrustedForDelegation @commonParams
        foreach ($u in $delegated) {
            [void]$report.DelegatedAccounts.Add([PSCustomObject]@{
                SamAccountName    = $u.SamAccountName
                DistinguishedName = $u.DistinguishedName
                SID               = $u.SID.Value
                TrustedForDelegation = $true
            })
        }

        # --- Sortie JSON ---
        $jsonPath = if ($OutputPath) {
            $OutputPath
        } else {
            $rootDir = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { (Get-Location).Path }
            Join-Path $rootDir 'output\AD\risky_accounts.json'
        }
        $outDir = [System.IO.Path]::GetDirectoryName($jsonPath)
        if (-not (Test-Path -LiteralPath $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }

        $serializable = @{
            PrivilegedAccounts = @($report.PrivilegedAccounts)
            StaleAccounts      = @($report.StaleAccounts)
            ServiceAccounts    = @($report.ServiceAccounts)
            DelegatedAccounts  = @($report.DelegatedAccounts)
        }
        $json = $serializable | ConvertTo-Json -Depth 5
        if (-not $PSCmdlet.ShouldProcess($jsonPath, 'Write risky_accounts.json')) {
            return $report
        }
        Set-Content -Path $jsonPath -Value $json -Encoding UTF8

        Write-Verbose "Rapport écrit : $jsonPath"
        return $report
    } catch {
        Write-Error "Get-ADRiskyAccounts : $_"
        throw
    }
}

if ($ExecutionContext.SessionState.Module) {
    Export-ModuleMember -Function Get-ADRiskyAccounts
}

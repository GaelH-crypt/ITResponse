<#
.SYNOPSIS
    IncidentKit - Collecte Exchange (règles boîte, transfert) et détection de règles suspectes.
.DESCRIPTION
    Connexion à Exchange Management Shell, export InboxRule + Forwarding, génération exchange_findings.json.
#>
[CmdletBinding()]
param()

$script:ExternalDomains = @('gmail.com', 'google.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com', 'proton.me', 'protonmail.com', 'free.fr', 'orange.fr', 'laposte.net', 'wanadoo.fr', 'sfr.fr', 'bbox.fr')

function Convert-ToFlatString {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Array]) {
        return (($Value | ForEach-Object { "$($_)" }) -join '; ').Trim()
    }
    return "$Value".Trim()
}

function Test-SmtpAddressExternal {
    param([string]$Address)
    if (-not $Address) { return $false }
    $addr = $Address.Trim().ToLowerInvariant()
    if ($addr.StartsWith('smtp:')) { $addr = $addr.Substring(5).Trim() }
    if ($addr.StartsWith('ex:/') -or $addr -match '^/o=') { return $false }
    foreach ($d in $script:ExternalDomains) {
        if ($addr -like "*@$d" -or $addr -eq $d) { return $true }
    }
    if ($addr -match '@[a-z0-9\-\.]+\.[a-z]{2,}$' -and $addr -notmatch '\.local$|\.lan$|\.internal$') {
        return $true
    }
    return $false
}

function Get-ExchangeSession {
    [CmdletBinding()]
    param(
        [string]$PsUri,
        [string]$Auth = 'Kerberos',
        [bool]$UseSSL = $false,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log
    )
    $opt = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $params = @{
        ConfigurationName = 'Microsoft.Exchange'
        ConnectionUri     = $PsUri
        SessionOption     = $opt
        ErrorAction       = 'Stop'
    }
    if ($UseSSL) {
        $params.ConnectionUri = $PsUri -replace '^http://', 'https://'
    }
    if ($Auth -eq 'Negotiate' -or $Auth -eq 'NTLM') {
        $params.Authentication = $Auth
    }
    if ($Credential) {
        $params.Credential = $Credential
    }
    try {
        $session = New-PSSession @params
        & $Log "Session Exchange établie : $PsUri"
        return $session
    } catch {
        & $Log "Échec session Exchange : $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        throw
    }
}

function Test-ExternalSmartHost {
    param([string]$Host)
    if (-not $Host) { return $false }
    $h = $Host.Trim().ToLowerInvariant()
    if (-not $h) { return $false }
    if ($h -eq 'localhost') { return $false }
    if ($h -match '\.local$|\.lan$|\.internal$') { return $false }
    if ($h -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)') { return $false }
    return $true
}

function Invoke-IncidentKitExchangeCollect {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config,
        [string]$OutputDir,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log,
        [switch]$WhatIf
    )
    $exDir = Join-Path $OutputDir 'Exchange'
    if (-not $WhatIf) {
        if (-not (Test-Path $exDir)) { New-Item -ItemType Directory -Path $exDir -Force | Out-Null }
    }

    $rulesPath = Join-Path $exDir 'exchange_rules.csv'
    $forwardPath = Join-Path $exDir 'exchange_forwarding.csv'
    $transportRulesPath = Join-Path $exDir 'exchange_transport_rules.csv'
    $connectorsPath = Join-Path $exDir 'exchange_connectors.csv'
    $findingsPath = Join-Path $exDir 'exchange_findings.json'
    $findingsCompatPath = Join-Path $exDir 'findings.json'

    if (-not $Config.exchange -or -not $Config.exchange.psUri) {
        & $Log "Exchange non configuré ; collecte Exchange ignorée."
        if (-not $WhatIf) {
            @() | Export-Csv -Path $rulesPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $forwardPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $transportRulesPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $connectorsPath -NoTypeInformation -Encoding UTF8
            @{ error = 'Exchange non configuré'; suspiciousRules = @(); externalForwarding = @(); suspiciousTransportRules = @(); suspiciousConnectors = @() } | ConvertTo-Json | Set-Content -Path $findingsPath -Encoding UTF8
            Copy-Item -Path $findingsPath -Destination $findingsCompatPath -Force
        }
        return @{ Success = $false; Error = 'Exchange non configuré'; RulesPath = $rulesPath; ForwardPath = $forwardPath; TransportRulesPath = $transportRulesPath; ConnectorsPath = $connectorsPath; FindingsPath = $findingsPath; FindingsCompatPath = $findingsCompatPath }
    }

    $session = $null
    try {
        if ($WhatIf) {
            & $Log "WhatIf: connexion Exchange à $($Config.exchange.psUri) puis collecte règles/forwarding."
            return @{ Success = $true; WhatIf = $true; RulesPath = $rulesPath; ForwardPath = $forwardPath; TransportRulesPath = $transportRulesPath; ConnectorsPath = $connectorsPath; FindingsPath = $findingsPath; FindingsCompatPath = $findingsCompatPath }
        }

        $session = Get-ExchangeSession -PsUri $Config.exchange.psUri -Auth $Config.exchange.auth -UseSSL $Config.exchange.useSSL -Credential $Credential -Log $Log
        Import-PSSession -Session $session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null

        $allRules = @()
        $allForwarding = @()
        $suspiciousRules = [System.Collections.ArrayList]::new()
        $externalForwarding = [System.Collections.ArrayList]::new()
        $allTransportRules = @()
        $allConnectors = @()
        $suspiciousTransportRules = [System.Collections.ArrayList]::new()
        $suspiciousConnectors = [System.Collections.ArrayList]::new()

        if ($Config.exchange.checks.inboxRules) {
            try {
                $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
                foreach ($mb in $mailboxes) {
                    try {
                        $rules = Get-InboxRule -Mailbox $mb.Identity -ErrorAction SilentlyContinue
                        foreach ($r in $rules) {
                            $o = [PSCustomObject]@{
                                MailboxOwnerID = $mb.Identity.ToString()
                                Name           = $r.Name
                                ForwardTo      = ($r.ForwardTo | Out-String).Trim()
                                RedirectTo     = ($r.RedirectTo | Out-String).Trim()
                                DeleteMessage  = $r.DeleteMessage
                            }
                            $allRules += $o
                            $ft = $o.ForwardTo; $rt = $o.RedirectTo
                            $externalFwd = Test-SmtpAddressExternal -Address $ft
                            $externalRedir = Test-SmtpAddressExternal -Address $rt
                            if ($externalFwd -or $externalRedir -or $r.DeleteMessage -eq $true) {
                                [void]$suspiciousRules.Add([PSCustomObject]@{
                                    mailbox   = $mb.Identity.ToString()
                                    ruleName  = $r.Name
                                    forwardTo = $ft
                                    redirectTo = $rt
                                    deleteMessage = $r.DeleteMessage
                                    reason    = @(
                                        $(if ($externalFwd) { 'ForwardTo externe' }),
                                        $(if ($externalRedir) { 'RedirectTo externe' }),
                                        $(if ($r.DeleteMessage) { 'DeleteMessage=true' })
                                    ) | Where-Object { $_ } -join '; '
                                })
                            }
                        }
                    } catch {
                        & $Log "InboxRule pour $($mb.Identity) : $_"
                        & $Log "Exception: $($_.Exception.GetType().FullName)"
                        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
                    }
                }
            } catch {
                & $Log "Get-Mailbox/Get-InboxRule : $_"
                & $Log "Exception: $($_.Exception.GetType().FullName)"
                if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
            }
        }

        if ($Config.exchange.checks.forwarding) {
            try {
                $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
                foreach ($mb in $mailboxes) {
                    $fwd = $mb.ForwardingSmtpAddress
                    $deliverAndForward = $mb.DeliverToMailboxAndForward
                    $allForwarding += [PSCustomObject]@{
                        Identity                  = $mb.Identity.ToString()
                        ForwardingSmtpAddress     = $fwd
                        DeliverToMailboxAndForward = $deliverAndForward
                    }
                    if ($fwd -and (Test-SmtpAddressExternal -Address $fwd)) {
                        [void]$externalForwarding.Add([PSCustomObject]@{
                            mailbox   = $mb.Identity.ToString()
                            address   = $fwd
                            deliverToMailboxAndForward = $deliverAndForward
                        })
                    }
                }
            } catch {
                & $Log "Get-Mailbox (forwarding) : $_"
                & $Log "Exception: $($_.Exception.GetType().FullName)"
                if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
            }
        }

        if ($Config.exchange.checks.transportRules) {
            try {
                $transportRules = Get-TransportRule -ErrorAction Stop
                foreach ($tr in $transportRules) {
                    $bccTo = Convert-ToFlatString -Value $tr.BccTo
                    $redirectTo = Convert-ToFlatString -Value $tr.RedirectMessageTo
                    $copyTo = Convert-ToFlatString -Value $tr.CopyTo
                    $row = [PSCustomObject]@{
                        Name              = $tr.Name
                        Priority          = $tr.Priority
                        State             = $tr.State
                        Mode              = $tr.Mode
                        BccTo             = $bccTo
                        RedirectMessageTo = $redirectTo
                        CopyTo            = $copyTo
                    }
                    $allTransportRules += $row

                    if ($bccTo -or $redirectTo -or $copyTo) {
                        [void]$suspiciousTransportRules.Add([PSCustomObject]@{
                            name     = $tr.Name
                            bccTo    = $bccTo
                            redirect = $redirectTo
                            copyTo   = $copyTo
                            reason   = 'Transport rule with BccTo/RedirectMessageTo/CopyTo'
                        })
                    }
                }
            } catch {
                & $Log "Get-TransportRule : $_"
                & $Log "Exception: $($_.Exception.GetType().FullName)"
                if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
            }
        }

        if ($Config.exchange.checks.sendConnectors) {
            try {
                $sendConnectors = Get-SendConnector -ErrorAction Stop
                foreach ($c in $sendConnectors) {
                    $smartHosts = Convert-ToFlatString -Value $c.SmartHosts
                    $addrSpaces = Convert-ToFlatString -Value $c.AddressSpaces
                    $row = [PSCustomObject]@{
                        Name              = $c.Name
                        Enabled           = $c.Enabled
                        AddressSpaces     = $addrSpaces
                        SmartHosts        = $smartHosts
                        SmartHostAuth     = $c.SmartHostAuthMechanism
                        DNSRoutingEnabled = $c.DNSRoutingEnabled
                        IsScopedConnector = $c.IsScopedConnector
                    }
                    $allConnectors += $row

                    $hasExternalSmartHost = $false
                    if ($c.SmartHosts) {
                        foreach ($sh in $c.SmartHosts) {
                            if (Test-ExternalSmartHost -Host "$sh") {
                                $hasExternalSmartHost = $true
                                break
                            }
                        }
                    }
                    if ($hasExternalSmartHost) {
                        [void]$suspiciousConnectors.Add([PSCustomObject]@{
                            name          = $c.Name
                            smartHosts    = $smartHosts
                            addressSpaces = $addrSpaces
                            reason        = 'Send connector with external smart host'
                        })
                    }
                }
            } catch {
                & $Log "Get-SendConnector : $_"
                & $Log "Exception: $($_.Exception.GetType().FullName)"
                if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
            }
        }

        $allRules | Export-Csv -Path $rulesPath -NoTypeInformation -Encoding UTF8
        $allForwarding | Export-Csv -Path $forwardPath -NoTypeInformation -Encoding UTF8
        $allTransportRules | Export-Csv -Path $transportRulesPath -NoTypeInformation -Encoding UTF8
        $allConnectors | Export-Csv -Path $connectorsPath -NoTypeInformation -Encoding UTF8
        $findingsObj = @{
            suspiciousRules    = @($suspiciousRules)
            externalForwarding = @($externalForwarding)
            suspiciousTransportRules = @($suspiciousTransportRules)
            suspiciousConnectors = @($suspiciousConnectors)
        }
        $findingsObj | ConvertTo-Json -Depth 4 | Set-Content -Path $findingsPath -Encoding UTF8
        Copy-Item -Path $findingsPath -Destination $findingsCompatPath -Force
        return @{ Success = $true; RulesPath = $rulesPath; ForwardPath = $forwardPath; TransportRulesPath = $transportRulesPath; ConnectorsPath = $connectorsPath; FindingsPath = $findingsPath; FindingsCompatPath = $findingsCompatPath }
    } catch {
        & $Log "Exchange : $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        if (-not $WhatIf) {
            if (-not (Test-Path $exDir)) { New-Item -ItemType Directory -Path $exDir -Force | Out-Null }
            @() | Export-Csv -Path $rulesPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $forwardPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $transportRulesPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $connectorsPath -NoTypeInformation -Encoding UTF8
            @{ error = $_.Exception.Message; suspiciousRules = @(); externalForwarding = @(); suspiciousTransportRules = @(); suspiciousConnectors = @() } | ConvertTo-Json | Set-Content -Path $findingsPath -Encoding UTF8
            Copy-Item -Path $findingsPath -Destination $findingsCompatPath -Force
        }
        return @{ Success = $false; Error = $_.Exception.Message; RulesPath = $rulesPath; ForwardPath = $forwardPath; TransportRulesPath = $transportRulesPath; ConnectorsPath = $connectorsPath; FindingsPath = $findingsPath; FindingsCompatPath = $findingsCompatPath }
    } finally {
        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

export-modulemember -Function Invoke-IncidentKitExchangeCollect, Test-SmtpAddressExternal, Get-ExchangeSession

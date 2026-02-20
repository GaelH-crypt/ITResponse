<#
.SYNOPSIS
    IncidentKit - Collecte Exchange (règles boîte, transfert) et détection de règles suspectes.
.DESCRIPTION
    Connexion à Exchange Management Shell, export InboxRule + Forwarding, génération exchange_findings.json.
#>
[CmdletBinding()]
param()

$script:ExternalDomains = @('gmail.com', 'google.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com', 'proton.me', 'protonmail.com', 'free.fr', 'orange.fr', 'laposte.net', 'wanadoo.fr', 'sfr.fr', 'bbox.fr')

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

function Get-MailboxDelegationUnexpectedReason {
    [CmdletBinding()]
    param(
        [string]$MailboxIdentity,
        [string]$DelegateIdentity,
        [string[]]$ExpectedDelegates
    )
    if (-not $DelegateIdentity) { return $null }
    $delegate = $DelegateIdentity.Trim().ToLowerInvariant()
    $mailbox = if ($MailboxIdentity) { $MailboxIdentity.Trim().ToLowerInvariant() } else { '' }

    if (-not $delegate -or $delegate -eq 'nt authority\\self') { return $null }
    if ($delegate -match '^s-1-5-') { return $null }
    if ($delegate -match 'nt authority\\|exchange trusted|healthmailbox|discoverysearchmailbox|federatedemail') { return $null }
    if ($mailbox -and $delegate -eq $mailbox) { return $null }

    $expected = @($ExpectedDelegates | Where-Object { $_ } | ForEach-Object { $_.ToString().Trim().ToLowerInvariant() })
    if ($expected.Count -gt 0 -and $expected -contains $delegate) { return $null }

    if ($expected.Count -eq 0) {
        return 'Aucune liste d''autorisations attendues définie'
    }
    return 'Compte absent de exchange.mailboxDelegation.expectedDelegates'
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
    $delegationPath = Join-Path $exDir 'exchange_delegations.csv'
    $findingsPath = Join-Path $exDir 'exchange_findings.json'

    if (-not $Config.exchange -or -not $Config.exchange.psUri) {
        & $Log "Exchange non configuré ; collecte Exchange ignorée."
        if (-not $WhatIf) {
            @() | Export-Csv -Path $rulesPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $forwardPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $delegationPath -NoTypeInformation -Encoding UTF8
            @{ error = 'Exchange non configuré'; suspiciousRules = @(); externalForwarding = @(); suspiciousDelegations = @() } | ConvertTo-Json | Set-Content -Path $findingsPath -Encoding UTF8
        }
        return @{ Success = $false; Error = 'Exchange non configuré'; RulesPath = $rulesPath; ForwardPath = $forwardPath; DelegationPath = $delegationPath; FindingsPath = $findingsPath }
    }

    $session = $null
    try {
        if ($WhatIf) {
            & $Log "WhatIf: connexion Exchange à $($Config.exchange.psUri) puis collecte règles/forwarding."
            return @{ Success = $true; WhatIf = $true; RulesPath = $rulesPath; ForwardPath = $forwardPath; DelegationPath = $delegationPath; FindingsPath = $findingsPath }
        }

        $session = Get-ExchangeSession -PsUri $Config.exchange.psUri -Auth $Config.exchange.auth -UseSSL $Config.exchange.useSSL -Credential $Credential -Log $Log
        Import-PSSession -Session $session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null

        $allRules = @()
        $allForwarding = @()
        $allDelegations = @()
        $suspiciousRules = [System.Collections.ArrayList]::new()
        $externalForwarding = [System.Collections.ArrayList]::new()
        $suspiciousDelegations = [System.Collections.ArrayList]::new()

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

        if ($Config.exchange.checks.mailboxDelegation) {
            try {
                $delegationScope = if ($Config.exchange.mailboxDelegation.scope) { $Config.exchange.mailboxDelegation.scope.ToString().ToLowerInvariant() } else { 'vip' }
                $vipListPath = if ($Config.exchange.mailboxDelegation.vipListPath) { $Config.exchange.mailboxDelegation.vipListPath } else { 'vip_list.txt' }
                if (-not [System.IO.Path]::IsPathRooted($vipListPath)) {
                    $vipListPath = Join-Path $PSScriptRoot "..\\$vipListPath"
                }
                $expectedDelegates = @($Config.exchange.mailboxDelegation.expectedDelegates)
                $targetMailboxes = @()

                if ($delegationScope -eq 'all') {
                    $targetMailboxes = @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
                    & $Log "MailboxDelegation: collecte sur toutes les boîtes ($($targetMailboxes.Count))."
                } else {
                    if (Test-Path -LiteralPath $vipListPath) {
                        $vipEntries = Get-Content -Path $vipListPath -Encoding UTF8 -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^\s*#' }
                        foreach ($entry in $vipEntries) {
                            try {
                                $targetMailboxes += Get-Mailbox -Identity $entry -ErrorAction Stop
                            } catch {
                                & $Log "MailboxDelegation: VIP introuvable '$entry' : $_"
                            }
                        }
                    } else {
                        & $Log "MailboxDelegation: fichier VIP introuvable ($vipListPath)."
                    }
                    & $Log "MailboxDelegation: collecte sur $($targetMailboxes.Count) boîte(s) VIP."
                }

                foreach ($mb in ($targetMailboxes | Sort-Object -Property Identity -Unique)) {
                    $mailboxIdentity = $mb.Identity.ToString()

                    try {
                        $fullPerms = Get-MailboxPermission -Identity $mailboxIdentity -ErrorAction SilentlyContinue | Where-Object {
                            $_.AccessRights -match 'FullAccess' -and
                            -not $_.IsInherited -and
                            $_.User -and
                            $_.User.ToString() -notmatch 'NT AUTHORITY\\SELF|S-1-5-10|S-1-5-21|DiscoverySearchMailbox|HealthMailbox|Exchange Trusted Subsystem'
                        }
                        foreach ($p in $fullPerms) {
                            $delegate = $p.User.ToString()
                            $unexpectedReason = Get-MailboxDelegationUnexpectedReason -MailboxIdentity $mailboxIdentity -DelegateIdentity $delegate -ExpectedDelegates $expectedDelegates
                            $row = [PSCustomObject]@{
                                MailboxIdentity = $mailboxIdentity
                                Delegate        = $delegate
                                DelegationType  = 'FullAccess'
                                Source          = 'Get-MailboxPermission'
                                IsUnexpected    = [bool]($null -ne $unexpectedReason)
                                Reason          = $unexpectedReason
                            }
                            $allDelegations += $row
                            if ($row.IsUnexpected) { [void]$suspiciousDelegations.Add($row) }
                        }
                    } catch {
                        & $Log "MailboxDelegation FullAccess pour $mailboxIdentity : $_"
                    }

                    try {
                        $sendAsRows = @()
                        if (Get-Command -Name 'Get-ADPermission' -ErrorAction SilentlyContinue) {
                            $sendAsPerms = Get-ADPermission -Identity $mailboxIdentity -ErrorAction SilentlyContinue | Where-Object {
                                $_.ExtendedRights -contains 'Send As' -and
                                -not $_.IsInherited -and
                                $_.User -and
                                $_.User.ToString() -notmatch 'NT AUTHORITY\\SELF|S-1-5-10|S-1-5-21|DiscoverySearchMailbox|HealthMailbox|Exchange Trusted Subsystem'
                            }
                            foreach ($p in $sendAsPerms) {
                                $sendAsRows += [PSCustomObject]@{ Delegate = $p.User.ToString(); Source = 'Get-ADPermission' }
                            }
                        } elseif (Get-Command -Name 'Get-RecipientPermission' -ErrorAction SilentlyContinue) {
                            $sendAsPerms = Get-RecipientPermission -Identity $mailboxIdentity -ErrorAction SilentlyContinue | Where-Object {
                                $_.AccessRights -match 'SendAs' -and
                                $_.Trustee -and
                                $_.Trustee.ToString() -notmatch 'NT AUTHORITY\\SELF|S-1-5-10|S-1-5-21|DiscoverySearchMailbox|HealthMailbox|Exchange Trusted Subsystem'
                            }
                            foreach ($p in $sendAsPerms) {
                                $sendAsRows += [PSCustomObject]@{ Delegate = $p.Trustee.ToString(); Source = 'Get-RecipientPermission' }
                            }
                        }

                        foreach ($sendAs in $sendAsRows) {
                            $delegate = $sendAs.Delegate
                            $unexpectedReason = Get-MailboxDelegationUnexpectedReason -MailboxIdentity $mailboxIdentity -DelegateIdentity $delegate -ExpectedDelegates $expectedDelegates
                            $row = [PSCustomObject]@{
                                MailboxIdentity = $mailboxIdentity
                                Delegate        = $delegate
                                DelegationType  = 'SendAs'
                                Source          = $sendAs.Source
                                IsUnexpected    = [bool]($null -ne $unexpectedReason)
                                Reason          = $unexpectedReason
                            }
                            $allDelegations += $row
                            if ($row.IsUnexpected) { [void]$suspiciousDelegations.Add($row) }
                        }
                    } catch {
                        & $Log "MailboxDelegation SendAs pour $mailboxIdentity : $_"
                    }

                    try {
                        $onBehalfTo = @($mb.GrantSendOnBehalfTo)
                        foreach ($grant in $onBehalfTo) {
                            $delegate = $grant.ToString()
                            if (-not $delegate) { continue }
                            $unexpectedReason = Get-MailboxDelegationUnexpectedReason -MailboxIdentity $mailboxIdentity -DelegateIdentity $delegate -ExpectedDelegates $expectedDelegates
                            $row = [PSCustomObject]@{
                                MailboxIdentity = $mailboxIdentity
                                Delegate        = $delegate
                                DelegationType  = 'SendOnBehalf'
                                Source          = 'GrantSendOnBehalfTo'
                                IsUnexpected    = [bool]($null -ne $unexpectedReason)
                                Reason          = $unexpectedReason
                            }
                            $allDelegations += $row
                            if ($row.IsUnexpected) { [void]$suspiciousDelegations.Add($row) }
                        }
                    } catch {
                        & $Log "MailboxDelegation GrantSendOnBehalfTo pour $mailboxIdentity : $_"
                    }
                }
            } catch {
                & $Log "Collecte MailboxDelegation : $_"
                & $Log "Exception: $($_.Exception.GetType().FullName)"
                if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
            }
        }

        $allRules | Export-Csv -Path $rulesPath -NoTypeInformation -Encoding UTF8
        $allForwarding | Export-Csv -Path $forwardPath -NoTypeInformation -Encoding UTF8
        $allDelegations | Export-Csv -Path $delegationPath -NoTypeInformation -Encoding UTF8
        $findingsObj = @{
            suspiciousRules    = @($suspiciousRules)
            externalForwarding = @($externalForwarding)
            suspiciousDelegations = @($suspiciousDelegations)
        }
        $findingsObj | ConvertTo-Json -Depth 4 | Set-Content -Path $findingsPath -Encoding UTF8
        return @{ Success = $true; RulesPath = $rulesPath; ForwardPath = $forwardPath; DelegationPath = $delegationPath; FindingsPath = $findingsPath }
    } catch {
        & $Log "Exchange : $_"
        & $Log "Exception: $($_.Exception.GetType().FullName)"
        if ($_.ScriptStackTrace) { & $Log "StackTrace: $($_.ScriptStackTrace)" }
        if (-not $WhatIf) {
            if (-not (Test-Path $exDir)) { New-Item -ItemType Directory -Path $exDir -Force | Out-Null }
            @() | Export-Csv -Path $rulesPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $forwardPath -NoTypeInformation -Encoding UTF8
            @() | Export-Csv -Path $delegationPath -NoTypeInformation -Encoding UTF8
            @{ error = $_.Exception.Message; suspiciousRules = @(); externalForwarding = @(); suspiciousDelegations = @() } | ConvertTo-Json | Set-Content -Path $findingsPath -Encoding UTF8
        }
        return @{ Success = $false; Error = $_.Exception.Message; RulesPath = $rulesPath; ForwardPath = $forwardPath; DelegationPath = $delegationPath; FindingsPath = $findingsPath }
    } finally {
        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

export-modulemember -Function Invoke-IncidentKitExchangeCollect, Test-SmtpAddressExternal, Get-ExchangeSession, Get-MailboxDelegationUnexpectedReason

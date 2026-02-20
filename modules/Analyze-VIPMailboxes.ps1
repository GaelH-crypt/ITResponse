<#
.SYNOPSIS
    Audit des boîtes aux lettres VIP : règles, transfert, FullAccess, SendAs.
.DESCRIPTION
    Pour chaque utilisateur listé dans vip_list.txt, collecte :
    - Règles de boîte de réception (Inbox rules)
    - Transfert (forwarding)
    - Permissions FullAccess
    - Permissions SendAs
    Sortie : output\Exchange\vip_audit.json
    Objectif : identifier une compromission ciblée (règles malveillantes, transfert externe, délégation anormale).
.NOTES
    Nécessite une session Exchange (Exchange Management Shell) ou -PsUri pour connexion à distance.
    Lecture seule. Aucune modification des boîtes ou des permissions.
.PARAMETER VipListPath
    Fichier contenant la liste des utilisateurs VIP (un par ligne ; identité mailbox : alias, SMTP, ou nom).
.PARAMETER OutputPath
    Chemin du fichier JSON de sortie.
.PARAMETER PsUri
    URI du endpoint Exchange Remote PowerShell (ex. http://serveur/PowerShell). Si fourni, une session est créée.
.PARAMETER Credential
    Identifiants pour la connexion Exchange (optionnel si session déjà établie).
.PARAMETER UseSSL
    Utiliser HTTPS pour la connexion Exchange.
.EXAMPLE
    .\Analyze-VIPMailboxes.ps1
    # Utilise vip_list.txt et output\Exchange\vip_audit.json par défaut (session Exchange déjà ouverte).
.EXAMPLE
    Audit-VIPMailboxes -VipListPath ".\vip_list.txt" -OutputPath ".\output\Exchange\vip_audit.json" -PsUri "http://mail.contoso.local/PowerShell"
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$script:DefaultVipListPath = 'vip_list.txt'
$script:DefaultOutputPath  = 'output\Exchange\vip_audit.json'

function Get-ExchangeSessionInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PsUri,
        [string]$Auth = 'Kerberos',
        [bool]$UseSSL = $false,
        [System.Management.Automation.PSCredential]$Credential
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
    New-PSSession @params
}

function Audit-VIPMailboxes {  # Approved verb exception: "Audit" kept for clarity (incident/audit scenario)
    [CmdletBinding(SupportsShouldProcess)]
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', 'Audit', Justification = 'Audit-VIPMailboxes required by design')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$VipListPath = (Join-Path (Get-Location) $script:DefaultVipListPath),
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path (Get-Location) $script:DefaultOutputPath),
        [Parameter(Mandatory = $false)]
        [string]$PsUri,
        [Parameter(Mandatory = $false)]
        [string]$Auth = 'Kerberos',
        [Parameter(Mandatory = $false)]
        [switch]$UseSSL,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Résolution du chemin de la liste VIP (depuis répertoire du script si chemin relatif et fichier absent en cwd)
    if (-not (Test-Path -LiteralPath $VipListPath)) {
        $altPath = Join-Path $PSScriptRoot $script:DefaultVipListPath
        if (Test-Path -LiteralPath $altPath) { $VipListPath = $altPath }
    }
    if (-not (Test-Path -LiteralPath $VipListPath)) {
        Write-Error "Liste VIP introuvable : $VipListPath"
        return
    }

    $vipEntries = Get-Content -Path $VipListPath -Encoding UTF8 -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^\s*#' }
    if (-not $vipEntries -or $vipEntries.Count -eq 0) {
        Write-Warning "Aucune entrée dans la liste VIP : $VipListPath"
        $result = @{ auditDate = (Get-Date).ToString('o'); vipCount = 0; vipMailboxes = @(); error = 'Liste VIP vide' }
        $outDir = [System.IO.Path]::GetDirectoryName($OutputPath)
        if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
        $result | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
        return $result
    }

    $session = $null
    if ($PsUri) {
        try {
            $session = Get-ExchangeSessionInternal -PsUri $PsUri -Auth $Auth -UseSSL $UseSSL -Credential $Credential
            Import-PSSession -Session $session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
            Write-Verbose "Session Exchange établie : $PsUri"
        } catch {
            Write-Error "Connexion Exchange : $_"
            return
        }
    } else {
        # Vérifier qu'une session Exchange est disponible
        if (-not (Get-Command -Name 'Get-Mailbox' -ErrorAction SilentlyContinue)) {
            Write-Error "Aucune session Exchange. Exécutez depuis Exchange Management Shell ou fournissez -PsUri (et éventuellement -Credential)."
            return
        }
    }

    try {
        $outDir = [System.IO.Path]::GetDirectoryName($OutputPath)
        if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }

        $vipMailboxes = [System.Collections.ArrayList]::new()
        foreach ($entry in $vipEntries) {
            $mb = $null
            try {
                $mb = Get-Mailbox -Identity $entry -ErrorAction Stop
            } catch {
                Write-Warning "Boîte non trouvée ou erreur pour '$entry' : $_"
                [void]$vipMailboxes.Add([PSCustomObject]@{
                    identity    = $entry
                    found       = $false
                    error       = $_.Exception.Message
                    inboxRules  = @()
                    forwarding  = $null
                    fullAccess  = @()
                    sendAs      = @()
                })
                continue
            }

            $identity = $mb.Identity.ToString()
            $primarySmtp = $mb.PrimarySmtpAddress.ToString()

            # --- Inbox rules ---
            $inboxRules = @()
            try {
                $rules = Get-InboxRule -Mailbox $identity -ErrorAction SilentlyContinue
                foreach ($r in $rules) {
                    $inboxRules += [PSCustomObject]@{
                        name          = $r.Name
                        forwardTo     = ($r.ForwardTo | Out-String).Trim()
                        redirectTo    = ($r.RedirectTo | Out-String).Trim()
                        deleteMessage = [bool]$r.DeleteMessage
                        enabled       = [bool]$r.Enabled
                    }
                }
            } catch {
                Write-Verbose "Get-InboxRule pour $identity : $_"
            }

            # --- Forwarding (Get-Mailbox) ---
            $forwarding = $null
            try {
                $mbFwd = Get-Mailbox -Identity $identity -ErrorAction Stop
                $forwarding = [PSCustomObject]@{
                    forwardingSmtpAddress     = if ($mbFwd.ForwardingSmtpAddress) { $mbFwd.ForwardingSmtpAddress.ToString() } else { $null }
                    deliverToMailboxAndForward = [bool]$mbFwd.DeliverToMailboxAndForward
                }
            } catch {
                Write-Verbose "Get-Mailbox (forwarding) pour $identity : $_"
            }

            # --- FullAccess ---
            $fullAccess = @()
            try {
                $perms = Get-MailboxPermission -Identity $identity -ErrorAction SilentlyContinue | Where-Object { $_.AccessRights -match 'FullAccess' -and $_.User -notmatch '^S-1-5-21' -and $_.User.ToString() -notmatch 'Default|Self|S-1-5-10' }
                foreach ($p in $perms) {
                    $fullAccess += [PSCustomObject]@{
                        user         = $p.User.ToString()
                        accessRights = @($p.AccessRights)
                        isInherited  = [bool]$p.IsInherited
                    }
                }
            } catch {
                Write-Verbose "Get-MailboxPermission pour $identity : $_"
            }

            # --- SendAs ---
            $sendAs = @()
            try {
                $recipPerms = Get-RecipientPermission -Identity $identity -ErrorAction SilentlyContinue | Where-Object { $_.AccessRights -match 'SendAs' }
                foreach ($rp in $recipPerms) {
                    if ($rp.Trustee -and $rp.Trustee.ToString() -notmatch '^S-1-5-21.*-500$') {
                        $sendAs += [PSCustomObject]@{
                            trustee      = $rp.Trustee.ToString()
                            accessRights = @($rp.AccessRights)
                        }
                    }
                }
            } catch {
                Write-Verbose "Get-RecipientPermission pour $identity : $_"
            }

            [void]$vipMailboxes.Add([PSCustomObject]@{
                identity    = $identity
                primarySmtp = $primarySmtp
                found       = $true
                inboxRules  = $inboxRules
                forwarding  = $forwarding
                fullAccess  = $fullAccess
                sendAs      = $sendAs
            })
        }

        $result = @{
            auditDate   = (Get-Date).ToString('o')
            vipCount    = $vipMailboxes.Count
            vipListPath = $VipListPath
            vipMailboxes = @($vipMailboxes)
        }

        if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Write vip_audit.json')) {
            return $result
        }
        $result | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
        Write-Verbose "Audit VIP enregistré : $OutputPath ($($vipMailboxes.Count) boîte(s))."
        return $result
    } finally {
        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

if ($ExecutionContext.SessionState.Module) {
    Export-ModuleMember -Function Audit-VIPMailboxes
}

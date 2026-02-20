<#
.SYNOPSIS
    Détection d'exfiltration mail via transfert (forwarding) de boîtes Exchange.
.DESCRIPTION
    Collecte Identity, ForwardingSmtpAddress, DeliverToMailboxAndForward pour chaque boîte.
    Distingue adresse interne (DN EX:/) d'une adresse SMTP externe.
    Alerte si ForwardingSmtpAddress contient un domaine externe.
    Génère output\Exchange\forwarding_alerts.json.
.NOTES
    À exécuter dans un contexte où les cmdlets Exchange sont disponibles
    (Exchange Management Shell ou après Import-PSSession).
#>
[CmdletBinding()]
param()

# Domaines connus comme externes (référentiel commun)
$script:ExternalDomains = @(
    'gmail.com', 'google.com', 'googlemail.com',
    'yahoo.com', 'yahoo.fr', 'outlook.com', 'hotmail.com', 'hotmail.fr', 'live.com', 'msn.com',
    'proton.me', 'protonmail.com', 'free.fr', 'orange.fr', 'laposte.net', 'wanadoo.fr', 'sfr.fr', 'bbox.fr',
    'icloud.com', 'me.com', 'aol.com', 'mail.com', 'zoho.com', 'yandex.com'
)

function Test-ForwardingAddressExternal {
    <#
    .SYNOPSIS
        Indique si une adresse de transfert est externe (SMTP externe) ou interne (DN EX:/).
    .DESCRIPTION
        - Interne : EX:/ ou /o= (Distinguished Name), pas d'alerte.
        - Externe : adresse SMTP (smtp:user@domain) vers un domaine externe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Address
    )
    if (-not $Address -or ($Address = $Address.Trim()) -eq '') { return $false }
    $addr = $Address.ToLowerInvariant()
    # Préfixe SMTP optionnel
    if ($addr.StartsWith('smtp:')) { $addr = $addr.Substring(5).Trim() }
    # DN interne Exchange : EX:/ ou /o= → interne
    if ($addr.StartsWith('ex:/') -or $addr -match '^/o=') { return $false }
    # Domaines externes connus
    foreach ($d in $script:ExternalDomains) {
        if ($addr -like "*@$d" -or $addr -eq $d) { return $true }
    }
    # Pattern SMTP type user@domain.tld : considéré externe sauf suffixes internes
    if ($addr -match '@([a-z0-9\-\.]+\.[a-z]{2,})$') {
        $domain = $matches[1]
        if ($domain -match '\.(local|lan|internal)$') { return $false }
        return $true
    }
    return $false
}

function Find-MailboxForwarding {
    <#
    .SYNOPSIS
        Détecte les transferts de boîtes mail vers des adresses externes (exfiltration).
    .DESCRIPTION
        Collecte Get-Mailbox | Select Identity, ForwardingSmtpAddress, DeliverToMailboxAndForward.
        Règle d'alerte : ForwardingSmtpAddress contient un domaine externe (pas un DN EX:/).
        Génère output\Exchange\forwarding_alerts.json au format :
        [ { "Mailbox": "", "ForwardingAddress": "", "External": true|false, "Risk": "HIGH" } ]
    .PARAMETER OutputPath
        Chemin du fichier JSON de sortie. Par défaut : output\Exchange\forwarding_alerts.json
    .EXAMPLE
        Find-MailboxForwarding
    .EXAMPLE
        Find-MailboxForwarding -OutputPath "C:\Reports\forwarding_alerts.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path (Get-Location) 'output\Exchange\forwarding_alerts.json')
    )
    $alerts = [System.Collections.ArrayList]::new()
    try {
        $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop |
            Select-Object -Property Identity, ForwardingSmtpAddress, DeliverToMailboxAndForward
    } catch {
        Write-Error "Get-Mailbox a échoué. Exécutez ce script dans Exchange Management Shell ou après Import-PSSession. $_"
        return
    }
    foreach ($mb in $mailboxes) {
        $fwd = $mb.ForwardingSmtpAddress
        if (-not $fwd) { continue }
        $fwdStr = $fwd.ToString().Trim()
        $identityStr = $mb.Identity.ToString()
        $isExternal = Test-ForwardingAddressExternal -Address $fwdStr
        $risk = if ($isExternal) { 'HIGH' } else { 'LOW' }
        [void]$alerts.Add([PSCustomObject]@{
            Mailbox           = $identityStr
            ForwardingAddress = $fwdStr
            External          = $isExternal
            Risk              = $risk
        })
    }
    $outDir = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $alerts | ConvertTo-Json -Depth 3 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Verbose "forwarding_alerts.json : $($alerts.Count) entrée(s), chemin $OutputPath"
    return $alerts
}

Export-ModuleMember -Function Find-MailboxForwarding, Test-ForwardingAddressExternal

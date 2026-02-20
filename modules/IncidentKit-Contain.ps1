<#
.SYNOPSIS
    IncidentKit - Actions de confinement avec confirmation interactive.
.DESCRIPTION
    Propose des actions (désactiver compte AD, reset MDP, bloquer poste simulé).
    Aucune action exécutée sans confirmation explicite. Toutes les actions sont journalisées.
#>
[CmdletBinding(SupportsShouldProcess)]
param()

function Write-ContainmentLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$ActionType = '',
        [string]$Target = '',
        [string]$Result = '',
        [scriptblock]$Log,
        [string]$LogFilePath = ''
    )
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [CONTAIN] $Message"
    if ($ActionType) { $line += " | Action=$ActionType" }
    if ($Target)     { $line += " | Cible=$Target" }
    if ($Result)     { $line += " | Resultat=$Result" }
    if ($Log) { & $Log $line }
    if ($LogFilePath -and (Test-Path (Split-Path $LogFilePath -Parent))) {
        Add-Content -Path $LogFilePath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

function Invoke-ContainmentActionDisableADAccount {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log,
        [string]$ContainLogPath,
        [switch]$WhatIf
    )
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "Module ActiveDirectory non disponible. Installez les outils RSAT (Active Directory)."
        if ($Log) { Write-ContainmentLog -Message "Echec : module AD absent" -ActionType "DisableADAccount" -Target $SamAccountName -Result "Module AD manquant" -Log $Log -LogFilePath $ContainLogPath }
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    try {
        $user = Get-ADUser -Identity $SamAccountName -ErrorAction Stop
        if (-not $user) { return $false }
        if ($user.Enabled -eq $false) {
            if ($Log) { Write-ContainmentLog -Message "Compte déjà désactivé" -ActionType "DisableADAccount" -Target $SamAccountName -Result "Deja desactive" -Log $Log -LogFilePath $ContainLogPath }
            return $true
        }
        $params = @{ Identity = $SamAccountName }
        if ($Credential) { $params.Credential = $Credential }
        if ($WhatIf) {
            if ($Log) { Write-ContainmentLog -Message "WhatIf : aurait désactivé le compte" -ActionType "DisableADAccount" -Target $SamAccountName -Result "WhatIf" -Log $Log -LogFilePath $ContainLogPath }
            return $true
        }
        Disable-ADAccount @params -ErrorAction Stop
        if ($Log) { Write-ContainmentLog -Message "Compte désactivé" -ActionType "DisableADAccount" -Target $SamAccountName -Result "OK" -Log $Log -LogFilePath $ContainLogPath }
        return $true
    } catch {
        if ($Log) { Write-ContainmentLog -Message "Erreur : $_" -ActionType "DisableADAccount" -Target $SamAccountName -Result "Erreur" -Log $Log -LogFilePath $ContainLogPath }
        Write-Warning $_
        return $false
    }
}

function Invoke-ContainmentActionResetPassword {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$NewPassword,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log,
        [string]$ContainLogPath,
        [switch]$WhatIf
    )
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "Module ActiveDirectory non disponible."
        if ($Log) { Write-ContainmentLog -Message "Echec : module AD absent" -ActionType "ResetPassword" -Target $SamAccountName -Result "Module AD manquant" -Log $Log -LogFilePath $ContainLogPath }
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    try {
        $params = @{ Identity = $SamAccountName; NewPassword = $NewPassword; Reset = $true }
        if ($Credential) { $params.Credential = $Credential }
        if ($WhatIf) {
            if ($Log) { Write-ContainmentLog -Message "WhatIf : aurait réinitialisé le mot de passe" -ActionType "ResetPassword" -Target $SamAccountName -Result "WhatIf" -Log $Log -LogFilePath $ContainLogPath }
            return $true
        }
        Set-ADAccountPassword @params -ErrorAction Stop
        Set-ADUser -Identity $SamAccountName -ChangePasswordAtLogon $true -ErrorAction SilentlyContinue
        if ($Log) { Write-ContainmentLog -Message "Mot de passe réinitialisé (changement à la prochaine connexion)" -ActionType "ResetPassword" -Target $SamAccountName -Result "OK" -Log $Log -LogFilePath $ContainLogPath }
        return $true
    } catch {
        if ($Log) { Write-ContainmentLog -Message "Erreur : $_" -ActionType "ResetPassword" -Target $SamAccountName -Result "Erreur" -Log $Log -LogFilePath $ContainLogPath }
        Write-Warning $_
        return $false
    }
}

function Invoke-ContainmentActionBlockWorkstationSimulated {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [scriptblock]$Log,
        [string]$ContainLogPath,
        [switch]$WhatIf
    )
    # Simulation : aucune action réelle sur le poste, uniquement journalisation.
    if ($Log) { Write-ContainmentLog -Message "Blocage poste SIMULE (aucune action réelle effectuée)" -ActionType "BlockWorkstationSimulated" -Target $ComputerName -Result "Simule" -Log $Log -LogFilePath $ContainLogPath }
    Write-Host "  [Simulation] Aucune action réelle sur le poste '$ComputerName'. Action journalisée uniquement." -ForegroundColor Yellow
    return $true
}

function Invoke-IncidentKitContainmentMenu {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportDir,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Log,
        [switch]$WhatIf
    )
    $containLogPath = Join-Path $ReportDir 'containment_actions.log'
    if (-not $WhatIf) {
        $null = New-Item -ItemType Directory -Path $ReportDir -Force -ErrorAction SilentlyContinue
        "# IncidentKit - Journal des actions de confinement - $(Get-Date -Format 'o')" | Set-Content -Path $containLogPath -Encoding UTF8
    }

    & $Log "Mode Contain : menu de confinement interactif (aucune action sans confirmation)"
    Write-ContainmentLog -Message "Démarrage menu confinement" -Log $Log -LogFilePath $containLogPath

    $choice = ''
    do {
        Write-Host ""
        Write-Host "=== Actions de confinement (confirmation requise pour chaque action) ===" -ForegroundColor Cyan
        Write-Host "  1. Désactiver un compte AD"
        Write-Host "  2. Forcer la réinitialisation du mot de passe (compte AD)"
        Write-Host "  3. Bloquer un poste (simulé - journalisation uniquement)"
        Write-Host "  Q. Quitter"
        Write-Host ""
        $choice = (Read-Host "Choix").Trim().ToUpperInvariant()

        if ($choice -eq 'Q') {
            Write-ContainmentLog -Message "Sortie menu confinement" -Log $Log -LogFilePath $containLogPath
            break
        }

        if ($choice -eq '1') {
            $account = (Read-Host "Nom du compte AD (sAMAccountName)").Trim()
            if (-not $account) { Write-Host "Compte non saisi, ignoré." -ForegroundColor Yellow; continue }
            Write-Host "Action proposée : DÉSACTIVER le compte AD : $account" -ForegroundColor Yellow
            $confirm = (Read-Host "Confirmer l'action ? (O/N)").Trim().ToUpperInvariant()
            if ($confirm -ne 'O' -and $confirm -ne 'Y') {
                Write-ContainmentLog -Message "Action refusée par l'utilisateur" -ActionType "DisableADAccount" -Target $account -Result "Refuse" -Log $Log -LogFilePath $containLogPath
                Write-Host "Action annulée." -ForegroundColor Gray
                continue
            }
            $ok = Invoke-ContainmentActionDisableADAccount -SamAccountName $account -Credential $Credential -Log $Log -ContainLogPath $containLogPath -WhatIf:$WhatIf
            if ($ok) { Write-Host "Compte désactivé." -ForegroundColor Green } else { Write-Host "Échec de l'action." -ForegroundColor Red }
        }
        elseif ($choice -eq '2') {
            $account = (Read-Host "Nom du compte AD (sAMAccountName)").Trim()
            if (-not $account) { Write-Host "Compte non saisi, ignoré." -ForegroundColor Yellow; continue }
            $securePass = $null
            try {
                $credPrompt = Get-Credential -Message "Saisir le NOUVEAU mot de passe pour le compte $account (le nom d'utilisateur saisi est ignoré)"
                if ($credPrompt) { $securePass = $credPrompt.Password }
            } catch {}
            if (-not $securePass) {
                Write-Host "Mot de passe non saisi, ignoré." -ForegroundColor Yellow
                continue
            }
            Write-Host "Action proposée : RÉINITIALISER le mot de passe du compte : $account" -ForegroundColor Yellow
            $confirm = (Read-Host "Confirmer l'action ? (O/N)").Trim().ToUpperInvariant()
            if ($confirm -ne 'O' -and $confirm -ne 'Y') {
                Write-ContainmentLog -Message "Action refusée par l'utilisateur" -ActionType "ResetPassword" -Target $account -Result "Refuse" -Log $Log -LogFilePath $containLogPath
                Write-Host "Action annulée." -ForegroundColor Gray
                continue
            }
            $ok = Invoke-ContainmentActionResetPassword -SamAccountName $account -NewPassword $securePass -Credential $Credential -Log $Log -ContainLogPath $containLogPath -WhatIf:$WhatIf
            if ($ok) { Write-Host "Mot de passe réinitialisé." -ForegroundColor Green } else { Write-Host "Échec de l'action." -ForegroundColor Red }
        }
        elseif ($choice -eq '3') {
            $computer = (Read-Host "Nom du poste (ordinateur) à bloquer (simulation)").Trim()
            if (-not $computer) { Write-Host "Nom non saisi, ignoré." -ForegroundColor Yellow; continue }
            Write-Host "Action proposée : BLOQUER le poste (SIMULATION) : $computer" -ForegroundColor Yellow
            $confirm = (Read-Host "Confirmer l'action (simulation journalisée) ? (O/N)").Trim().ToUpperInvariant()
            if ($confirm -ne 'O' -and $confirm -ne 'Y') {
                Write-ContainmentLog -Message "Action refusée par l'utilisateur" -ActionType "BlockWorkstationSimulated" -Target $computer -Result "Refuse" -Log $Log -LogFilePath $containLogPath
                Write-Host "Action annulée." -ForegroundColor Gray
                continue
            }
            $null = Invoke-ContainmentActionBlockWorkstationSimulated -ComputerName $computer -Log $Log -ContainLogPath $containLogPath -WhatIf:$WhatIf
        }
        else {
            if ($choice -ne '') { Write-Host "Choix non reconnu." -ForegroundColor Yellow }
        }
    } while ($choice -ne 'Q')

    Write-Host ""
    Write-Host "Journal des actions de confinement : $containLogPath" -ForegroundColor Cyan
}

Export-ModuleMember -Function Invoke-IncidentKitContainmentMenu, Invoke-ContainmentActionDisableADAccount, Invoke-ContainmentActionResetPassword, Invoke-ContainmentActionBlockWorkstationSimulated, Write-ContainmentLog

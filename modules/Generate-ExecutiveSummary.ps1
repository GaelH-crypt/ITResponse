<#
.SYNOPSIS
    Génère un résumé exécutif non technique (5 lignes) pour la direction.
.DESCRIPTION
    Produit un fichier executive_summary.txt dans le dossier Report avec :
    - Ce qui s'est passé
    - Impact
    - Actions prises
    - Niveau de risque
    - Recommandations
.NOTES
    Sortie : <ReportDir>\executive_summary.txt
#>
[CmdletBinding(SupportsShouldProcess)]
param()

function New-ExecutiveSummary {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportDir,
        [Parameter(Mandatory = $false)]
        [ValidateSet('infostealer', 'phishing', 'ransomware_suspect', 'account_compromise', '')]
        [string]$IncidentType = 'account_compromise',
        [Parameter(Mandatory = $false)]
        [string]$SeverityLevel = '',
        [Parameter(Mandatory = $false)]
        [string]$WhatHappened = '',
        [Parameter(Mandatory = $false)]
        [string]$Impact = '',
        [Parameter(Mandatory = $false)]
        [string]$ActionsTaken = '',
        [Parameter(Mandatory = $false)]
        [string]$RiskLevel = '',
        [Parameter(Mandatory = $false)]
        [string]$Recommendations = '',
        [switch]$WhatIf
    )

    # Valeurs par défaut selon le type d'incident si non fournies
    $typeLabels = @{
        'account_compromise'   = 'compromission de compte'
        'phishing'             = 'campagne de phishing'
        'infostealer'          = 'infection type infostealer / vol de données'
        'ransomware_suspect'   = 'suspicion de ransomware ou activité malveillante'
    }
    $label = $typeLabels[$IncidentType]
    if (-not $label) { $label = 'incident de sécurité' }

    if (-not $WhatHappened) {
        $WhatHappened = "Un $label a été détecté ou suspecté sur l'environnement."
    }
    if (-not $Impact) {
        $Impact = "Risque pour la confidentialité et l'intégrité des données ; exposition possible des comptes et des accès."
    }
    if (-not $ActionsTaken) {
        $ActionsTaken = "Collecte des preuves (AD, messagerie, postes), analyse des journaux et génération du rapport d'incident."
    }
    if (-not $RiskLevel) {
        $RiskLevel = if ($SeverityLevel) { $SeverityLevel } else { "À évaluer (voir rapport technique et score EBIOS)." }
    }
    if (-not $Recommendations) {
        $Recommendations = "Renforcer l'authentification (MFA), revue des droits et des règles de messagerie ; suivi du rapport technique pour actions correctives."
    }

    $lines = @(
        "Ce qui s'est passé : $WhatHappened",
        "Impact : $Impact",
        "Actions prises : $ActionsTaken",
        "Niveau de risque : $RiskLevel",
        "Recommandations : $Recommendations"
    )
    $content = $lines -join "`r`n"
    $outPath = Join-Path $ReportDir 'executive_summary.txt'

    if (-not $WhatIf) {
        if (-not (Test-Path $ReportDir)) {
            New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
        }
        Set-Content -Path $outPath -Value $content -Encoding UTF8
    }
    return $outPath
}

Export-ModuleMember -Function New-ExecutiveSummary

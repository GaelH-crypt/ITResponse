# Rapport technique d'incident – {{INCIDENT_DATE}}

**Type d'incident :** {{INCIDENT_TYPE}}  
**Cible éventuelle :** {{TARGET_HOST}}  
**Organisation :** {{ORG_NAME}}  
**Fenêtre d'analyse :** {{TIME_WINDOW_DAYS}} jours

---

## 1. Résumé exécutif

{{EXEC_SUMMARY}}

**Score EBIOS (interne v0.1) :** {{EBIOS_SCORE}}  
**Niveau de gravité estimé :** {{SEVERITY_LEVEL}}

---

## 2. Contexte de l'exécution

- **Date/heure d'exécution :** {{RUN_TIMESTAMP}}
- **Poste d'exécution :** {{RUN_HOSTNAME}}
- **Utilisateur :** {{RUN_USER}}
- **Profil config :** {{CONFIG_PATH}}
- **Dossier de sortie :** {{OUTPUT_PATH}}

### Éléments réalisés / non réalisés

| Composant | Statut | Détail |
|-----------|--------|--------|
| Collecte AD | {{AD_STATUS}} | {{AD_DETAIL}} |
| Collecte Exchange | {{EXCHANGE_STATUS}} | {{EXCHANGE_DETAIL}} |
| Collecte Endpoint | {{ENDPOINT_STATUS}} | {{ENDPOINT_DETAIL}} |

{{COVERAGE_WARNING}}

---

## 3. Constats Active Directory

### 3.1 Nouveaux comptes (Event ID 4720)

{{AD_NEW_ACCOUNTS}}

### 3.2 Ajouts aux groupes d'administration (4728 / 4732)

{{AD_ADMIN_ADDITIONS}}

### 3.3 Connexions RDP (LogonType 10)

{{AD_RDP_LOGONS}}

### 3.4 Adresses IP externes (hors RFC1918)

{{AD_EXTERNAL_IPS}}

### 3.5 Pics d'échecs de connexion (4625)

{{AD_FAILURE_PEAKS}}

---

## 4. Constats Exchange

### 4.1 Règles de boîte aux lettres suspectes

{{EXCHANGE_SUSPICIOUS_RULES}}

### 4.2 Transfert (forwarding) vers adresses externes

{{EXCHANGE_EXTERNAL_FORWARDING}}

---

## 5. Constats Endpoint (si collecte)

{{ENDPOINT_FINDINGS}}

---

## 6. Cartographie MITRE ATT&CK

Techniques probables identifiées :

{{MITRE_TECHNIQUES}}

---

## 7. Recommandations

- Consulter les logs détaillés et le transcript dans le dossier de sortie.
- Conserver les preuves (Evidence.zip) sans modification.
- Ne pas effectuer de nettoyage automatique sans validation.

---

*Rapport généré par IncidentKit v0.1*

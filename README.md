# IncidentKit — Manuel opérationnel de réponse à incident

**Version : 0.1**  
*Outil de collecte, analyse et aide à la décision en situation de cyberattaque.*

---

## 1. Présentation

### But de l'outil

IncidentKit est un **outil de réponse à incident informatique** conçu pour être utilisé **en situation réelle** par un RSI (Référent Sécurité Informatique) ou un administrateur système, seul ou en petite équipe, lorsqu’une cyberattaque est suspectée ou en cours.

Il permet de **collecter rapidement** des données sur Active Directory, Exchange et éventuellement un poste cible, de **les analyser** pour repérer des signaux d’alerte (comptes compromis, transferts de messagerie, connexions suspectes), puis de **produire un rapport** et un score de gravité pour aider à la décision. En mode confinement, il propose des **actions de sécurité** (désactivation de compte, réinitialisation de mot de passe, etc.) avec confirmation explicite pour chaque action.

L’objectif : **gagner du temps et de la clarté** pendant la crise, sans remplacer une intervention forensique complète ni un prestataire spécialisé.

### Ce qu’il fait

- **Collecte** : extraction des événements de sécurité AD (connexions, créations de comptes, ajouts aux groupes admin, etc.), règles et transferts Exchange, et optionnellement données d’un poste (processus, services, tâches planifiées, connexions réseau).
- **Analyse** : repérage de comportements à risque (nouveaux comptes, IP externes, pics d’échecs de connexion, règles de boîte aux lettres suspectes, transfert vers des adresses externes).
- **Rapport** : génération d’un rapport technique (Markdown/texte), d’une synthèse exécutive, d’un score EBIOS interne, d’une cartographie MITRE ATT&CK et d’une timeline.
- **Confinement** : proposition d’actions (désactiver un compte AD, réinitialiser un mot de passe, « bloquer » un poste en mode simulé) avec **confirmation obligatoire** pour chaque action et journalisation.

### Ce qu’il ne fait pas

- **Il ne chiffre pas** les données ni les communications.
- **Il ne nettoie pas** les malwares ni ne « répare » les systèmes.
- **Il ne remplace pas** une analyse forensique complète (disque, mémoire, réseau).
- **Il ne remplace pas** un CERT, une équipe IR externe ou une assurance cyber : il sert à la **prise de décision rapide** et à la **préservation des preuves** en attendant une intervention spécialisée.

### Types d’incidents couverts

IncidentKit est prévu pour les scénarios typiques suivants (paramètre `-IncidentType`) :

| Type | Usage recommandé |
|------|------------------|
| **account_compromise** | Compromission de compte (phishing, vol de mot de passe, prise de contrôle). |
| **infostealer** | Suspicions d’exfiltration de données ou de logiciel voleur d’informations. |
| **phishing** | Incident lié au phishing (comptes ciblés, règles Exchange, transferts). |
| **ransomware_suspect** | Ransomware suspecté : collecte rapide pour évaluer l’étendue et les vecteurs. |

Le type d’incident influence le contexte du rapport et les recommandations ; la collecte reste la même.

### Limites

- **Ne remplace pas un CERT / IR externe** : en cas d’attaque avérée ou de doute sur l’étendue, faire appel à un prestataire de réponse à incident et à votre assurance cyber.
- **Environnement cible** : conçu pour un **Active Directory on-premises** et **Exchange on-premises** (collectivités, petites équipes). Pas de prise en charge native du cloud (Azure AD, Microsoft 365) dans cette version.
- **Pas d’action automatique** : en mode Contain, aucune action n’est exécutée sans votre confirmation (O/N).
- **Blocage poste** : l’action « bloquer un poste » est **simulée** (journalisation uniquement) ; le blocage réel (pare-feu, GPO, etc.) reste à faire par vos moyens.

---

## 2. Périmètre de confiance de l’outil

Cette section précise ce que l’outil **permet d’affirmer** et ce qu’il **ne permet pas d’affirmer**, afin que le rapport soit utilisé à bon escient en audit et en situation réelle.

### Ce que l’outil permet d’affirmer

- Que des **données ont été collectées** à une date et heure données, depuis les sources configurées (DC, Exchange, poste cible).
- Que certains **constats** (nouveaux comptes, IP externes, règles Exchange, etc.) sont **présents dans les journaux analysés** sur la fenêtre de temps demandée.
- Que ces constats ont été **documentés** dans le rapport et les fichiers de sortie, de manière reproductible.

### Ce que l’outil ne permet pas d’affirmer

- **L’absence d’IOC (Indicateurs de Compromission) dans le rapport ne signifie pas l’absence d’attaque.** L’outil ne fait qu’analyser les données qu’il a pu collecter ; un attaquant peut avoir effacé des traces, ou les journaux peuvent être incomplets.
- **L’analyse repose uniquement sur les journaux et artefacts disponibles** au moment de l’exécution. Elle ne couvre pas la mémoire vive, les zones non loguées, ni les systèmes non interrogés.
- **Les conclusions dépendent directement de la rétention des logs** (taille et durée de conservation du journal Security, politique Exchange, etc.). Si la période demandée n’est pas entièrement couverte, le rapport le signale ; les conclusions restent partielles.
- **L’outil sert à la décision rapide**, pas à une **certification de non-compromission**. Il aide à évaluer une situation et à choisir les prochaines étapes (confinement, escalade), mais il ne constitue pas une attestation d’absence de compromission pour un tiers (assurance, audit, juridique).

En résumé : le rapport reflète **ce qui a été vu dans les données collectées**, pas une garantie que tout a été vu.

---

## 3. Principe de fonctionnement

Le déroulement est volontairement simple : **collecte → analyse → rapport → confinement (optionnel)**.

### 1. Collecte

L’outil interroge dans l’ordre :

- **Active Directory** : journaux de sécurité d’un contrôleur de domaine (événements de connexion, création de comptes, modifications de groupes, etc.) sur une fenêtre de temps configurée (ex. 7 jours).
- **Exchange** (si configuré) : règles de boîtes aux lettres et paramètres de transfert (forwarding) pour repérer des redirections vers l’extérieur.
- **Endpoint** (si vous avez indiqué un poste cible avec `-TargetHost`) : processus, services, tâches planifiées, connexions réseau (netstat), fichiers récents, éléments de type Autoruns, et repérage de processus aux noms suspects.

Aucune modification n’est faite sur les systèmes : **lecture et export uniquement**.

### 2. Analyse

Les données collectées sont analysées pour produire des **findings** (constats) :

- AD : nouveaux comptes, ajouts aux groupes d’administration, connexions RDP, adresses IP externes (hors réseau interne), pics d’échecs de connexion.
- Exchange : règles suspectes, transferts vers des adresses externes.
- Endpoint : processus suspects, résumé des artefacts collectés.

Un **score EBIOS** (interne, v0.1) et une **cartographie MITRE ATT&CK** sont calculés à partir de ces constats.

### 3. Rapport

Un dossier horodaté est créé avec :

- Rapport technique (Markdown + version texte), synthèse exécutive, score EBIOS, timeline, logs, et optionnellement une archive des preuves (Evidence.zip).

Vous vous basez sur ce rapport pour **décider des prochaines étapes** (confinement, escalade, appel à un prestataire).

### 4. Confinement (mode Contain uniquement)

En mode **Contain**, après la génération du rapport, un menu propose des actions (désactiver un compte AD, réinitialiser un mot de passe, « bloquer » un poste en simulation). **Chaque action demande une confirmation explicite (O/N)**. Toutes les actions sont enregistrées dans un journal dédié.

### Pourquoi l’ordre des actions est important

- **D’abord collecter** : sans données, impossible d’analyser correctement. En cas de doute, lancez d’abord un **Collect** pour figer des preuves et éviter de perdre des journaux (rotation, redémarrage).
- **Ensuite analyser et lire le rapport** : le mode **Investigate** fait collecte + analyse + rapport. C’est le flux normal pour comprendre la situation.
- **Confinement seulement après analyse** : ne lancez **Contain** qu’après avoir lu le rapport et identifié les comptes ou postes à traiter. Agir trop tôt peut désactiver un compte légitime ou masquer des indices.

---

## 4. Prérequis

### PowerShell

- **PowerShell 5.1** ou supérieur (Windows PowerShell intégré à Windows).
- Vérification : `$PSVersionTable.PSVersion`

### Outils et accès

- **RSAT (Outils d’administration de serveur de rôles)** : recommandé pour utiliser confortablement les cmdlets Active Directory depuis un poste d’administration. Au minimum, le poste doit pouvoir **lire les journaux de sécurité** sur au moins un contrôleur de domaine (via réseau et droits appropriés).
- **Accès réseau au(x) contrôleur(s) de domaine** : résolution DNS du DC, port **TCP 135** (RPC) et accès aux journaux d’événements à distance. Pare-feu et stratégie de domaine ne doivent pas bloquer ces accès.
- **Accès Exchange** (si vous utilisez la collecte Exchange) : accès au **Exchange Management Shell** (URI PowerShell configuré dans `config.json`). Depuis un poste hors domaine, authentification **Negotiate** ou **NTLM** selon votre environnement.
- **WinRM** (si vous collectez un **Endpoint** distant avec `-TargetHost`) : WinRM doit être activé et autorisé sur le poste cible ; le compte utilisé doit avoir les droits nécessaires sur ce poste.

### Droits nécessaires

- **Lecture des journaux de sécurité** sur au moins un DC (événements Security).
- **Lecture des boîtes aux lettres / règles Exchange** selon votre architecture (droits Exchange habituels pour un admin).
- Aucun droit « d’écriture » n’est requis pour la collecte et l’analyse ; pour le **confinement** (désactiver compte, reset MDP), il faut les droits AD correspondants.

### Poste recommandé

- Utiliser un **poste d’administration sain** (idéalement joint au domaine, avec RSAT), **non compromis**. En cas de doute sur votre poste, privilégier un poste de secours ou un poste dédié à la réponse à incident.

---

## 5. Installation

### Étape 1 : Décompression

- Copiez l’intégralité du dossier IncidentKit sur le poste où vous exécuterez l’outil (réseau interne, lecteur local).  
- Ne pas placer le dossier sur un partage ouvert à tout le monde ; privilégier un accès restreint (admin, RSI).

### Étape 2 : Configuration (config.json)

Deux possibilités :

**Option A — Assistant de configuration (recommandé pour la première fois)**  
En PowerShell, depuis le dossier IncidentKit :

```powershell
.\IncidentKit-Setup.ps1
```

Le script vous demande : nom de l’organisation, domaine, liste des DC, DC préféré, serveur Exchange (optionnel), URI PowerShell Exchange, dossier de sortie, fenêtre d’analyse en jours. Il effectue des tests de connectivité (DNS, ports LDAP 389, HTTP/HTTPS Exchange) et génère un fichier `config.json`.

**Option B — Copie et adaptation de l’exemple**  
Si vous préférez éditer à la main :

```powershell
Copy-Item sample-config.json config.json
# Ouvrir config.json et adapter : domaine, DC, Exchange, chemins, etc.
```

Ne **jamais** stocker de mots de passe dans `config.json`. Les identifiants sont saisis à la demande (poste hors domaine ou `-CredentialMode Prompt`).

### Étape 3 : Premier test

Depuis le dossier IncidentKit, avec un compte ayant les droits nécessaires :

```powershell
.\IncidentKit.ps1 -Mode Collect -IncidentType account_compromise -Verbose
```

- Si la collecte AD et (si configuré) Exchange se déroule correctement, un dossier horodaté est créé sous le dossier de sortie configuré (ex. `Output\2025-02-20_1430_account_compromise_no-target\`).
- En mode Collect, il n’y a pas de rapport ni de score ; vous vérifiez uniquement que la **collecte** fonctionne.
- En cas d’erreur (DC inaccessible, Exchange inaccessible), consulter la section **Dépannage** (section 14).

Si la politique d’exécution PowerShell bloque les scripts :

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

(À exécuter une seule fois, en tant qu’administrateur si nécessaire.)

---

## 6. Configuration (config.json)

Le fichier `config.json` pilote tous les composants. Chaque section est décrite ci-dessous. **Ne jamais y mettre de mots de passe.**

### Organisation (org)

| Champ | Description |
|-------|-------------|
| **name** | Nom de votre organisation (collectivité, entité). Utilisé dans le rapport. |
| **timezone** | Fuseau horaire pour les dates (ex. `Romance Standard Time`). |

### Active Directory (ad)

| Champ | Description |
|-------|-------------|
| **domainFqdn** | Nom de domaine complet (ex. `contoso.local`). |
| **domainNetbios** | Nom NetBIOS du domaine (ex. `CONTOSO`). |
| **dcList** | Liste des contrôleurs de domaine (FQDN), ex. `["dc01.contoso.local","dc02.contoso.local"]`. |
| **preferredDc** | DC utilisé en priorité pour la collecte (ex. `dc01.contoso.local`). |
| **eventIds** | Identifiants des événements Security collectés. Par défaut : 4624, 4625, 4672, 4720, 4722, 4728, 4732, 4740 (connexions, échecs, privilèges, création de compte, modifications de groupes, etc.). |
| **timeWindowDays** | Nombre de jours en arrière pour la collecte AD (ex. `7`). Peut être surchargé en ligne de commande avec `-TimeWindowDays`. |
| **exportPaths** | Chemins relatifs des fichiers générés (ex. `AD/analyse_ad.csv`, `AD/ad_findings.json`). En général, ne pas modifier sauf besoin spécifique. |

### Exchange (exchange)

À remplir uniquement si vous utilisez Exchange on-premises et la collecte Exchange.

| Champ | Description |
|-------|-------------|
| **serverFqdn** | Nom complet du serveur Exchange (ex. `mail.contoso.local`). |
| **psUri** | URI du Exchange Management Shell (ex. `http://mail.contoso.local/PowerShell/` ou `https://...`). |
| **auth** | Méthode d’authentification : `Kerberos` (poste joint au domaine) ou `Negotiate` / `NTLM` depuis un poste hors domaine. |
| **useSSL** | `true` si l’URI utilise HTTPS, sinon `false`. |
| **checks** | Sous-objet : `inboxRules: true` pour les règles de boîte, `forwarding: true` pour les transferts. Mettre à `false` pour désactiver une vérification. |

### Endpoint (endpoint)

Options de collecte sur le poste cible (local ou distant avec `-TargetHost`).

| Champ | Description |
|-------|-------------|
| **collectProcesses** | Collecte des processus. |
| **collectServices** | Collecte des services. |
| **collectScheduledTasks** | Tâches planifiées. |
| **collectNetstat** | Connexions réseau (équivalent netstat). |
| **collectAutoruns** | Éléments type Autoruns (démarrage). |
| **collectRecentFiles** | Fichiers récents. |
| **collectFileHashes** | Calcul de hachages des fichiers (optionnel, plus lent). |
| **suspiciousNames** | Liste de noms de processus considérés comme suspects pour le rapport (ex. `["PDFClick.exe","update.exe","svchost.exe"]`). À adapter à votre contexte. |

### Sortie (output)

| Champ | Description |
|-------|-------------|
| **basePath** | Dossier racine des sorties (ex. `Output`). Les exécutions créent un sous-dossier horodaté sous ce chemin. |
| **reportFormats** | Formats du rapport : `["md","txt"]` pour Markdown et texte. |
| **zipEvidence** | `true` pour générer une archive `Evidence.zip` (AD, Exchange, Report) à des fins de preuve ; `false` pour désactiver. |

### Whitelist IP (optionnel)

Pour une analyse avancée des adresses IP (module d’analyse IP optionnel), vous pouvez utiliser un fichier **whitelist** (une IP par ligne, lignes commentées avec `#`). Ce fichier n’est pas dans `config.json` ; il s’agit en général d’un fichier du type `whitelist_ips.txt` à placer à la racine du projet si vous utilisez des scripts d’analyse IP tiers. Les IP listées sont alors exclues des listes « suspectes ». À adapter selon vos VPN, proxies et plages connues.

### Exemple commenté (extrait)

```json
{
  "_comment": "Configuration IncidentKit - Ne jamais stocker de mots de passe.",
  "org": {
    "name": "Ma Collectivité",
    "timezone": "Romance Standard Time"
  },
  "ad": {
    "domainFqdn": "contoso.local",
    "domainNetbios": "CONTOSO",
    "dcList": ["dc01.contoso.local", "dc02.contoso.local"],
    "preferredDc": "dc01.contoso.local",
    "eventIds": [4624, 4625, 4672, 4720, 4722, 4728, 4732, 4740],
    "timeWindowDays": 7,
    "exportPaths": {
      "eventsCsv": "AD/analyse_ad.csv",
      "findingsJson": "AD/ad_findings.json"
    }
  },
  "exchange": {
    "serverFqdn": "mail.contoso.local",
    "psUri": "http://mail.contoso.local/PowerShell/",
    "auth": "Kerberos",
    "useSSL": false,
    "checks": { "inboxRules": true, "forwarding": true }
  },
  "endpoint": {
    "collectProcesses": true,
    "collectServices": true,
    "collectScheduledTasks": true,
    "collectNetstat": true,
    "collectAutoruns": true,
    "collectRecentFiles": true,
    "collectFileHashes": true,
    "suspiciousNames": ["PDFClick.exe", "update.exe", "svchost.exe"]
  },
  "output": {
    "basePath": "Output",
    "reportFormats": ["md", "txt"],
    "zipEvidence": true
  }
}
```

---

## 7. Modes d’exécution

Le paramètre **`-Mode`** détermine ce que fait IncidentKit.

### Mode Collect (collecte uniquement)

**Commande typique :**

```powershell
.\IncidentKit.ps1 -Mode Collect -IncidentType account_compromise
```

- **Effet** : collecte AD (et Exchange si configuré, et Endpoint si `-TargetHost` est renseigné). **Aucune analyse**, aucun score EBIOS, aucun rapport technique.
- **Quand l’utiliser** : en tout début de crise pour **figer rapidement des données** sans perdre de temps. Recommandé comme **premier geste** : vous gardez des preuves même si vous décidez ensuite d’analyser plus tard ou de faire intervenir un prestataire.

### Mode Investigate (analyse et scoring)

**Commande typique :**

```powershell
.\IncidentKit.ps1 -Mode Investigate -IncidentType account_compromise
```

- **Effet** : collecte **puis** analyse, score EBIOS, rapport technique, synthèse exécutive, timeline, et optionnellement Evidence.zip.
- **Quand l’utiliser** : après une première collecte (ou directement si vous voulez tout en une fois) pour **comprendre la situation** et décider des actions (confinement, escalade).

### Mode Contain (actions de sécurité avec confirmation)

**Commande typique :**

```powershell
.\IncidentKit.ps1 -Mode Contain -IncidentType account_compromise
```

- **Effet** : comme Investigate, puis affichage d’un **menu** proposant :
  1. Désactiver un compte AD  
  2. Forcer la réinitialisation du mot de passe (compte AD)  
  3. Bloquer un poste (simulation : seule la décision est journalisée, aucune action réelle sur le poste)  

Chaque action **demande une confirmation explicite (O/N)**. Aucune action n’est exécutée sans votre accord. Toutes les actions sont enregistrées dans `Report\containment_actions.log`.

- **Quand l’utiliser** : **uniquement après avoir lu le rapport** et identifié les comptes ou postes à traiter.

### Risques de lancer Contain trop tôt

- **Désactiver un compte trop tôt** : vous pouvez couper l’accès d’un compte légitime ou perdre la possibilité d’observer le comportement de l’attaquant.
- **Réinitialiser un mot de passe sans analyse** : même risque et perte de cohérence avec d’éventuelles enquêtes (sessions en cours, preuves).
- **Agir sans preuves** : en cas de litige, assurance ou audit, des actions non documentées ou non justifiées par un rapport peuvent poser problème.

**Règle pratique** : toujours faire au moins **Collect** (idéalement **Investigate**), **lire le rapport**, puis lancer **Contain** si vous avez décidé quelles actions appliquer.

---

## 8. Procédure en cas d’attaque

Cette section est un **guide pas à pas** pour une personne sous stress. À adapter à votre organisation (procédures internes, assurance, hiérarchie).

### Scénario : ransomware suspect (ou activité malveillante détectée)

#### Étape 1 : Ce qu’il faut faire immédiatement

1. **Ne pas éteindre ni redémarrer** les postes concernés sans avis (risque de perte de preuves en mémoire).
2. **Ne pas lancer de scan antivirus / nettoyage** tout de suite sur les postes suspects (risque d’écraser des artefacts).
3. **Lancer une collecte** depuis un **poste sain** (admin, RSI) :

```powershell
cd C:\Chemin\IncidentKit
.\IncidentKit.ps1 -Mode Collect -IncidentType ransomware_suspect -TimeWindowDays 14 -Verbose
```

Si vous avez déjà identifié un **poste cible** à inclure dans la collecte :

```powershell
.\IncidentKit.ps1 -Mode Collect -IncidentType ransomware_suspect -TargetHost "NOM-DU-POSTE" -TimeWindowDays 14 -Verbose
```

- Cela crée un dossier horodaté sous `Output\` avec les données AD, Exchange (si configuré) et Endpoint (si `-TargetHost` est fourni). **Conserver ce dossier intact.**

#### Étape 2 : Quoi analyser dans le rapport

Ensuite, lancez une **analyse** pour obtenir un rapport lisible :

```powershell
.\IncidentKit.ps1 -Mode Investigate -IncidentType ransomware_suspect -TargetHost "NOM-DU-POSTE" -TimeWindowDays 14
```

Ouvrez le **rapport technique** (`Report\rapport_tech.md` ou `rapport_exec.txt`) et concentrez-vous sur :

- **AD — Nouveaux comptes (4720)** : comptes créés récemment que vous ne reconnaissez pas.
- **AD — Ajouts aux groupes d’administration (4728 / 4732)** : élévation de privilèges suspecte.
- **AD — Connexions RDP (LogonType 10)** : qui s’est connecté en bureau à distance, et depuis quelle machine.
- **AD — Adresses IP externes** : connexions depuis des IP hors réseau interne (hors RFC1918) : VPN, domicile, ou attaquant.
- **AD — Pics d’échecs de connexion (4625)** : tentatives de force brute ou ciblage de comptes.
- **Exchange — Règles suspectes et transfert vers l’extérieur** : redirection de mails vers une adresse inconnue = signe classique de compromission de boîte.

Notez les **comptes** et **postes** qui reviennent dans les constats et qui pourraient être compromis.

#### Étape 3 : Quand lancer Contain

- **Après** avoir lu le rapport et identifié au moins un compte ou un poste à isoler.
- **Après** avoir décidé (si possible avec votre hiérarchie ou votre procédure) quelles actions appliquer (désactiver compte, reset MDP, etc.).

Commande :

```powershell
.\IncidentKit.ps1 -Mode Contain -IncidentType ransomware_suspect -TimeWindowDays 14
```

Répondez aux confirmations (O/N) pour chaque action. Le journal `Report\containment_actions.log` garde la trace de ce qui a été fait. L’action « bloquer un poste » est une **simulation** : le blocage réel (pare-feu, GPO, etc.) reste à faire par vos moyens.

#### Étape 4 : Quand appeler un prestataire IR

- **Dès que** l’étendue dépasse vos compétences ou vos moyens (plusieurs serveurs, doute sur la persistance, exigence assurance / juridique).
- **Dès que** votre procédure ou votre assurance l’exige (déclaration sinistre, intervention certifiée).
- **Ne pas attendre** d’avoir « tout nettoyé » : un prestataire a besoin de **preuves et logs intacts**. Conservez le dossier de sortie IncidentKit (et Evidence.zip) sans modification.

---

## 9. Actions à NE PAS FAIRE immédiatement

**Consigne d’urgence** — En situation de crise, respecter les points suivants pour ne pas aggraver la situation ni détruire des preuves :

- **Ne pas redémarrer un serveur** (DC, Exchange, serveur métier) sans avis. Un redémarrage peut effacer des artefacts en mémoire et compliquer l’enquête.
- **Ne pas lancer un antivirus global immédiatement** sur l’ensemble du parc. Un scan massif peut modifier ou supprimer des fichiers utiles à l’analyse et saturer les ressources alors que la priorité est la collecte.
- **Ne pas supprimer ni désactiver un compte suspect sans collecte préalable.** Une fois le compte désactivé, certaines traces (sessions, actions en cours) deviennent inexploitables. Toujours lancer au moins une **Collect** (idéalement **Investigate**) avant toute action de confinement.
- **Ne pas nettoyer un poste (réinstallation, suppression de fichiers) avant analyse.** Le nettoyage détruit les preuves. Collecter d’abord, analyser le rapport, puis décider du sort du poste (nettoyage, isolation, intervention externe).

En résumé : **d’abord collecter et documenter, ensuite décider et agir.**

---

## 10. Interprétation des résultats

### Suspicious IP (IP suspectes)

- Les **adresses IP externes** (hors plages privées RFC1918) dans les événements AD indiquent des connexions depuis l’extérieur du réseau (VPN, domicile, ou attaquant).
- **Grave** : IP inconnues associées à des comptes sensibles (admin, VIP) ou à des créations de compte / ajouts aux groupes admin. À croiser avec votre whitelist (VPN, proxies) si vous en utilisez une.
- **Moins grave** : IP externes connues (télétravail, VPN d’entreprise) pour des comptes habituels, sans autre constat.

### AD findings (constats Active Directory)

- **Nouveaux comptes (4720)** : vérifier que chaque compte correspond à une création légitime (projet, nouveau collaborateur). Un compte inconnu = alerte.
- **Ajouts aux groupes d’administration (4728, 4732)** : toute élévation non prévue (Domain Admins, Administrateurs, etc.) est **très grave**.
- **Connexions RDP (LogonType 10)** : identifier la machine source et le compte. Un RDP depuis une machine inconnue ou un compte non habilité = alerte.
- **Pics d’échecs 4625** : nombreux échecs de connexion sur un même compte ou depuis une même IP = tentative de force brute ou compromission en cours.

### Exchange alerts

- **Règles de boîte aux lettres suspectes** : règles qui redirigent, suppriment ou déplacent des mails sans justification = **très suspect** (technique courante après compromission de boîte).
- **Transfert (forwarding) vers adresses externes** : redirection des e-mails vers une adresse hors de votre domaine = **grave** ; souvent utilisé pour exfiltrer des données ou garder une copie des mails.

### Coverage logs (couverture des journaux)

- Le rapport peut indiquer que **la période demandée n’est pas entièrement couverte** par les journaux du DC (rétention insuffisante, journal Security saturé).
- **À prendre au sérieux** : vos conclusions peuvent être faussées par des trous dans les logs. Dans ce cas, noter la limite dans le rapport et, si possible, augmenter la rétention des journaux pour les prochaines fois.

### Timeline

- La **timeline** fusionnée (`Report\timeline.csv`) ordonne les événements dans le temps. Utilisez-la pour voir l’**ordre des actions** (création de compte → ajout au groupe admin → connexion RDP, etc.) et pour expliquer le scénario à un prestataire ou à l’assurance.

---

## 11. Journalisation et preuves

### Transcript

- Dès le démarrage, IncidentKit enregistre tout ce qui s’affiche dans la console dans un **transcript** (fichier texte). Une copie est placée dans le dossier `Report\` du run.
- Ce transcript fait partie des **preuves** : il montre les commandes exécutées, les messages d’erreur et les choix effectués.

### Logs générés

- **Report\incidentkit.log** : journal détaillé de l’exécution (étapes, erreurs).
- **Report\containment_actions.log** (mode Contain) : chaque action de confinement proposée, acceptée ou refusée, et son résultat.
- Les dossiers **AD\**, **Exchange\**, **Endpoint\** contiennent les données brutes et les findings (CSV, JSON).

### Pourquoi il ne faut pas supprimer

- **Assurance / audit** : en cas de sinistre cyber, l’assurance et les auditeurs peuvent exiger la preuve des actions et des données disponibles au moment de l’incident.
- **CNIL / juridique** : la conservation des preuves dans un cadre défini (durée, accès) peut être nécessaire pour répondre à une enquête ou à une demande de justification.
- **Amélioration continue** : les logs permettent de comprendre un échec de collecte (DC inaccessible, Exchange injoignable) et d’ajuster la configuration ou les procédures.

Conserver le **dossier de sortie complet** (y compris Evidence.zip si généré) sans modification, sur un support sécurisé et selon votre politique de rétention.

---

## 12. Gestion des preuves

Pour que les éléments collectés restent exploitables en audit, assurance, dépôt de plainte ou vis-à-vis de la CNIL, les règles suivantes doivent être appliquées.

- **Ne pas modifier les fichiers générés** : ne pas éditer, renommer ni déplacer les fichiers dans le dossier de sortie horodaté (AD, Exchange, Endpoint, Report). Toute modification altère la valeur probante.
- **Ne pas ouvrir les CSV dans Excel avant d’en avoir fait une copie.** Excel peut reformater des dates, tronquer des valeurs ou modifier des caractères. Pour consulter un CSV, utiliser une copie ; conserver l’original intact.
- **Conserver Evidence.zip intact** : ne pas réouvrir l’archive pour en extraire ou modifier des fichiers. L’archive telle que générée constitue un lot de preuves cohérent ; la conserver sans altération.
- **Copier sur support externe** : dès que possible, copier l’intégralité du dossier de sortie (ou au minimum Evidence.zip et le transcript) sur un support dédié (clé USB, disque externe, espace sécurisé) identifié comme « preuves incident » et protégé en écriture si possible. Cela limite les risques de perte ou d’écrasement sur le poste d’exécution.
- **Importance pour l’assurance, le dépôt de plainte et la CNIL** : en cas de sinistre cyber, l’assurance peut exiger la preuve des actions réalisées et des données disponibles au moment des faits. En cas de dépôt de plainte, les autorités peuvent demander des éléments techniques ; des preuves non modifiées et documentées sont indispensables. En cas de violation de données à caractère personnel, la CNIL et les personnes concernées peuvent exiger des justifications ; le rapport et les logs constituent une trace de la réaction de l’organisation.

---

## 13. Bonnes pratiques

- **Ne pas nettoyer trop tôt** : éviter de lancer un « nettoyage » antivirus ou une réinstallation avant d’avoir collecté les preuves et compris l’étendue. Vous risquez de détruire des indices.
- **Ne pas redémarrer** les postes suspects sans nécessité : la mémoire RAM contient des artefacts utiles ; un redémarrage les efface.
- **Ne pas scanner immédiatement** les postes compromis avec un antivirus agressif : certains outils modifient ou suppriment des fichiers qui servent à l’enquête.
- **Préserver les preuves** : ne pas modifier, renommer ni déplacer les dossiers de sortie IncidentKit après exécution. Si vous copiez pour envoi à un prestataire, utiliser une copie et garder l’original.
- **Tester en amont** : faire au moins une exécution en **Collect** (et si possible **Investigate**) en temps calme pour vérifier que la config et les accès fonctionnent. En crise, vous n’aurez pas le temps de déboguer le DC ou Exchange.
- **Poste sain** : exécuter IncidentKit depuis un poste d’administration que vous considérez comme non compromis. En cas de doute, utiliser un poste dédié ou de secours.

---

## 14. Dépannage

### DC inaccessible

- **Symptôme** : erreur du type « RPC server is unavailable », « access denied », « The server is not operational », ou timeout.
- **Vérifications** :  
  - Le poste résout bien le nom du DC (ping, `nslookup dc01.contoso.local`).  
  - Le pare-feu (poste et DC) autorise l’accès aux journaux d’événements à distance (RPC, port 135).  
  - Le compte utilisé a les **droits de lecture** sur le journal Security du DC.  
- **Poste hors domaine** : utiliser `-CredentialMode Prompt` et saisir un compte domaine ayant les droits nécessaires.

### Exchange inaccessible

- **Symptôme** : erreur lors de la collecte Exchange (connexion refusée, authentification échouée).
- **Vérifications** :  
  - L’URI PowerShell dans `config.json` est correct (HTTP vs HTTPS, chemin `/PowerShell/`).  
  - Depuis un poste hors domaine : utiliser `auth: "Negotiate"` ou `"NTLM"` selon votre environnement.  
  - WinRM et pare-feu côté Exchange autorisent les connexions depuis votre poste.  
- L’outil **continue** même si Exchange échoue ; l’erreur est indiquée dans le rapport. Vous pouvez relancer plus tard une fois Exchange accessible.

### Credentials refusés

- **Symptôme** : « access denied », « logon failure ».
- Vérifier que le compte a bien les droits (lecture Security sur le DC, droits Exchange si utilisé).  
- Depuis un poste hors domaine : saisir le compte au format **domaine\utilisateur** (ou utilisateur@domaine selon le type d’auth).  
- Vérifier qu’il n’y a pas de blocage de compte (trop d’échecs) ou de stratégie (mot de passe expiré, compte désactivé).

### WinRM bloqué (collecte Endpoint à distance)

- **Symptôme** : erreur lors de la collecte avec `-TargetHost` (connexion WinRM impossible).
- **Vérifications** :  
  - Sur le **poste cible** : WinRM est activé (`Enable-PSRemoting` ou GPO).  
  - Pare-feu : règles « Windows Remote Management » autorisées.  
  - Le compte utilisé a les droits sur le poste cible (ex. membre des Admins locaux ou droit équivalent).  
- Si WinRM ne peut pas être activé sur la cible, la collecte Endpoint devra se faire **localement** sur le poste concerné (copier IncidentKit sur ce poste et lancer sans `-TargetHost` pour une collecte locale, si votre procédure le prévoit).

### Configuration introuvable

- **Symptôme** : « Configuration introuvable : … config.json ».
- Exécuter `.\IncidentKit-Setup.ps1` pour générer `config.json`, ou copier `sample-config.json` vers `config.json` et l’adapter. Le chemin peut être précisé avec `-ProfilePath "C:\Chemin\config.json"`.

---

## 15. Quand escalader

Les situations suivantes **nécessitent** de faire appel à un prestataire de réponse à incident (IR) et, le cas échéant, à votre assurance cyber. Ne pas rester seul sur ces cas.

- **Compte administrateur compromis** (ou suspicion forte) : un compte à privilèges élevés (Domain Admin, administrateur Exchange, etc.) compromis peut avoir servi à déployer des backdoors ou à étendre l’attaque. Une analyse forensique spécialisée est recommandée.
- **Plusieurs serveurs concernés** : dès que l’incident touche ou pourrait toucher plusieurs serveurs (plusieurs DC, plusieurs rôles), l’étendue dépasse en général le périmètre d’un outil de décision rapide ; un IR peut cartographier et contenir de façon cohérente.
- **Présence de chiffrement** (ransomware avéré, fichiers chiffrés) : la gestion du chiffrement, des clés et de la restauration relève d’une démarche structurée (forensic, négociation, restauration) et souvent d’un prestataire expérimenté.
- **Connexion externe inconnue sur un contrôleur de domaine** : une connexion depuis une IP externe inconnue vers un DC (ou des événements d’administration depuis cette IP) est un signal critique ; l’intégrité du DC et du domaine doit être évaluée par des spécialistes.
- **Doute sur l’étendue** : si vous ne savez pas jusqu’où l’attaque s’est étendue (persistance, autres comptes, autres systèmes), l’escalade permet d’obtenir une analyse de périmètre et un plan d’action adapté.

En cas de doute, privilégier l’escalade : un prestataire IR intervient sur la base des preuves déjà collectées (dossier IncidentKit, Evidence.zip) ; mieux vaut le solliciter tôt avec des preuves intactes que tard après des actions non documentées.

---

## 16. Valeur du rapport

Le rapport généré par IncidentKit (rapport technique, synthèse exécutive, score EBIOS, timeline, logs) a une valeur opérationnelle et de documentation ; sa portée doit être comprise par la direction et les responsables hiérarchiques.

- **Support de décision interne** : le rapport permet au RSI et à l’encadrement de prendre des décisions éclairées (confinement, changement de mots de passe, isolation de postes, appel à un prestataire) en s’appuyant sur des constats objectifs et datés.
- **Preuve de diligence** : il atteste que l’organisation a réagi en collectant et en analysant des éléments techniques dans un cadre défini. En cas d’audit, de sinistre assurance ou de contrôle, il constitue un élément de démonstration de la réaction à l’incident.
- **Documentation post-incident** : il sert de trace pour le retour d’expérience, la mise à jour des procédures et, le cas échéant, les échanges avec un prestataire IR ou les autorités.

**Ce que le rapport n’est pas** : il ne constitue **pas une expertise judiciaire** ni une attestation juridique. Pour des besoins d’expertise en vue d’une procédure judiciaire, une expertise réalisée par un tiers habilité (expert agréé, prestataire certifié) reste nécessaire. Le rapport IncidentKit peut en revanche être fourni comme **élément de contexte** ou de première documentation.

---

## 17. Avertissements importants

> **Encadré — À retenir**
>
> - **Cet outil ne chiffre pas** les données collectées ni les communications. Les fichiers sont stockés en clair dans le dossier de sortie. À vous de protéger ce dossier (droits, chiffrement du disque ou du support si nécessaire).
>
> - **Cet outil ne nettoie pas** les malwares ni les composants malveillants. Il collecte et analyse pour **aider à la décision**. Le nettoyage et la remédiation restent de votre responsabilité (interne ou via un prestataire).
>
> - **Il ne remplace pas un forensic complet** : pas d’analyse mémoire, pas d’analyse disque bas niveau, pas de reconstruction complète de la chaîne d’attaque. Pour une enquête approfondie ou des exigences juridiques/assurance, faire appel à des spécialistes.
>
> - **Il sert à la prise de décision rapide** : en situation de crise, il permet de recueillir des indices, de produire un rapport lisible et de proposer des actions de confinement documentées. Utilisez-le comme **socle** pour décider des prochaines étapes (confinement, escalade, déclaration, prestataire IR).

---

*Document généré pour IncidentKit v0.1 — Manuel opérationnel, usage RSI / administrateur système.*
 "# ITResponse" 

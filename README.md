# IncidentKit — Manuel opérationnel de réponse à incident
**Version : 0.1**

Outil de collecte, analyse et aide à la décision en situation de cyberattaque.

---

## 1. Présentation

### But de l’outil

IncidentKit est un **outil de réponse à incident informatique** conçu pour être utilisé **en situation réelle** par un RSI ou un administrateur système lorsqu’une cyberattaque est suspectée ou en cours.

Il permet de :

- collecter rapidement des données Active Directory, Exchange et Endpoint
- analyser ces données pour repérer des signaux d’alerte
- produire un rapport
- aider à la décision (agir ou escalader)

L’objectif est de **gagner du temps et de la clarté pendant la crise**, sans remplacer une intervention forensique complète.

---

### Ce que fait l’outil

- **Collecte** : journaux AD (connexions, privilèges, créations de comptes), règles Exchange, données d’un poste
- **Analyse** : détection d’activités suspectes
- **Rapport** : rapport technique + synthèse
- **Confinement** : actions proposées avec confirmation (désactivation compte, reset MDP)

---

### Ce qu’il ne fait pas

- ne nettoie pas les malwares
- ne répare pas les systèmes
- ne remplace pas un CERT ou un prestataire forensic

Il sert uniquement à la **prise de décision rapide** et à la **préservation des preuves**.

---

### Types d’incidents couverts

| Type | Usage recommandé |
|------|------------------|
| account_compromise | Compromission de compte |
| phishing | Phishing ciblé |
| infostealer | Vol d’informations |
| ransomware_suspect | Suspicion ransomware |

---

## 2. Périmètre de confiance de l’outil

### Ce que le rapport permet d’affirmer

- que des données ont été collectées à une date donnée
- que certains événements existent dans les journaux analysés
- que les constats sont reproductibles

### Ce qu’il ne permet PAS d’affirmer

- absence d’attaque
- absence d’intrusion
- absence de persistance

Absence d’IOC ≠ absence de compromission.

L’outil analyse **uniquement les journaux disponibles**.  
Si les logs sont incomplets ou effacés, le rapport l’est aussi.

Il sert à **décider rapidement**, pas à certifier un SI sain.

---

## 3. Principe de fonctionnement

Ordre volontaire :

1. Collecte
2. Analyse
3. Rapport
4. Confinement (optionnel)

### Pourquoi cet ordre est important

Toujours collecter avant d’agir.

Agir trop tôt :
- détruit les preuves
- masque l’attaque
- complique l’enquête

---

## 4. Prérequis

- PowerShell 5.1 ou supérieur
- Accès réseau au contrôleur de domaine
- Lecture des journaux Security AD
- Accès Exchange (si utilisé)
- WinRM activé pour un poste distant

### Poste recommandé
Utiliser un **poste d’administration sain**.

---

## 5. Installation

1. Copier le dossier IncidentKit sur un poste admin
2. Exécuter :

```powershell
.\IncidentKit-Setup.ps1

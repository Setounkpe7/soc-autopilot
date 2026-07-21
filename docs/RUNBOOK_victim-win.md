# RUNBOOK — VM `victim-win` (Voie B)

Guide autonome pour configurer la VM Windows du labo, **sans avoir besoin de VS Code**.

---

## COMMENT LIRE CE FICHIER SANS VS CODE

VS Code consomme 1-2 Go — trop quand la VM Windows tourne (4 Go). Utilise plutôt :

```bash
export SOC_DIR="/media/mdoub/Data/Personal Projects/soc-autopilot"
less "$SOC_DIR/docs/RUNBOOK_victim-win.md"
```

Navigation dans `less` : flèches / `Espace` = page suivante / `/motcle` = rechercher /
`n` = occurrence suivante / `q` = quitter. **Coût mémoire quasi nul.**

Alternative un peu plus confortable (léger aussi) :
```bash
gnome-text-editor "$SOC_DIR/docs/RUNBOOK_victim-win.md"
```

> **Règle de session « détection » :** VM Windows (4 Go) + Wazuh (~3 Go) + hôte (~2,5 Go)
> ≈ 9,5 Go sur 11,6 Go. Ça passe **à condition de fermer VS Code et le navigateur**.

---

## RAPPEL — CE QU'ON CONSTRUIT

```
[Atomic Red Team]  simule une technique d'attaque réelle (MITRE ATT&CK)
        |
[Sysmon]           observe et journalise le comportement du processus
        |
[Agent Wazuh]      expédie ces journaux vers le manager
        |          (réseau 192.168.56.x)
[Wazuh Manager]    sur l'HÔTE Linux (192.168.56.1) — règles -> alerte
        |
[soc-autopilot]    enrichit (VirusTotal + threat-intel), ouvre un cas,
                   demande une approbation Slack, exécute la réponse
```

**Plan d'adressage (Voie B) :**
- `192.168.56.1`  = **ton hôte Linux** (Wazuh y tourne en conteneurs)
- `192.168.56.20` = **la VM Windows** (réservation DHCP sur le MAC `52:54:00:56:00:20`)

> La Voie B diffère de la doc d'origine : le SIEM n'est pas dans une VM à `.10`,
> il est **sur l'hôte**. Partout où la doc dit `192.168.56.10`, lis `192.168.56.1`.

---

## ÉTAPE 0 — PRESSE-PAPIERS PARTAGÉ (à faire en premier !)

**Pourquoi :** sans ça, tu ne peux **pas copier-coller** entre ton hôte et la VM — tu
devrais retaper toutes les commandes à la main. `spice-guest-tools` installe l'agent
invité qui active le presse-papiers partagé (et le redimensionnement d'écran).

**C'est la seule commande que tu devras taper manuellement.** Dans la VM,
**PowerShell en Administrateur** (clic droit sur le menu Démarrer -> *Terminal (Admin)*) :

```powershell
New-Item -ItemType Directory -Path C:\Tools -Force
Invoke-WebRequest -Uri "https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe" -OutFile C:\Tools\spice-guest-tools.exe
Start-Process C:\Tools\spice-guest-tools.exe -Wait
Restart-Computer
```

Après le redémarrage, le copier-coller hôte <-> VM fonctionne. **Tout le reste devient
du copier-coller.**

---

## ÉTAPE 1 — RÉSEAU ET ADRESSAGE

**Pourquoi :** c'est le **seul chemin** par lequel la télémétrie remontera vers Wazuh.
On avait coupé le lien réseau pour forcer la création d'un compte local pendant
l'installation ; il faut le rétablir.

**Sur l'HÔTE (ton terminal Linux) :**
```bash
virsh -c qemu:///system domif-setlink victim-win 52:54:00:56:00:20 up
```

**Dans la VM (PowerShell Admin) :**
```powershell
ipconfig
ping 192.168.56.1
```

**Ce que tu dois voir :**
- IPv4 = **`192.168.56.20`** — garanti par la réservation DHCP liée à l'adresse MAC.
  Une IP stable rend tes tests **reproductibles** (un labo non déterministe ne prouve rien).
- `ping 192.168.56.1` **répond** — c'est ton hôte Linux, futur point de collecte.

**Si ça casse :**
- Pas d'IP -> vérifier le réseau côté hôte : `virsh -c qemu:///system net-list --all`
  (`soc-hostonly` doit être *active*).
- IP en `169.254.x.x` -> le DHCP n'a pas répondu : lien réseau encore coupé (rejoue la
  commande `domif-setlink ... up`).
- `virbr-soc: <NO-CARRIER> state DOWN` côté hôte -> aucune interface invitée active :
  VM éteinte, ou lien coupé (`domif-setlink ... up`).

### 1.3 Pare-feu de l'hôte (ufw) — CRITIQUE pour l'agent Wazuh

**Pourquoi :** `ufw` est actif sur l'hôte en *deny incoming*. En Voie B le manager Wazuh
tourne **sur l'hôte** : sans règle explicite, l'agent de la VM ne pourra **jamais** s'y
connecter — et le symptôme (`Never connected`) n'indique pas la cause. À faire **avant**
l'Étape 4.

**Sur l'HÔTE :**
```bash
sudo ufw allow in on virbr-soc proto tcp to any port 1514,1515,55000 comment 'Wazuh agent + API depuis le labo'
sudo ufw reload
sudo ufw status | grep virbr-soc
```

**Rôle de chaque port :**

| Port | Rôle |
|------|------|
| 1514 | flux d'événements agent -> manager |
| 1515 | enrôlement (enregistrement) de l'agent |
| 55000 | API REST Wazuh (appelée par le SOAR, ex. `wazuh.isolate_host`) |

> On n'ouvre **que ces 3 ports**, et uniquement **sur l'interface du labo** (`virbr-soc`),
> pas globalement : c'est du moindre privilège. Un `ufw allow in on virbr-soc` tout court
> marcherait aussi, mais ouvrirait toute la surface de l'hôte au réseau du labo.

> **Astuce transfert de fichiers** (si le presse-papiers coince) : ouvre temporairement
> le port 8000, sers un dossier depuis l'hôte, récupère-le dans la VM.
> ```bash
> sudo ufw allow in on virbr-soc proto tcp to any port 8000
> cd "$SOC_DIR/tools" && python3 -m http.server 8000 --bind 192.168.56.1
> ```
> Dans la VM : `Invoke-WebRequest http://192.168.56.1:8000/monfichier.ps1 -OutFile C:\Tools\monfichier.ps1`
> Referme ensuite : `sudo ufw delete allow in on virbr-soc proto tcp to any port 8000`

---

## ÉTAPE 2 — DÉSACTIVER DEFENDER (ET SAVOIR LE JUSTIFIER)

**Pourquoi :** Defender bloque les atomics **avant** leur exécution. Résultat : aucune
télémétrie générée, donc **rien à détecter**. Le labo ne teste plus rien.

### 2.1 D'abord la Protection contre les falsifications (piège Windows 11)

La *Tamper Protection* empêche PowerShell de modifier Defender. Désactive-la **dans
l'interface graphique** :

> Paramètres -> Confidentialité et sécurité -> Sécurité Windows ->
> Protection contre les virus et menaces -> **Gérer les paramètres** ->
> **Protection contre les falsifications : Désactivé**

### 2.2 Ensuite, en PowerShell Admin

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
New-Item -ItemType Directory -Path C:\AtomicRedTeam -Force
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```

**Vérifier :**
```powershell
Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath
```
`DisableRealtimeMonitoring` doit être `True`.

### 🎯 JUSTIFICATION D'ENTREVUE (à retenir par cœur)

> « Je désactive Defender uniquement sur une VM jetable, isolée, sans accès entrant.
> En production on ferait l'inverse : on garde l'EDR et on utilise un anneau de test
> avec des exclusions ciblées et validées. »

Désactiver Defender **sans expliquer** = amateur.
Expliquer **et donner l'alternative de production** = ingénieur.

---

## ÉTAPE 3 — SYSMON : LA PIÈCE MAÎTRESSE

**Pourquoi :** Windows seul ne dit pas **quel processus a lancé quoi, avec quelle ligne
de commande**. Sans Sysmon, **~80 % des détections Windows sont impossibles**. Sysmon est
un pilote Microsoft gratuit qui ajoute ces événements dans un journal dédié.

```powershell
New-Item -ItemType Directory -Path C:\Tools -Force
Set-Location C:\Tools

# 1. Sysmon (Microsoft Sysinternals)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force

# 2. Config de référence de l'industrie (SwiftOnSecurity)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile C:\Tools\Sysmon\sysmonconfig.xml

# 3. Installation
Set-Location C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Vérifier :**
```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List TimeCreated, Id
```
Tu dois voir des **EID 1** (Process Create). **Si ces événements apparaissent, la
fondation de tout le projet existe.**

**Pourquoi une config toute faite ?** Sysmon sans configuration journalise soit trop peu,
soit tout (et noie le SIEM). La config SwiftOnSecurity est un filtre affiné par la
communauté : elle garde le signal, jette le bruit.

### Aide-mémoire — EID Sysmon à connaître

| EID | Événement           | Détecte quoi                                        |
|-----|---------------------|-----------------------------------------------------|
| 1   | Process Create      | ligne de commande + parent + hash — **la base**      |
| 3   | Network Connection  | C2, exfiltration, beaconing                          |
| 7   | Image Loaded        | DLL sideloading                                      |
| 8   | CreateRemoteThread  | injection de processus                               |
| 10  | ProcessAccess       | **dump de LSASS** (T1003.001)                        |
| 11  | File Create         | droppers, persistance                                |
| 13  | Registry Set        | Run keys, persistance (T1547.001)                    |
| 22  | DNS Query           | résolution de domaine malveillant                    |

### 🎯 QUESTION D'ENTREVUE QUASI GARANTIE

> « Pourquoi Sysmon plutôt que l'audit natif Windows ? »
>
> « L'EID 4688 natif n'inclut pas la ligne de commande sans une GPO spécifique, n'a pas
> de hash, pas de GUID de processus fiable pour reconstruire l'arbre, et pas de
> télémétrie réseau par processus. Sysmon donne les trois, avec un GUID stable qui
> permet de corréler parent-enfant à travers les redémarrages. »

---

## ÉTAPE 4 — AGENT WAZUH

> ⚠️ **NE FAIS CETTE ÉTAPE QU'APRÈS que Wazuh tourne sur l'hôte** (étape « C » du projet).
> L'agent s'enrôle auprès du manager au moment de l'installation : si le manager n'est
> pas joignable sur `192.168.56.1`, l'enrôlement échoue.

**Pourquoi :** Sysmon **journalise localement**. L'agent Wazuh est le **transporteur** qui
expédie ces journaux vers le SIEM. Sans lui, ta télémétrie reste prisonnière de la VM.

### 4.1 Installation

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"

msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q `
  WAZUH_MANAGER="192.168.56.1" `
  WAZUH_REGISTRATION_SERVER="192.168.56.1" `
  WAZUH_AGENT_NAME="victim-win"

Start-Service WazuhSvc
Get-Service WazuhSvc
```

> Note Voie B : le manager est à **`192.168.56.1`** (ton hôte), pas `.10` comme dans la doc.

### 4.2 Dire à l'agent de collecter Sysmon

**Pourquoi :** par défaut l'agent ne remonte pas le journal Sysmon. Il faut le déclarer
explicitement, ainsi que les journaux Security et PowerShell.

```powershell
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$blocks = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
(Get-Content $conf -Raw) -replace '</ossec_config>', "$blocks`r`n</ossec_config>" | Set-Content $conf -Encoding UTF8
Restart-Service WazuhSvc
```

**Vérifier (depuis l'HÔTE Linux) :**
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```
Doit afficher : `ID: 001, Name: victim-win, ..., Active`.

Puis dans le Dashboard Wazuh -> **Discover** -> filtre `agent.name: victim-win` :
tu dois voir des événements Sysmon arriver **en direct**.

---

## ÉTAPE 5 — ATOMIC RED TEAM

**Pourquoi :** c'est la bibliothèque de tests qui **simule de vraies techniques
MITRE ATT&CK**. C'est ce qui va générer la télémétrie que tes règles Sigma doivent
attraper. Sans elle, tu ne peux **pas prouver** que tes détections fonctionnent.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force -InstallPath C:\AtomicRedTeam
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

**Vérifier :**
```powershell
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```
Tu dois voir la liste des tests disponibles pour PowerShell (T1059.001).

> ⚠️ On **liste** seulement pour l'instant (`-ShowDetailsBrief`). On **exécutera** les
> tests plus tard, une fois les règles de détection écrites — sinon tu génères du bruit
> sans savoir quoi en faire.

---

## ÉTAPE 6 — SNAPSHOT (obligatoire)

**Pourquoi :** tu reviendras sur ce point de départ propre **après chaque test
d'attaque**. C'est ce qui rend tes tests **reproductibles** — l'argument le plus fort
de ton labo en entrevue.

> ⚠️ La doc parle de VirtualBox ; nous sommes sur **KVM/libvirt**, la commande diffère.

**Sur l'HÔTE Linux :**
```bash
# (recommandé) éteindre proprement la VM depuis Windows, puis :
virsh -c qemu:///system snapshot-create-as victim-win 03-victim-prete \
  "Sysmon + agent Wazuh + Atomic Red Team installes"

# lister les snapshots
virsh -c qemu:///system snapshot-list victim-win

# REVENIR à l'état propre (après un test d'attaque)
virsh -c qemu:///system snapshot-revert victim-win 03-victim-prete
```

> Astuce : si tu prends le snapshot **VM allumée**, il inclut aussi la RAM — le retour
> arrière te replace instantanément dans la session en cours. Plus lourd en disque,
> mais très pratique.

---

## DÉPANNAGE RAPIDE

| Symptôme | Cause probable | Correctif |
|---|---|---|
| Pas de copier-coller VM <-> hôte | `spice-guest-tools` absent | Étape 0 |
| Pas d'IP / `169.254.x.x` | lien réseau coupé | `domif-setlink ... up` (Étape 1) |
| `Set-MpPreference` échoue | Tamper Protection active | Étape 2.1 (interface graphique) |
| Aucun EID Sysmon | service non démarré | `Get-Service Sysmon64` -> `Start-Service Sysmon64` |
| Agent Wazuh `Never connected` | manager pas démarré / mauvaise IP | Wazuh up sur l'hôte + vérifier `.1` |
| VM très lente | RAM saturée | fermer VS Code + navigateur sur l'hôte |
| virt-manager ne se connecte pas | groupe `libvirt` pas actif | déconnexion/reconnexion de session |

---

## COMMANDES UTILES CÔTÉ HÔTE

```bash
export SOC_DIR="/media/mdoub/Data/Personal Projects/soc-autopilot"

# État de la VM
virsh -c qemu:///system list --all
virsh -c qemu:///system domifaddr victim-win        # IP vue par le DHCP

# Démarrer / arrêter la VM
virsh -c qemu:///system start victim-win
virsh -c qemu:///system shutdown victim-win         # propre
virsh -c qemu:///system destroy victim-win          # forcer (comme couper le courant)

# Réseau
virsh -c qemu:///system net-list --all
virsh -c qemu:///system domif-setlink victim-win 52:54:00:56:00:20 up|down

# Postgres du projet
cd "$SOC_DIR/infra/soc-stack" && docker compose up -d      # démarrer
cd "$SOC_DIR/infra/soc-stack" && docker compose stop       # arrêter (libère la RAM)
```

---

## ORDRE RECOMMANDÉ

1. Étape 0 (presse-papiers) — **fais-la en premier, tout devient copier-coller**
2. Étape 1 (réseau) -> Étape 2 (Defender) -> Étape 3 (Sysmon)
3. **PAUSE** : démarrer Wazuh sur l'hôte (étape « C » du projet)
4. Étape 4 (agent Wazuh) -> Étape 5 (Atomic) -> Étape 6 (snapshot)

# SOC Autopilot — Fichier 2/5
# Installation complète : ton poste + le labo

> Objectif : à la fin de ce fichier, tu as **un labo qui tourne** et **tous les outils sur ton poste**. Durée : **3 à 4 heures**. Fais-le aujourd'hui (J1, 16 juillet).
> Chaque bloc suit le même format : **Pourquoi** → **Installer** → **Vérifier** → **Si ça casse**.

---

## 0. Avant de commencer — vérifie ton matériel

```bash
# Linux
free -h            # RAM
nproc              # cœurs CPU
df -h /            # espace disque
```
```powershell
# Windows (PowerShell)
Get-CimInstance Win32_ComputerSystem | Select TotalPhysicalMemory, NumberOfLogicalProcessors
Get-PSDrive C
```

| Ressource | Minimum | Confortable |
|---|---|---|
| RAM | **16 Go** | 32 Go |
| CPU | 4 cœurs | 8 cœurs |
| Disque libre | **80 Go** | 150 Go |
| Virtualisation | activée dans le BIOS (VT-x / AMD-V) | — |

### ⚠️ Si tu as seulement 8 Go de RAM
Ne renonce pas. Plan B :
- **Pas de VM Windows.** Tu fais tout le labo en Linux (Wazuh + agent Linux sur la même machine ou une seule VM).
- Tu remplaces les tests Windows/Sysmon par les **atomics Linux** (T1059.004 bash, T1053.003 cron, T1136.001 useradd, T1070.002 effacement de logs, T1046 scan réseau).
- Tu perds Sysmon. **Compense en entrevue :** *« Mon labo est Linux par contrainte de RAM. La chaîne est identique ; sur Windows la seule différence est la source de télémétrie — Sysmon EID 1 au lieu d'auditd/execve — et mes règles Sigma sont écrites avec le logsource `product: windows` pour trois d'entre elles, converties mais non exécutées faute de poste Windows. »* **L'honnêteté chiffrée passe toujours.**

### Vérifier que la virtualisation est active
```bash
# Linux
grep -Eoc '(vmx|svm)' /proc/cpuinfo    # doit retourner > 0
```
```powershell
# Windows
systeminfo | Select-String "Hyper-V"
```
Si c'est désactivé → redémarre, entre dans le BIOS/UEFI (F2/F10/Suppr), active **Intel VT-x** ou **AMD-V** / **SVM Mode**.

---

## 1. Architecture des machines

Tu vas avoir **3 machines** (ou 2 en plan B) :

| Machine | Rôle | RAM | Qui l'héberge |
|---|---|---|---|
| **Ton poste** | Développement, Git, VS Code, Terraform, Helm, sigma-cli | — | toi |
| **VM `soc-lab`** (Ubuntu 22.04) | Wazuh, TheHive, PostgreSQL, k3s, soc-autopilot | **8 Go**, 4 vCPU, 60 Go | VirtualBox / Hyper-V / VMware |
| **VM `victim-win`** (Windows 10/11) | La cible : Sysmon + agent Wazuh + Atomic Red Team | **4 Go**, 2 vCPU, 40 Go | idem |

**Réseau :** les deux VMs sur un réseau **Host-Only** ou **Bridged**, **jamais** exposées à Internet en entrant.
Plan d'adressage (utilise-le tel quel, ça t'évitera de réfléchir) :

```
soc-lab     : 192.168.56.10
victim-win  : 192.168.56.20
ton poste   : 192.168.56.1   (interface host-only)
```

> **Pourquoi une VM et pas ton poste directement ?** Trois raisons à dire en entrevue : (1) **isolation** — j'exécute de vraies techniques d'attaque, ça ne touche pas ma machine ; (2) **snapshot** — je reviens à un état propre entre deux tests, ce qui rend mes tests **reproductibles** ; (3) **c'est ce qu'on fait en vrai** — un labo de détection est jetable par conception.

---

## 2. Ton poste — les outils

### 2.1 Git

**Pourquoi :** tout le projet est du Detection-as-Code. Git n'est pas un outil de sauvegarde ici, c'est **la source de vérité de tes détections**.

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y git
```
```powershell
# Windows
winget install --id Git.Git -e
```
**Configurer (une fois) :**
```bash
git config --global user.name "Michel-Ange Doubogan"
git config --global user.email "mdoubogan@yahoo.fr"
git config --global init.defaultBranch main
git config --global pull.rebase true
```
**Vérifier :** `git --version` → ≥ 2.34

---

### 2.2 Python 3.12 + uv

**Pourquoi Python 3.12 :** c'est la version de `threat-intel-api`. Reste cohérent — un évaluateur qui voit deux versions différentes se demande pourquoi.
**Pourquoi `uv` :** gestionnaire de paquets Python écrit en Rust, 10 à 100× plus rapide que pip. En CI, ça fait passer un job de 90 s à 8 s. C'est un détail qui montre que tu suis l'écosystème. *(Si tu préfères rester sur `pip` + `venv`, aucun problème — remplace `uv pip` par `pip` partout.)*

```bash
# Ubuntu
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3.12-dev
# uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```
```powershell
# Windows
winget install --id Python.Python.3.12 -e
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```
**Vérifier :**
```bash
python3.12 --version   # Python 3.12.x
uv --version
```

---

### 2.3 Docker + Docker Compose

**Pourquoi :** Wazuh, TheHive, PostgreSQL et ton app tournent en conteneurs. Et l'offre demande explicitement « conteneurisation ».

```bash
# Ubuntu — installation officielle (n'utilise PAS le paquet apt "docker.io", il est vieux)
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Pouvoir lancer docker sans sudo (déconnecte/reconnecte après)
sudo usermod -aG docker $USER
newgrp docker
```
```powershell
# Windows → Docker Desktop (active le backend WSL2 dans les settings)
winget install --id Docker.DockerDesktop -e
```
**Vérifier :**
```bash
docker run --rm hello-world
docker compose version    # v2.x
```
**Si ça casse :** `permission denied on /var/run/docker.sock` → tu as oublié le `newgrp docker` ou il faut te déconnecter/reconnecter.

---

### 2.4 VS Code + extensions

```bash
# Ubuntu
sudo snap install --classic code
```
```powershell
winget install --id Microsoft.VisualStudioCode -e
```
**Extensions à installer** (Ctrl+Shift+X) :
| Extension | Pourquoi |
|---|---|
| `ms-python.python` + `charliermarsh.ruff` | Python + linter/formatter |
| `redhat.vscode-yaml` | **Critique** — validation de schéma sur tes playbooks et Sigma |
| `hashicorp.terraform` | Autocomplétion HCL |
| `ms-kubernetes-tools.vscode-kubernetes-tools` | k8s + Helm |
| `github.vscode-github-actions` | Éditer les workflows sans se tromper |
| `eamodio.gitlens` | Voir l'historique d'une règle de détection en un coup d'œil |

---

### 2.5 sigma-cli + backends

**Pourquoi :** c'est le traducteur. Il prend ta règle Sigma universelle et sort la requête native du SIEM.

```bash
uv tool install sigma-cli
# Les backends (un par SIEM cible)
sigma plugin install elasticsearch
sigma plugin install splunk
sigma plugin install opensearch     # Wazuh Indexer = fork OpenSearch
```
**Vérifier :**
```bash
sigma list targets     # doit lister elasticsearch, splunk, opensearch...
sigma version
```
**Si `sigma plugin install` échoue :** fallback pip explicite —
```bash
uv tool install sigma-cli --with pysigma-backend-elasticsearch --with pysigma-backend-splunk
```

---

### 2.6 Terraform

**Pourquoi :** IaC exigé par l'offre. Et c'est un de tes gaps roadmap — cette semaine il disparaît.

```bash
# Ubuntu
wget -O- https://apt.releases.hashicorp.com/gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y terraform
```
```powershell
winget install --id Hashicorp.Terraform -e
```
**Vérifier :** `terraform version` → ≥ 1.7

---

### 2.7 kubectl + Helm

```bash
# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# Helm
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```
```powershell
winget install --id Kubernetes.kubectl -e
winget install --id Helm.Helm -e
```
**Vérifier :** `kubectl version --client` et `helm version`

---

### 2.8 Outils de sécurité du pipeline

**Pourquoi :** ce sont les jobs de ta CI. Tu les installes en local pour les faire échouer **avant** de pousser — c'est le principe du shift-left que tu as appliqué sur RailsGoat et Find-One.

```bash
uv tool install ruff          # lint + format (ruleset sécurité)
uv tool install bandit        # SAST Python
uv tool install mypy          # typage strict
uv tool install pip-audit     # SCA
uv tool install checkov       # IaC (Terraform + K8s)
uv tool install detect-secrets
uv tool install pre-commit

# Semgrep
uv tool install semgrep

# Trivy (scan de conteneur)
sudo apt install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
  sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
  https://aquasecurity.github.io/trivy-repo/deb generic main" | \
  sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install -y trivy

# tfsec
curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash

# Cosign (signature d'image, keyless via OIDC)
curl -sLO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign && sudo chmod +x /usr/local/bin/cosign

# Hadolint (lint Dockerfile)
sudo wget -O /usr/local/bin/hadolint \
  https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
sudo chmod +x /usr/local/bin/hadolint

# kubeconform (validation des manifests k8s)
curl -sL https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-linux-amd64.tar.gz \
  | tar xz && sudo mv kubeconform /usr/local/bin/
```

**Vérifier :** `ruff --version && bandit --version && trivy --version && checkov --version && cosign version`

---

### 2.9 VirtualBox (ou Hyper-V)

**Pourquoi :** pour les 2 VMs du labo.

```bash
# Ubuntu
sudo apt install -y virtualbox virtualbox-ext-pack
```
```powershell
# Windows : soit VirtualBox…
winget install --id Oracle.VirtualBox -e
# …soit Hyper-V (déjà présent en Pro/Enterprise) :
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```
> ⚠️ **Sur Windows, Hyper-V et VirtualBox se battent.** Si tu as Docker Desktop (qui utilise WSL2 = Hyper-V), VirtualBox sera lent ou refusera de démarrer une VM 64 bits. **Choisis Hyper-V** dans ce cas, c'est plus simple.

**Créer le réseau host-only (VirtualBox) :**
`Fichier → Outils → Gestionnaire de réseau hôte → Créer` → IPv4 `192.168.56.1/24`, DHCP désactivé.

---

## 3. La VM `soc-lab` (Ubuntu 22.04)

### 3.1 Créer la VM
1. Télécharge l'ISO : https://releases.ubuntu.com/22.04/ (Server, pas Desktop — pas besoin de GUI, tu économises 2 Go de RAM).
2. VirtualBox → Nouvelle → Linux / Ubuntu 64-bit → **8192 Mo** RAM → **4 CPU** → disque **60 Go** dynamique.
3. Réseau : Adaptateur 1 = **NAT** (pour Internet), Adaptateur 2 = **Réseau host-only** (pour te connecter).
4. Installe Ubuntu Server, crée l'utilisateur `michelange`, coche **OpenSSH server**.

### 3.2 IP fixe
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
```yaml
network:
  version: 2
  ethernets:
    enp0s3:                 # adaptateur NAT — vérifie le nom avec `ip a`
      dhcp4: true
    enp0s8:                 # adaptateur host-only
      dhcp4: false
      addresses: [192.168.56.10/24]
```
```bash
sudo netplan apply
ip a                        # vérifie 192.168.56.10
```
**Depuis ton poste :** `ssh michelange@192.168.56.10` → à partir de maintenant, travaille en SSH, c'est plus confortable.

### 3.3 Préparer la VM
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git jq net-tools
```
**Docker sur la VM :** rejoue exactement le bloc §2.3 (version Ubuntu).

### 3.4 ⚠️ Le paramètre kernel qui te fera perdre 2 heures si tu l'oublies
```bash
# Elasticsearch/OpenSearch refuse de démarrer sans ça
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```
> **Pourquoi :** Elasticsearch utilise `mmap` intensivement pour lire ses index. La limite Linux par défaut (65530) est trop basse et le conteneur meurt au démarrage avec une erreur cryptique. **C'est l'erreur n°1 de tous ceux qui installent Wazuh.** Si tu le sais, tu le dis en entrevue — c'est un détail d'opérateur, pas de lecteur de tutoriel.

### 3.5 Snapshot !
```
VirtualBox → soc-lab → Instantanés → Prendre → "01-base-propre"
```
> **Prends un snapshot après chaque étape majeure.** Quand tu casseras Wazuh à 23 h (ça arrivera), tu reviendras en 20 secondes au lieu de recommencer.

---

## 4. Wazuh (SIEM + EDR) — le cœur du labo

### 4.1 Ce que tu installes exactement

Wazuh, c'est **3 conteneurs** :
| Conteneur | Rôle | Analogie |
|---|---|---|
| **Wazuh Manager** | Reçoit les événements des agents, applique les règles (les *decoders* parsent, les *rules* décident), déclenche les alertes et les active responses | Le cerveau |
| **Wazuh Indexer** | Stocke et rend cherchable (fork d'OpenSearch = Elasticsearch) | La mémoire |
| **Wazuh Dashboard** | L'interface web (fork de Kibana) | Les yeux |

### 4.2 Installation
```bash
cd ~
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node

# 1. Générer les certificats TLS (Wazuh chiffre tout en interne)
docker compose -f generate-indexer-certs.yml run --rm generator

# 2. Démarrer
docker compose up -d

# 3. Regarder ça monter (~3-5 min la première fois)
docker compose logs -f wazuh.manager
```
**Vérifier :**
```bash
docker compose ps          # 3 conteneurs "running"
curl -k -u admin:SecretPassword https://localhost:9200/_cluster/health | jq
```
Puis dans ton navigateur (sur ton poste) : **https://192.168.56.10:443**
- Identifiants par défaut : `admin` / `SecretPassword`
- ⚠️ **Change-les.** Tu ne peux pas mettre sur GitHub un projet de sécurité avec les creds par défaut. Édite `docker-compose.yml` + `config/wazuh_indexer/internal_users.yml`. Documente la procédure dans `docs/`.

### 4.3 Si ça casse
| Symptôme | Cause | Fix |
|---|---|---|
| `wazuh.indexer` redémarre en boucle | `vm.max_map_count` | §3.4 |
| `max virtual memory areas too low` | idem | §3.4 |
| Dashboard « Server not ready » | l'indexer n'est pas encore up | attends 3 min, `docker compose logs wazuh.indexer` |
| Certificats invalides | génération incomplète | `docker compose down -v` puis rejoue le générateur |
| Pas de RAM | 8 Go, c'est le strict minimum | ferme tout le reste |

### 4.4 L'API Wazuh — ton point d'intégration
```bash
# Obtenir un token (valide 15 min)
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr37P450r.*- -X POST \
  "https://192.168.56.10:55000/security/user/authenticate?raw=true")
echo $TOKEN

# Lister les agents
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://192.168.56.10:55000/agents?pretty=true" | jq '.data.affected_items[] | {id,name,status}'
```
> **Note-le :** cette API est ce que ton action `wazuh.isolate_host` va appeler. Le token expire en 15 min → ton client Python devra le **rafraîchir automatiquement**. C'est un détail que tu mentionneras (« gestion du cycle de vie du token, avec cache et refresh anticipé »).

### 4.5 Snapshot → `"02-wazuh-ok"`

---

## 5. La VM `victim-win` (Windows 10/11)

### 5.1 Obtenir Windows légalement et gratuitement
- **Option A (recommandée) :** VMs d'évaluation Microsoft, 90 jours, prêtes à l'emploi :
  https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/ → « MSEdge on Win10 » ou VM d'évaluation Windows 11 Enterprise.
- **Option B :** ISO Windows 11 Enterprise Evaluation (90 j) sur le Microsoft Evaluation Center.
- Config VM : **4096 Mo**, 2 vCPU, 40 Go, réseau **host-only** + NAT.
- IP fixe : `192.168.56.20`.

### 5.2 Désactiver Defender — et pourquoi c'est légitime ici
```powershell
# PowerShell en Administrateur, SUR LA VM UNIQUEMENT
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```
> **Justification à mettre dans le README et à dire en entrevue :** *« Defender bloque les atomics avant qu'ils ne s'exécutent, donc aucune télémétrie n'est générée et je ne peux pas tester mes détections. Je le désactive uniquement sur une VM jetable, isolée, sans accès entrant. En production, on ferait l'inverse : on garde Defender et on utilise un anneau de test avec exclusions ciblées et validées. »*
> Un candidat qui désactive Defender sans expliquer = amateur. Un candidat qui explique **et donne l'alternative de production** = ingénieur.

### 5.3 Sysmon — LA pièce maîtresse

**Pourquoi (à savoir par cœur) :** sans Sysmon, Windows ne te dit pas quel processus a lancé quoi avec quelle ligne de commande. **80 % des détections Windows deviennent impossibles.** Sysmon est un pilote Microsoft gratuit qui ajoute ces événements dans un journal dédié.

```powershell
# PowerShell Admin sur victim-win
New-Item -ItemType Directory -Path C:\Tools -Force
Set-Location C:\Tools

# 1. Télécharger Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force

# 2. Télécharger la config de référence (SwiftOnSecurity — le standard de l'industrie)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile C:\Tools\Sysmon\sysmonconfig.xml

# 3. Installer
Set-Location C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```
**Vérifier :**
```powershell
Get-Service Sysmon64                                  # Running
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List TimeCreated, Id, Message
```
Tu dois voir des **EID 1** (Process Create) défiler.

**Les EID que tu dois connaître par cœur :**
| EID | Événement | Détecte quoi |
|---|---|---|
| **1** | Process Create | ligne de commande complète + parent + hash → **la base de tout** |
| **3** | Network Connection | C2, exfiltration, beaconing |
| **7** | Image Loaded | DLL sideloading |
| **8** | CreateRemoteThread | injection de processus |
| **10** | ProcessAccess | **dump de LSASS** (T1003.001) |
| **11** | File Create | droppers, persistence |
| **13** | Registry Set | Run keys, persistence (T1547.001) |
| **22** | DNS Query | résolution de domaine malveillant |

> **Question d'entrevue :** « Pourquoi Sysmon plutôt que l'audit natif Windows ? » → *« L'EID 4688 natif n'inclut pas la ligne de commande sans une GPO spécifique, n'a pas de hash, pas de GUID de processus fiable pour reconstruire l'arbre, et pas de télémétrie réseau par processus. Sysmon donne les trois, avec un GUID stable qui permet de corréler parent-enfant à travers les redémarrages. »*

### 5.4 Agent Wazuh sur `victim-win`
```powershell
# PowerShell Admin
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" `
  -OutFile "$env:TEMP\wazuh-agent.msi"

msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q `
  WAZUH_MANAGER="192.168.56.10" `
  WAZUH_REGISTRATION_SERVER="192.168.56.10" `
  WAZUH_AGENT_NAME="victim-win"

Start-Service WazuhSvc
Get-Service WazuhSvc
```

**Dire à l'agent de collecter Sysmon** — édite `C:\Program Files (x86)\ossec-agent\ossec.conf`, ajoute dans `<ossec_config>` :
```xml
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
```
```powershell
Restart-Service WazuhSvc
```
**Vérifier depuis `soc-lab` :**
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
# doit afficher : ID: 001, Name: victim-win, IP: any, Active
```
Puis dans le Dashboard Wazuh → **Discover** → filtre `agent.name: victim-win` → tu dois voir des événements Sysmon arriver **en direct**. 🎉

> **C'est le moment le plus important de la semaine.** Si tu vois cette ligne apparaître, la fondation existe. Tout le reste se construit dessus.

### 5.5 Atomic Red Team
```powershell
# PowerShell Admin sur victim-win
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force -InstallPath C:\AtomicRedTeam
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```
**Vérifier :**
```powershell
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```
Tu dois voir la liste des tests disponibles pour PowerShell.

### 5.6 Snapshot → `"03-victim-prete"`
> **Snapshot obligatoire ici.** Tu vas revenir dessus après **chaque** test d'attaque. C'est ce qui rend tes tests reproductibles.

---

## 6. TheHive 5 + PostgreSQL (sur `soc-lab`)

**Pourquoi TheHive :** c'est le dossier d'enquête. Ton playbook y ouvre un cas pré-rempli avec les observables. Sans lui, ton SOAR notifie mais ne **capitalise** rien.

```bash
mkdir -p ~/soc-stack && cd ~/soc-stack
nano docker-compose.yml
```
```yaml
services:
  cassandra:
    image: cassandra:4.1
    container_name: cassandra
    environment:
      - MAX_HEAP_SIZE=512M
      - HEAP_NEWSIZE=128M
      - CASSANDRA_CLUSTER_NAME=thp
    volumes: [ "cassandra-data:/var/lib/cassandra" ]
    restart: unless-stopped

  elasticsearch-thehive:
    image: elasticsearch:7.17.22
    container_name: elasticsearch-thehive
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes: [ "es-data:/usr/share/elasticsearch/data" ]
    restart: unless-stopped

  thehive:
    image: strangebee/thehive:5.2
    container_name: thehive
    depends_on: [cassandra, elasticsearch-thehive]
    ports: [ "9000:9000" ]
    environment:
      - JVM_OPTS=-Xms1024M -Xmx1024M
    command:
      - --secret
      - "changeme-generate-a-real-one"
      - --cql-hostnames
      - cassandra
      - --index-backend
      - elasticsearch
      - --es-hostnames
      - elasticsearch-thehive
    volumes: [ "thehive-data:/opt/thp/thehive/data" ]
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    container_name: soc-postgres
    environment:
      POSTGRES_DB: soc_autopilot
      POSTGRES_USER: soc
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}
    ports: [ "5432:5432" ]
    volumes: [ "pg-data:/var/lib/postgresql/data" ]
    restart: unless-stopped

volumes:
  cassandra-data: {}
  es-data: {}
  thehive-data: {}
  pg-data: {}
```
```bash
echo "POSTGRES_PASSWORD=$(openssl rand -base64 24)" > .env
chmod 600 .env
docker compose up -d
docker compose ps
```
**Accès :** http://192.168.56.10:9000 → `admin@thehive.local` / `secret` → **change-le immédiatement**, puis crée une organisation `SOC` et un utilisateur de type **service** avec une **clé API** (Admin → Users → New → type `service`). **Garde la clé**, ton playbook en aura besoin.

> ⚠️ **Si TheHive refuse de démarrer par manque de RAM** (Cassandra + ES + TheHive = ~3 Go), plan B honnête : remplace TheHive par une table `cases` dans ton PostgreSQL et une action `case.create` locale. Tu perds l'intégration avec un outil du marché — **dis-le en entrevue plutôt que de le cacher** : *« TheHive tourne dans mon compose mais je l'ai désactivé sur ce labo par contrainte de RAM ; l'action est abstraite derrière l'interface `CaseBackend`, donc le basculer est une variable d'environnement. »* Ce genre de réponse **vaut plus** que si ça marchait.

---

## 7. threat-intel-api — ton projet, en tant que service

Il est déjà déployé sur Railway :
```bash
curl -s https://threat-intel-api-production.up.railway.app/health | jq
curl -s "https://threat-intel-api-production.up.railway.app/docs"
```
**Décision :** pour le labo, appelle **la version Railway** (zéro installation, et ça prouve qu'elle tourne en prod). Ajoute juste un **timeout de 5 s** + `on_error: continue` dans le playbook — parce qu'un enrichissement ne doit **jamais** bloquer la création du cas.

> **Argument d'entrevue :** *« L'enrichissement est en best-effort. Si ma source de threat intel est down, l'incident est quand même créé, juste avec moins de contexte. Un SOAR qui plante parce qu'une source d'enrichissement rate-limit, c'est un SOAR qui a mal été conçu. »*

---

## 7 bis. VirusTotal (deuxième couche d'enrichissement)

**Pourquoi :** VirusTotal donne la **réputation d'un IOC concret** (hash, IP, domaine), là où ton `threat-intel-api` donne la **priorisation sectorielle**. Deux couches complémentaires — c'est ce qui rend ton histoire d'architecture solide (voir fichier 01, Décision 7).

### Obtenir une clé (gratuit)
1. Crée un compte sur https://www.virustotal.com/gui/join-us
2. Clique sur ton avatar → **API key** → copie la clé (format : 64 caractères hex).
3. **Plafond de l'API gratuite : 4 requêtes/minute, 500/jour.** C'est LA contrainte à retenir — elle dicte le cache et le rate limiting côté code (fichier 03).

### Vérifier la clé
```bash
# Remplace VT_KEY par ta clé. Test sur le hash EICAR (fichier de test antivirus inoffensif, connu de tous les moteurs).
export VT_KEY="ta_cle_ici"
curl -s -H "x-apikey: $VT_KEY" \
  "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" \
  | jq '.data.attributes.last_analysis_stats'
```
Tu dois voir un objet `{ "malicious": N, "suspicious": ..., "harmless": ..., ... }`. Si tu obtiens `{}` ou une erreur 401 → mauvaise clé. Si 429 → tu as dépassé le rate limit, attends une minute.

> ⚠️ **Règle absolue à ne jamais oublier (et à dire en entrevue) :** on interroge VirusTotal **par hash / IP / domaine uniquement, jamais par upload de fichier**. Envoyer un hash = 64 caractères anonymes. Uploader un fichier = le rendre public sur une plateforme où d'autres abonnés peuvent le télécharger. Dans un contexte défense comme CAE, uploader un fichier interne est un **incident de sécurité**, pas un enrichissement.

### Où va la clé
Dans ton `.env` (jamais dans Git — voir §10) : `VIRUSTOTAL_API_KEY=...`. Le `.env.example` (§10) contient déjà la ligne de gabarit.

---

## 8. Slack (approbations)

1. https://api.slack.com/apps → **Create New App** → *From scratch* → nom `soc-autopilot`, workspace perso (crée-en un gratuit si besoin).
2. **OAuth & Permissions** → Bot Token Scopes : `chat:write`, `chat:write.public`, `channels:read`.
3. **Install to Workspace** → copie le **Bot User OAuth Token** (`xoxb-…`).
4. Crée les canaux `#soc-alerts` et `#soc-actions`, invite le bot : `/invite @soc-autopilot`.
5. **Interactivity & Shortcuts** → ON → Request URL = ton endpoint public.
   - Pour exposer ton labo temporairement : `ngrok http 8000` (installe : `sudo snap install ngrok`).
   - **Alternative sans ngrok (recommandée pour la démo) :** mode **polling** — le playbook écrit un message avec des boutons et attend qu'un `POST /approvals/{id}` arrive. Pendant la démo, tu cliques toi-même via `curl` ou une petite page. Moins joli, zéro dépendance réseau — **et une démo qui échoue à cause d'un tunnel ngrok, c'est une entrevue perdue.**

> **Règle de démo :** tout ce qui dépend d'Internet en direct est un risque. Prévois toujours le mode dégradé.

---

## 9. k3s (sur `soc-lab`)

```bash
curl -sfL https://get.k3s.io | sh -
sudo k3s kubectl get nodes          # NAME=soc-lab STATUS=Ready

# Pouvoir utiliser kubectl sans sudo
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
chmod 600 ~/.kube/config
kubectl get nodes
```
**Depuis ton poste :** copie ce fichier, remplace `127.0.0.1` par `192.168.56.10` :
```bash
scp michelange@192.168.56.10:~/.kube/config ~/.kube/k3s-soclab
sed -i 's/127.0.0.1/192.168.56.10/' ~/.kube/k3s-soclab
export KUBECONFIG=~/.kube/k3s-soclab
kubectl get nodes
```
> **Si k3s mange trop de RAM avec Wazuh :** installe-le sans Traefik ni metrics-server —
> `curl -sfL https://get.k3s.io | sh -s - --disable traefik --disable metrics-server`

---

## 10. Le repo

**Emplacement du projet :** `/media/mdoub/Data/Personal Projects/soc-autopilot` — sur la partition `Data` (NTFS), partagée avec Windows en dual-boot.
> ⚠️ Le chemin contient un **espace** (`Personal Projects`) : mets-le **toujours entre guillemets**, ou passe par la variable `$SOC_DIR` définie ci-dessous.

```bash
# Le chemin du projet, une fois pour toutes (session courante + persistant)
export SOC_DIR="/media/mdoub/Data/Personal Projects/soc-autopilot"
grep -q 'SOC_DIR=' ~/.bashrc || \
  echo 'export SOC_DIR="/media/mdoub/Data/Personal Projects/soc-autopilot"' >> ~/.bashrc

# Créer et initialiser le repo
mkdir -p "$SOC_DIR"
cd "$SOC_DIR"
git init -b main
uv venv --python 3.12
source .venv/bin/activate
```

> ⚠️ **Particularités NTFS — à lire, sinon tu perdras du temps :**
> - **Partition montée ?** `findmnt /media/mdoub/Data` doit répondre avant de commencer. Sinon : ouvre « Fichiers » et clique sur `Data`, ou ajoute une entrée `/etc/fstab` pour un montage automatique au boot.
> - **Permissions :** `git init` détecte le NTFS et met `core.filemode=false` tout seul. Si tu vois de faux diffs de permissions : `git config core.filemode false`. Un `chmod` (ex. `600` sur le `.env`) est **sans effet** sur NTFS — raison de plus pour que ce `.env` ne contienne que des secrets de labo.
> - **La `.venv` est Linux-only.** Le jour où tu ouvres le projet depuis Windows, recrée une venv côté Windows (`uv venv`) — une venv ne se partage jamais entre OS.
> - **Plan B si la venv est lente ou capricieuse sur NTFS :** crée-la hors de la partition — `uv venv ~/.venvs/soc-autopilot --python 3.12` puis `source ~/.venvs/soc-autopilot/bin/activate`.

**Arborescence à créer maintenant** (tu la remplis toute la semaine) :
```bash
cd "$SOC_DIR"
mkdir -p soc_autopilot/{engine,actions,api/routes,models} \
         playbooks detections/{windows,linux} \
         tests/{unit,integration,fixtures} \
         charts/soc-autopilot/templates \
         infra docs tools .github/workflows
touch soc_autopilot/__init__.py
```

### `.gitignore` — AVANT le premier commit
```gitignore
.venv/
__pycache__/
*.pyc
.env
.env.*
!.env.example
*.log
.coverage
htmlcov/
.pytest_cache/
.mypy_cache/
.ruff_cache/
*.tfstate
*.tfstate.*
.terraform/
.terraform.lock.hcl
kubeconfig
*.key
*.pem
*.crt
secrets/
build/
```

### `.pre-commit-config.yaml` — le garde-fou anti-secret
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.7
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: check-yaml
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: check-added-large-files
      - id: detect-private-key
```
```bash
cd "$SOC_DIR"
detect-secrets scan > .secrets.baseline
pre-commit install
```
> **Pourquoi c'est non négociable :** un secret dans un repo intitulé « SOC » est **éliminatoire**. Et si tu en pousses un puis le supprimes, il reste **dans l'historique git à jamais**. `pre-commit` l'arrête **avant** le commit. Tu connais TruffleHog via Find-One — même logique, appliquée dès la ligne 1.

### `.env.example` (celui-là va dans Git — jamais le vrai `.env`)
```bash
# --- Wazuh ---
WAZUH_API_URL=https://192.168.56.10:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=changeme
WAZUH_VERIFY_TLS=false          # labo uniquement — documenté dans le threat model

# --- Webhook ---
WEBHOOK_HMAC_SECRET=changeme

# --- TheHive ---
THEHIVE_URL=http://192.168.56.10:9000
THEHIVE_API_KEY=changeme

# --- Threat Intel (mon service — priorisation sectorielle) ---
THREAT_INTEL_URL=https://threat-intel-api-production.up.railway.app
THREAT_INTEL_TIMEOUT=5

# --- VirusTotal (réputation d'IOC — clé gratuite sur virustotal.com) ---
VIRUSTOTAL_API_KEY=changeme
VIRUSTOTAL_TIMEOUT=10

# --- Slack ---
SLACK_BOT_TOKEN=xoxb-changeme
SLACK_ALERT_CHANNEL=#soc-alerts
SLACK_ACTION_CHANNEL=#soc-actions

# --- DB ---
DATABASE_URL=postgresql+asyncpg://soc:changeme@192.168.56.10:5432/soc_autopilot

# --- Comportement ---
DRY_RUN=true                    # true = aucune action destructive n'est réellement exécutée
APPROVAL_TIMEOUT_SECONDS=900
```

### Premier commit
```bash
cd "$SOC_DIR"
git add .
git commit -m "chore: bootstrap project structure, pre-commit hooks, env template"
gh repo create soc-autopilot --public --source=. --push
# (ou crée le repo sur github.com et : git remote add origin … && git push -u origin main)
```

---

## 11. Checklist de fin de J1 — coche tout avant de dormir

- [ ] `docker run --rm hello-world` OK sur le poste **et** sur `soc-lab`
- [ ] `sigma list targets` liste elasticsearch, splunk, opensearch
- [ ] `terraform version`, `helm version`, `kubectl version --client` OK
- [ ] `trivy --version`, `checkov --version`, `cosign version` OK
- [ ] Wazuh Dashboard accessible sur https://192.168.56.10:443, mot de passe **changé**
- [ ] `agent_control -l` montre `victim-win` en **Active**
- [ ] Des **EID Sysmon 1** apparaissent dans Discover, filtre `agent.name: victim-win`
- [ ] `Invoke-AtomicTest T1059.001 -ShowDetailsBrief` répond
- [ ] TheHive accessible sur :9000, clé API de service créée et notée
- [ ] `kubectl get nodes` → `Ready`
- [ ] `curl .../health` de threat-intel-api → 200
- [ ] VirusTotal : clé obtenue, test EICAR → `last_analysis_stats` renvoyé
- [ ] Slack : bot installé, token noté, canaux créés
- [ ] Repo `soc-autopilot` créé dans `/media/mdoub/Data/Personal Projects/`, public sur GitHub, `pre-commit` actif, `.env` **non commité**
- [ ] Snapshots : `01-base-propre`, `02-wazuh-ok`, `03-victim-prete`

**Si tout est coché : tu as fait le plus dur.** L'infra, c'est 60 % de la douleur pour 20 % de la valeur. Le reste, c'est du code — ton terrain.

**→ Ouvre le fichier 03.**

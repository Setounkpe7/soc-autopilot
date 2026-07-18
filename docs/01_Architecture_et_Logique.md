# SOC Autopilot — Fichier 1/5
# Architecture et logique : comprendre AVANT de construire

> **Entrevue : jeudi 23 juillet 2026.** Tu as **7 jours** (16 → 22 juillet).
> Ce fichier ne contient aucune commande. Il contient le **pourquoi**. Lis-le en entier avant de toucher au clavier — c'est ce fichier qui te fera gagner l'entrevue, pas le code.

---

## 1. La règle d'or de cette semaine

> **Tu ne dois jamais avoir dans ton repo une ligne que tu ne peux pas expliquer à voix haute pendant 60 secondes.**

Un ingénieur CAE va ouvrir ton repo pendant l'entrevue et pointer une ligne au hasard. Si tu hésites, tout s'effondre — parce que ça veut dire que quelqu'un d'autre (ou une IA) a écrit ton projet. Si tu expliques la ligne **et le compromis derrière**, tu passes de « candidat junior avec un projet » à « ingénieur ».

**Corollaire : un projet plus petit que tu maîtrises à 100 % bat un projet plus gros que tu maîtrises à 60 %.** C'est pour ça que le plan sur 7 jours coupe volontairement dans le périmètre.

---

## 2. Le problème que le projet résout (la version que tu racontes en 90 secondes)

Imagine un SOC. Un analyste reçoit **300 alertes par jour**. Pour chacune, il fait la même danse :

1. Il lit l'alerte. « PowerShell encodé sur le poste WS-042. »
2. Il ouvre le SIEM pour voir ce qu'il y a autour. *(3 min)*
3. Il copie l'IP/le hash, le colle dans VirusTotal, puis dans MISP, puis dans un flux de threat intel. *(5 min)*
4. Il regarde qui est l'utilisateur, si c'est un admin, si la machine est critique. *(2 min)*
5. Il crée un ticket, colle tout dedans à la main. *(2 min)*
6. Il décide : je ferme ? j'escalade ? j'isole la machine ?

**≈ 12 minutes.** × 300 alertes = impossible. Donc l'analyste **coupe les coins**. Il ferme des alertes sans les enquêter. C'est comme ça que les vraies intrusions passent : pas parce que la détection a manqué, mais parce que **l'humain était saturé**.

**Ce que fait `soc-autopilot` :** les étapes 2 à 5 sont mécaniques et déterministes. Une machine les fait en 40 secondes, sans se fatiguer, sans oublier une source, à 3 h du matin. L'humain garde **l'étape 6** — la décision. Et la décision arrive avec un dossier complet au lieu d'une ligne de log.

> **Ce n'est pas « remplacer l'analyste ». C'est « rendre à l'analyste les 11 minutes où il réfléchit au lieu de faire du copier-coller ».**
> Dis cette phrase-là en entrevue. C'est la thèse du poste. L'offre l'écrit littéralement : *« améliorer les systèmes afin d'augmenter l'efficacité du SOC »*.

---

## 3. Le vocabulaire — vulgarisé, pour que tu ne bafouilles jamais

Tu dois pouvoir définir chacun de ces mots **sans réfléchir**. Voici la définition + l'analogie + le piège.

### SIEM (Security Information and Event Management)
- **Quoi :** une base de données géante qui avale tous les journaux (logs) de toutes les machines, et qui déclenche une alerte quand un motif suspect apparaît.
- **Analogie :** le poste de surveillance d'un centre commercial. Toutes les caméras y arrivent, et un logiciel crie « mouvement à 3 h du matin dans le rayon bijoux ».
- **Exemples :** Splunk, Elastic Security, Microsoft Sentinel, **Wazuh** (le nôtre).
- **Piège d'entrevue :** un SIEM **détecte et corrèle**, il n'**agit** pas. C'est là que le SOAR entre.

### EDR (Endpoint Detection and Response)
- **Quoi :** un agent installé **sur la machine elle-même** qui voit ce que le réseau ne voit pas (quel processus a lancé quoi, quelle clé de registre a été écrite) et qui peut **agir** localement (tuer un processus, couper le réseau de la machine).
- **Analogie :** un garde du corps assis dans le bureau, pas juste une caméra au plafond.
- **Exemples :** CrowdStrike, Defender for Endpoint, **Wazuh agent** (le nôtre — il fait EDR *et* alimente le SIEM).
- **Piège :** « EDR = antivirus » → **non**. L'antivirus bloque le connu. L'EDR **enregistre le comportement** pour qu'on détecte l'inconnu.

### SOAR (Security Orchestration, Automation and Response)
- **Quoi :** le chef d'orchestre. Il reçoit l'alerte du SIEM, va chercher du contexte partout (threat intel, annuaire, EDR), remplit le dossier, et exécute les actions décidées d'avance dans un **playbook**.
- **Analogie :** un assistant qui, dès qu'une alarme sonne, sort le dossier du client, appelle les 3 bons services, prépare le formulaire, et le pose sur ton bureau — signé, prêt, il ne manque que ta décision.
- **Exemples :** Cortex XSOAR, Splunk SOAR, Shuffle, **notre moteur maison**.
- **Piège :** ce n'est **pas** de l'IA. C'est de la logique déterministe écrite d'avance par un humain. Si tu dis « IA » en entrevue, tu perds.

### Playbook
- **Quoi :** la recette. « Si alerte de type X, alors fais 1, 2, 3, demande une approbation, puis 4. »
- **Pourquoi en YAML et pas en Python :** parce que dans un vrai SOC, c'est l'**analyste** (pas le développeur) qui doit pouvoir écrire ou corriger un playbook à 3 h du matin. Séparer le **moteur** (Python, complexe, stable) du **contenu** (YAML, simple, changeant) est **le** choix d'architecture du projet. C'est exactement ce que font XSOAR et Sentinel. → **Question d'entrevue quasi garantie.**

### Sigma
- **Quoi :** un format de règle de détection **universel**, écrit en YAML, qu'on **convertit** ensuite vers le langage de chaque SIEM.
- **Analogie :** tu écris la recette une fois en français, et un traducteur la sort en anglais, en espagnol, en allemand. Tu changes de pays ? Tu ne réécris pas tes recettes.
- **Pourquoi c'est énorme pour CAE :** l'offre cite « Splunk, Elastic, Sentinel ». Avec Sigma, tu réponds : *« mes détections sont portables sur les trois — je ne suis pas marié à un SIEM. »*
- **Piège :** Sigma ne s'exécute pas tout seul. C'est **du texte**. Il faut le **convertir** (`sigma convert`) et le **déployer**. Ce transport, c'est le Detection-as-Code.

### Detection-as-Code
- **Quoi :** traiter les règles de détection **exactement comme du code applicatif** : dans Git, revues par Pull Request, testées automatiquement, déployées par pipeline, réversibles par `git revert`.
- **Analogie :** avant, un analyste cliquait dans l'interface du SIEM pour créer une règle. Personne ne savait qui l'avait faite, ni pourquoi, ni comment revenir en arrière. C'est l'équivalent de modifier un serveur de production en RDP. Detection-as-Code, c'est le passage au CI/CD — **ce que tu fais depuis 4 ans chez WSP**.
- **Ton avantage :** tu n'apprends pas ce concept. Tu l'as déjà appliqué à des runbooks Azure. Tu ne fais que le **transposer** aux détections.

### MITRE ATT&CK
- **Quoi :** un catalogue mondial et numéroté de **tout ce qu'un attaquant fait**, organisé en **tactiques** (le *pourquoi* : Exécution, Persistance, Exfiltration…) et **techniques** (le *comment* : T1059.001 = PowerShell).
- **Analogie :** la classification décimale de Dewey, mais pour les attaques. Ça donne un langage commun : quand tu dis « T1003.001 », un ingénieur à Singapour comprend exactement « dump de LSASS ».
- **Usage dans le projet :** chaque règle Sigma porte son tag ATT&CK. Chaque playbook aussi. Résultat : on peut calculer **ce qu'on couvre et ce qu'on ne couvre pas**.

### DeTT&CT
- **Quoi :** un outil qui croise deux listes : (a) les sources de données que tu **collectes** vraiment, (b) les techniques que tu **détectes** vraiment. Il te sort une carte colorée : vert = couvert, rouge = aveugle.
- **Analogie :** la carte du centre commercial avec les zones couvertes par les caméras coloriées en vert, et les angles morts en rouge. **Les angles morts, c'est là que le vol a lieu.**
- **Pourquoi c'est dans le projet :** l'offre dit littéralement *« Identifier les lacunes dans la télémétrie, les journaux et les alertes »*. DeTT&CT **est** la réponse à cette puce.

### Sysmon
- **Quoi :** un outil Microsoft (Sysinternals) gratuit à installer sur Windows. Windows par défaut journalise très mal. Sysmon ajoute les événements qui comptent : création de processus **avec la ligne de commande complète et le processus parent** (EID 1), connexions réseau (EID 3), accès à la mémoire d'un autre processus (EID 10), écriture de registre (EID 13)…
- **Analogie :** Windows de base, c'est une caméra qui filme la porte d'entrée. Sysmon, c'est une caméra dans chaque pièce, avec le son.
- **Règle absolue :** **sans Sysmon, 80 % des détections Windows sont impossibles.** Si tu ne comprends que ça de la journée 1, c'est déjà énorme.
- **Piège d'entrevue :** « pourquoi Sysmon et pas juste les logs Windows ? » → parce que l'événement natif 4688 n'a pas la ligne de commande activée par défaut, ni le hash, ni le parent fiable, ni les connexions réseau par processus.

### Atomic Red Team
- **Quoi :** une bibliothèque de **petits tests d'attaque** (des « atomics »), un par technique ATT&CK, exécutables en une commande, avec une procédure de nettoyage.
- **Analogie :** un exercice d'incendie. Tu ne brûles pas l'immeuble ; tu déclenches l'alarme pour vérifier que les gicleurs marchent.
- **Pourquoi c'est décisif dans ton projet :** ça transforme « j'ai écrit une règle » en **« j'ai prouvé que ma règle détecte l'attaque réelle, et j'ai prouvé qu'elle ne se déclenche pas sur du trafic normal »**. C'est la différence entre un étudiant et un ingénieur de détection.

### TheHive
- **Quoi :** l'outil de gestion de cas (tickets d'incident) du SOC. Un cas contient des observables (IP, hash, domaine), une timeline, des tâches, une sévérité, un TLP.
- **Analogie :** le dossier d'enquête du détective.
- **TLP (Traffic Light Protocol) :** un code de partage. TLP:RED = ne partage avec personne hors de la réunion. TLP:AMBER = ton organisation. TLP:GREEN = communauté. TLP:CLEAR = public. **Dans une boîte de défense comme CAE, connaître le TLP est un signal de sérieux.**

### IOC (Indicator of Compromise)
- **Quoi :** un indicateur concret et observable qu'une intrusion a eu lieu — un hash de fichier, une adresse IP, un domaine, une URL. C'est la « trace » matérielle.
- **Analogie :** l'empreinte digitale sur la scène de crime. Elle ne dit pas *qui* ni *pourquoi*, mais elle est vérifiable et comparable à une base connue.
- **À ne pas confondre avec une CVE :** une CVE est une *vulnérabilité* (une porte non verrouillée) ; un IOC est une *trace de passage* (une empreinte sur la poignée). Ton projet a maintenant les deux couches — voir ci-dessous.

### VirusTotal
- **Quoi :** un service qui agrège ~70 moteurs antivirus. On lui donne un IOC (hash, IP, domaine) et il répond « voici combien de moteurs le considèrent malveillant ».
- **Analogie :** un second avis médical multiplié par 70. Un seul médecin peut se tromper ; 45 sur 70 qui disent « malin », c'est un verdict.
- **Les 4 pièges à connaître par cœur (un ingénieur CAE les testera) :**
  1. **Rate limit** — API gratuite : 4 requêtes/min, 500/jour. C'est LA contrainte qui impose le cache.
  2. **Confidentialité** — envoyer un *hash* = 64 caractères anonymes ; uploader un *fichier* = le rendre public. **On interroge par hash, JAMAIS par upload de fichier.** Dans un contexte défense, uploader un fichier interne est un incident.
  3. **L'absence n'est pas l'innocence** — un hash inconnu de VT ne veut pas dire « sûr », il veut dire « jamais vu » — ce qui est précisément le cas d'un malware ciblé.
  4. **Consensus, pas compte brut** — on raisonne en ratio (malicious/total), pas en présence. « 3 sur 70 » est souvent du faux positif.

### Enrichissement à deux couches (le fil rouge threat intel du projet)
Ton projet croise deux niveaux d'intelligence, qui répondent à deux questions différentes :

| Source | Répond à | Nature |
|---|---|---|
| **VirusTotal** | « Cet IOC concret est-il *déjà connu* comme malveillant ? » | Réputation — tactique, immédiat |
| **threat-intel-api** (le tien) | « Cette *classe de menace* est-elle prioritaire pour mon secteur ? » | Priorisation par CVE/secteur — stratégique |

> **La phrase à retenir :** *« VirusTotal me dit si ce hash est mauvais maintenant ; mon service me dit si cette famille de menace compte pour un profil défense. Les deux sont en best-effort avec cache et rate limiting — un enrichissement qui timeout ne doit jamais empêcher la création du cas. »*

---

## 4. L'architecture — en français, puis en schéma

### 4.1 En français, comme tu la raconterais à ta grand-mère

> Sur chaque ordinateur, il y a un **mouchard** (agent Wazuh + Sysmon) qui note tout ce qui se passe et l'envoie à un **entrepôt central** (Wazuh Manager + Elasticsearch). Dans cet entrepôt, il y a des **règles** qui disent « ça, c'est louche ». Ces règles ne sont pas écrites à la main dans l'interface : elles sont **dans Git**, et un **robot** (GitHub Actions) les traduit et les installe automatiquement, après les avoir **testées contre de vraies attaques**.
>
> Quand une règle se déclenche, l'entrepôt envoie un **coup de fil** (webhook) à **mon programme** (`soc-autopilot`). Mon programme ouvre la **recette** (playbook YAML) correspondante et l'exécute : il va chercher des infos sur l'attaquant dans **mon service de threat intel** (mon autre projet), il ouvre un **dossier d'enquête** (TheHive), il calcule un **score de gravité**, et si c'est grave, il **demande la permission à un humain sur Slack** avant de **couper le réseau de la machine infectée** (via l'EDR). Chaque geste est **écrit dans un registre inviolable** (audit trail), et chaque geste **sait comment s'annuler** (rollback).
>
> Tout ça tourne dans des **conteneurs** sur **Kubernetes**, installé par **Terraform**, et une **carte** se met à jour toute seule pour montrer quelles attaques je sais voir et lesquelles sont dans mes angles morts.

**Si tu peux dire ça de mémoire, fluide, en 90 secondes — en français ET en anglais — tu as déjà gagné la moitié de l'entrevue.**

### 4.2 Le schéma

```
        ╔═══════════════════ PLAN DE CONTRÔLE (Git) ══════════════════╗
        ║  detections/*.yml (Sigma)   playbooks/*.yml   charts/  infra/║
        ╚════════════════════════════╤════════════════════════════════╝
                                     │ git push → GitHub Actions
             ┌───────────────────────┼────────────────────────────┐
             │ lint · test · sigma check · convert · TEST ATTAQUE │
             │ SAST/SCA · build+Cosign · Checkov/tfsec · deploy    │
             └───────────────────────┼────────────────────────────┘
                                     │  déploie les règles (API)
   ┌──────────────┐            ┌─────▼──────────────────────┐
   │ VM Windows   │  events    │   WAZUH MANAGER (SIEM)     │
   │ + Sysmon     ├───────────▶│   + Wazuh Indexer          │
   │ + agent Wazuh│◀───────────┤     (= Elasticsearch)      │
   │              │  active    │   + Wazuh Dashboard        │
   │ ATOMIC RED   │  response  │                            │
   │ TEAM (tests) │            └─────┬──────────────────────┘
   └──────────────┘                  │ ① webhook HMAC
   ┌──────────────┐                  │    (alerte JSON)
   │ VM Ubuntu    │  events          ▼
   │ + agent Wazuh├──────────▶ ┌───────────────────────────────┐
   └──────────────┘            │      SOC-AUTOPILOT            │
                               │      (FastAPI / Python)       │
                               │  ┌─────────────────────────┐  │
                               │  │ loader → resolver →     │  │
                               │  │ executor (DAG) → audit  │  │
                               │  └─────────────────────────┘  │
                               └──┬────┬─────┬─────┬────┬──────┘
                        ② enrich  │    │③cas │④notif│⑤containment
                                  ▼    ▼     ▼     ▼    ▼
              ┌── VirusTotal      TheHive  Slack  Wazuh API
              │   (réputation IOC) (cases) (approb) (isolate)
              └── threat-intel-api
                  (TON projet — priorisation sectorielle)
                                  │
                                  ▼
                            PostgreSQL (audit trail immuable)

   Le tout : conteneurs → Helm chart → k3s (Kubernetes) → Terraform
   Observabilité : Prometheus /metrics + Grafana (MTTD, MTTR, % auto)
   Couverture : DeTT&CT → ATT&CK Navigator → GitHub Pages
```

### 4.3 Le fil rouge (la question « comment tout ça tient ensemble ? »)

C'est **le tag ATT&CK** qui coud tout :

```
Atomic Red Team T1059.001          (l'attaque qu'on rejoue)
        ↓ génère de la télémétrie
Sysmon EID 1 + Wazuh                (ce qu'on voit)
        ↓ matché par
detections/powershell_encoded.yml   tags: attack.t1059.001
        ↓ déclare
response_playbook: PB-0007          (le lien détection → réaction)
        ↓ exécute
playbooks/PB-0007.yml               trigger.mitre: [T1059.001]
        ↓ alimente
DeTT&CT → Navigator layer           (T1059.001 = vert)
```

> **Une seule technique ATT&CK traverse les 5 composants.** Quand on te demandera « montre-moi comment ça marche », tu suis ce fil du haut vers le bas. C'est ta démo. C'est ta réponse. C'est tout le projet en un exemple.

---

## 5. Les 7 décisions d'architecture — et leur défense

En entrevue, on ne te demandera pas « qu'as-tu utilisé ». On te demandera **« pourquoi »**. Une décision technique se défend toujours de la même façon : **le besoin → l'option retenue → l'option écartée → le compromis assumé**.

### Décision 1 — Wazuh comme SIEM + EDR
- **Besoin :** j'ai besoin de télémétrie d'endpoint (EDR) ET de corrélation centrale (SIEM) ET d'une capacité d'action (containment), avec un budget de 0 $.
- **Retenu :** Wazuh. Un seul agent me donne les trois. Son indexer est un fork d'OpenSearch (donc Elasticsearch), API REST propre, et l'**active response** me donne une vraie action de containment.
- **Écarté :** Splunk (licence), Sentinel (coût Azure + m'enferme dans KQL), Elastic Security seul (pas d'action de réponse sans licence).
- **Compromis assumé :** Wazuh n'est pas un EDR de classe CrowdStrike — pas d'analyse comportementale native poussée, pas de tamper protection. Pour un labo de démonstration d'**intégration**, c'est sans importance : ce que je démontre, c'est le pipeline, et il est identique quel que soit l'EDR derrière. **C'est justement pourquoi j'ai abstrait les actions derrière un registre : changer `wazuh.isolate_host` pour `crowdstrike.contain_host` est un fichier de 40 lignes.**
- **⚡ Cette dernière phrase est la meilleure réponse du projet. Apprends-la.**

### Décision 2 — Un moteur SOAR maison plutôt que Shuffle/n8n/XSOAR
- **Besoin :** le poste est explicitement « à l'intersection de l'ingénierie logicielle, du DevOps et de la cybersécurité ».
- **Retenu :** l'écrire. Ça prouve les trois axes d'un coup.
- **Écarté :** brancher un n8n — ça n'aurait prouvé qu'un axe (savoir cliquer).
- **Compromis assumé :** en entreprise, **je n'écrirais jamais mon propre SOAR** — j'utiliserais l'outil en place. Je l'ai écrit pour **comprendre les mécanismes** qu'un intégrateur doit maîtriser : idempotence, DAG, échec partiel, rollback, sandbox de templating. Quand un playbook XSOAR casse en production à 2 h du matin, c'est **un** de ces mécanismes qui a lâché — et je saurai lequel.
- **Assurance :** monte **un** playbook dans **Shuffle** (2 h, J7 si le temps le permet) pour pouvoir dire « j'ai aussi utilisé un SOAR du marché ».

### Décision 3 — Playbooks déclaratifs en YAML
- **Besoin :** dans un SOC, celui qui connaît la réponse à incident est l'**analyste**, pas le dev. Si chaque changement de playbook exige un dev + un déploiement, le SOC se fige.
- **Retenu :** moteur en Python, contenu en YAML validé par un schéma Pydantic. Hot-reload.
- **Écarté :** playbooks en Python — plus rapide à écrire, mais réservé aux devs, intestable isolément, et **chaque playbook devient une porte d'exécution de code arbitraire**.
- **Compromis assumé :** un DSL YAML est moins expressif que Python. Si un playbook a besoin de logique vraiment complexe, j'ajoute une **action** en Python au registre plutôt que de complexifier le DSL. **Le DSL reste bête ; l'intelligence est dans les actions.** C'est le principe qui empêche tous les DSL de dégénérer.

### Décision 4 — Approbation humaine avec timeout = DENY
- **Besoin :** isoler un hôte, c'est couper un employé de son travail. Si c'est un serveur de production, c'est un incident majeur causé par… l'outil de sécurité.
- **Retenu :** au-dessus d'un score seuil, l'action destructive exige une approbation Slack. **Pas de réponse en 15 min → refus.**
- **Écarté :** l'auto-containment total (dangereux), l'approbation systématique (annule l'intérêt).
- **Compromis assumé :** on perd en vitesse sur les cas graves nocturnes. C'est un choix : **un faux négatif coûte une enquête, un faux positif destructif coûte la confiance dans l'outil — et un SOC dont personne ne fait confiance à l'automatisation est un SOC sans automatisation.**
- **Le principe :** *fail-safe, pas fail-open*. Un système sûr, en cas de doute, **ne fait rien**.
- **⚡ C'est LA question qu'un ingénieur senior te posera. Prépare-la mot pour mot.**

### Décision 5 — Idempotence par clé de déduplication
- **Besoin :** Wazuh peut renvoyer le même webhook (retry réseau). Une même alerte peut matcher plusieurs règles.
- **Retenu :** clé `sha256(alert.id + playbook.id)` stockée en base, contrainte d'unicité. Rejeu → on retourne l'exécution existante, on ne recrée rien.
- **Sans ça :** 40 cas TheHive identiques, 40 notifications Slack, et un analyste qui désactive ton outil dans l'heure.
- **Principe général :** *toute action déclenchée par un événement réseau doit être idempotente*. C'est vrai pour un SOAR, une API de paiement, ou un runbook Azure — **tu l'as déjà rencontré chez WSP**, dis-le.

### Décision 6 — k3s + Helm + Terraform
- **Besoin :** l'offre demande conteneurisation, IaC, Kubernetes.
- **Retenu :** k3s (Kubernetes complet, 512 Mo de RAM), Helm pour packager, Terraform pour provisionner.
- **Écarté :** AKS/EKS (coût), minikube (moins « prod-like »), docker-compose seul (ne coche pas « Kubernetes »).
- **Compromis assumé et à dire tel quel :** *« C'est un cluster de labo mono-nœud. Je n'ai pas fait de capacity planning, ni de gestion d'incident à 3 h du matin sur un cluster multi-tenant. Je connais la mécanique — Deployment, Service, Ingress, NetworkPolicy, RBAC, securityContext — et les points de rupture. L'échelle, je l'apprendrai chez vous. »*
- **⚡ La modestie exacte marque plus de points que l'exagération. L'exagération se détecte en 30 secondes.**

### Décision 7 — Enrichissement à deux couches : VirusTotal + `threat-intel-api`
- **Besoin :** enrichir les IOC concrets d'une alerte **et** prioriser les gaps de détection — deux questions distinctes.
- **Retenu :** deux sources complémentaires.
  - **VirusTotal** répond « ce hash / cette IP est-il *déjà connu* comme malveillant ? » → réputation d'IOC, tactique, immédiat.
  - **Mon `threat-intel-api`** répond « cette *classe de menace* est-elle prioritaire pour mon secteur ? » → score par profil sectoriel (finance, ICS, gov…) à partir de NVD + CISA KEV + GitHub Advisories, stratégique.
- **Écarté (pour l'instant) :** MISP, OTX, AbuseIPDB → même rôle que VirusTotal, redondant pour la démo. Roadmap.
- **Le vrai gain :** ça transforme deux projets isolés en **un système** à deux étages de threat intel. Réponse imparable : *« VirusTotal me donne la réputation immédiate d'un indicateur concret ; mon service me donne la couche au-dessus — est-ce que cette famille de menace compte pour un profil défense. Les deux en best-effort avec cache et rate limiting, parce qu'un enrichissement qui timeout ne doit jamais bloquer la création du cas. »*
- **Le point qui fait mouche (contexte CAE) :** *« Je n'envoie que des hash à VirusTotal, jamais de fichier. Dans une boîte de défense, uploader un fichier interne sur une plateforme publique n'est pas un enrichissement, c'est un incident. »*
- **Note CAE :** CAE = aéronautique/défense. Le profil sectoriel pertinent est **ICS/gov**. Ajoute-le à ta démo.

---

## 6. Le périmètre des 7 jours — ce qu'on construit et ce qu'on coupe

| Composant | Statut J-7 | Pourquoi |
|---|---|---|
| Pipeline de télémétrie (Wazuh + Sysmon + 2 agents) | ✅ **Complet** | Fondation, sans ça rien n'existe |
| Moteur SOAR + 4 playbooks | ✅ **Complet** | C'est le cœur du poste |
| Intégrations (Wazuh, TheHive, **VirusTotal**, threat-intel-api, Slack) | ✅ **Complet** | « Développer des intégrations » = la 1ʳᵉ responsabilité ; VirusTotal + mon service = enrichissement à deux couches |
| Detection-as-Code (8 règles Sigma + CI) | ✅ **Complet** | 8 règles impeccables > 15 bâclées |
| Tests d'attaque automatisés (Atomic Red Team) | ✅ **Complet** | **Le différenciateur — ne coupe jamais ça** |
| k3s + Helm + Terraform | ✅ **Complet** | Coche 3 exigences, 1 journée |
| CI/CD 7 jobs + Cosign + Trivy | ✅ **Complet** | Tu sais déjà faire, c'est du copier-adapter |
| DeTT&CT + Navigator | 🟡 **Version courte** | 1 layer + 1 page d'analyse suffit pour la démo |
| Prometheus/Grafana | 🟡 **/metrics seulement** | Expose les métriques, dashboard = bonus |
| Falco, kube-bench, MISP, Shuffle | ❌ **Coupé** | Roadmap. **À citer comme « prochaine étape »** — ça montre que tu as une vision |
| Vidéo démo 5 min | ✅ **Obligatoire** | Le recruteur ne clone pas ton repo |

> **Ne pas tout faire est une décision d'ingénieur, pas un échec.** En entrevue : *« J'ai priorisé la chaîne de bout en bout plutôt que la largeur. Falco et MISP sont dans le README en roadmap avec la raison. »*

---

## 7. Ce que tu dis le 23 juillet quand on ouvre ton repo

**Le pitch (90 s, à réciter par cœur, FR et EN) :**

> « J'ai construit une plateforme d'ingénierie SOC. Le principe : dans un SOC, l'analyste passe 12 minutes par alerte à faire du copier-coller déterministe — enrichir, contextualiser, ouvrir le ticket. J'ai automatisé ces 12 minutes en 40 secondes et j'ai gardé l'humain sur la seule chose qui demande un jugement : la décision de containment.
>
> Concrètement : mes détections sont des règles Sigma dans Git. Un pipeline GitHub Actions les valide, les convertit vers Elastic, Splunk et Wazuh, et — c'est le point qui compte — **les teste contre une vraie attaque rejouée par Atomic Red Team, plus un test de faux positif**. Aucune règle ne part en production sans les deux.
>
> Quand une règle se déclenche, le SIEM appelle mon orchestrateur en FastAPI. Il charge un playbook YAML déclaratif — moteur en Python, contenu en YAML, pour qu'un analyste puisse l'écrire sans moi — l'exécute en DAG avec idempotence et audit trail, enrichit via mon propre service de threat intel, ouvre le cas dans TheHive, et si le score dépasse le seuil, demande l'approbation humaine sur Slack avant d'isoler l'hôte via l'EDR. Timeout d'approbation = refus, jamais autorisation.
>
> Le tout est packagé en Helm, déployé sur k3s par Terraform, l'image est signée avec Cosign, et une carte MITRE ATT&CK de ma couverture et de mes angles morts se régénère à chaque commit. »

**Puis tu te tais.** Laisse-les poser la question. Ils en poseront une des trois : *le timeout*, *pourquoi maison*, *les tests de détection*. Les trois réponses sont dans le fichier 5.

---

## 8. Ordre de lecture des fichiers

| Fichier | Contenu | Quand |
|---|---|---|
| **01 — Architecture et Logique** | ← tu y es | Maintenant, en entier |
| **02 — Installation** | Chaque outil, chaque commande, sur ton poste | Aujourd'hui (J1) |
| **03 — Construction J1→J7** | Le code, jour par jour, ligne par ligne expliquée | J1 à J7 |
| **04 — Tests d'attaque & validation** | Simuler les attaques, prouver que ça marche | J5 (mais lis-le avant J4) |
| **05 — Prep entrevue 23 juillet** | Questions, réponses, démo, script | J7 — et relis-le chaque soir |

**Prochaine étape : ouvre le fichier 02 et lance l'installation. Le chronomètre tourne.**

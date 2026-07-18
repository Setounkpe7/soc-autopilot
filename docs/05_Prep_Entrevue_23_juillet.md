# SOC Autopilot — Fichier 5/5
# Préparation entrevue — CAE, jeudi 23 juillet 2026
### Spécialiste en intégration DevOps pour la cybersécurité — Montréal / Saint-Laurent

> **Relis ce fichier chaque soir de la semaine, pas seulement le 22.**
> Construire le projet et savoir en parler sont deux compétences différentes. La deuxième est celle qu'on évalue jeudi.

---

## 1. Ce qu'ils évaluent vraiment

Ils t'ont convoqué. Ton CV est déjà validé. **Le 23, on ne vérifie pas ce que tu as fait — on vérifie comment tu penses.**

Les quatre choses réellement testées :

| Ce qu'on teste | Comment ça se voit | Ce qui te coule |
|---|---|---|
| **Est-ce qu'il a vraiment fait ça ?** | Les détails que seul quelqu'un qui l'a fait connaît (UTF-16LE, `vm.max_map_count`, `USER 1001` numérique) | Les généralités |
| **Est-ce qu'il raisonne ou récite ?** | Il défend des **compromis**, pas des choix | « J'ai utilisé X parce que c'est le meilleur » |
| **Est-ce qu'il connaît ses limites ?** | Il nomme ses failles **avant** qu'on les trouve | La survente |
| **Est-ce qu'on peut travailler avec lui ?** | Il dit « je ne sais pas » sans paniquer | La défensive |

> **La règle de la semaine :** *l'exagération se détecte en 30 secondes ; la mesure de soi, jamais.*

---

## 2. Le pitch — 90 secondes, par cœur, FR et EN

**Français :**

> « J'ai construit une plateforme d'ingénierie SOC. Le point de départ : dans un SOC, l'analyste passe environ 12 minutes par alerte à faire du copier-coller déterministe — enrichir, contextualiser, ouvrir le ticket. Aucune décision là-dedans. J'ai automatisé ces 12 minutes en environ 40 secondes et j'ai gardé l'humain sur la seule chose qui demande un jugement : la décision de containment.
>
> Concrètement, mes détections sont des règles Sigma dans Git. Un pipeline GitHub Actions les valide, les convertit vers Elastic, Splunk et Wazuh, et — c'est le point qui compte — les teste contre une vraie attaque rejouée par Atomic Red Team, plus un test de faux positif contre de l'activité administrative légitime. Aucune règle ne merge sans les deux verts.
>
> Quand une règle se déclenche, Wazuh appelle mon orchestrateur en FastAPI. Il charge un playbook YAML déclaratif — moteur en Python, contenu en YAML, pour qu'un analyste puisse l'écrire sans moi — l'exécute en DAG avec idempotence et audit trail complet, enrichit à deux couches — VirusTotal pour la réputation des IOC, mon propre service pour la priorisation sectorielle — ouvre le cas dans TheHive, et si le score dépasse le seuil, demande l'approbation humaine sur Slack avant d'isoler l'hôte via l'EDR. Timeout d'approbation égale refus, jamais autorisation.
>
> Le tout est packagé en Helm, déployé sur k3s par Terraform, l'image est signée avec Cosign, et une carte MITRE ATT&CK de ma couverture — et de mes angles morts — se régénère à chaque commit. »

**English (répète-le 10 fois à voix haute — c'est ton vrai risque) :**

> "I built a SOC engineering platform. The premise: in a SOC, an analyst spends about 12 minutes per alert doing deterministic copy-paste — enriching, adding context, opening the ticket. No judgment involved. I automated those 12 minutes down to about 40 seconds, and I kept the human on the one thing that needs judgment: the containment decision.
>
> My detections are Sigma rules in Git. A GitHub Actions pipeline validates them, converts them to Elastic, Splunk and Wazuh, and — this is the part that matters — tests them against real attack telemetry replayed from Atomic Red Team, plus a false-positive test against legitimate admin activity. No rule merges without both passing.
>
> When a rule fires, Wazuh calls my FastAPI orchestrator. It loads a declarative YAML playbook — engine in Python, content in YAML, so an analyst can write one without me — runs it as a DAG with idempotency and a full audit trail, enriches in two layers — VirusTotal for IOC reputation, my own service for sector-based prioritisation — opens a case in TheHive, and above a score threshold it asks for human approval on Slack before isolating the host through the EDR. Approval timeout means deny — never allow.
>
> It's packaged as a Helm chart, deployed to k3s with Terraform, the image is signed with Cosign, and a MITRE ATT&CK coverage map — including my blind spots — regenerates on every commit."

> **Après le pitch : TAIS-TOI.** Le silence est ton allié. Ils poseront la question qui les intéresse, et tu répondras à celle-là au lieu de deviner.

---

## 3. Les 12 questions — avec les réponses

### 🔴 Q1 — « Pourquoi timeout = refus et pas approbation ? »
*(La plus probable. Si elle ne vient pas, provoque-la.)*

> « Fail-safe, pas fail-open. Le coût des deux erreurs n'est pas symétrique. Un faux négatif me coûte une enquête manuelle. Un faux positif destructif me coûte la confiance dans l'outil — et un SOC qui ne fait pas confiance à son automatisation est un SOC sans automatisation ; on la désactive et on retourne au manuel.
>
> C'est le raisonnement du disjoncteur : en cas d'anomalie, il ouvre le circuit, il ne le ferme pas. Il y a une couche au-dessus : une liste d'actifs protégés — un contrôleur de domaine ou un serveur SQL de prod n'est jamais isolé automatiquement, quel que soit le score, et ce contrôle s'applique **avant** le dry-run dans mon code, donc même en mode armé.
>
> Et la limite que je connais : mes approbations en attente sont dans un dict en mémoire. Si le pod redémarre, elles sont perdues — donc refusées, ce qui est le bon comportement, mais l'analyste ne le sait pas. En production : Redis avec TTL et notification d'expiration. C'est dans mes limites connues au README. »

---

### 🔴 Q2 — « Pourquoi un SOAR maison plutôt que XSOAR ou Shuffle ? »

> « En entreprise, je n'écrirais jamais mon propre SOAR. J'utiliserais l'outil en place — c'est un problème résolu, et réinventer un SOAR est une mauvaise décision d'ingénierie.
>
> Je l'ai écrit pour comprendre les mécanismes qu'un intégrateur doit maîtriser : idempotence, DAG, échec partiel, rollback, séparation moteur/contenu, sandbox de templating. Quand un playbook XSOAR casse en production à 2 h du matin, c'est un de ces mécanismes qui a lâché — et je saurai lequel regarder.
>
> Et le poste est décrit comme l'intersection de l'ingénierie logicielle, du DevOps et de la cybersécurité. Écrire l'orchestrateur prouve les trois. Brancher un n8n n'en prouve qu'un. »

*(Si tu as eu le temps de faire le playbook Shuffle, ajoute : « J'ai aussi monté un playbook sur Shuffle pour avoir le point de comparaison — le vrai gain d'un SOAR du marché, c'est le catalogue d'intégrations maintenues, pas le moteur. »)*

---

### 🔴 Q3 — « Comment tu testes tes détections ? »
*(La question où tu es le plus fort. Ralentis. Savoure.)*

> « Deux tests obligatoires par règle, tous les deux en CI, tous les deux bloquants.
>
> Le vrai positif : j'exécute l'attaque réelle avec Atomic Red Team sur une VM Windows avec Sysmon, je capture la télémétrie générée, je la sanitise pour retirer les SID et les noms de machine, et elle devient un fixture. En CI, ma règle passe sur ce fixture et doit produire au moins un hit.
>
> Le faux positif : un fixture d'activité administrative légitime — et il contient délibérément un cas piège, du PowerShell encodé lancé par un agent de monitoring. Ça ressemble exactement à l'attaque. Si ma règle le matche, elle est inutilisable en prod parce que SCCM fait ça toute la journée. Ma règle doit produire zéro hit.
>
> Le pattern est celui des tests d'intégration classiques : on capture une fois, on rejoue mille fois. Pas de VM en CI, 3 secondes, 100 % déterministe, zéro test flaky.
>
> Et ça a servi : ma règle LSASS a échoué au premier essai. J'avais copié le masque `GrantedAccess: 0x1010` d'un article de blog. La télémétrie réelle de procdump donne `0x1fffff`. Sans ce test, la règle serait partie en prod, elle aurait été verte sur ma carte ATT&CK, et elle n'aurait jamais détecté un seul dump de LSASS. C'est exactement le faux négatif silencieux que ces tests existent pour attraper. »

---

### 🟡 Q4 — « Comment tu identifies les lacunes de télémétrie ? »

> « DeTT&CT. Je croise deux choses : les sources que je collecte réellement, avec leur qualité et leur rétention, et les techniques que je détecte — ces dernières sont générées automatiquement depuis les tags ATT&CK de mes règles Sigma, jamais saisies à la main. Ça produit trois couches ATT&CK Navigator : ce que je vois, ce que je détecte, et l'écart.
>
> Le point important, c'est que ma carte n'est jamais périmée, parce qu'elle est dérivée du code. La plupart des SOC ont une matrice ATT&CK dans un PowerPoint qui datait déjà le jour de la présentation. La mienne se régénère à chaque commit. La couverture est un produit du code, pas un document.
>
> Pour la priorisation, je n'ordonne pas par facilité. J'utilise mon service de threat intel, qui score les CVE par profil sectoriel à partir de NVD, CISA KEV et GitHub Advisories — pour CAE ce serait gov/ICS. Les mêmes menaces n'ont pas la même priorité selon le secteur.
>
> Mon gap n°1 aujourd'hui : le script block logging PowerShell n'est pas activé. Coût de remédiation nul, une GPO, et ça complète T1059.001 et T1027. C'est en tête de mon backlog. »

---

### 🟡 Q4 bis — « Comment tu enrichis une alerte ? / Pourquoi VirusTotal ET ton propre service ? »

> « Deux couches, parce qu'elles répondent à deux questions différentes.
>
> VirusTotal répond à la question tactique : ce hash, cette IP, ce domaine est-il *déjà connu* comme malveillant ? C'est de la réputation d'indicateur, immédiate. Mon propre service répond à la question stratégique : cette *famille de menace* est-elle prioritaire pour mon secteur ? Il score les CVE par profil — pour CAE ce serait gov/ICS.
>
> Les deux sont en best-effort : timeout court, `on_error: continue`. Si VirusTotal rate-limit ou si mon service est down, le cas est quand même créé, juste avec moins de contexte. Un SOAR qui plante parce qu'une source d'enrichissement est indisponible est un SOAR mal conçu.
>
> Sur VirusTotal, trois choses précises : je respecte le rate limit de l'API gratuite avec un sémaphore, je cache les verdicts parce que le même malware frappe plusieurs postes, et je raisonne en ratio de moteurs — quarante-cinq sur soixante-dix, pas trois sur soixante-dix, qui est souvent du faux positif. Et un hash inconnu de VirusTotal, je ne le traite jamais comme bénin : inconnu veut dire jamais vu, ce qui est précisément le cas d'un malware ciblé.
>
> Et le point qui compte pour vous : je n'interroge VirusTotal que par hash, jamais en uploadant un fichier. Dans une boîte de défense, uploader un fichier interne sur une plateforme publique n'est pas un enrichissement, c'est un incident. Mon code n'a aucun chemin d'upload — c'est structurel. »

> ⚡ **La dernière phrase — hash jamais fichier — est celle qui te classe.** Place-la même si on ne te pose que « pourquoi VirusTotal ». C'est le réflexe de quelqu'un qui a pensé au contexte CAE, pas au SOC générique.

---

### 🟡 Q5 — « Kubernetes, tu as ça où ? »
*(Ne surjoue pas. La précision vaut plus que l'ampleur.)*

> « k3s en labo, mono-nœud. J'ai écrit le chart Helm : Deployment, Service, ConfigMap pour les playbooks, Secret, ServiceAccount avec RBAC minimal, securityContext restreint — non-root UID 1001, readOnlyRootFilesystem, capabilities drop ALL, seccomp RuntimeDefault — NetworkPolicy en deny-all avec egress explicite, et le namespace en Pod Security Admission `restricted`. Provisionné par Terraform avec les providers kubernetes et helm.
>
> Ce que je n'ai pas : du capacity planning, du multi-tenant, de la gestion d'incident à 3 h du matin sur un cluster de production. Je connais la mécanique et les points de rupture — par exemple, `readOnlyRootFilesystem` casse tout de suite si tu n'ajoutes pas un emptyDir sur /tmp, et `USER soc` au lieu de `USER 1001` fait refuser le pod par `runAsNonRoot` parce que Kubernetes vérifie l'UID numérique, pas le nom.
>
> L'échelle, je l'apprendrai chez vous. »

---

### 🟡 Q6 — « Pourquoi la NetworkPolicy ? »

> « Parce que mon SOAR a les clés du royaume : il peut isoler des machines, il détient les credentials de Wazuh, TheHive et Slack. Si on le compromet, il ne doit pas pouvoir parler à autre chose que ces quatre destinations. C'est de la limitation du rayon d'explosion.
>
> Et parce que Kubernetes est plat par défaut : sans NetworkPolicy, n'importe quel pod parle à n'importe quel pod, y compris à l'API du cluster. Beaucoup de gens l'ignorent — ils pensent que le namespace isole. Le namespace isole les noms, pas le réseau. »

---

### 🟡 Q7 — « Ton webhook, il est protégé comment ? »

> « HMAC-SHA256 sur le corps de la requête, avec un secret généré par Terraform — il n'a jamais été tapé par un humain et n'existe nulle part en clair hors du Secret Kubernetes.
>
> Pourquoi c'est critique : mon webhook peut déclencher l'isolation d'un hôte. S'il est ouvert, n'importe qui sur le réseau forge une alerte et me fait couper un serveur de production. Le SOAR devient l'arme de l'attaquant. La signature prouve que l'alerte vient bien du manager Wazuh.
>
> Un détail : j'utilise `hmac.compare_digest`, pas `==`. Une comparaison de chaînes normale s'arrête au premier octet différent, ce qui fuit de l'information par timing et permet de deviner la signature octet par octet. `compare_digest` est à temps constant. C'est de l'OWASP ASVS L2 — je l'avais déjà appliqué sur mon API de threat intel. »

---

### 🟡 Q8 — « Tu réponds 202 et tu traites en arrière-plan. Pourquoi ? »

> « Wazuh a un timeout court sur ses intégrations. Mon playbook prend jusqu'à 40 secondes — plus si une approbation humaine est en jeu. Si je réponds à la fin, Wazuh croit que j'ai échoué et renvoie l'alerte. D'où l'idempotence : clé de déduplication en base, contrainte d'unicité, un rejeu retourne l'exécution existante sans rien recréer.
>
> La contrainte est en base, pas en mémoire — donc la garantie tient même à trois replicas.
>
> Et la limite : `BackgroundTasks` de FastAPI perd les tâches en cours si le pod meurt. En production, ce serait une vraie file — Redis avec Celery ou RabbitMQ — pour survivre à un redémarrage. C'est dans mes limites connues. »

---

### 🟡 Q9 — « Pourquoi les playbooks en YAML ? »

> « Séparation du moteur et du contenu. Dans un SOC, celui qui connaît la réponse à incident, c'est l'analyste, pas le dev. Si chaque modification de playbook exige un développeur et un déploiement applicatif, le SOC se fige — et un SOC figé, c'est un SOC qui ne s'adapte pas à la menace.
>
> Avec du YAML validé par un schéma Pydantic, un analyste écrit son playbook, la CI le valide, il part en ConfigMap. Le moteur ne bouge pas.
>
> Le compromis : un DSL YAML est moins expressif que Python. Ma règle : si un playbook a besoin de logique complexe, j'ajoute une action Python au registre plutôt que de complexifier le DSL. Le DSL reste bête ; l'intelligence est dans les actions. C'est ce qui empêche tous les DSL de dégénérer en mauvais langage de programmation.
>
> C'est aussi ce que font XSOAR, Splunk SOAR et Sentinel — je n'ai pas inventé le pattern, je l'ai reproduit parce qu'il est correct. »

---

### 🔴 Q10 — « Ton moteur exécute du Jinja2. C'est pas dangereux ? »
*(Si on te la pose, c'est qu'on a lu ton code. Excellent signe.)*

> « Très. C'est le point de sécurité n°1 de mon projet, et je l'ai traité comme tel.
>
> Un `jinja2.Environment` standard donne accès aux attributs internes Python. Un playbook contenant `{{ ''.__class__.__mro__[1].__subclasses__() }}` c'est une RCE sur mon SOAR — et mon SOAR a les credentials de l'EDR. J'utilise `SandboxedEnvironment`, qui bloque l'accès aux dunder et les appels dangereux.
>
> Trois contrôles autour : un test unitaire qui **prouve** que l'évasion échoue — c'est le test le plus important de mon repo ; une règle Semgrep custom en CI qui fait échouer le build si quelqu'un importe `Environment` au lieu de `SandboxedEnvironment` ; et `StrictUndefined`, pour qu'une variable manquante lève une exception au lieu de rendre une chaîne vide — sinon une typo comme `alert.agnet.name` isolerait l'hôte nommé chaîne vide. Échouer bruyamment plutôt qu'agir silencieusement sur la mauvaise cible.
>
> Plus la défense en profondeur : les playbooks arrivent par PR sur une branche protégée et sont montés en ConfigMap read-only. »

---

### 🟢 Q11 — « Raconte-moi un problème que tu as rencontré. »
*(→ L'histoire LSASS de Q3. Ne raconte rien d'autre. C'est ton anecdote signature.)*

---

### 🟢 Q12 — « Comment tu ferais évoluer ça chez nous ? »
*(La question de fin. Elle teste si tu comprends leur contexte, pas ton projet.)*

> « Trois choses, dans cet ordre.
>
> D'abord, je remplacerais mon moteur par le vôtre. Si vous avez XSOAR ou Sentinel, mon travail devient : porter les playbooks, brancher les intégrations, et écrire les tests — parce que la partie qui a de la valeur dans mon projet, ce n'est pas le moteur, c'est la discipline autour : Detection-as-Code, tests de vrai et faux positif, audit trail, réponse graduée.
>
> Ensuite, j'appliquerais le pipeline de test de détection à vos règles existantes. Je pense que c'est là que je créerais le plus de valeur rapidement : la plupart des SOC ont des centaines de règles dont personne ne sait lesquelles fonctionnent encore. Un backlog de fixtures et un job CI, et vous savez.
>
- Enfin, la couverture ATT&CK dérivée du code plutôt que maintenue à la main.
>
> Mais surtout, j'aurais des questions avant de proposer quoi que ce soit — je ne connais ni votre SIEM, ni votre volume, ni votre modèle de menace. Un simulateur de vol et une flotte de postes bureautiques n'ont pas le même profil de risque. »

> **⚡ La dernière phrase est celle qui compte.** Elle dit : je ne suis pas là pour vous vendre mon projet, je suis là pour comprendre le vôtre.

---

## 4. Les questions QUE TU POSES

**Poses-en 3 à 5. Elles sont évaluées autant que tes réponses.** Ce sont des questions d'ingénieur, pas de candidat.

1. **« Quel est votre SIEM principal aujourd'hui, et est-ce que vos règles de détection sont versionnées ou éditées dans l'interface ? »**
   → Tu vises exactement le cœur du poste. Leur réponse te dit tout sur la maturité de l'équipe.

2. **« Est-ce que vous avez un SOAR en place, ou est-ce que ce poste doit le construire ? »**
   → Réponse cruciale pour toi : construire ≠ maintenir.

3. **« Quel est le ratio actuel entre développement d'outils et support d'incidents dans ce rôle ? Est-ce qu'il y a de la garde ? »**
   → Question pratique et légitime. **Et tu dois avoir tranché ta propre position sur la garde avant jeudi** (c'était déjà en suspens pour Croesus et Precicom).

4. **« Est-ce que le SOC couvre aussi des environnements OT ou des systèmes embarqués des simulateurs, ou uniquement l'IT corporatif ? »**
   → ⚡ **La meilleure question.** CAE fait des simulateurs de vol. Personne ne pose celle-là. Elle dit : j'ai réfléchi à *votre* modèle de menace, pas au SOC générique.

5. **« Comment mesurez-vous l'efficacité du SOC aujourd'hui — MTTD, MTTR, taux d'automatisation ? »**
   → Tu parles le langage du gestionnaire. Et ça relance sur tes propres métriques.

6. **« L'offre mentionne la collaboration avec l'ingénierie de détection — c'est une équipe séparée ? Comment se fait le passage de la règle à la réponse ? »**
   → Tu ramènes sur ton fil rouge `response_playbook` sans le forcer.

---

## 5. Le sujet à ne pas éviter : l'anglais

**L'offre le répète deux fois.** C'est ton vrai risque, plus que la technique.

**Ne le contourne pas — devance-le, une fois, calmement, et n'y reviens pas :**

> « Mon français est natif, mon anglais est fonctionnel — je lis et j'écris sans difficulté, tout mon repo et ma documentation sont en anglais. À l'oral, je suis plus lent, surtout sur un sujet nouveau. Je le travaille activement. Si une partie de l'entrevue se fait en anglais, allons-y — c'est mieux que vous le sachiez maintenant plutôt qu'après. »

**Puis fais-le.** Ils basculeront peut-être en anglais. **Sois prêt :**
- Pitch en anglais : **10 répétitions à voix haute** cette semaine, chronométré.
- Les 4 réponses les plus probables (Q1, Q2, Q3, Q5) : au moins **3 fois chacune en anglais**.
- Le vocabulaire à ne pas chercher sur le moment : *fail-safe, blast radius, false positive/negative, blind spot, trade-off, containment, out of scope, known limitation, best-effort, idempotent, deterministic*.

> **Si tu bloques sur un mot :** *« Sorry — how do I say… »* et continue. **Ne t'excuse pas deux fois.** Un ingénieur qui cherche un mot mais dit quelque chose de juste bat un anglophone qui parle bien et ne dit rien.

---

## 6. La démo en direct — protocole anti-catastrophe

**Ils demanderont peut-être à voir. Prépare-toi comme si oui.**

### Avant (le 22 au soir)
- [ ] Labo **allumé et vérifié** — une alerte de test passe de bout en bout
- [ ] Snapshots à jour sur les deux VMs
- [ ] Le repo ouvert dans VS Code, sur `main`, CI verte
- [ ] La vidéo YouTube ouverte dans un onglet (**ton filet de sécurité**)
- [ ] Un terminal avec les commandes prêtes dans l'historique
- [ ] **Teste le partage d'écran.** Ferme Slack perso, notifications OFF, fond d'écran neutre

### L'ordre de démo (5 min max)
1. Le schéma d'architecture (20 s)
2. Une règle Sigma — pointe `response_playbook` : **c'est le fil rouge** (30 s)
3. Le playbook YAML correspondant — pointe `destructive`, `rollback`, `when` (45 s)
4. `pytest tests/detection/ -v` → vert en 0,4 s (30 s) — **le moment fort**
5. Le job `sigma` dans GitHub Actions (30 s)
6. Les logs d'une exécution + le cas TheHive (60 s)
7. La carte ATT&CK — **et tu pointes le rouge** (30 s)

### 🚨 Si ça plante
> **« Ça, c'est le labo qui me rappelle que c'est un labo. Je vous montre l'enregistrement, et pendant ce temps je vous explique ce qui aurait dû se passer. »**
>
> Puis **ouvre la vidéo**, calmement, sans t'excuser trois fois.
> **La façon dont tu gères une démo qui casse est plus révélatrice que la démo elle-même.** Un ingénieur de production sait que tout casse un jour ; ce qu'on évalue, c'est ton calme et ton plan B. **Tu en as un. Utilise-le.**

---

## 7. Les 7 phrases qui gagnent l'entrevue

Elles doivent sortir **naturellement**, pas récitées. Place-les quand le contexte s'y prête.

1. **« Le SOAR change, la discipline reste. Ce qui a de la valeur dans mon projet, c'est le Detection-as-Code, les tests de vrai et faux positif, et l'audit trail — pas mon moteur. »**
2. **« On détecte le comportement, pas l'outil. L'outil est une variable ; l'objectif de l'attaquant est une constante. »**
3. **« Fail-safe, pas fail-open. En cas de doute, le système ne fait rien. »**
4. **« Une matrice ATT&CK toute verte est toujours un mensonge. »**
5. **« La question n'est pas "est-ce que je peux automatiser", c'est "qu'est-ce qui mérite d'être automatisé, et jusqu'où". »**
6. **« Si vous utilisez CrowdStrike au lieu de Wazuh, je n'ouvre pas le moteur — j'ajoute un fichier de 40 lignes et je change une ligne dans le playbook. »**
7. **« Mes chiffres manuels sont optimistes, parce que je connaissais déjà les alertes. Un vrai analyste serait plus lent. »**

---

## 8. Les 6 pièges

| Piège | Ce que tu ne dis jamais | Ce que tu dis à la place |
|---|---|---|
| **Survendre** | « Je maîtrise Kubernetes » | « k3s en labo, j'ai écrit le chart, je connais les points de rupture. L'échelle, je l'apprendrai chez vous. » |
| **Dire IA** | « Mon SOAR utilise de l'IA pour décider » | « C'est de la logique déterministe écrite d'avance. Zéro IA, volontairement — je dois pouvoir expliquer chaque décision en audit. » |
| **Se défendre** | « Oui mais c'est juste un labo… » | « Bonne question. Non, je ne l'ai pas fait. Voilà pourquoi, et voilà ce que je ferais. » |
| **Meubler** | *(30 s de flou parce que tu ne sais pas)* | « Je ne sais pas. Je regarderais X en premier. » — **et tu t'arrêtes.** |
| **Ignorer le trou** | *(cacher T1087 dans la démo)* | « Ici je ne détecte pas. C'est documenté, priorisé, et voici la remédiation. » |
| **Réciter** | *(débiter le pitch en robot)* | Pitch, **silence**, puis réponds à leur question à eux |

> **« Je ne sais pas » est une réponse complète.** La suivre de « voici ce que je regarderais en premier » la transforme en démonstration de méthode. **Personne n'est éliminé pour un « je ne sais pas ». Beaucoup le sont pour un bluff.**

---

## 9. Répétition — le planning

| Quand | Quoi | Durée |
|---|---|---|
| **Chaque soir 17-21** | Le pitch FR à voix haute, chronométré | 10 min |
| **Sam 18** | Q1, Q2 à voix haute, FR | 20 min |
| **Dim 19** | Q3, Q4 — après avoir écrit les règles, elles seront naturelles | 20 min |
| **Lun 20** | **L'histoire LSASS** — elle vient de naître aujourd'hui | 15 min |
| **Mar 21** | Q5, Q6, Q7 — juste après avoir écrit le chart | 25 min |
| **Mer 22 matin** | **Pitch EN × 10**, chronométré | 45 min |
| **Mer 22 aprèm** | Q1-Q3-Q5 en EN × 3 | 40 min |
| **Mer 22 soir** | Démo complète en solo, chronométrée, comme si c'était eux | 30 min |
| **Jeu 23 matin** | Relis §7 et §8. **Ne code pas. Ne touche à rien.** | 15 min |

> ⚠️ **Le 23 au matin : ne pousse aucun commit.** Un repo qui casse le matin de l'entrevue, ça arrive, et ça détruit ta confiance juste avant. **Freeze le 22 au soir. Tag `v0.3.0`. Terminé.**

---

## 10. Checklist du 22 au soir

**Le projet**
- [ ] CI verte sur `main`
- [ ] `pytest tests/detection/` vert — screenshot dans le README
- [ ] Vidéo 5 min en ligne, lien en haut du README
- [ ] `docs/threat-model.md`, `telemetry-gap-analysis.md`, `e2e-validation.md`, `lessons-learned.md` écrits
- [ ] Section « Limites connues » **honnête** dans le README
- [ ] Repo et doc **en anglais**
- [ ] `detect-secrets` sur tout l'historique → **zéro secret**
- [ ] Tag `v0.3.0` poussé

**Toi**
- [ ] Pitch FR fluide, sans notes, ≤ 100 s
- [ ] Pitch EN fluide, ≤ 110 s
- [ ] Q1, Q2, Q3, Q5 solides en FR ; Q1, Q3 en EN
- [ ] L'histoire LSASS répétée
- [ ] Tes 5 questions écrites sur une feuille
- [ ] Ta position sur la garde 24/7 : **tranchée**
- [ ] Ta fourchette salariale : **prête** (réf. §13 : Cyber Analyst QC 85-130K ; ce poste = 3-6 ans d'exp demandés → **vise 90-110K**, ne donne pas de chiffre en premier)

**Le matériel**
- [ ] Labo allumé, alerte de test passée ce soir
- [ ] Partage d'écran testé, notifications OFF
- [ ] Vidéo ouverte dans un onglet
- [ ] Repo ouvert dans VS Code
- [ ] Batterie, casque, connexion vérifiés

---

## 11. Le dernier mot

Tu ne présentes pas un projet d'étudiant. Tu présentes une plateforme qui :
- **teste ses détections contre de vraies attaques** — la majorité des SOC en production ne le font pas ;
- **traite son propre orchestrateur comme un système privilégié**, avec un threat model ;
- **régénère sa couverture ATT&CK depuis le code** au lieu d'un PowerPoint périmé ;
- **documente ses angles morts** au lieu de peindre la matrice en vert ;
- **refuse par défaut** quand personne ne répond.

Et par-dessus, tu as quelque chose que peu de candidats ont : **quatre ans à automatiser de l'infrastructure de production**. Les runbooks, les rollbacks, les procédures documentées, la branch protection — ce n'est pas de la théorie chez toi. La 8ᵉ responsabilité de l'offre, « documenter les processus, architectures et procédures opérationnelles », c'est ton métier depuis 2022.

Le 23 juillet, tu ne vas pas *demander* ce poste. Tu vas montrer à quoi ressembleraient tes six premiers mois chez eux.

**Ils t'ont déjà appelé. Ils veulent que tu sois bon. Va être bon.**

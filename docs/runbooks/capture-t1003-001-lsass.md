# Runbook — Capture de télémétrie T1003.001 (LSASS Memory Access) sur `victim-win`

> **But** : détoner `procdump -ma lsass.exe` (Atomic Red Team T1003.001, test 1) sur
> la VM `victim-win`, capturer la télémétrie **Sysmon EID 10 (ProcessAccess)** réelle,
> et rapatrier un fichier `t1003.001_lsass_test1.json` vers l'hôte pour faire passer
> le test vrai-positif de `skip` à **vert** et promouvoir la règle en `stable`.
>
> **Principe non négociable (détection pilotée par la menace)** : on ne fabrique
> jamais la télémétrie. Si l'attaque ne produit pas d'EID 10, on corrige la *source
> de log* (Sysmon) — on ne bricole pas le JSON à la main.

---

## 0. Faut-il cloner soc-autopilot dans la VM ? — NON

La VM ne produit que de la **télémétrie brute**. Le code de détection vit sur l'hôte.
Ce runbook est **autosuffisant** : la logique de capture est inlinée plus bas (§4).
Pré-requis dans la VM :

| Composant | État attendu | Vérif |
|---|---|---|
| PowerShell **Admin** | requis | `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')` → `True` |
| Atomic Red Team | déjà installé | dossier `C:\AtomicRedTeam` présent |
| Sysmon | installé **et** journalise `ProcessAccess` sur lsass | voir §2 |

---

## 1. Snapshot AVANT (fortement recommandé)

Le test manipule la mémoire de LSASS et écrit un `.dmp`. Prends un snapshot pour
revenir à un état propre (côté **hôte**, la VM peut rester allumée) :

```bash
# Sur l'HÔTE (bac à sable ne pilote pas libvirt/VirtualBox → à toi de lancer)
VBoxManage snapshot "victim-win" take "pre-t1003.001" --live
# (ou, si libvirt :  virsh snapshot-create-as victim-win pre-t1003.001 )
```

---

## 2. Vérifier que Sysmon journalise `ProcessAccess` (EID 10) — LE piège n°1

Ta règle est `logsource: process_access`. Si Sysmon n'inclut pas de règle
`ProcessAccess` ciblant `lsass.exe`, **la détonation ne produira aucun EID 10** :
le JSON sera vide de la télémétrie utile et le test ne pourra pas verdir. C'est une
règle *aveugle par construction*, pas fausse.

**Test de présence** (PowerShell Admin) :

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -MaxEvents 100 -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'lsass\.exe' } |
  Select-Object -First 3 TimeCreated, @{n='Msg';e={ ($_.Message -split "`n" | Select-String 'TargetImage|GrantedAccess|SourceImage') -join ' | ' }} |
  Format-List
```

- **Des événements s'affichent** → config OK, passe à la §3.
- **Rien ne s'affiche** → ProcessAccess n'est pas capturé. Corrige la config Sysmon :

<details>
<summary><b>Patch config Sysmon — ajouter la capture ProcessAccess sur lsass</b></summary>

`sysmon -c <fichier>` **remplace toute la config active**. Il faut donc **éditer ta
config existante**, pas en pousser une minimale (qui effacerait tes autres règles).

1. Retrouve le fichier de config utilisé à l'install (souvent `sysmonconfig.xml`,
   `sysmon-config.xml`, config SwiftOnSecurity ou Olaf Hartong).
2. Dans le bloc `<EventFiltering>`, ajoute (ou dé-commente) :

   ```xml
   <RuleGroup name="ProcAccess-LSASS" groupRelation="or">
     <ProcessAccess onmatch="include">
       <!-- Toute ouverture de handle vers lsass = signal T1003.001 -->
       <TargetImage condition="image">lsass.exe</TargetImage>
     </ProcessAccess>
   </RuleGroup>
   ```

   > Beaucoup de configs "anti-bruit" (SwiftOnSecurity) **excluent** ProcessAccess
   > par défaut à cause du volume. En labo, on l'inclut assumé — le bruit est le prix
   > de la visibilité credential-access.

3. Recharge :
   ```powershell
   # adapte le nom du binaire (sysmon.exe / sysmon64.exe) et le chemin de la config
   Sysmon64.exe -c C:\chemin\sysmonconfig.xml
   ```
4. Re-lance le test de présence ci-dessus (après une petite activité) pour confirmer.

*Si tu ne retrouves pas ta config : note-le, on la reconstruit ensemble au retour.*
</details>

---

## 3. Marqueur Defender (piège n°2)

`procdump -ma lsass.exe` est souvent bloqué/mis en quarantaine par Defender. Si la
§4 ne produit aucun EID 10 **alors que** la §2 est verte, c'est probablement Defender.

**On ne désactive pas la sécurité pour "réussir".** Deux options *documentées* :

```powershell
# Vérifier si Defender a bloqué quelque chose
Get-MpThreatDetection | Select-Object -First 5 InitialDetectionTime, ThreatID, Resources

# Option assumée : exclusion CIBLÉE du dossier de test (à noter dans lessons-learned)
Add-MpPreference -ExclusionPath "C:\captures"
Add-MpPreference -ExclusionProcess "procdump.exe"
```

> Si tu dois exclure : dis-le-moi au retour, je le consigne dans
> `docs/lessons-learned.md` comme *limite connue* de la mesure.

---

## 4. Détonation + capture (script inliné — aucun fichier du repo requis)

Colle **tout ce bloc** dans PowerShell **Admin**. Il fait : marqueur temporel →
prérequis Atomic → attaque → extraction Sysmon → écriture au format de fixture →
cleanup Atomic.

```powershell
$Technique   = "T1003.001"
$TestNumbers = "1"
$OutDir      = "C:\captures"

Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# 1) Marqueur AVANT — on ne garde que le delta causé par l'attaque
$start = (Get-Date).AddSeconds(-2)
Write-Host "[*] Marqueur : $start" -ForegroundColor Cyan

# 2) Prérequis (télécharge procdump si besoin)
Write-Host "[*] Prérequis $Technique..." -ForegroundColor Cyan
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers -GetPrereqs

# 3) L'ATTAQUE
Write-Host "[!] Exécution $Technique test $TestNumbers" -ForegroundColor Red
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers
Start-Sleep -Seconds 5   # Sysmon écrit de façon asynchrone

# 4) Extraction Sysmon (tous les événements depuis le marqueur)
Write-Host "[*] Extraction Sysmon..." -ForegroundColor Cyan
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $start
} -ErrorAction SilentlyContinue

$parsed = foreach ($e in $events) {
    $xml  = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [PSCustomObject]@{
        EventID     = $e.Id
        TimeCreated = $e.TimeCreated.ToString("o")
        Computer    = $e.MachineName
        EventData   = $data
    }
}

# 5) Écriture au format de fixture attendu par tests/detection/
$outFile = Join-Path $OutDir "$Technique`_test$TestNumbers.json"
@{
    technique   = $Technique
    test        = $TestNumbers
    captured    = (Get-Date).ToString("o")
    source      = "Atomic Red Team"
    event_count = @($parsed).Count
    events      = $parsed
} | ConvertTo-Json -Depth 10 | Out-File $outFile -Encoding utf8
Write-Host "[+] $(@($parsed).Count) événements → $outFile" -ForegroundColor Green

# 6) Cleanup Atomic (supprime le .dmp / annule la persistance)
Write-Host "[*] Cleanup..." -ForegroundColor Cyan
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers -Cleanup
```

---

## 5. Sanity-check du JSON AVANT de le rapatrier

Confirme qu'on a bien au moins un **EID 10 vers lsass** et note le `GrantedAccess`
(notre point de décision côté règle) :

```powershell
$j = Get-Content C:\captures\T1003.001_test1.json -Raw | ConvertFrom-Json
Write-Host "Total événements : $($j.event_count)"
$j.events | Where-Object EventID -eq 10 |
  ForEach-Object { $_.EventData } |
  Select-Object SourceImage, TargetImage, GrantedAccess, CallTrace |
  Format-List
```

**Attendu** : au moins une ligne où `TargetImage` finit par `\lsass.exe`, `SourceImage`
finit par `\procdump.exe` (ou `procdump64.exe`), et un `GrantedAccess` (souvent
`0x1fffff` pour `procdump -ma`).

- **Zéro EID 10** → reviens en §2 (Sysmon) puis §3 (Defender). **Ne rapatrie pas**
  un JSON sans EID 10, il ne sert à rien.
- **Un `GrantedAccess` absent de la liste de la règle** (voir annexe) → parfait, c'est
  exactement l'ajustement piloté-par-la-menace : ramène le JSON, je corrige le masque.

---

## 6. Rapatrier le JSON vers l'hôte

Objectif : déposer `T1003.001_test1.json` sur l'hôte. **Ne le renomme pas, ne le
sanitise pas toi-même** — je fais `sanitize_fixtures.py` + le renommage côté hôte.

### Méthode A — dossier partagé VirtualBox (le plus simple si Guest Additions actif)

```powershell
Copy-Item C:\captures\T1003.001_test1.json "\\VBOXSVR\<nom_partage>\"
```
→ le fichier apparaît dans le dossier partagé côté hôte.

### Méthode B — la VM sert, l'hôte tire (Python-free, symétrique du port 8000)

Sur la **VM** (PowerShell Admin) :

```powershell
# Autorise le port 8000 en entrée sur l'adaptateur host-only
New-NetFirewallRule -DisplayName "tmp-capture-8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow | Out-Null

$file = "C:\captures\T1003.001_test1.json"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://+:8000/")
$listener.Start()
Write-Host "Sert $file sur http://192.168.56.20:8000/capture.json  — Ctrl+C après le pull"
$ctx = $listener.GetContext()                       # attend 1 requête
$bytes = [IO.File]::ReadAllBytes($file)
$ctx.Response.ContentType = "application/json"
$ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
$ctx.Response.Close(); $listener.Stop()
# Nettoyage de la règle firewall temporaire
Remove-NetFirewallRule -DisplayName "tmp-capture-8000"
```

Sur l'**HÔTE** (dans le repo) :

```bash
cd "/media/mdoub/Data/Personal Projects/soc-autopilot"
curl -o /tmp/t1003.001_lsass_raw.json http://192.168.56.20:8000/capture.json
ls -l /tmp/t1003.001_lsass_raw.json
```

> Puis dis-moi « c'est rapatrié dans /tmp/t1003.001_lsass_raw.json » et je prends le
> relais (sanitize → placement → pytest → tuning masque → promotion → coverage → PR).

---

## 7. Cleanup / restauration

```powershell
# Retire l'exclusion Defender si tu l'avais ajoutée (§3)
Remove-MpPreference -ExclusionPath "C:\captures" -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionProcess "procdump.exe" -ErrorAction SilentlyContinue
```

```bash
# Sur l'HÔTE, restaure le snapshot propre si tu veux repartir de zéro
VBoxManage snapshot "victim-win" restore "pre-t1003.001"
```

---

## Ce que tu me ramènes (checklist)

- [ ] `§2` verte (Sysmon logue ProcessAccess/lsass) — ou tu me signales qu'elle était rouge.
- [ ] Le JSON contient **≥ 1 EID 10** `TargetImage=…\lsass.exe`, `SourceImage=…\procdump.exe`.
- [ ] La valeur `GrantedAccess` observée (copie-la dans ton message).
- [ ] Le fichier déposé sur l'hôte (méthode A ou B), chemin exact.
- [ ] Defender a-t-il bloqué / as-tu dû exclure ? (oui/non — pour `lessons-learned.md`).

---

## Annexe — masques `GrantedAccess` de référence

| Masque | Sémantique | Outil typique |
|---|---|---|
| `0x1010` | `QUERY_INFORMATION` + `VM_READ` (lecture mémoire minimale) | mimikatz |
| `0x1410` | + `VM_READ` | mimikatz |
| `0x1438` / `0x143a` | variantes `sekurlsa` | mimikatz |
| `0x1fffff` | `PROCESS_ALL_ACCESS` | **procdump `-ma`** |
| `0x1f0fff` / `0x1f1fff` / `0x1f2fff` | accès quasi-total | dumpers divers |

La règle (`detections/windows/t1003.001_lsass_memory_access.yml`) liste déjà la
plupart. Si la télémétrie réelle sort un masque **hors liste**, c'est le signal qu'on
ajuste la règle d'après la menace observée — et qu'on le documente.

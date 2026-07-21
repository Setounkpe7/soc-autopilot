# Leçons & décisions de détection

Ce document consigne les décisions de conception des règles et les points de
validation encore ouverts. Il est **factuel** : rien ici n'est une anecdote
reconstituée — les mesures et le vécu de détonation restent à produire sur le labo.

## T1003.001 — LSASS : pourquoi le masque `GrantedAccess` doit être validé, pas copié

La règle `detections/windows/t1003.001_lsass_memory_access.yml` cible un handle
vers `lsass.exe` avec un masque d'accès permettant la lecture mémoire, puis exclut
les sources signées (Defender/EDR) via `filter_signed`.

**Point ouvert, assumé :** la liste des masques `GrantedAccess` (`0x1010`, `0x1410`,
… `0x1fffff`) provient de la règle communautaire Sigma, **pas** d'une capture sur
mon propre index. Les sources ne sont d'ailleurs pas unanimes — la documentation
interne de ce projet cite tantôt `0x1410`, tantôt `0x1fffff` pour procdump. C'est
exactement pourquoi la règle est `status: experimental` et pourquoi son test de
vrai positif **se skippe** tant que la télémétrie réelle n'est pas capturée :

```powershell
# Sur victim-win (snapshot avant) :
.\tools\capture_atomic.ps1 -Technique T1003.001 -TestNumbers 1
# puis rapatrier vers tests/fixtures/attack/t1003.001_lsass_test1.json
```

Une fois le fixture en place, `pytest tests/detection/` valide (ou infirme) le masque.
Si le masque réel diffère de la liste, on l'ajoute — et **c'est cette correction,
pilotée par la télémétrie, qui fait la différence entre une règle qui détecte et
une règle verte-mais-aveugle.**

**La leçon générale :** une valeur de détection copiée d'un blog est une hypothèse.
Sans test contre la télémétrie réelle, un faux négatif silencieux part en production,
reste vert sur la carte ATT&CK, et ne détecte jamais l'attaque qu'il prétend couvrir.

## T1059.001 — le filtre de faux positif est venu du fixture bénin

Le fixture `tests/fixtures/benign/admin_activity.json` contient délibérément un
**cas-piège** : du PowerShell **encodé** lancé par un agent de monitoring légitime
(`MonitoringHost.exe`). Sans filtre, la règle encodée le matche — elle serait
inutilisable en production (SCCM/agents font ça en continu). Le test de faux positif
a donc justifié l'ajout de `filter_legit` (exclusion par `ParentImage`). C'est le test
qui a dicté la règle, pas l'inverse.

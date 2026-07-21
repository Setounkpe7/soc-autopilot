"""Retire les identifiants machine/utilisateur des fixtures avant de les commiter.

Un fixture brut contient nom de machine, SID, nom d'utilisateur, topologie réseau :
le commiter, c'est publier sa reconnaissance interne. Même réflexe que le PII
scrubbing des logs structurés.

Usage : python3 tools/sanitize_fixtures.py [répertoire]  (défaut : tests/fixtures)
"""

import re
import sys
from pathlib import Path

REPLACEMENTS = [
    (re.compile(r"\bDESKTOP-[A-Z0-9]+\b"), "VICTIM-WIN"),
    (re.compile(r"192\.168\.56\.\d+"), "10.0.0.20"),
    (re.compile(r"\\Users\\[^\\\"]+"), r"\\Users\\testuser"),
    (
        re.compile(r"S-1-5-21-[\d-]+"),
        "S-1-5-21-0000000000-0000000000-0000000000-1001",
    ),
]


def sanitize(root: Path) -> int:
    count = 0
    for path in root.rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        new = text
        for pattern, repl in REPLACEMENTS:
            new = pattern.sub(repl, new)
        if new != text:
            path.write_text(new, encoding="utf-8")
            print(f"sanitisé : {path}")
            count += 1
    return count


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/fixtures")
    changed = sanitize(target)
    print(f"{changed} fichier(s) modifié(s) sous {target}")

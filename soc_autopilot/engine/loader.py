from pathlib import Path

import structlog
import yaml

from soc_autopilot.engine.schema import Playbook

log = structlog.get_logger()


class PlaybookStore:
    """Charge, valide et indexe les playbooks. Hot-reload."""

    def __init__(self, directory: str) -> None:
        self._dir = Path(directory)
        self._by_id: dict[str, Playbook] = {}
        self._by_rule: dict[str, list[Playbook]] = {}
        self._by_mitre: dict[str, list[Playbook]] = {}
        self.reload()

    def reload(self) -> None:
        by_id: dict[str, Playbook] = {}
        by_rule: dict[str, list[Playbook]] = {}
        by_mitre: dict[str, list[Playbook]] = {}
        errors = []
        for path in sorted(self._dir.glob("*.yml")):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                pb = Playbook(**raw)
            except Exception as exc:
                errors.append(f"{path.name}: {exc}")
                continue
            if pb.id in by_id:
                errors.append(f"{path.name}: id dupliqué {pb.id}")
                continue
            by_id[pb.id] = pb
            for rid in pb.trigger.rule_ids:
                by_rule.setdefault(rid, []).append(pb)
            for tech in pb.trigger.mitre:
                by_mitre.setdefault(tech, []).append(pb)

        if errors:
            # Fail-fast : on refuse de charger une config partiellement cassée
            raise ValueError("Playbooks invalides:\n  - " + "\n  - ".join(errors))

        self._by_id, self._by_rule, self._by_mitre = by_id, by_rule, by_mitre
        log.info("playbooks_loaded", count=len(by_id), ids=sorted(by_id))

    def match(self, alert: dict) -> list[Playbook]:
        """Retourne les playbooks déclenchés par cette alerte."""
        rule_id = str(alert.get("rule", {}).get("id", ""))
        level = int(alert.get("rule", {}).get("level", 0))
        mitre = alert.get("rule", {}).get("mitre", {}).get("id", []) or []

        candidates: dict[str, Playbook] = {}
        for pb in self._by_rule.get(rule_id, []):
            candidates[pb.id] = pb
        for tech in mitre:
            for pb in self._by_mitre.get(tech, []):
                candidates[pb.id] = pb

        return [pb for pb in candidates.values() if level >= pb.trigger.severity_min]

    def get(self, pb_id: str) -> Playbook:
        return self._by_id[pb_id]

    def all(self) -> list[Playbook]:
        return list(self._by_id.values())

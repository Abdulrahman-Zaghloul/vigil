"""The MITRE ATT&CK techniques that Vigil's rules report.

ATT&CK (https://attack.mitre.org) is a public catalogue of real-world attacker
behavior. Tagging each alert with a technique id lets analysts and other security tools
understand it instantly, and shows which parts of the catalogue Vigil can and cannot see.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactic: str  # the attacker's goal at this stage, e.g. "Credential Access"

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"


TECHNIQUES: dict[str, Technique] = {
    t.id: t
    for t in (
        Technique("T1110", "Brute Force", "Credential Access"),
        Technique("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
        Technique("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    )
}


def technique(technique_id: str) -> Technique:
    try:
        return TECHNIQUES[technique_id]
    except KeyError:
        raise KeyError(f"unknown ATT&CK technique {technique_id!r}") from None

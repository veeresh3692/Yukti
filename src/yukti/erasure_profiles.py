from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ErasureProfile:
    name: str
    passes: int
    verify: bool
    standard: str


ERASURE_PROFILES: dict[str, ErasureProfile] = {
    "clear": ErasureProfile("clear", passes=1, verify=True, standard="NIST_800_88_CLEAR"),
    "purge": ErasureProfile("purge", passes=3, verify=True, standard="NIST_800_88_PURGE"),
    "dod": ErasureProfile("dod", passes=3, verify=True, standard="DOD_5220_22_M"),
}


"""Tier definitions (T1-T5) per SRS section 3.2."""

from __future__ import annotations

from enum import IntEnum


class Tier(IntEnum):
    """Risk tiers, ordered from least to most dangerous.

    Comparisons (e.g. ``Tier.T4 > Tier.T2``) work naturally because this is
    an IntEnum ordered by severity.
    """

    T1 = 1  # Read-only
    T2 = 2  # Safe write
    T3 = 3  # Moderate risk — confirm + explanation (y/n)
    T4 = 4  # Destructive / hard-to-reverse — typed confirmation phrase
    T5 = 5  # Irreversible / high blast radius — deny by default

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def requires_confirmation(self) -> bool:
        return self >= Tier.T3

    @property
    def requires_typed_phrase(self) -> bool:
        return self >= Tier.T4

    @property
    def denied_by_default(self) -> bool:
        return self >= Tier.T5


_LABELS = {
    Tier.T1: "Read-only",
    Tier.T2: "Safe write",
    Tier.T3: "Moderate risk",
    Tier.T4: "Destructive / hard-to-reverse",
    Tier.T5: "Irreversible / high blast radius",
}

# Default-deny floor: any tool/command without an explicit ruleset entry is
# classified no lower than this (FR-2.3, §2.5).
DEFAULT_UNMAPPED_TIER = Tier.T4

# Minimum tier a user may configure a rule to via ruleset editing — rules may
# be tightened freely but never silently loosened below this (FR-2.5).
MIN_LOOSENABLE_TIER = Tier.T3

# Default per-tier execution timeouts in seconds (FR-4.3): lower default
# timeout for higher tiers.
DEFAULT_TIER_TIMEOUTS_SECONDS = {
    Tier.T1: 30,
    Tier.T2: 30,
    Tier.T3: 20,
    Tier.T4: 10,
    Tier.T5: 5,
}

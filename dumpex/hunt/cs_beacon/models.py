"""Internal data-transfer objects for the CS beacon scan pipeline.

These are NOT the public JSON shape — `aggregate.py` is the only place
that turns a Candidate/ScanOutcome into the public `findings` dict
(`configs`, `coverage`, ...). Keeping them separate means a future field
added here for internal bookkeeping can't accidentally leak into --json
output the way a bare dataclass placed directly into `findings` would
(see dumpex/hunt/encoding/models.py's docstring for the bug this avoids).
"""
from dataclasses import dataclass, field


@dataclass
class Candidate:
    """One structurally-valid (sanity-checked) beacon config found by scanner.py."""
    xor_key: int
    hit_va: int
    hit_fo: int
    fields: dict


@dataclass
class ScanOutcome:
    """Everything scanner.py learned from walking every memory segment."""
    segment_count: int
    hits: list                 # list[Candidate]
    coverage: "CoverageTracker"
    budget_exhausted: bool
    budget_reason: "str | None"
    total_candidates: int
    total_decoded_bytes: int
    total_scanned_bytes: int


@dataclass
class CorroboratedHit:
    """One Candidate plus context.py's independent memory-context verdict."""
    candidate: Candidate
    region: object              # MemoryInfo region, or None if unresolved
    corroborated: bool
    corrob_reasons: list = field(default_factory=list)

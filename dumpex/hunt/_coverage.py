"""
Shared coverage/status reduction for hunt modules.

Every phase-two hunter (injection/stomping/pipe/obfuscation) needs to
answer the same two questions at the end of a scan:

  1. coverage_status — did this hunter have what it needed to run, and
     did it get through everything it was supposed to look at?
     ("not_evaluated" / "partial" / "complete")
  2. status — the top-level DETECTED / NOT_DETECTED_IN_SCANNED_SCOPE /
     INCONCLUSIVE / NOT_EVALUATED a console/JSON/CSV consumer reads.

Before this module existed, each hunter hand-rolled the same two
if/elif chains separately (stomping.py, pipe.py, encoding.py each wrote
an near-identical copy; injection.py used a similarly-shaped but
differently-named helper — this history predates the injection.py ->
dumpex/hunt/injection/, stomping.py -> dumpex/hunt/stomping/, and
pipe.py -> dumpex/hunt/pipe/ package splits). That duplication is exactly how the four
hunters' coverage semantics could quietly drift apart from each other —
`derive_coverage_status()` and `derive_status()` are the single place
this reduction happens now; every hunter calls these two functions
rather than re-deriving the rule locally.

The reduction rule (the same for every hunter):

    no necessary data source / never actually ran  -> NOT_EVALUATED
    score > 0                                       -> DETECTED
                                                        (coverage_status
                                                        can still be
                                                        "partial")
    score == 0 and coverage incomplete              -> INCONCLUSIVE
    score == 0 and coverage complete                -> NOT_DETECTED_IN_SCANNED_SCOPE
"""
from dataclasses import dataclass, field

from dumpex.hunt._ui import (
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE,
)


def derive_coverage_status(evaluated: bool, complete: bool) -> str:
    """
    "not_evaluated"  — the hunter had none of the data sources it needed
                        (e.g. every required stream was missing) and
                        never actually ran its scan loop at all.
    "partial"        — it ran, but hit at least one coverage gap along
                        the way (a skipped/oversized region, a failed
                        read, an exhausted budget, a stream that was
                        present but incomplete, ...).
    "complete"        — it ran and got through everything in scope.
    """
    if not evaluated:
        return "not_evaluated"
    return "complete" if complete else "partial"


def derive_status(evaluated: bool, detected: bool, complete: bool = True) -> str:
    """
    Reduce (did this hunter actually get to scan, did coverage come out
    complete, did it find something) into the four top-level statuses.

    `detected` (score > 0) always wins over `complete` — a hunter that
    found something in what it DID manage to scan is DETECTED regardless
    of whether other parts of the dump were unreachable; that gap is
    still visible separately via coverage_status/coverage_reasons, not
    lost by downgrading a real hit to INCONCLUSIVE.
    """
    if not evaluated:
        return NOT_EVALUATED
    if detected:
        return DETECTED
    return INCONCLUSIVE if not complete else NOT_DETECTED_IN_SCANNED_SCOPE


@dataclass
class CoverageTracker:
    """
    Reusable accumulator for the generic shape a "scan every region/item,
    skip/fail on some of them" loop keeps running into across hunters:
    how many items existed, how many were actually scanned, and how many
    were skipped/failed for each of a handful of common reasons.

    Not every hunter's coverage gaps fit this generic shape exactly —
    the verified-content-diff loop in dumpex.hunt.stomping has several
    genuinely domain-specific gap reasons (reference file missing,
    reference identity mismatch, relocation normalization failure, ...)
    that don't map cleanly onto skipped_oversize/read_failed/short_reads,
    so it keeps its own richer coverage_counts dict rather than forcing
    those into this shape. Use CoverageTracker where the gaps genuinely
    ARE just "region too big / read failed / short read / ran out of
    time-or-budget" (the per-layer region scans in dumpex.hunt.encoding
    and the region scan in dumpex.hunt.pipe.memory_scan) — for everything
    else, track whatever the hunter's own reasons array needs and call
    derive_status()/derive_coverage_status()
    directly with an explicit `complete` boolean.
    """
    total:            int = 0   # eligible items found (before any skip/fail)
    scanned:          int = 0   # items actually read and analyzed
    skipped_oversize: int = 0   # eligible item skipped only for exceeding a size cap
    read_failed:      int = 0   # read raised/returned nothing usable
    short_reads:      int = 0   # read succeeded but returned less than expected
    timed_out:        int = 0   # abandoned once a deadline was hit
    budget_exhausted: bool = False
    reasons: list = field(default_factory=list)

    def note_skipped_oversize(self):
        self.skipped_oversize += 1

    def note_read_failed(self):
        self.read_failed += 1

    def note_short_read(self):
        self.short_reads += 1

    def note_timed_out(self):
        self.timed_out += 1

    def note_scanned(self):
        self.scanned += 1

    @property
    def complete(self) -> bool:
        """True iff nothing here forced a gap in what was actually scanned."""
        return not (self.skipped_oversize or self.read_failed
                    or self.short_reads or self.timed_out or self.budget_exhausted)

    def build_reasons(self, *, oversize_label="oversized item(s) skipped",
                       read_failed_label="item(s) failed to read",
                       short_read_label="item(s) had a short/incomplete read",
                       timed_out_label="item(s) abandoned after the scan deadline") -> list:
        """
        Render the accumulated counters into human-readable
        coverage_reasons strings, in a stable order. Any reasons already
        added via `reasons.append(...)` directly (e.g. a hunter-specific
        message) are kept and appended after the generic ones.
        """
        out = []
        if self.skipped_oversize:
            out.append(f"{self.skipped_oversize} {oversize_label}")
        if self.read_failed:
            out.append(f"{self.read_failed} {read_failed_label}")
        if self.short_reads:
            out.append(f"{self.short_reads} {short_read_label}")
        if self.timed_out:
            out.append(f"{self.timed_out} {timed_out_label}")
        if self.budget_exhausted:
            out.append("scan budget exhausted")
        out.extend(self.reasons)
        return out

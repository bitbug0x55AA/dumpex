"""What every `--report` enrichment section shares: the EnrichmentSection
envelope, its evidence-state and scope vocabularies, and the bounded-text
rules.

Report enrichment is bounded context attached to a `--report` run: one
process-wide ReportProcessEnrichment for the whole invocation, plus
per-card exception, allocation-neighborhood, handle-correlation, and
string-context projections carried on each TriageCardRecord.

Every projection is captured evidence and navigation context. None of it
reaches `findings`, `finding_details`, `verdict`, or the exit code -- a
card's verdict is decided by _TRIAGE_FINDING_KEYS alone, and an
enrichment section is free to be empty without changing any of them.

Each projection carries an EnrichmentSection saying what was evaluated,
how much was kept, and under which cap -- so a fully-evaluated empty
subset ("complete", included 0) is never mistaken for an absent stream
("missing").
"""
from dataclasses import dataclass

from dumpex.output.records.common import (
    ENRICHMENT_TEXT_CAP,
    _require_bool,
    _require_nonneg_int,
    _require_optional_nonneg_int,
)


ENRICHMENT_MISSING  = "missing"    # the stream/pages this section needs are not in the
                                     # dump: nothing was evaluated, and the empty subset
                                     # carries no negative
ENRICHMENT_PARTIAL  = "partial"    # some of the required evidence was usable and some
                                     # was not -- the subset is real but incomplete
ENRICHMENT_COMPLETE = "complete"   # the bounded evaluation ran to its own end; an empty
                                     # subset means "no eligible item", not "not looked at"
_ENRICHMENT_STATES = (ENRICHMENT_MISSING, ENRICHMENT_PARTIAL, ENRICHMENT_COMPLETE)

ENRICHMENT_SCOPE_PROCESS = "process"   # one result per --report invocation, shared by every card
ENRICHMENT_SCOPE_CARD    = "card"      # one result per triage card, about that card's own anchor
_ENRICHMENT_SCOPES = (ENRICHMENT_SCOPE_PROCESS, ENRICHMENT_SCOPE_CARD)


@dataclass(frozen=True)
class EnrichmentSection:
    """The scope, evidence state, counting, and provenance envelope every
    report-enrichment projection carries.

    `total` is the eligible count for this section's own selection class,
    or None when that population is not determinable from captured
    evidence. `included` is what was retained after `cap`. When `total` is
    known, `truncated` is exactly `included < total`: an eligible item is
    dropped only by the cap, never silently.

    `provenance` names the dump streams or collectors the section was
    built from, and `limitations` carries short notes on what the section
    could not establish. Both exist so a short or empty subset can be
    explained without re-reading the dump."""
    name:        str
    scope:       str            # ENRICHMENT_SCOPE_*
    status:      str            # ENRICHMENT_*
    total:       "int | None"
    included:    int
    cap:         "int | None"
    truncated:   bool
    provenance:  tuple = ()
    limitations: tuple = ()

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("EnrichmentSection.name must be a non-empty string")
        if self.scope not in _ENRICHMENT_SCOPES:
            raise ValueError(
                f"EnrichmentSection.scope must be one of {_ENRICHMENT_SCOPES}, "
                f"got {self.scope!r}")
        if self.status not in _ENRICHMENT_STATES:
            raise ValueError(
                f"EnrichmentSection.status must be one of {_ENRICHMENT_STATES}, "
                f"got {self.status!r}")
        _require_optional_nonneg_int(self.total, "EnrichmentSection.total")
        _require_nonneg_int(self.included, "EnrichmentSection.included")
        _require_optional_nonneg_int(self.cap, "EnrichmentSection.cap")
        _require_bool(self.truncated, "EnrichmentSection.truncated")
        object.__setattr__(self, "provenance", tuple(self.provenance))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        for label, values in (("provenance", self.provenance), ("limitations", self.limitations)):
            if any(not isinstance(v, str) or not v for v in values):
                raise ValueError(
                    f"EnrichmentSection.{label} must be a sequence of non-empty strings")
        if self.total is not None:
            if self.included > self.total:
                raise ValueError(
                    "EnrichmentSection.included must not exceed total -- a section retains a "
                    "subset of what it found eligible, never more")
            if self.truncated != (self.included < self.total):
                raise ValueError(
                    "EnrichmentSection.truncated must equal included < total whenever total is "
                    "known -- an eligible item is dropped only by the cap")
        if self.cap is not None and self.included > self.cap:
            raise ValueError("EnrichmentSection.included must not exceed cap")
        if self.status == ENRICHMENT_MISSING:
            if self.total is not None or self.included != 0 or self.truncated:
                raise ValueError(
                    "EnrichmentSection(status='missing') requires total=None, included=0, and "
                    "truncated=False -- nothing was evaluated, so nothing was eligible or cut")
        if self.status == ENRICHMENT_COMPLETE and self.total is None:
            raise ValueError(
                "EnrichmentSection(status='complete') requires a known total -- a completed "
                "bounded evaluation knows how many items were eligible")

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "scope":       self.scope,
            "status":      self.status,
            "total":       self.total,
            "included":    self.included,
            "cap":         self.cap,
            "truncated":   self.truncated,
            "provenance":  list(self.provenance),
            "limitations": list(self.limitations),
        }


def _require_enrichment_section(value, field_name: str, *, scope: str, name: str) -> None:
    if not isinstance(value, EnrichmentSection):
        raise TypeError(f"{field_name} must be an EnrichmentSection")
    if value.scope != scope:
        raise ValueError(f"{field_name}.scope must be {scope!r}, got {value.scope!r}")
    if value.name != name:
        raise ValueError(f"{field_name}.name must be {name!r}, got {value.name!r}")


def _require_optional_bounded_text(value, field_name: str,
                                   cap: "int | None" = None) -> None:
    """The retained-text cap for a field that may legitimately be absent.
    None is not a truncation and is left alone; any value present is held
    to the same cap as every other dump-derived string in this section."""
    if value is None:
        return
    limit = ENRICHMENT_TEXT_CAP if cap is None else cap
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be None or a non-empty string")
    if len(value) > limit:
        raise ValueError(f"{field_name} must be at most {limit} characters, got {len(value)}")

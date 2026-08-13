"""Internal data-transfer objects for the YARA scan/aggregate pipeline.
Not the public JSON shape -- aggregate.py reads these to build the
`findings` dict, unchanged in shape from before this package split.
"""
from dataclasses import dataclass, field


@dataclass
class RuleBundle:
    """Result of compiling every .yar/.yara file in a rules directory,
    plus reproducible content provenance for the exact files used (see
    dumpex/hunt/yara_hunt/__init__.py's get_yara_provenance())."""
    rule_files: list = field(default_factory=list)   # [(filename, compiled_rules), ...]
    compile_failed: int = 0
    provenance: dict = None


@dataclass
class ScanOutcome:
    """Everything scanner.py learned from walking every memory segment
    against every compiled rule file."""
    all_hits: list = field(default_factory=list)
    scanned: int = 0
    # One dumpex.output.coverage.ScanTarget per segment skipped ONLY for
    # exceeding config.max_seg_scan -- the segment itself is retained, not
    # just tallied, so a partial result names the exact VAs an
    # investigator still has to rescan or recollect. `skipped` stays
    # readable as a plain count, derived from this list so the two can
    # never disagree (mirrors dumpex.hunt._coverage.CoverageTracker,
    # which yara_hunt deliberately does not use -- see its own docstring
    # on hunters whose gap reasons don't fit that generic shape).
    skipped_targets: list = field(default_factory=list)
    read_failed: int = 0
    # One ScanTarget per segment that failed/short-read, same reasoning as
    # skipped_targets above (issue #28) -- unlike skipped_targets, these
    # counts stay meaningful even if a caller never appends a target (kept
    # as separate scalar counters, not derived, since CoverageLimitation's
    # own targets support on these two codes is OPTIONAL -- see
    # dumpex.output.coverage._require_optional_targets_matching_count).
    read_failed_targets: list = field(default_factory=list)
    short_reads: int = 0
    short_read_targets: list = field(default_factory=list)
    timed_out: int = 0
    # ScanTarget per TIMED-OUT/FAILED CALL, not deduplicated per segment
    # (issue #28 P4 follow-up) -- `timed_out`/`match_failed` themselves
    # count CALLS (see scanner.py's own comment on why that stays true),
    # so a segment failing against two different rule files contributes
    # its target twice, keeping len(...) == the corresponding count
    # exactly when non-empty (CoverageLimitation's own optional-targets
    # rule).
    timed_out_targets: list = field(default_factory=list)
    match_failed: int = 0
    match_failed_targets: list = field(default_factory=list)
    truncated: bool = False
    # ScanTarget per segment mid-processing or never started when the hit
    # cap was reached (issue #28 P5 follow-up) -- segment granularity,
    # not a byte remainder (yara examines a segment as one atomic unit
    # against each rule file, unlike injection's own byte-wise scan).
    truncated_targets: list = field(default_factory=list)
    # `truncated`'s own single, unambiguous budget (issue #28 P6
    # follow-up) -- always "max_total_hits" when truncated is True, never
    # any other resource, so this is set directly rather than tracked via
    # a _mark_*() call site the way budget_exhausted's own (ambiguous
    # between two resources) kind needs to be.
    truncated_budget_limit: "int | None" = None
    budget_exhausted: bool = False
    # Unlike truncated_targets above, can legitimately be EMPTY even when
    # budget_exhausted is True (issue #28 P6 follow-up): the deadline can
    # be discovered only after the scan's very last (segment, rule_file)
    # pairing already finished being fully examined -- a genuine
    # wall-clock overrun, but not a coverage gap, since nothing was
    # actually left unexamined. Mirrors CS Beacon's own
    # budget_exhausted_targets, which already had this shape.
    budget_exhausted_targets: list = field(default_factory=list)
    # WHICH of the two independent whole-scan budgets
    # ("scan_deadline_seconds"/"max_total_bytes_scanned") stopped the
    # scan, and that budget's own configured limit (issue #28 P6
    # follow-up) -- both None together when budget_exhausted is False.
    budget_exhausted_kind: "str | None" = None
    budget_exhausted_limit: "int | None" = None
    # The REAL amount of `budget_exhausted_kind`'s own resource actually
    # consumed at the moment it was attributed (issue #28 review
    # follow-up) -- NOT assumed to equal `budget_exhausted_limit`: the
    # post-read defensive backstop on total bytes scanned can genuinely
    # exceed the configured cap, and wall-clock elapsed time is measured
    # directly rather than assumed to equal the configured deadline. None
    # exactly when budget_exhausted is False.
    budget_exhausted_consumed: "int | None" = None
    total_bytes_scanned: int = 0
    suppressed_module_pe: int = 0
    suppressed_scoped: int = 0
    context_unverified: int = 0
    triggered_rules: set = field(default_factory=set)
    unverified_rules: set = field(default_factory=set)

    @property
    def skipped(self) -> int:
        return len(self.skipped_targets)


@dataclass
class RuleGroup:
    """One rule's hits, deduplicated by segment base VA, plus the display
    facts presentation.py needs -- built once by aggregate.py so it and
    the score/status computation agree on the same grouping."""
    rule_name: str
    file: str
    tags: list
    meta: dict
    seen_vas: dict            # seg_va -> hit
    rule_is_unverified: bool
    unverified_contexts: set = field(default_factory=set)

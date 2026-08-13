"""The canonical, recursively immutable domain model for the YARA hunter --
`YaraReport` plus the coverage/rules/scan-diagnostics snapshots and evidence
container it is built from. Mirrors `dumpex.hunt.cs_beacon.domain` (and,
through it, the five completed reference pilots) for the general "one
canonical result representation" shape -- but YARA deliberately does NOT
build on `dumpex.hunt._domain.CheckResult`/`dumpex.hunt._finding.Finding`
(issue #6's decision, issue #11's Goal: "without forcing YARA matches into
the Finding model"). `HunterRecord.findings` stays permanently `[]` for
`hunter="yara"` (dumpex/output/records.py's own yara-only-null rule), so
nothing here may build a Finding-shaped object at all.

Before this migration, `dumpex.hunt.yara_hunt.aggregate.Report` mixed the
public `findings` dict together with console-progress STATE that has
nothing to do with the scan's own result: `render_kind` (which of five
early-return branches fired), `scan_note` (a pre-rendered progress-line
suffix), raw `rules_dir`/`rule_file_count`/`segment_count` duplicating facts
`coverage_report` already carried, and a raw `modules` list kept alive
purely so `presentation.py` could resolve `addr_to_module()` at RENDER TIME
for every hit. `YaraReport` stores each fact exactly once:

  coverage  -- the immutable snapshot of what this run could and could not
               see, INCLUDING whether it ran at all (CoverageSnapshot).
  evidence  -- every individual rule match this run observed, with module/
               region context already resolved (YaraEvidence).

and DERIVES everything else -- `score`, `status`, `coverage_status`,
`verdict_level`, `triggered_rules`, `unverified_rules`, `has_hits` -- as
properties. There is no `render_kind`: which of the four "prerequisite
missing" cases (no yara-python, no rules directory, no usable rule files, no
memory segments) applies is always derivable from `coverage.rules`/
`coverage.scan` alone (see `CoverageSnapshot.evaluated`), the same way CS
Beacon's own `build_not_evaluated_report()` needs no stored reason string.
"""
from dataclasses import dataclass, field

from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._domain import require_recursively_immutable, as_tuple
from dumpex.hunt.yara_hunt.models import RuleMatchEvidence, RulesProvenance
from dumpex.output.coverage import ScanTarget


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {type(value).__name__}: {value!r}")


def _require_count(value, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{field_name} must be a non-negative int, got {type(value).__name__}: {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_optional_count(value, field_name: str) -> None:
    if value is not None:
        _require_count(value, field_name)


def _require_optional_str(value, field_name: str) -> None:
    if value is not None and type(value) is not str:
        raise TypeError(f"{field_name} must be a str or None, got {type(value).__name__}: {value!r}")


def _require_scan_targets(value, field_name: str) -> tuple:
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if type(item) is not ScanTarget:
            raise TypeError(
                f"{field_name}[{index}] must be a ScanTarget, got {type(item).__name__}: {item!r}")
    return items


@dataclass(frozen=True)
class ScanDiagnostics:
    """What scanner.py actually did across every captured memory segment --
    resource-budget/coverage FACTS, resolved once at scan time, rather than
    a live mutable `ScanOutcome`. Mirrors `dumpex.hunt.cs_beacon.domain.
    ScanDiagnostics`'s own "facts, not rendered reasons" rule.
    """
    segment_count:              int = 0
    scanned:                     int = 0
    skipped_oversize_targets:   tuple = field(default_factory=tuple)
    read_failed_targets:        tuple = field(default_factory=tuple)
    short_read_targets:         tuple = field(default_factory=tuple)
    timed_out_targets:          tuple = field(default_factory=tuple)
    match_failed_targets:       tuple = field(default_factory=tuple)
    truncated:                   bool = False
    truncated_targets:           tuple = field(default_factory=tuple)
    truncated_budget_limit:      "int | None" = None
    budget_exhausted:            bool = False
    budget_exhausted_targets:    tuple = field(default_factory=tuple)
    budget_exhausted_kind:       "str | None" = None
    budget_exhausted_limit:      "int | None" = None
    budget_exhausted_consumed:   "int | None" = None
    total_bytes_scanned:         int = 0
    suppressed_module_pe:        int = 0
    suppressed_scoped:           int = 0
    context_unverified:          int = 0   # HIT-level count (not distinct rules -- see
                                             # YaraReport.unverified_rules for that)

    def __post_init__(self):
        _require_count(self.segment_count, "ScanDiagnostics.segment_count")
        _require_count(self.scanned, "ScanDiagnostics.scanned")
        object.__setattr__(self, "skipped_oversize_targets", _require_scan_targets(
            self.skipped_oversize_targets, "ScanDiagnostics.skipped_oversize_targets"))
        object.__setattr__(self, "read_failed_targets", _require_scan_targets(
            self.read_failed_targets, "ScanDiagnostics.read_failed_targets"))
        object.__setattr__(self, "short_read_targets", _require_scan_targets(
            self.short_read_targets, "ScanDiagnostics.short_read_targets"))
        object.__setattr__(self, "timed_out_targets", _require_scan_targets(
            self.timed_out_targets, "ScanDiagnostics.timed_out_targets"))
        object.__setattr__(self, "match_failed_targets", _require_scan_targets(
            self.match_failed_targets, "ScanDiagnostics.match_failed_targets"))
        _require_bool(self.truncated, "ScanDiagnostics.truncated")
        object.__setattr__(self, "truncated_targets", _require_scan_targets(
            self.truncated_targets, "ScanDiagnostics.truncated_targets"))
        _require_optional_count(self.truncated_budget_limit, "ScanDiagnostics.truncated_budget_limit")
        _require_bool(self.budget_exhausted, "ScanDiagnostics.budget_exhausted")
        object.__setattr__(self, "budget_exhausted_targets", _require_scan_targets(
            self.budget_exhausted_targets, "ScanDiagnostics.budget_exhausted_targets"))
        _require_optional_str(self.budget_exhausted_kind, "ScanDiagnostics.budget_exhausted_kind")
        _require_optional_count(self.budget_exhausted_limit, "ScanDiagnostics.budget_exhausted_limit")
        _require_optional_count(self.budget_exhausted_consumed,
                                 "ScanDiagnostics.budget_exhausted_consumed")
        _require_count(self.total_bytes_scanned, "ScanDiagnostics.total_bytes_scanned")
        _require_count(self.suppressed_module_pe, "ScanDiagnostics.suppressed_module_pe")
        _require_count(self.suppressed_scoped, "ScanDiagnostics.suppressed_scoped")
        _require_count(self.context_unverified, "ScanDiagnostics.context_unverified")
        require_recursively_immutable(self, "ScanDiagnostics")

    @property
    def skipped_oversize(self) -> int:
        return len(self.skipped_oversize_targets)

    @property
    def read_failed(self) -> int:
        return len(self.read_failed_targets)

    @property
    def short_reads(self) -> int:
        return len(self.short_read_targets)

    @property
    def timed_out(self) -> int:
        return len(self.timed_out_targets)

    @property
    def match_failed(self) -> int:
        return len(self.match_failed_targets)

    @property
    def has_real_budget_gap(self) -> bool:
        """`budget_exhausted` alone is NOT a coverage gap -- it can be True
        with an EMPTY `budget_exhausted_targets` when the whole-scan budget
        is only discovered exhausted after the very last (segment,
        rule-file) pairing already finished cleanly (pure wall-clock
        telemetry, nothing left unexamined). Only a non-empty target list
        means genuinely unresolved scope. Mirrors CS Beacon's own
        `ScanDiagnostics.has_real_budget_gap`."""
        return self.budget_exhausted and bool(self.budget_exhausted_targets)

    @property
    def scan_complete(self) -> bool:
        return not (self.skipped_oversize or self.read_failed or self.short_reads
                    or self.timed_out or self.match_failed or self.truncated
                    or self.has_real_budget_gap)


@dataclass(frozen=True)
class RulesDiagnostics:
    """What `_load_yara_rules`'s three prerequisite checks (yara-python
    import, rules-directory resolution, rule compilation) found -- FACTS,
    resolved once, that let the console derive which of its four
    "prerequisite missing" cases applies without a stored `render_kind`
    string.

      yara_available  -- `import yara` succeeded.
      rules_dir       -- the resolved rules directory, or None if none was
                          found (yara-python missing OR no directory
                          resolvable).
      attempted       -- compilation was actually attempted against
                          `rules_dir` (distinguishes "attempted, directory
                          held zero usable files" from "never attempted at
                          all" -- both leave `compiled_ok == compile_failed
                          == 0`, so that pair alone can't tell them apart).
      compiled_ok      -- count of rule files that compiled successfully.
      compile_failed   -- count of candidate files that did not.
      provenance       -- the full per-file `RulesProvenance`, when
                          available -- always present on the real
                          `_load_yara_rules()` path; may be `None` when
                          `attempted` is True but only the (rule_files,
                          compile_failed) summary was supplied (e.g. a
                          test double replacing `_load_yara_rules`
                          wholesale) -- `compiled_ok`/`compile_failed`
                          alone are enough to derive coverage/status; the
                          console's own per-file error detail and
                          `get_yara_provenance()` are the only consumers
                          that need the richer object.
    """
    yara_available:  bool = False
    rules_dir:        "str | None" = None
    attempted:         bool = False
    compiled_ok:       int = 0
    compile_failed:    int = 0
    provenance:       "RulesProvenance | None" = None

    def __post_init__(self):
        _require_bool(self.yara_available, "RulesDiagnostics.yara_available")
        _require_optional_str(self.rules_dir, "RulesDiagnostics.rules_dir")
        _require_bool(self.attempted, "RulesDiagnostics.attempted")
        _require_count(self.compiled_ok, "RulesDiagnostics.compiled_ok")
        _require_count(self.compile_failed, "RulesDiagnostics.compile_failed")
        if self.provenance is not None and not isinstance(self.provenance, RulesProvenance):
            raise TypeError(
                f"RulesDiagnostics.provenance must be a RulesProvenance or None, got "
                f"{type(self.provenance).__name__}: {self.provenance!r}")
        if self.attempted and self.rules_dir is None:
            raise ValueError(
                "RulesDiagnostics.attempted is True but rules_dir is None -- compilation can "
                "only have been attempted against a resolved directory")
        if self.attempted and not self.yara_available:
            raise ValueError(
                "RulesDiagnostics.attempted is True but yara_available is False -- compilation "
                "requires yara-python")
        if not self.attempted and (self.compiled_ok or self.compile_failed):
            raise ValueError(
                "RulesDiagnostics.attempted is False but compiled_ok/compile_failed is nonzero "
                "-- counts require an actual attempt")
        if self.provenance is not None and (self.provenance.compiled_ok != self.compiled_ok
                                             or self.provenance.compile_failed != self.compile_failed):
            raise ValueError(
                "RulesDiagnostics.provenance's own compiled_ok/compile_failed must match "
                "compiled_ok/compile_failed")
        require_recursively_immutable(self, "RulesDiagnostics")

    @property
    def no_rule_files(self) -> bool:
        """Rules directory resolved and compilation was attempted, but not
        one usable rule compiled -- either the directory was empty of
        .yar/.yara files, or every candidate file failed to compile."""
        return self.attempted and self.compiled_ok == 0

    @property
    def ready(self) -> bool:
        """At least one rule is actually usable -- the sole gate for
        whether scanning could even begin."""
        return self.attempted and self.compiled_ok > 0


@dataclass(frozen=True)
class CoverageSnapshot:
    """What this YARA run could and could not see, as FACTS.

      rules  -- prerequisite/compilation diagnostics (RulesDiagnostics).
      scan   -- this run's own ScanDiagnostics; `segment_count == 0` (the
                default) whenever the scan loop never actually started --
                either a prerequisite was missing, or the dump had no
                memory segments to begin with.
    """
    rules:  RulesDiagnostics = field(default_factory=RulesDiagnostics)
    scan:    ScanDiagnostics = field(default_factory=ScanDiagnostics)

    def __post_init__(self):
        if not isinstance(self.rules, RulesDiagnostics):
            raise TypeError(
                f"CoverageSnapshot.rules must be a RulesDiagnostics, got "
                f"{type(self.rules).__name__}: {self.rules!r}")
        if not isinstance(self.scan, ScanDiagnostics):
            raise TypeError(
                f"CoverageSnapshot.scan must be a ScanDiagnostics, got "
                f"{type(self.scan).__name__}: {self.scan!r}")
        if self.scan.segment_count > 0 and not self.rules.ready:
            raise ValueError(
                "CoverageSnapshot.scan.segment_count is nonzero but rules is not ready -- "
                "segments cannot have been scanned without at least one compiled rule")
        require_recursively_immutable(self, "CoverageSnapshot")

    @property
    def evaluated(self) -> bool:
        """The scan loop actually ran against at least one segment --
        the sole gate distinguishing every "prerequisite missing"
        NOT_EVALUATED case from a real (possibly empty) result."""
        return self.rules.ready and self.scan.segment_count > 0

    @property
    def complete(self) -> bool:
        """Whether this run counts as fully covered: it ran, the scan
        loop itself hit no gap, and every rule file that was found
        actually compiled."""
        return (self.evaluated and self.scan.scan_complete
                and self.rules.compile_failed == 0)


@dataclass(frozen=True)
class YaraEvidence:
    """Every individual rule match this hunter observed, in scan order --
    NOT deduplicated by `(rule, seg_va)`: two different rule files (or
    namespaces) whose same-named rule both match the same region are two
    distinct pieces of evidence and both belong here (see
    `dumpex.hunt.yara_hunt.scanner`'s own docstring for why collapsing
    them would silently drop a legitimate match from the wire contract).
    The only thing rejected below is a TRUE duplicate -- the exact same
    `(rule, namespace, file, seg_va)` identity appearing twice, which the
    scan loop's own structure (each (segment, rule_file) pairing visited
    at most once, at most one Match per rule name per call) never
    produces legitimately, so seeing one at all means a caller poisoned
    the evidence some other way.
    """
    matches:  tuple = field(default_factory=tuple)

    def __post_init__(self):
        items = as_tuple(self.matches, "YaraEvidence.matches")
        seen = set()
        for index, item in enumerate(items):
            if not isinstance(item, RuleMatchEvidence):
                raise TypeError(
                    f"YaraEvidence.matches[{index}] must be a RuleMatchEvidence, got "
                    f"{type(item).__name__}: {item!r}")
            key = (item.rule, item.namespace, item.file, item.seg_va)
            if key in seen:
                raise ValueError(
                    f"YaraEvidence.matches[{index}] duplicates an earlier entry for rule "
                    f"{item.rule!r} (namespace={item.namespace!r}, file={item.file!r}) at "
                    f"seg_va=0x{item.seg_va:x} -- this exact identity cannot legitimately "
                    f"appear twice")
            seen.add(key)
        object.__setattr__(self, "matches", items)
        require_recursively_immutable(self, "YaraEvidence")


@dataclass(frozen=True)
class YaraReport:
    """The YARA hunter's canonical result -- see this module's own
    docstring for what is stored versus derived, and why.

    Deliberately absent, and never to be added: `render_kind`, `scan_note`,
    a raw `modules` list, a `rules_dir`/`rule_file_count`/`segment_count`
    duplicating `coverage`'s own facts, an `outcome`/`rule_groups` parallel
    representation, and any `dumpex.hunt._finding.Finding`/
    `dumpex.hunt._domain.CheckResult` (see this module's own docstring on
    why YARA does not build on the shared Finding model).
    """
    coverage:  CoverageSnapshot = field(default_factory=CoverageSnapshot)
    evidence:  YaraEvidence = field(default_factory=YaraEvidence)

    def __post_init__(self):
        if not isinstance(self.coverage, CoverageSnapshot):
            raise TypeError(
                f"YaraReport.coverage must be a CoverageSnapshot, got "
                f"{type(self.coverage).__name__}: {self.coverage!r}")
        if not isinstance(self.evidence, YaraEvidence):
            raise TypeError(
                f"YaraReport.evidence must be a YaraEvidence, got "
                f"{type(self.evidence).__name__}: {self.evidence!r}")
        if self.evidence.matches and not self.coverage.evaluated:
            raise ValueError(
                "YaraReport.evidence.matches is non-empty but coverage.evaluated is False -- "
                "matches cannot exist without an actual scan")
        # Final, whole-graph immutability sweep -- see
        # dumpex.hunt.cs_beacon.domain.CSBeaconReport's own __post_init__
        # for why this runs LAST, over the whole assembled Report, rather
        # than being assumed to follow from the per-field isinstance
        # checks above.
        require_recursively_immutable(self, "YaraReport")

    @property
    def has_hits(self) -> bool:
        return bool(self.evidence.matches)

    @property
    def triggered_rules(self) -> tuple:
        """Distinct rule names with at least one confidently-classified
        (non-context_unverified) hit -- drives `score`/DETECTED. A rule
        with both a confirmed hit and a separate unverified hit appears
        here (and NOT in `unverified_rules`, whose own definition is
        "every hit for this rule was unverified") -- mirrors the
        pre-migration scanner.py's own per-hit `triggered_rules`/
        `unverified_rules` sets exactly."""
        return tuple(sorted({m.rule for m in self.evidence.matches if not m.context_unverified}))

    @property
    def unverified_rules(self) -> tuple:
        """Distinct rule names whose EVERY hit is context_unverified."""
        by_rule = {}
        for m in self.evidence.matches:
            by_rule.setdefault(m.rule, []).append(m.context_unverified)
        return tuple(sorted(rule for rule, flags in by_rule.items() if all(flags)))

    @property
    def score(self) -> int:
        return len(self.triggered_rules)

    @property
    def scan_complete(self) -> bool:
        """`coverage.complete`, except hits that exist but could ALL only
        be classified as context_unverified force coverage to read
        partial regardless of whether the scan loop itself hit a gap --
        an unclassified hit is itself a reason a negative can't be
        trusted, matching the pre-migration builder's own unconditional
        `coverage_status = "partial"` for that case. This is also the
        exact v1.1 legacy `findings["scan_complete"]` value (see
        `report_legacy.py`) -- a real part of this hunter's public output
        contract, not an internal-only derivation."""
        if self.has_hits and not self.triggered_rules:
            return False
        return self.coverage.complete

    @property
    def status(self) -> str:
        return derive_status(self.coverage.evaluated, bool(self.triggered_rules),
                              self.scan_complete)

    @property
    def coverage_status(self) -> str:
        return derive_coverage_status(self.coverage.evaluated, self.scan_complete)

    @property
    def verdict_level(self) -> str:
        if not self.coverage.evaluated:
            return "not_evaluated"
        if self.triggered_rules:
            return "high" if self.score >= 3 else "likely"
        if self.has_hits:
            return "inconclusive"
        return "inconclusive" if not self.coverage.complete else "clean"

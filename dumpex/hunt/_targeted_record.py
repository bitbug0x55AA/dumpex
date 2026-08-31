"""Project one targeted rescan's observation into a ``HunterRecord``.

A targeted (``--hunt-addr``) invocation produces an
:class:`~dumpex.hunt._observation.ObservationResult`: one
:class:`~dumpex.hunt._observation.ObservationClosure` per independently
validated ``(source, scope)`` coverage closure, plus the analyzer's own
evidence payload. This module is the single place that becomes a
:class:`~dumpex.output.records.HunterRecord`.

Two authorities meet here and neither is allowed to speak for the other:

* The analyzer's registered ``targeted_report_projector`` turns the payload
  into that analyzer's canonical ``Report``, which is where score, verdict
  tier, confidence, lead count, review priority, findings, and the details
  shape come from -- the same ``aggregate.build_report()`` full scope uses.
* The observation's closures decide coverage. ``HunterRecord.coverage.status``
  is ``complete`` only when every closure is complete, ``not_evaluated`` only
  when every closure is not evaluated, and ``partial`` otherwise -- never the
  report's own full-scope-shaped snapshot, which also weighs sources outside
  this invocation's single grant.

``status``/``verdict_level`` are then re-derived from that coverage and the
report's own detection, through the same
:func:`dumpex.hunt._coverage.derive_status` reduction every hunter uses. This
is what keeps a targeted record internally consistent: a scoped negative reads
``NOT_DETECTED_IN_SCANNED_SCOPE``/``clean`` only when every required closure
completed, and drops to ``INCONCLUSIVE``/``inconclusive`` the moment one did
not -- exactly the biconditional the output schema enforces between
``status``, ``verdict_level``, and ``coverage.status``.

Coverage is explicit about what a rescan did NOT do. A targeted record's
``coverage.sources`` carries ``targeted_scan`` plus the analyzer's whole
published source vocabulary, so a consumer sees the same roster a full-scope
record has, and each source this analyzer's targeted invocation never
evaluates is absent with its own ``TARGETED_SOURCE_NOT_EVALUATED``. A completed
targeted stomping rescan therefore cannot read as "stomping is completely
covered" -- the sources its completeness claim excludes say so in the document,
not only in console prose.

That set is declared per analyzer
(:func:`dumpex.hunt._registry.unevaluated_targeted_sources`), never inferred
from which sources produced a limitation. A source the rescan really does read
-- YARA's rule compilation and match-context classification are where its
verdict comes from -- stays present, so the record never invents a gap on its
own detection path.
"""
from dataclasses import dataclass, replace

from dumpex.hunt import _registry
from dumpex.hunt._coverage import derive_status
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, CoverageStatus, LimitationCode,
    SourceObservation, SourceState,
)
from dumpex.output.records import TargetedScopeRecord, hex_address

__all__ = [
    "TARGETED_COVERAGE_SOURCE",
    "TargetedProjection",
    "targeted_scope_records",
    "build_targeted_coverage",
    "build_targeted_record",
]

# The coverage-source name ``TARGETED_SOURCE_NOT_EVALUATED`` is fixed to: the
# rescan itself, as distinct from the analyzer source it was asked to run.
TARGETED_COVERAGE_SOURCE = "targeted_scan"

_VERDICT_BY_STATUS = {
    "NOT_EVALUATED": "not_evaluated",
    "INCONCLUSIVE": "inconclusive",
    "NOT_DETECTED_IN_SCANNED_SCOPE": "clean",
}


def _observation(name: str, observed: bool) -> SourceObservation:
    """One source's state for a targeted record: ``present`` when this rescan
    observed it, ``absent`` when it did not. ``absent`` here means "this run
    has no observation for it", never "the dump lacks it" -- the accompanying
    limitation is what says which.

    ``record_count`` is 1 for an observed source because ``PRESENT`` requires a
    positive count; a targeted record's per-source counts carry no meaning of
    their own, the closures do."""
    return SourceObservation(
        name=name, state=SourceState.PRESENT if observed else SourceState.ABSENT,
        record_count=1 if observed else None)


def _source_observed(name: str, granted: set, evaluated: set, out_of_scope: frozenset,
                     anything_ran: bool) -> bool:
    """Whether this rescan observed ``name``.

    A declared never-evaluated source is never observed. A granted source is
    observed exactly when its own closure ran. Every other published source is
    one the adapter consults on the way to running its grant -- YARA's rule
    compilation and match-context classification, CS Beacon's thread contexts,
    the MemoryInfo lookup that resolves the containing descriptor -- so it is
    observed exactly when the scan itself got going."""
    if name in out_of_scope:
        return False
    if name in granted:
        return name in evaluated
    return anything_ran


def _captured_size(closure) -> "int | None":
    """How many of the requested bytes the dump actually holds, or ``None``
    when availability is genuinely unknown.

    Read from the closure's own measurement, which every adapter carries
    whether or not the closure ran -- so a partially captured range whose
    algorithm never started still reports the real prefix length rather than
    "unknown", which is the number a re-collection or a chunked rescan is
    sized from. ``None`` is reserved for a closure that genuinely never
    measured: an uncaptured range normalizes to ``0`` and a closure that ran
    derives it from its own read slice, both inside
    :class:`~dumpex.hunt._observation.ObservationClosure`."""
    return closure.captured_bytes


def targeted_scope_records(request, result) -> list:
    """One :class:`~dumpex.output.records.TargetedScopeRecord` per closure, in
    the adapter's own fixed closure order.

    Identity is always the REQUESTED range -- never the containing descriptor
    and never the captured prefix -- so a closure means the same thing whatever
    the capture outcome was.
    """
    requested = request.target_range
    return [
        TargetedScopeRecord(
            source=closure.source, scope=closure.scope,
            base_address=hex_address(requested.base_address), size=requested.size,
            captured_size=_captured_size(closure),
            capture_state=closure.capture_state.value,
            coverage_status=closure.coverage_status)
        for closure in result.closures
    ]


def _not_evaluated_limitation(closure) -> CoverageLimitation:
    """``TARGETED_SOURCE_NOT_EVALUATED`` for one granted closure that did not
    run, scoped to that closure.

    Built only from the closure's own ``coverage_status``, in this one
    function, so it can never accompany a closure that did run. It names no
    cause -- an unmet prerequisite, an ineligible descriptor, and a range below
    the algorithm's minimum input are the same fact to a consumer, and each
    keeps its own prerequisite limitation alongside this one."""
    return CoverageLimitation(
        code=LimitationCode.TARGETED_SOURCE_NOT_EVALUATED,
        source=TARGETED_COVERAGE_SOURCE, scope=closure.scope)


def _out_of_scope_limitation(source: str) -> CoverageLimitation:
    """``TARGETED_SOURCE_NOT_EVALUATED`` for one coverage source a targeted
    invocation of this analyzer never evaluates.

    This is a positive, machine-readable statement, not an omission. Without
    it a completed targeted stomping rescan would ship ``coverage.status:
    "complete"`` with an empty ``limitations`` array, and a consumer keying on
    ``hunter`` + ``coverage.status`` would read "stomping is completely
    covered" from a run whose completeness claim covers ``ioc_string_scan``
    alone. The limitation is sourced to that source itself, so a consumer
    joins it to ``coverage.sources`` by name.

    The set is declared per analyzer
    (:func:`dumpex.hunt._registry.unevaluated_targeted_sources`), never
    inferred from which sources happened to produce a limitation: that
    inference is backwards, marking a source unevaluated exactly when it
    succeeded and leaving it unmarked when it failed. A source the rescan does
    read -- YARA's rule compilation and match-context classification, CS
    Beacon's thread contexts, the MemoryInfo lookup that resolves the
    containing descriptor -- is never claimed here."""
    return CoverageLimitation(
        code=LimitationCode.TARGETED_SOURCE_NOT_EVALUATED, source=source)


def build_targeted_coverage(result, identity: str) -> CoverageReport:
    """The ``HunterRecord.coverage`` for one targeted rescan of ``identity``.

    Status is the closure reduction alone: ``complete`` when every closure is
    complete, ``not_evaluated`` when every closure is not evaluated, and
    ``partial`` otherwise. A source outside the rescan's own grant never moves
    it -- a targeted rescan's conclusion is about the range it was given, and a
    source it was never asked to run cannot make that conclusion partial. It is
    always SAID, though: see :func:`_out_of_scope_limitation`.

    ``sources`` is the analyzer's whole published coverage vocabulary, so a
    consumer sees the same roster a full-scope record carries and can tell, per
    source, which ones this run actually observed. The granted source is
    present when its closure ran; a source this analyzer's targeted invocation
    structurally never evaluates is absent and carries its own limitation; the
    rest -- the ones the adapter consults on the way to running its grant --
    are present once the scan got going.

    ``status`` can therefore be ``complete`` while ``limitations`` is
    non-empty, which full-scope coverage never does. That is deliberate: the
    out-of-scope entries are not gaps IN this scan, and letting them force
    ``partial`` would make every targeted rescan exit 3 and destroy the
    exit-code contract. Status answers "did the requested range get fully
    evaluated for the granted source"; the limitations answer "what is this
    result NOT about".

    Limitations are ordered: the closures' own, in the adapter's fixed closure
    order, with a closure's derived "did not run" ahead of the prerequisite
    facts explaining it; then one entry per out-of-scope source, sorted.
    """
    statuses = [closure.coverage_status for closure in result.closures]
    if all(status == "complete" for status in statuses):
        status = CoverageStatus.COMPLETE
    elif all(status == "not_evaluated" for status in statuses):
        status = CoverageStatus.NOT_EVALUATED
    else:
        status = CoverageStatus.PARTIAL

    granted_sources = {closure.source for closure in result.closures}
    evaluated_sources = {closure.source for closure in result.closures
                         if closure.coverage_status != "not_evaluated"}
    anything_ran = bool(evaluated_sources)
    out_of_scope = _registry.unevaluated_targeted_sources(identity)

    limitations = []
    for closure in result.closures:
        if closure.coverage_status == "not_evaluated":
            limitations.append(_not_evaluated_limitation(closure))
        limitations.extend(closure.limitations)

    # A source declared never-evaluated cannot also be one an adapter reported
    # a gap on: one of the two is wrong, and shipping both would put a
    # contradiction in one record.
    contradicted = out_of_scope & {limitation.source for limitation in limitations}
    if contradicted:
        raise ValueError(
            f"{identity}: {sorted(contradicted)} is declared never-evaluated by a targeted "
            f"rescan, but a closure limitation reports on it -- the declared set and the "
            f"adapter disagree")

    # The roster is the analyzer's published vocabulary plus whatever its
    # closures ran for -- never widened by a limitation, so a limitation
    # naming something outside it is caught below rather than silently
    # legitimised by its own presence.
    roster = _registry.coverage_sources_for(identity) | granted_sources
    sources = {TARGETED_COVERAGE_SOURCE: _observation(
        TARGETED_COVERAGE_SOURCE, anything_ran)}
    for name in sorted(roster):
        sources[name] = _observation(
            name, _source_observed(name, granted_sources, evaluated_sources,
                                   out_of_scope, anything_ran))

    # Every limitation must name a source the roster carries. Full-scope
    # coverage gets this from `build_coverage_report`'s own cross-source
    # validation; this path builds its report directly, so the same rule is
    # enforced here rather than left to each adapter's discipline -- a
    # limitation naming a source absent from `sources` ships a document that
    # contradicts itself.
    for limitation in limitations:
        if limitation.source not in sources:
            raise ValueError(
                f"{identity}: targeted coverage limitation {limitation.code.value} names "
                f"source {limitation.source!r}, which is not one of this record's own "
                f"sources {sorted(sources)} -- a limitation cannot describe a source the "
                f"record does not report")

    # One gap, reported once. Every gap has a single owning closure -- an
    # adapter raises a budget's exhaustion on the closure that owns that
    # budget, and a closure merely constrained by it says so through its own
    # status and diagnostics -- so this collapse is a defensive backstop, not
    # a routine step: it exists so an adapter that does raise one gap from two
    # closures cannot double it in `limitations`, in the derived `reasons`, on
    # the console, and in a consumer's gap tally.
    #
    # Collapsed by full structural equality (never by code, and never by
    # `(code, source, scope)`): two gaps differing in `detail`, `targets`, or
    # `affected_count` are two facts. First occurrence wins, so the closures'
    # own fixed order is what a reader sees.
    deduplicated = []
    for limitation in limitations:
        if limitation not in deduplicated:
            deduplicated.append(limitation)
    limitations = deduplicated

    limitations.extend(_out_of_scope_limitation(source) for source in sorted(out_of_scope))
    return CoverageReport(status=status, sources=sources, limitations=limitations)


@dataclass(frozen=True)
class TargetedProjection:
    """One targeted rescan projected exactly once.

    ``record`` is what reaches console, JSON, and the exit code. ``report`` is
    the analyzer's own canonical report it was built from, carried out so a
    caller needing an analyzer-specific hook (YARA's rule provenance) reads it
    off THIS invocation's report rather than a process-wide global."""
    record: object
    report: object


def build_targeted_record(spec, context, result) -> TargetedProjection:
    """The :class:`~dumpex.output.records.HunterRecord` for one targeted
    rescan of ``spec``'s analyzer, with the report it came from.

    ``spec.targeted_report_projector`` supplies the evidence side and
    ``spec.record_projector`` shapes it exactly as a full-scope record; this
    function then replaces the coverage with the closure-derived one, restates
    ``status``/``verdict_level`` so they agree with it, and attaches the
    per-closure ``details.targeted_scope``.
    """
    report = spec.targeted_report_projector(context, result)
    base = spec.record_projector(report)
    coverage = build_targeted_coverage(result, spec.identity)

    evaluated = coverage.status != CoverageStatus.NOT_EVALUATED
    if not evaluated and base.score:
        # Evidence that exists without a closure that ran is a contradiction
        # between an adapter and its own projector, and would produce a record
        # whose status, score, and coverage disagree. Fail closed rather than
        # publish it.
        raise ValueError(
            f"{spec.identity}: every targeted closure reports not_evaluated, but the "
            f"projected report scores {base.score} -- evidence cannot come from a "
            f"source that never ran")
    status = derive_status(evaluated, base.status == "DETECTED",
                           coverage.status == CoverageStatus.COMPLETE)
    # A detected verdict keeps the analyzer's own score-to-tier table (only it
    # knows what its points weigh); every other status has exactly one legal
    # verdict level, which is also what the schema's status/verdict_level/
    # coverage.status biconditional requires.
    verdict_level = _VERDICT_BY_STATUS.get(status, base.verdict_level)
    details = replace(base.details,
                      targeted_scope=targeted_scope_records(context.request, result))
    record = replace(base, status=status, verdict_level=verdict_level, coverage=coverage,
                     details=details)
    return TargetedProjection(record=record, report=report)

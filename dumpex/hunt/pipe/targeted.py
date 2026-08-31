"""Targeted pipe rescan: the pipe-name and C2-context passes over one range.

A targeted ``--hunt-addr`` pipe invocation asks the region scanner to collect
``\\pipe\\`` name occurrences -- and the C2-context records around them -- from
one investigator-selected half-open virtual-address range.
:func:`run_targeted_pipe` is the executor the analyzer registry resolves as
``pipe``'s ``AnalyzerSpec.targeted_adapter`` (through the
``dumpex.hunt._run_targeted_pipe`` facade seam).

The registered capability is ``pipe`` / ``pipe_name_scan`` with no finer
subdivision, so one request routes here whichever budget-exhaustion
relationship originated it. One execution runs BOTH passes over ONE read and
projects them as two independent
:class:`~dumpex.hunt._observation.ObservationClosure` values, scoped
``pipe_name`` and ``c2_context``: completing one never closes the other, and a
reused observation exposes each scope's own honest status.

Only ``PIPE_SCAN_MAX`` is bypassed, and only for this one range. Both
whole-invocation budgets stay at their full-scope values and stay independent
-- the pipe-name budget's hits, retained bytes, and deadline bound name
collection; the C2 budget's bound context gathering -- and both are registered
on ``context.budgets``, so several ranges rescanned on one
:class:`~dumpex.hunt._execution.HuntExecutionContext` share one cumulative
allowance rather than each getting a fresh one. Every per-region cap
(``PIPE_MAX_MATCHES_PER_REGION``, ``PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION``,
``PIPE_C2_CONTEXT_BYTES``, ``PIPE_C2_TOKEN_PREVIEW``, ``PIPE_NAME_MAX_CHARS``)
is threaded unchanged.

Both budgets are registered before the range is read, so each deadline bounds
the read as well as the passes that follow it -- reading a range up to the
request ceiling is scan work, not free setup -- and a range both budgets are
already spent for is never read at all.

Source eligibility and evaluation are anchored to the ``MemoryInfo`` region
containing the requested base: a request that runs past its end is captured in
full but evaluated only up to the boundary, and each closure that ran is
``partial`` with ``SCAN_REGION_EVALUATION_TRUNCATED``. A request lying wholly
inside a larger allocation carries a diagnostic naming that allocation, because
a name or context window spanning either requested boundary is examined by
neither this rescan nor the bytes around it.

C2 gathering is anchored on this range's own pipe-name hits, so a pipe-name
pass the pipe-name budget cut short leaves the C2 pass with incomplete anchors.
That is reported on the ``c2_context`` closure as the pipe-name budget's own
``SCAN_BUDGET_EXHAUSTED`` -- the two budgets stay separately attributed, and
the C2 negative is never presented as a full-search negative.

The result is one :class:`~dumpex.hunt._observation.ObservationResult` carrying
a :class:`TargetedPipeEvidence` payload: the string leads and C2 records the
range produced, the scan's own frozen coverage, and the containing-allocation
:class:`~dumpex.output.coverage.ScanTarget`. Handle evidence is a different
coverage source and is not evaluated here; a clean ``pipe_name_scan`` closure
makes no claim about it.
"""
import dataclasses

from dumpex.core import va_range
from dumpex.core.memory import get_modules, read_region_spanning
from dumpex.core.va_range import CaptureState
from dumpex.rules_pkg.loader import get_rules, get_rules_source_info

import dumpex.hunt.pipe as _pipe
from dumpex.hunt import _registry, _targeted
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._coverage import CoverageTracker
from dumpex.hunt._observation import (
    BudgetOutcome, ObservationClosure, ObservationResult,
)
from dumpex.hunt.pipe import correlation, memory_scan
from dumpex.hunt.pipe.config import (
    PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION, PIPE_CONTEXT_DISTANCE, PIPE_MAX_MATCHES_PER_REGION,
)
from dumpex.hunt.pipe.models import HandleScanResult, PipeNameScanResult
from dumpex.output.coverage import CoverageLimitation, LimitationCode

__all__ = [
    "run_targeted_pipe", "project_targeted_report",
    "TargetedPipeEvidence", "TargetedPipeError",
    "ALGORITHM_VERSION", "TARGETED_SOURCE", "TARGETED_SCOPES",
]

# The observation-key algorithm identity for this executor -- bumped only when
# a change to which bytes reach which pass would make a cached result from an
# earlier version unsafe to reuse.
ALGORITHM_VERSION = "pipe-targeted/1"

# The one granted coverage source (the capability matrix grants `pipe` exactly
# `pipe_name_scan`).
TARGETED_SOURCE = "pipe_name_scan"

# Fixed closure order. These are the two signals `pipe_name_scan` already
# reports independent budget exhaustion for full-scope; they are closure
# attribution, not a public selection -- one request always runs both.
TARGETED_SCOPES = ("pipe_name", "c2_context")

# The ledger names both budgets are registered under, so a second adapter call
# on one context reuses the same cumulative allowance.
BUDGET_PIPE_NAME = "pipe_name"
BUDGET_C2 = "pipe_c2"

# Raised in place of `PIPE_SCAN_MAX`. Far above the 256 MiB pipe request
# ceiling, so no range inside a valid targeted request is ever skipped for
# size -- and nothing here is a buffer allocation, only a `RegionSize > cap`
# comparison.
_CAP_BYPASS = 1 << 40


class TargetedPipeError(Exception):
    """The context handed to :func:`run_targeted_pipe` is not a legal pipe
    targeted request. Raised before any dump read, so the
    ``dumpex.hunt._run_targeted_pipe`` monkeypatch seam cannot route another
    analyzer's request into this executor and past its own request ceiling."""


@dataclasses.dataclass(frozen=True)
class TargetedPipeEvidence:
    """The scan results behind one targeted ``ObservationResult`` -- carried as
    its ``payload`` so a consumer can render what the rescan found.

    ``string_leads`` is the scanner's tuple of
    :class:`~dumpex.hunt.pipe.models.PipeStringEvidence`, each carrying an
    absolute ``va`` and .dmp ``file_offset``; ``c2_regions`` its tuple of
    :class:`~dumpex.hunt.pipe.models.RegionC2Records`. ``coverage`` is the
    frozen :class:`~dumpex.hunt.pipe.models.PipeScanCoverage` both closures
    were derived from. ``containing_region`` is the
    :class:`~dumpex.output.coverage.ScanTarget` for the allocation the
    requested range was evaluated inside -- distinct from the requested range
    and from any hit address, so a consumer can tell whether a full-region
    closure is licensed."""
    string_leads: tuple
    c2_regions: tuple
    coverage: object
    containing_region: object


def _validate_request(request) -> None:
    """Fail closed unless ``request`` is a pipe ``pipe_name_scan`` targeted
    request covering exactly the granted (empty) scope set."""
    if not getattr(request, "is_targeted", False):
        raise TargetedPipeError("run_targeted_pipe requires a targeted HuntRequest")
    if request.selected != "pipe" or request.targeted_source != TARGETED_SOURCE:
        raise TargetedPipeError(
            f"run_targeted_pipe is pipe/{TARGETED_SOURCE} only, got "
            f"{request.selected!r}/{request.targeted_source!r}")
    granted = _registry.REGISTRY.granted_scopes("pipe", TARGETED_SOURCE)
    if request.targeted_scopes != granted:
        raise TargetedPipeError(
            f"a pipe targeted request covers exactly {sorted(granted)}, got "
            f"{sorted(request.targeted_scopes)}")


def _fresh_pipe_name_budget() -> ScanBudget:
    """The pipe-name collection budget -- identical shape and values to
    ``_build_pipe_report``'s, read through the ``dumpex.hunt.pipe`` module
    globals so an override moves full-scope and targeted together."""
    p = _pipe
    return ScanBudget(
        max_bytes_read=p.PIPE_NAME_BUDGET_MAX_RETAINED * 4,
        max_attempts=10 ** 9,
        max_retained_bytes=p.PIPE_NAME_BUDGET_MAX_RETAINED,
        max_hits=p.PIPE_NAME_BUDGET_MAX_HITS,
        deadline=p.time.monotonic() + p.PIPE_NAME_BUDGET_TIME_SECONDS,
    )


def _fresh_c2_budget() -> ScanBudget:
    """The C2-context gathering budget -- identical shape and values to
    ``_build_pipe_report``'s, and deliberately separate from the pipe-name
    one: one signal's exhaustion never cuts off the other's coverage."""
    p = _pipe
    return ScanBudget(
        max_bytes_read=p.PIPE_C2_BUDGET_MAX_RETAINED * 4,
        max_attempts=10 ** 9,
        max_retained_bytes=p.PIPE_C2_BUDGET_MAX_RETAINED,
        max_hits=p.PIPE_C2_BUDGET_MAX_HITS,
        deadline=p.time.monotonic() + p.PIPE_C2_BUDGET_TIME_SECONDS,
    )


def _budget(context, name: str, factory) -> ScanBudget:
    if name in context.budgets:
        return context.budgets.get(name)
    return context.budgets.register(name, factory())


def _not_evaluated_result(key, capture, note: str, payload=None) -> ObservationResult:
    """A not-evaluated result for the whole request.

    ``captured_bytes`` is the measured availability of the requested range,
    carried even though nothing ran: a closure that never reached its algorithm
    still knows how much of the range the dump holds, and reporting that as
    unknown would cost an investigator the one number a re-collection or a
    chunked rescan is sized from.
    """
    closures = tuple(
        ObservationClosure(source=TARGETED_SOURCE, scope=scope,
                           coverage_status="not_evaluated",
                           capture_state=capture.state,
                           captured_bytes=capture.captured_bytes, diagnostics=(note,))
        for scope in TARGETED_SCOPES)
    return ObservationResult(key=key, closures=closures, payload=payload)


def _unreconciled(cov) -> int:
    return cov.unaccounted + cov.over_accounted + cov.ledger_imbalance


def _shared_gap(cov, capture_state: CaptureState, *, truncated: bool) -> bool:
    """Whether anything about the READ ITSELF stops either scope short: the
    dump did not back the whole request, evaluation stopped at the containing
    region's end, fewer bytes came back than the range declared, the range was
    skipped for size, or the scan's own ledger does not balance. Both passes
    ran over the same bytes, so every one of these is equally both scopes'."""
    return (capture_state != CaptureState.COMPLETE or truncated
            or bool(cov.short_reads) or bool(cov.skipped_oversize_targets)
            or bool(_unreconciled(cov)))


def _search_incomplete_reasons(scope: str, cov, *, overlapping: bool) -> tuple:
    """Why this scope reached the requested bytes but could not search them
    exhaustively -- each a bound the scan imposed on its own search, none of
    them a whole-hunt budget and none of them a read gap.

    ``PIPE_MAX_MATCHES_PER_REGION`` and ``PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION``
    are ordinary per-region quotas full-scope rarely reaches, because full
    scope never hands one region more than ``PIPE_SCAN_MAX``. Targeted mode
    hands a single synthetic region up to the whole request ceiling, so a
    rescan of exactly the oversized region this feature exists for is where
    they bite -- and a quota that silently dropped occurrences must not leave a
    closure reporting a full-search negative.
    """
    reasons = []
    if overlapping:
        reasons.append("overlapping_capture")
    if scope == "pipe_name" and cov.match_cap_hit:
        reasons.append("match_cap_reached")
    if scope == "c2_context":
        # A cut pipe-name walk leaves fewer proximity anchors than the range
        # actually holds, so the C2 pass searched against an incomplete anchor
        # set even when its own quota was never reached.
        if cov.match_cap_hit:
            reasons.append("match_cap_reached")
        if cov.context_only_cap_hit:
            reasons.append("context_only_cap_reached")
    return tuple(reasons)


def _scope_status(scope: str, cov, capture_state: CaptureState, *, reached: bool,
                  prevented: bool, truncated: bool, search_incomplete: tuple) -> str:
    """This closure's honest ``coverage_status``.

    ``not_evaluated`` -- the range never reached this pass: the containing
    region's own eligibility filter excluded it, the read returned nothing, the
    pipe-name budget was already spent so no pattern ran at all, or -- for
    ``c2_context`` -- its own budget was already spent when the range was
    reached and the range did hold anchors that pass would have worked on.

    Otherwise ``partial`` on any gap -- a read gap shared by both scopes, the
    budget that bounds THIS scope's own work having blocked some of it, or a
    per-target quota having left part of the range unsearched -- and
    ``complete`` only when the whole requested range was captured and this pass
    got through all of it. Finding no pipe name, or no C2 artifact, in eligible
    input is a result, not a gap.
    """
    if not reached or prevented:
        return "not_evaluated"
    if _shared_gap(cov, capture_state, truncated=truncated):
        return "partial"
    if cov.pipe_name_budget_exhausted_targets:
        # The pipe-name budget bounds `c2_context` too: C2 records are retained
        # against THIS range's own pipe-name hits, so a cut name pass leaves
        # the proximity anchors incomplete.
        return "partial"
    if scope == "c2_context" and cov.c2_budget_exhausted_targets:
        return "partial"
    if search_incomplete:
        return "partial"
    return "complete"


def _budget_limitation(scope: str, detail: str, targets: list) -> CoverageLimitation:
    """One ``SCAN_BUDGET_EXHAUSTED`` for a pipe budget, ``scope``-tagged with
    the budget that ran out -- the same attribution
    ``report_facts.project_coverage_report`` uses full-scope, so a budget name
    means the same thing on either path."""
    extra = {"affected_count": len(targets), "targets": list(targets)} if targets else {}
    return CoverageLimitation(
        code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source=TARGETED_SOURCE,
        scope=scope, detail=detail, **extra)


def _limitations(scope: str, cov, *, truncation_limitation,
                 search_incomplete: tuple) -> tuple:
    """The structured gaps for one closure -- the same ``CoverageLimitation``
    shapes ``report_facts.project_coverage_report`` builds for a full-scope
    pipe run, over this one range."""
    out = []
    if cov.skipped_oversize_targets:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source=TARGETED_SOURCE,
            scope=scope, affected_count=len(cov.skipped_oversize_targets),
            targets=list(cov.skipped_oversize_targets)))
    if cov.read_failed:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source=TARGETED_SOURCE,
            scope=scope, affected_count=cov.read_failed,
            targets=list(cov.read_failed_targets)))
    if cov.short_reads:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source=TARGETED_SOURCE,
            scope=scope, affected_count=cov.short_reads,
            targets=list(cov.short_read_targets)))
    if truncation_limitation is not None:
        out.append(truncation_limitation)
    unreconciled = _unreconciled(cov)
    if unreconciled:
        # No `targets` -- see SCAN_ITEMS_UNACCOUNTED on LimitationCode for why
        # this gap cannot name what it lost.
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_ITEMS_UNACCOUNTED, source=TARGETED_SOURCE,
            scope=scope, affected_count=unreconciled))
    # Each budget's exhaustion is raised by the ONE closure that owns that
    # budget, so a gap has a single owner wherever it is read -- on the
    # `ObservationResult`, on the record, or by a consumer walking closures
    # directly. The pipe-name budget does bound `c2_context` as well, because
    # C2 records are retained against this range's own pipe-name hits, but that
    # dependency reaches the `c2_context` closure through its own `partial`
    # status (`_closure_status`) and its own diagnostic, not through a second
    # copy of a limitation another closure owns.
    #
    # Each is raised from the TARGETS the scanner recorded at the site the
    # budget actually blocked work -- never from the budget's final state, so a
    # budget that ran out on this range's last retained hit is not reported as
    # having cut it short. A recorded target always follows a real exhaustion,
    # so the reason those targets travel with is always a real budget reason.
    if scope == "c2_context" and cov.c2_budget_exhausted_targets:
        out.append(_budget_limitation(
            "c2_context", cov.c2_budget_reason,
            list(cov.c2_budget_exhausted_targets)))
    if scope == "pipe_name" and cov.pipe_name_budget_exhausted_targets:
        out.append(_budget_limitation(
            "pipe_name", cov.pipe_name_budget_reason,
            list(cov.pipe_name_budget_exhausted_targets)))
    for detail in search_incomplete:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE, source=TARGETED_SOURCE,
            scope=scope, detail=detail, affected_count=1))
    return tuple(out)


def run_targeted_pipe(context) -> ObservationResult:
    """Collect pipe names and C2 context from ``context.request.target_range``
    and return one :class:`~dumpex.hunt._observation.ObservationResult` with an
    independent ``pipe_name`` and ``c2_context`` closure and a
    :class:`TargetedPipeEvidence` payload.

    ``context`` is a targeted :class:`~dumpex.hunt._execution.HuntExecutionContext`.
    Raises :class:`TargetedPipeError` for any other request shape, before any
    dump read.
    """
    _validate_request(context.request)

    mf = context.mf
    requested = context.request.target_range
    key = context.observation_key("pipe", algorithm_version=ALGORITHM_VERSION)

    capture = context.capture_of(requested)
    region_enum = context.captured_region_enumeration()
    containing = va_range.region_containing(requested.base_address, region_enum.views)

    if containing is None:
        dropped = ""
        if region_enum.skipped:
            dropped = (f" ({region_enum.skipped} region descriptor(s) were dropped as "
                       f"unrepresentable; the requested base may lie inside one of them)")
        return _not_evaluated_result(
            key, capture,
            f"no representable MemoryInfoListStream region contains the requested base "
            f"{requested.base_address:#018x}; source eligibility could not be established"
            + dropped)

    boundary = _targeted.resolve_region_boundary(mf, requested, containing)
    eval_range = boundary.eval_range

    modules = get_modules(mf)
    c2_pattern = get_rules(announce=False)["pipe_c2_context_patterns"]
    synthetic = _targeted.SyntheticRegion.from_captured_region(
        eval_range.base_address, eval_range.size, containing)

    # Both budgets are acquired BEFORE the range is read, so each one's deadline
    # is already running while the read runs. Reading a range up to the request
    # ceiling is itself scan work an investigator waits on, and a budget whose
    # whole allowance elapsed inside that read is spent -- a pass that starts
    # after it must report that, not treat the deadline as if it began once the
    # bytes were in hand.
    pipe_name_budget = _budget(context, BUDGET_PIPE_NAME, _fresh_pipe_name_budget)
    c2_budget = _budget(context, BUDGET_C2, _fresh_c2_budget)
    # Snapshotted before the scan: a budget already spent here PREVENTED its
    # pass, which is a different fact from one this pass itself spent.
    c2_prevented = c2_budget.exhausted()
    name_prevented = pipe_name_budget.exhausted()
    # Neither pass can make a claim about the range, so the scanner's own gate
    # will decline it before calling the reader.
    unread = name_prevented and c2_prevented

    # The one read of the requested (clipped) bytes both passes share, deferred
    # into the reader rather than performed here so the scanner's own
    # already-spent-budget gate runs FIRST: a range neither pass can make a
    # claim about costs no read at all. The scanner reads each region once, and
    # the bytes are held so a second call would reuse them rather than re-read.
    #
    # The result is clamped to the captured prefix the dump's own segment table
    # backs -- the raw reader can over-serve past a descriptor the capture model
    # dropped, and no pass may retain a hit from bytes the closure then reports
    # as uncaptured. A clamp shorter than the synthetic region's size surfaces
    # to the scanner as an ordinary short read.
    read = []

    def _reader(_mf, addr, size):
        if addr != eval_range.base_address:
            return b""
        if not read:
            read.append(read_region_spanning(
                mf, eval_range.base_address, eval_range.size)[:capture.captured_bytes])
        return read[0][:size]

    scan = memory_scan.scan_pipe_names(
        mf, _reader, [synthetic], modules, CoverageTracker(),
        pipe_name_budget, c2_budget, c2_pattern, scan_max=_CAP_BYPASS)
    cov = scan.coverage

    # A range the scanner never read has no read to describe. Every closure over
    # one is `not_evaluated`, which carries no `read_slice` anyway.
    read_slice = (None if capture.state == CaptureState.NONE or not read
                  else capture.read_input(len(read[0])))

    # Whether the range reached a pattern at all. `scanned` is the scanner's
    # own disposition for "at least one pattern ran over these bytes", so it
    # already accounts for an eligibility filter miss, a failed read, and a
    # pipe-name budget that left nothing to run.
    reached = bool(cov.scanned)

    # Whether the C2 pass had anything to anchor on at all. A spent C2 budget
    # only PREVENTED that pass where the range actually produced a retained
    # pipe-name lead; over a range with none, C2 gathering would not have run
    # under any budget, and reporting a gap there would send an investigator
    # after a larger-budget rerun that can never return anything.
    has_anchors = bool(scan.string_leads)

    # Only a stop INSIDE the evaluated range leaves an unexamined suffix a
    # closure has to name: bytes past the containing region's end were never in
    # this scan's scope and are already reported by the truncation limitation.
    # The suffix belongs to the short-read gap alone, never to a budget one: a
    # budget that cut a pattern walk short leaves no byte offset behind (the
    # walk sweeps the whole buffer per pattern), so its own honest target stays
    # the whole evaluated range.
    stopped_short = read_slice is not None and read_slice.read_bytes < eval_range.size
    unexamined = _targeted.unexamined_suffix_target(read_slice) if stopped_short else None

    closures = []
    for scope in TARGETED_SCOPES:
        prevented = scope == "c2_context" and c2_prevented and has_anchors
        # A negative over an ambiguous capture, or over a range a per-target
        # quota stopped searching, is "not found in the bytes that were
        # searched", never "not found after a full search".
        search_incomplete = _search_incomplete_reasons(
            scope, cov, overlapping=reached and capture.overlapping)
        status = _scope_status(scope, cov, capture.state, reached=reached,
                               prevented=prevented, truncated=boundary.truncated,
                               search_incomplete=search_incomplete)
        ran = status != "not_evaluated"

        truncation_limitation = (
            _targeted.evaluation_truncated_limitation(
                TARGETED_SOURCE, scope, boundary.requested_target)
            if boundary.truncated and ran else None)
        limitations = _limitations(
            scope, cov, truncation_limitation=truncation_limitation,
            search_incomplete=search_incomplete if ran else ())

        diagnostics = []
        if not ran:
            diagnostics.append(_not_evaluated_note(
                cov, prevented=prevented, name_prevented=name_prevented, unread=unread))
        if boundary.truncated and ran:
            diagnostics.append(_targeted.truncation_diagnostic(
                boundary.region_range, requested, eval_range))
        if boundary.sub_region and ran:
            diagnostics.append(_targeted.sub_region_diagnostic(
                boundary.region_range, requested))
        if unexamined is not None and ran:
            diagnostics.append(
                f"[{unexamined.base_address:#018x}, "
                f"{unexamined.base_address + unexamined.size:#018x}) of the requested range "
                f"was never examined for a pipe name")
        if scope == "c2_context" and ran and cov.pipe_name_budget_exhausted_targets:
            diagnostics.append(
                "the pipe-name pass over this range stopped short of its own budget, so the "
                "C2 proximity anchors are incomplete; a C2 artifact next to a name that was "
                "never collected is not reported here")
        if scope == "c2_context" and ran and cov.image_pipe_refs and not scan.c2_regions:
            diagnostics.append(
                f"the {cov.image_pipe_refs} pipe reference(s) in this range are all expected "
                f"system-DLL references and are not retained as leads, so the C2-context "
                f"passes had no anchor to gather around; a C2 artifact beside one of them "
                f"was not examined")
        if ran and cov.match_cap_hit:
            diagnostics.append(
                f"the pipe-name walk stopped at PIPE_MAX_MATCHES_PER_REGION "
                f"({PIPE_MAX_MATCHES_PER_REGION}) occurrences for this range; occurrences "
                f"past that, in scan order, were not processed")
        if scope == "c2_context" and ran and cov.context_only_cap_hit:
            diagnostics.append(
                f"context-only C2 retention stopped at PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION "
                f"({PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION}) records for this range; further "
                f"non-adjacent artifacts were not kept")
        if "overlapping_capture" in search_incomplete and ran:
            diagnostics.append(
                "the dump's segment table maps one or more requested virtual addresses to "
                "multiple file offsets (overlapping segments); the searched bytes are one "
                "arbitrary choice among conflicting claims")

        budget_name = BUDGET_PIPE_NAME if scope == "pipe_name" else BUDGET_C2
        exhausted = (cov.pipe_name_budget_exhausted if scope == "pipe_name"
                     else cov.c2_budget_exhausted)
        closures.append(ObservationClosure(
            source=TARGETED_SOURCE, scope=scope, coverage_status=status,
            capture_state=capture.state, captured_bytes=capture.captured_bytes,
            read_slice=read_slice if ran else None,
            limitations=limitations,
            budget_outcomes=(BudgetOutcome(name=budget_name, exhausted=exhausted),),
            diagnostics=tuple(diagnostics)))

    payload = TargetedPipeEvidence(
        string_leads=scan.string_leads, c2_regions=scan.c2_regions, coverage=cov,
        containing_region=boundary.containing_target)
    return ObservationResult(key=key, closures=tuple(closures), payload=payload)


def _not_evaluated_note(cov, *, prevented: bool, name_prevented: bool,
                        unread: bool) -> str:
    """Why this scope's pass never ran -- read off the scan's own frozen
    coverage rather than re-derived from the region, so the note and the
    closure's status always name the same cause.

    ``unread`` and ``name_prevented`` are the two the coverage cannot
    distinguish on its own, both snapshotted before the read: with both budgets
    already spent the range is never read at all, and a pipe-name budget that
    expired *during* the read leaves the same ledger as one that was already
    spent when the range was reached. The note says which, because a budget the
    read itself consumed points at a different rerun than one an earlier range
    had already used up.
    """
    if unread:
        return ("both the pipe-name and C2-context budgets were already spent when this "
                "range was reached; it was not read and no pattern was run over it")
    if prevented:
        return ("the C2-context budget was already spent when this range was reached; "
                "no C2 artifact around a pipe name here was gathered")
    if not cov.eligible_total:
        return ("the MemoryInfo region containing the requested base is not committed "
                "memory, so the pipe-name scan does not apply to it")
    if cov.read_failed:
        return "the requested range returned no readable bytes; no pattern was run over it"
    if name_prevented:
        return ("the pipe-name budget was already spent when this range was reached; no "
                "pattern was run over it")
    return ("the pipe-name budget ran out while this range was being read, before any "
            "pattern was run over it")


def project_targeted_report(context, result):
    """The :class:`~dumpex.hunt.pipe.domain.PipeReport` behind one targeted
    rescan's :class:`~dumpex.output.records.HunterRecord`.

    The range's own string leads, C2 records, and scan coverage are fed to the
    SAME ``aggregate.build_report`` full scope uses, so a targeted verdict is
    scored and classified by one authority rather than a parallel targeted-only
    rule. Correlation runs over an EMPTY handle scan and empty thread/module
    tables: a targeted rescan evaluates ``pipe_name_scan`` alone, so the
    handle-anchored scored checks have nothing to fire on and the report never
    asserts a handle source it did not read. ``handle_data_stream`` is
    ``False`` for the same reason -- not a claim the dump lacks the stream, but
    the fact that this rescan did not evaluate it.

    The report's own coverage snapshot describes this one range; the record's
    document-level coverage is rebuilt from the observation's closures (see
    :mod:`dumpex.hunt._targeted_record`).
    """
    payload = result.payload
    evaluated = any(closure.coverage_status != "not_evaluated"
                    for closure in result.closures)
    if payload is None:
        return _pipe.build_report(memory_info_stream=False, handle_data_stream=False)
    cov = payload.coverage
    scan = PipeNameScanResult(string_leads=payload.string_leads,
                              c2_regions=payload.c2_regions, coverage=cov)
    # Framework attribution and the ruleset's own content hash come from the
    # same loader call `_build_pipe_report` makes, so a targeted verdict names
    # the same rule content a full-scope one does.
    rules = get_rules(announce=False)
    rules_source = get_rules_source_info()
    corr = correlation.correlate(
        HandleScanResult(), scan, thread_contexts=[], infos=[], modules=[], regions=[],
        known_framework_pipes=rules["framework_pipes"],
        context_distance=PIPE_CONTEXT_DISTANCE)
    return _pipe.build_report(
        (), scan.string_leads, corr.corroborated_handles, corr.start_address_leads,
        corr.c2_context, corr.framework_string_hits, corr.unbacked_threads,
        memory_info_stream=evaluated, handle_data_stream=False,
        skipped_oversize=cov.skipped_oversize_targets,
        read_failed=cov.read_failed, read_failed_targets=cov.read_failed_targets,
        short_reads=cov.short_reads, short_read_targets=cov.short_read_targets,
        unaccounted=cov.unaccounted, over_accounted=cov.over_accounted,
        ledger_imbalance=cov.ledger_imbalance,
        c2_budget_exhausted=cov.c2_budget_exhausted, c2_budget_reason=cov.c2_budget_reason,
        pipe_name_budget_exhausted=cov.pipe_name_budget_exhausted,
        pipe_name_budget_reason=cov.pipe_name_budget_reason,
        pipe_name_budget_exhausted_targets=cov.pipe_name_budget_exhausted_targets,
        c2_budget_exhausted_targets=cov.c2_budget_exhausted_targets,
        image_pipe_refs=cov.image_pipe_refs, image_pipe_modules=cov.image_pipe_modules,
        rule_version=rules_source["sha256"] if rules_source else None)

"""Targeted CS Beacon rescan: the config marker search over one segment slice.

A targeted ``--hunt-addr`` cs-beacon invocation asks the segment scanner to
search one investigator-selected half-open virtual-address range for
structurally-valid Cobalt Strike beacon configurations.
:func:`run_targeted_cs_beacon` is the executor the analyzer registry resolves as
``cs-beacon``'s ``AnalyzerSpec.targeted_adapter`` (through the
``dumpex.hunt._run_targeted_cs_beacon`` facade seam).

The requested range is resolved to the captured segment containing its base and
handed to :func:`dumpex.hunt.cs_beacon.scanner.scan_segments` as a single
:class:`~dumpex.hunt._targeted.SyntheticSegment`: virtual base at the requested
address, size the requested (clipped) extent, and file offset the containing
segment's own offset displaced by the slice's distance from that segment's
base. A hit's ``hit_va`` / ``hit_fo`` -- both derived from ``slice base + marker
offset`` -- are therefore the same absolute values a full-scope scan of the
whole segment would report, and each hit's enclosing ``MemoryInfo`` region is
resolved from the real region table exactly as it is full-scope.

Only ``CS_MAX_SEG_SCAN`` is bypassed, and only for this one slice. Every other
budget is retained at its full-scope value -- the candidate cap, the decoded-byte
cap, the hit cap, the whole-scan deadline, the total-scanned-bytes cap, and the
per-candidate decode cap.

Those budgets are fresh per ADAPTER CALL, not accumulated across a
:class:`~dumpex.hunt._execution.HuntExecutionContext`: the scanner builds its
own deadline and counters internally and nothing here is registered on
``context.budgets``. One targeted command runs this adapter once, so today that
is the same thing. An orchestrator that ever runs several ranges on one context
must thread a shared budget through instead, or each range would silently get a
whole fresh deadline and byte allowance.

Source eligibility and evaluation are anchored to the containing segment: a
request that runs past its end is captured in full but evaluated only up to the
boundary, and the closure is ``partial`` with
``SCAN_REGION_EVALUATION_TRUNCATED``. A request lying wholly inside a larger
segment carries a diagnostic naming that segment, because a marker or TLV
structure spanning either requested boundary is examined by neither this rescan
nor the bytes around it.

A budget names the exact bytes it left unsearched. A stop before a single byte
was read leaves the whole request; a stop part-way through the marker walk
leaves everything from the scanner's own stop cursor
(``ScanDiagnostics.budget_stop_offset``) to the end of the request. The cursor
is reported only where it genuinely bounds the gap -- the walk sweeps the
buffer once per XOR key, so only once the last key's pass is under way is every
offset below the cursor searched by every key. Where no cursor bounds the gap
the whole evaluated slice stands, a conservative superset, never a narrower
range than what is actually unresolved. A short read is separate and is exact:
its unread suffix is carried by ``SCAN_REGION_SHORT_READ`` and by the closure's
``read_slice``.

The result is one :class:`~dumpex.hunt._observation.ObservationResult` with a
single ``segment_scan`` closure and a :class:`TargetedCSBeaconEvidence` payload
carrying the scanner's own config hits and diagnostics, each hit's memory-context
corroboration, and the containing-segment
:class:`~dumpex.output.coverage.ScanTarget`.
"""
import dataclasses

from dumpex.core import va_range
from dumpex.core.memory import get_memory_regions, get_thread_contexts
from dumpex.core.va_range import CaptureState

import dumpex.hunt.cs_beacon as _cs
from dumpex.hunt import _registry, _targeted
from dumpex.hunt._observation import ObservationClosure, ObservationResult
from dumpex.hunt._runtime import HunterRuntime
from dumpex.hunt.cs_beacon import context as context_mod
from dumpex.hunt.cs_beacon import scanner
from dumpex.output.coverage import (
    CoverageLimitation, LimitationCode, ScanTarget, ScanTargetKind,
)

__all__ = [
    "run_targeted_cs_beacon", "project_targeted_report",
    "TargetedCSBeaconEvidence", "TargetedCSBeaconError",
    "ALGORITHM_VERSION", "TARGETED_SOURCE",
]

# The observation-key algorithm identity for this executor -- bumped only when
# a change to which bytes reach the marker search would make a cached result
# from an earlier version unsafe to reuse.
ALGORITHM_VERSION = "cs-beacon-targeted/1"

# The one granted coverage source (the capability matrix grants `cs-beacon`
# exactly `segment_scan`, with no finer subdivision, so the closure carries no
# scope).
TARGETED_SOURCE = "segment_scan"

# Raised in place of `CS_MAX_SEG_SCAN`. Far above the 256 MiB cs-beacon request
# ceiling, so no slice inside a valid targeted request is ever skipped for
# size -- and nothing here is a buffer allocation, only a `seg.size > cap`
# comparison.
_CAP_BYPASS = 1 << 40


class TargetedCSBeaconError(Exception):
    """The context handed to :func:`run_targeted_cs_beacon` is not a legal CS
    Beacon targeted request. Raised before any dump read, so the
    ``dumpex.hunt._run_targeted_cs_beacon`` monkeypatch seam cannot route
    another analyzer's request into this executor and past its own request
    ceiling."""


@dataclasses.dataclass(frozen=True)
class TargetedCSBeaconEvidence:
    """The scan results behind one targeted ``ObservationResult`` -- carried as
    its ``payload`` so a consumer can render what the rescan found.

    ``hits`` is the scanner's tuple of
    :class:`~dumpex.hunt.cs_beacon.models.ConfigEvidence`, each carrying an
    absolute ``hit_va`` / ``hit_fo``, its decoded config fields, and its
    enclosing region. ``corroborations`` is the per-hit memory-context
    judgement for those hits; ``diagnostics`` the scanner's own
    :class:`~dumpex.hunt.cs_beacon.domain.ScanDiagnostics`.
    ``containing_segment`` is the
    :class:`~dumpex.output.coverage.ScanTarget` for the captured segment the
    requested range was evaluated inside -- distinct from the requested range
    and from any hit address, so a consumer can tell whether a full-segment
    closure is licensed."""
    hits: tuple
    corroborations: object
    diagnostics: object
    containing_segment: object
    # How many thread contexts this run actually parsed. Carried rather than
    # re-derived by the report projector: the walk is cheap, but deriving the
    # same fact twice in one invocation is how the two derivations drift.
    contexts_parsed: int = 0


def _validate_request(request) -> None:
    """Fail closed unless ``request`` is a cs-beacon ``segment_scan`` targeted
    request covering exactly the granted (empty) scope set."""
    if not getattr(request, "is_targeted", False):
        raise TargetedCSBeaconError(
            "run_targeted_cs_beacon requires a targeted HuntRequest")
    if request.selected != "cs-beacon" or request.targeted_source != TARGETED_SOURCE:
        raise TargetedCSBeaconError(
            f"run_targeted_cs_beacon is cs-beacon/{TARGETED_SOURCE} only, got "
            f"{request.selected!r}/{request.targeted_source!r}")
    granted = _registry.REGISTRY.granted_scopes("cs-beacon", TARGETED_SOURCE)
    if request.targeted_scopes != granted:
        raise TargetedCSBeaconError(
            f"a cs-beacon targeted request covers exactly {sorted(granted)}, got "
            f"{sorted(request.targeted_scopes)}")


def _not_evaluated_result(key, capture, note: str) -> ObservationResult:
    """A not-evaluated result for the whole request.

    ``captured_bytes`` is the measured availability of the requested range,
    carried even though nothing ran: a closure that never reached its algorithm
    still knows how much of the range the dump holds, and reporting that as
    unknown would cost an investigator the one number a re-collection or a
    chunked rescan is sized from.
    """
    return ObservationResult(
        key=key,
        closures=(ObservationClosure(
            source=TARGETED_SOURCE, coverage_status="not_evaluated",
            capture_state=capture.state, captured_bytes=capture.captured_bytes,
            diagnostics=(note,)),),
        payload=None)


def _coverage_status(diag, capture_state: CaptureState, *, truncated: bool) -> str:
    """This closure's honest ``coverage_status``.

    ``not_evaluated`` -- the slice never reached the marker search: the read
    raised or returned nothing, or a retained whole-scan budget was already
    spent when the scan reached it.

    Otherwise ``partial`` on any gap -- a short capture, evaluation stopped at
    the containing segment's end, a short read, an unreconciled ledger, or a
    candidate/decode/hit/byte/deadline cap -- and ``complete`` only when the
    whole requested range was captured and the search got through all of it.
    """
    if diag.scanned == 0:
        return "not_evaluated"
    if capture_state != CaptureState.COMPLETE or truncated:
        return "partial"
    if (diag.skipped_oversize or diag.read_failed or diag.short_reads
            or diag.unreconciled or diag.has_real_budget_gap):
        return "partial"
    return "complete"


def _budget_residual_targets(diag, read_slice, unexamined, containing) -> list:
    """The exact bytes a budget left unsearched, or ``[]`` to fall back to the
    scanner's own whole-slice target.

    Two cases are byte-exact. A budget that stopped before a single byte was
    read leaves the whole request. A budget that stopped part-way through the
    marker walk leaves everything from the scanner's stop cursor to the end of
    the request -- the cursor is reported only where it truly bounds the gap
    (see ``ScanDiagnostics.budget_stop_offset``), so its absence means no
    suffix describes what is left and the whole slice stands.
    """
    if read_slice is None:
        return []
    if unexamined is not None and read_slice.read_bytes == 0:
        return [unexamined]
    if diag.budget_stop_offset is None:
        return []
    requested = read_slice.requested
    residual = requested.suffix_after(min(diag.budget_stop_offset, requested.size))
    if residual is None:
        return []
    backing = va_range.segment_containing(residual.base_address, read_slice.capture.segments)
    return [ScanTarget(
        kind=ScanTargetKind.MEMORY_SEGMENT,
        base_address=residual.base_address, size=residual.size,
        file_offset=(backing.file_offset_at(residual.base_address)
                     if backing is not None else None),
        captured_size=max(0, read_slice.capture.captured_bytes - diag.budget_stop_offset),
        # This target starts AT the stop cursor, so none of it was walked:
        # the byte-exact figure the docstring above claims, recorded where
        # coverage.missed_bytes can read it.
        examined_size=0,
    )]


def _limitations(diag, *, truncation_limitation, budget_targets,
                 search_incomplete: tuple) -> tuple:
    """The structured gaps for the closure -- the same ``CoverageLimitation``
    shapes ``report_facts.project_coverage_report`` builds for a full-scope CS
    Beacon run, over this one slice.

    ``budget_targets`` replaces the scanner's own whole-slice target list on
    the code that names unexamined scope, and is non-empty only when the budget
    stopped the scan before a single byte was read -- see
    :func:`run_targeted_cs_beacon`."""
    out = []
    if diag.skipped_oversize:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source=TARGETED_SOURCE,
            affected_count=diag.skipped_oversize,
            targets=list(diag.skipped_oversize_targets)))
    if diag.read_failed:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source=TARGETED_SOURCE,
            affected_count=diag.read_failed, targets=list(diag.read_failed_targets)))
    if diag.short_reads:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source=TARGETED_SOURCE,
            affected_count=diag.short_reads, targets=list(diag.short_read_targets)))
    if truncation_limitation is not None:
        out.append(truncation_limitation)
    if diag.unreconciled:
        # No `targets` -- see SCAN_ITEMS_UNACCOUNTED on LimitationCode for why
        # this gap cannot name what it lost.
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_ITEMS_UNACCOUNTED, source=TARGETED_SOURCE,
            affected_count=diag.unreconciled))
    if diag.has_real_budget_gap:
        targets = budget_targets if budget_targets else list(diag.budget_exhausted_targets)
        out.append(CoverageLimitation(
            code=LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED, source=TARGETED_SOURCE,
            detail=diag.budget_reason, affected_count=len(targets), targets=targets,
            scope=diag.budget_exhausted_kind, budget_limit=diag.budget_exhausted_limit,
            budget_consumed=diag.budget_exhausted_consumed))
    for detail in search_incomplete:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE, source=TARGETED_SOURCE,
            detail=detail, affected_count=1))
    return tuple(out)


def run_targeted_cs_beacon(context) -> ObservationResult:
    """Search ``context.request.target_range`` for beacon configurations and
    return one :class:`~dumpex.hunt._observation.ObservationResult` with a
    single ``segment_scan`` closure and a :class:`TargetedCSBeaconEvidence`
    payload.

    ``context`` is a targeted :class:`~dumpex.hunt._execution.HuntExecutionContext`.
    Raises :class:`TargetedCSBeaconError` for any other request shape, before
    any dump read.
    """
    _validate_request(context.request)

    mf = context.mf
    requested = context.request.target_range
    key = context.observation_key("cs-beacon", algorithm_version=ALGORITHM_VERSION)

    capture = context.capture_of(requested)
    segment_enum = context.captured_segment_enumeration()
    containing = va_range.segment_containing(requested.base_address, segment_enum.views)

    if containing is None:
        dropped = ""
        if segment_enum.skipped:
            dropped = (f" ({segment_enum.skipped} segment descriptor(s) were dropped as "
                       f"unrepresentable; the requested base may lie inside one of them)")
        return _not_evaluated_result(
            key, capture,
            f"no captured segment contains the requested base "
            f"{requested.base_address:#018x}; the dump holds no bytes to search"
            + dropped)

    boundary = _targeted.resolve_segment_boundary(
        requested, containing, captured_bytes=capture.captured_bytes)

    # MemoryInfo and the thread contexts are corroboration sources only -- their
    # absence never blocks detection, and neither is part of this closure's
    # required source. Both are read exactly as the full-scope builder reads
    # them, so a targeted hit is corroborated by the same rule.
    regions = get_memory_regions(mf)
    thread_contexts = get_thread_contexts(mf)

    config = dataclasses.replace(_cs._cs_beacon_config(), max_seg_scan=_CAP_BYPASS)
    runtime = HunterRuntime(monotonic=_cs.time.monotonic)
    hits, diag = scanner.scan_segments(
        mf, [boundary.slice_segment], config, regions, runtime.monotonic)

    # The scanner reads the slice exactly once, so its cumulative
    # total_scanned_bytes IS this run's read length. Clamped to the captured
    # prefix: a read that somehow over-served past what the dump's own segment
    # table backs must not be recorded as evidence the dump does not hold.
    read_bytes = min(diag.total_scanned_bytes, capture.captured_bytes)
    read_slice = (None if capture.state == CaptureState.NONE
                  else capture.read_input(read_bytes))

    status = _coverage_status(diag, capture.state, truncated=boundary.truncated)
    reached = status != "not_evaluated"

    # A negative over an ambiguous capture is "not found in the bytes that were
    # searched", not "not found after a full search": the dump's segment table
    # places one or more requested addresses at more than one file offset, so
    # the searched bytes are one arbitrary choice among conflicting claims.
    search_incomplete = ("overlapping_capture",) if reached and capture.overlapping else ()
    if search_incomplete and status == "complete":
        status = "partial"

    # Only a stop INSIDE the slice leaves an unexamined suffix this closure has
    # to name here: bytes past the containing segment's end were never in this
    # scan's scope at all and are already reported by the truncation
    # limitation. When the scan did stop short, the suffix runs from where the
    # read stopped through the end of the whole request.
    stopped_short = read_slice is not None and read_slice.read_bytes < boundary.eval_range.size
    unexamined = _targeted.unexamined_suffix_target(read_slice) if stopped_short else None
    budget_targets = _budget_residual_targets(diag, read_slice, unexamined, containing)
    truncation_limitation = (
        _targeted.evaluation_truncated_limitation(
            TARGETED_SOURCE, None, boundary)
        if boundary.truncated and reached else None)
    limitations = _limitations(
        diag, truncation_limitation=truncation_limitation,
        budget_targets=budget_targets, search_incomplete=search_incomplete)

    diagnostics = []
    if boundary.truncated and reached:
        diagnostics.append(_targeted.truncation_diagnostic(
            boundary.segment_range, requested, boundary.eval_range, unit="segment"))
    if boundary.sub_segment and reached:
        diagnostics.append(_targeted.sub_segment_diagnostic(
            boundary.segment_range, requested))
    if unexamined is not None:
        diagnostics.append(
            f"[{unexamined.base_address:#018x}, "
            f"{unexamined.base_address + unexamined.size:#018x}) of the requested range "
            f"was never searched for a config marker")
    if search_incomplete:
        diagnostics.append(
            "the dump's segment table maps one or more requested virtual addresses to "
            "multiple file offsets (overlapping segments); the searched bytes are one "
            "arbitrary choice among conflicting claims")

    closure = ObservationClosure(
        source=TARGETED_SOURCE, coverage_status=status, capture_state=capture.state,
        captured_bytes=capture.captured_bytes,
        read_slice=read_slice if reached else None,
        limitations=limitations, diagnostics=tuple(diagnostics))
    payload = TargetedCSBeaconEvidence(
        hits=hits, corroborations=context_mod.corroborate(hits, regions, thread_contexts),
        diagnostics=diag, containing_segment=boundary.containing_target,
        contexts_parsed=len(thread_contexts))
    return ObservationResult(key=key, closures=(closure,), payload=payload)


def project_targeted_report(context, result):
    """The :class:`~dumpex.hunt.cs_beacon.domain.CSBeaconReport` behind one
    targeted rescan's :class:`~dumpex.output.records.HunterRecord`.

    The range's own config hits, per-hit corroboration, and scan diagnostics
    are fed to the SAME ``aggregate.build_report`` full scope uses, so a
    targeted verdict is scored and classified by one authority rather than a
    parallel targeted-only rule.

    The MemoryInfo and thread-context facts come from the dump exactly as the
    full-scope builder reads them, because this rescan really did read both:
    they are corroboration sources it evaluated, not sources it skipped. The
    parsed-context count rides on the payload rather than being walked a
    second time here. The
    record's document-level coverage still comes from the observation's own
    ``segment_scan`` closure -- corroboration is observational and never gates
    it (see :mod:`dumpex.hunt._targeted_record`).
    """
    payload = result.payload
    mf = context.mf
    if payload is None:
        return _cs.aggregate.build_not_evaluated_report()
    return _cs.aggregate.build_report(
        payload.hits, payload.corroborations, scan=payload.diagnostics,
        mem_info_available=bool(mf.memory_info and mf.memory_info.infos),
        thread_list_stream_available=bool(mf.threads and mf.threads.threads),
        threads_total=len(mf.threads.threads) if (mf.threads and mf.threads.threads) else 0,
        contexts_parsed=payload.contexts_parsed)

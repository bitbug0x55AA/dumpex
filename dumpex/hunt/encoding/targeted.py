"""Targeted obfuscation rescan: the three encoding layers over one range.

A targeted ``--hunt-addr`` obfuscation invocation asks the sleep-mask, entropy,
and decode layers to evaluate one investigator-selected half-open
virtual-address range. :func:`run_targeted_encoding` is the executor the
analyzer registry resolves as ``obfuscation``'s ``targeted_adapter`` (through
the ``dumpex.hunt._run_targeted_obfuscation`` facade seam).

Only each layer's ordinary per-region size cap is bypassed
(``SLEEP_MASK_REGION_MAX`` / ``ENTROPY_SCAN_MAX`` / ``DECODE_SCAN_MAX`` and the
inner ``XOR_SCAN_MAX``). Every other budget is retained at its full-scope value:
the shared decode/sleep-mask :class:`~dumpex.hunt._budget.ScanBudget`
(attempts, retained bytes, hits, wall-clock deadline) is the invocation's own,
reused across adapter calls on one :class:`~dumpex.hunt._execution.HuntExecutionContext`
so its cumulative caps really are per-invocation; entropy's 256-byte minimum
input and sleep-mask's candidate/window/validation bounds are threaded
unchanged.

The requested bytes are captured once (:meth:`HuntExecutionContext.capture_of`)
and shared by all three closures. The containing region is resolved through the
context's memoized, representability-filtered
:meth:`~dumpex.hunt._execution.HuntExecutionContext.captured_regions` view, so
capture and eligibility agree about which descriptors exist. Source eligibility
and evaluation are anchored to that region; a request that runs past its end is
captured in full but evaluated only up to the boundary, and each in-scope
closure is ``partial`` with ``SCAN_REGION_EVALUATION_TRUNCATED``. A request that
lies wholly inside a larger allocation carries a diagnostic naming that
allocation: a transformation spanning the requested end boundary is evaluated
by neither this rescan nor anything past it, so only a request covering the
whole containing region can license boundary-sensitive full-region closure.

Source eligibility is resolved once, before any layer runs
(:func:`_ineligible_reasons`), and answers a different question from coverage.
A layer whose own descriptor gate declines the target is ``not_applicable``
with that gate named: it does not apply to these bytes at all, so there is
nothing here it could have missed and no re-collection, larger budget, or
narrower request would change it. A layer that WOULD have applied and was
stopped is ``not_evaluated``, which is a coverage failure. Only the second
takes part in the record's coverage reduction, so one inapplicable layer never
turns its completed siblings into a partial result -- and a spent shared budget
is never blamed on a layer whose gate declined the target, which would imply a
bigger-budget rerun could help where it never could.

Entropy is measured in bounded windows here, unlike full scope. Bypassing the
size cap and computing one Shannon value over an investigator-supplied range
does not recover what the cap hid: an average over a sparse oversized
allocation is dominated by its zero-filled majority, so a bounded encrypted
payload inside it sits below the threshold as one number and above it as its
own window -- and the skipped-target queue supplies the containing target, not
the sub-window. See :func:`~dumpex.hunt.encoding.entropy.scan_entropy_targeted`
for which of the two becomes a hit.

Every closure carries bounded ``measurements``: what the layer did to these
bytes, plus the structural context the range sits in. They exist so a layer
that completed without a hit still says what it measured, rather than reducing
to an unexplained negative. They are observations only -- no finding, no score,
and no claim about any other layer's or hunter's coverage.

The result is one :class:`~dumpex.hunt._observation.ObservationResult` with an
independent :class:`~dumpex.hunt._observation.ObservationClosure` per layer, in
the fixed order ``sleep_mask``, ``entropy``, ``decode``, and a
:class:`TargetedEncodingEvidence` payload carrying each layer's own
``LayerResult`` / ``DecodeResult`` (recovered keys, decoded payloads, hit VAs,
entropy values), the entropy window pass, and the containing-region
:class:`~dumpex.output.coverage.ScanTarget`. One layer's negative or gap never
changes another layer's closure.
"""
import dataclasses
import time

from dumpex.core import va_range
from dumpex.core.memory import addr_to_module, get_modules, read_region_spanning
from dumpex.core.va_range import CaptureState
from dumpex.rules_pkg.loader import get_rules

import dumpex.hunt.encoding as _encoding
from dumpex.hunt import _registry, _targeted
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._observation import (
    BudgetOutcome, ObservationClosure, ObservationResult,
)
from dumpex.output.coverage import CoverageLimitation, LimitationCode
from dumpex.output.records import TargetedMeasurement, hex_address

from dumpex.hunt.encoding.config import EncodingConfig
from dumpex.hunt.encoding.models import DecodeResult, LayerResult
from dumpex.hunt.encoding.sleep_mask import _scan_sleep_mask
from dumpex.hunt.encoding.entropy import (
    entropy_region_ineligible_reason, scan_entropy_targeted,
)
from dumpex.hunt.encoding.decoding import _is_system_dll, scan_decode_layers

__all__ = [
    "run_targeted_encoding", "project_targeted_report",
    "TargetedEncodingEvidence", "TargetedEncodingError",
    "ALGORITHM_VERSION", "TARGETED_LAYERS",
]

# The observation-key algorithm identity for this executor -- bumped only when
# a change to which bytes reach which layer would make a cached result from an
# earlier version unsafe to reuse.
ALGORITHM_VERSION = "encoding-targeted/1"

# Fixed closure order (docs/developer/hunt_targeted_rescan_contract.md
# "Capability matrix": obfuscation always attempts three closures in this
# order; there is no public per-layer selection).
TARGETED_LAYERS = ("sleep_mask", "entropy", "decode")

_BUDGET_USING_LAYERS = frozenset({"sleep_mask", "decode"})

# Raised in place of each layer's per-region size cap. Far above the 32 MiB
# obfuscation request ceiling, so no region inside a valid targeted request is
# ever skipped for size -- and nothing here is a buffer allocation, only a
# ``RegionSize > cap`` comparison.
_CAP_BYPASS = 1 << 40

_BUDGET_NAME = "encoding_decode"

# One sentence per eligibility gate, naming the layer and what about the target
# put it outside that layer's scope. The structured
# ``TARGETED_SOURCE_NOT_APPLICABLE`` limitation carries the same reason as a
# machine-readable token; this is the console's reading of it.
_INAPPLICABLE_NOTES = {
    "region_not_committed":
        "the region containing the requested base is not MEM_COMMIT, so the {layer} "
        "layer does not apply to it; no {layer} conclusion is available for this range",
    "region_type_ineligible":
        "the region containing the requested base is not a memory type the {layer} layer "
        "examines; no {layer} conclusion is available for this range",
    "region_protection_ineligible":
        "the region containing the requested base is not PAGE_READWRITE, which is the "
        "protection a sleeping beacon leaves its encoded heap under, so the {layer} "
        "layer does not apply to it",
    "region_module_backed":
        "the requested base is inside a loaded module, and the {layer} layer examines "
        "unbacked private memory only; no {layer} conclusion is available for this range",
    "region_system_module":
        "the requested base is inside a system module the {layer} layer deliberately "
        "leaves out; no {layer} conclusion is available for this range",
    "range_below_source_minimum":
        "the requested range is shorter than the shortest range the {layer} layer's "
        "algorithm can apply to; no {layer} conclusion is available for this range",
}


class TargetedEncodingError(Exception):
    """The context handed to :func:`run_targeted_encoding` is not a legal
    obfuscation targeted request. Raised before any dump read, so the
    ``dumpex.hunt._run_targeted_obfuscation`` monkeypatch seam cannot route a
    pipe/full-scope request into this executor and past obfuscation's lower
    32 MiB request ceiling."""


@dataclasses.dataclass(frozen=True)
class TargetedEncodingEvidence:
    """The per-layer scan results behind one targeted ``ObservationResult`` --
    carried as its ``payload`` so a consumer can render what each layer found.

    ``sleep_mask`` / ``entropy`` are ``LayerResult``; ``decode`` is a
    ``DecodeResult``. ``containing_region`` is the
    :class:`~dumpex.output.coverage.ScanTarget` for the allocation the requested
    range was evaluated inside -- distinct from the requested range and from any
    hit offset, so a consumer can tell whether a full-region closure is
    licensed.

    ``windowed_entropy`` is the entropy layer's window pass
    (:class:`~dumpex.hunt.encoding.entropy.WindowedEntropy`), or ``None`` when
    that layer never reached it. It is retained whether or not any window
    crossed the threshold: what the layer measured is the answer to "what did
    the rescan actually do", and a no-hit layer that records nothing leaves
    that question open."""
    sleep_mask: LayerResult
    entropy: LayerResult
    decode: DecodeResult
    containing_region: object
    windowed_entropy: object = None


def _base_config() -> EncodingConfig:
    """Every ``encoding.*`` tunable at its full-scope value, read through the
    ``dumpex.hunt.encoding`` module globals -- the same re-exported,
    monkeypatchable seam ``_build_encoding_report`` reads, so an override of
    ``dumpex.hunt.encoding.<CONST>`` moves full-scope and targeted together."""
    e = _encoding
    return EncodingConfig(
        entropy_private_threshold=e.ENTROPY_PRIVATE_THRESHOLD,
        entropy_rwx_threshold=e.ENTROPY_RWX_THRESHOLD, entropy_scan_max=e.ENTROPY_SCAN_MAX,
        entropy_min_input=e.ENTROPY_MIN_INPUT, entropy_window_size=e.ENTROPY_WINDOW_SIZE,
        entropy_max_windows=e.ENTROPY_MAX_WINDOWS,
        entropy_top_windows=e.ENTROPY_TOP_WINDOWS,
        b64_min_len=e.B64_MIN_LEN, xor_scan_max=e.XOR_SCAN_MAX,
        xor_sample_size=e.XOR_SAMPLE_SIZE, xor_score_min=e.XOR_SCORE_MIN,
        xor_structural_window=e.XOR_STRUCTURAL_WINDOW,
        decompress_max_output=e.DECOMPRESS_MAX_OUTPUT, decode_scan_max=e.DECODE_SCAN_MAX,
        sleep_mask_key_size=e.SLEEP_MASK_KEY_SIZE, sleep_mask_min_repeat=e.SLEEP_MASK_MIN_REPEAT,
        sleep_mask_max_byte_freq=e.SLEEP_MASK_MAX_BYTE_FREQ, sleep_mask_min_acbd=e.SLEEP_MASK_MIN_ACBD,
        sleep_mask_max_candidates=e.SLEEP_MASK_MAX_CANDIDATES,
        sleep_mask_region_max=e.SLEEP_MASK_REGION_MAX,
        sleep_mask_validate_sample=e.SLEEP_MASK_VALIDATE_SAMPLE,
        sleep_mask_validation_marker=e.SLEEP_MASK_VALIDATION_MARKER,
        sleep_mask_max_windows=e.SLEEP_MASK_MAX_WINDOWS,
    )


def _fresh_budget() -> ScanBudget:
    """One decode/sleep-mask budget -- identical shape and values to
    ``_build_encoding_report``'s. Registered on the context ledger and reused
    across adapter calls in one invocation."""
    e = _encoding
    return ScanBudget(
        max_bytes_read=e.ENCODING_BUDGET_MAX_RETAINED * 4,
        max_attempts=e.ENCODING_BUDGET_MAX_ATTEMPTS,
        max_retained_bytes=e.ENCODING_BUDGET_MAX_RETAINED,
        max_hits=e.ENCODING_BUDGET_MAX_HITS,
        deadline=time.monotonic() + e.ENCODING_BUDGET_TIME_SECONDS,
    )


def _sleep_mask_ineligible_reason(region, base_address: int, size: int,
                                  modules) -> "str | None":
    """Why the sleep-mask layer's descriptor gate declines this target, or
    ``None`` when it accepts it -- a statement of ``_scan_sleep_mask``'s own
    filters, in the vocabulary
    ``LimitationCode.TARGETED_SOURCE_NOT_APPLICABLE`` renders."""
    if region.state != "MEM_COMMIT":
        return "region_not_committed"
    if region.type != "MEM_PRIVATE":
        return "region_type_ineligible"
    if region.protection != "PAGE_READWRITE":
        return "region_protection_ineligible"
    if size < _encoding.SLEEP_MASK_KEY_SIZE * _encoding.SLEEP_MASK_MIN_REPEAT:
        return "range_below_source_minimum"
    if addr_to_module(base_address, modules) is not None:
        return "region_module_backed"
    return None


def _decode_ineligible_reason(region, base_address: int, modules) -> "str | None":
    """Why the decode layer's descriptor gate declines this target, or ``None``
    when it accepts it -- a statement of ``scan_decode_layers``'s own
    filters."""
    if region.state != "MEM_COMMIT":
        return "region_not_committed"
    if region.type not in ("MEM_PRIVATE", "MEM_IMAGE"):
        return "region_type_ineligible"
    if region.type == "MEM_IMAGE" and _is_system_dll(addr_to_module(base_address, modules)):
        return "region_system_module"
    return None


def _entropy_ineligible_reason(synthetic, size: int, modules) -> "str | None":
    """Why the entropy layer declines this target, or ``None`` when it applies.

    The descriptor gate is ``_scan_entropy``'s own. The extent check on top of
    it is this executor's, and it is deliberately NOT pushed into the shared
    scanner: full scope walks whole regions and accounts for one shorter than
    the minimum as an eligible item with a not-applicable disposition, which is
    a ledger fact this must not disturb.

    Here the extent is the investigator's own request, so it answers a
    different question. A requested range shorter than a Shannon value can be
    computed over cannot be evaluated by any capture of it, which makes it a
    property of the target rather than of the dump -- unlike a range that IS
    long enough but whose captured prefix falls short, where a fuller
    collection is exactly what closes the gap and the closure stays
    ``not_evaluated``."""
    reason = entropy_region_ineligible_reason(synthetic, modules)
    if reason is not None:
        return reason
    if size < _encoding.ENTROPY_MIN_INPUT:
        return "range_below_source_minimum"
    return None


def _ineligible_reasons(region, synthetic, base_address: int, size: int, modules) -> dict:
    """Each layer's own eligibility verdict for this target, keyed by layer:
    the reason it declined, or ``None`` when it applies.

    Resolved once, before any layer runs, and used for two decisions that must
    not disagree. It is what makes a declined layer ``not_applicable`` with a
    named gate rather than an unexplained ``not_evaluated``; and it is what
    keeps a spent shared budget from being blamed on a layer that would never
    have applied here anyway, which would imply a bigger-budget rerun could
    help where it never could.

    ``size`` is the evaluable extent -- the request clipped to its containing
    descriptor -- never the captured prefix. A layer declining a target for its
    extent is declining the range that was asked for, which no capture of it
    would change."""
    return {
        "sleep_mask": _sleep_mask_ineligible_reason(region, base_address, size, modules),
        "entropy": _entropy_ineligible_reason(synthetic, size, modules),
        "decode": _decode_ineligible_reason(region, base_address, modules),
    }


def _validate_request(request) -> frozenset:
    """Fail closed unless ``request`` is a full obfuscation ``encoding_scan``
    targeted request. Returns the granted layer set."""
    if not getattr(request, "is_targeted", False):
        raise TargetedEncodingError(
            "run_targeted_encoding requires a targeted HuntRequest")
    if request.selected != "obfuscation" or request.targeted_source != "encoding_scan":
        raise TargetedEncodingError(
            f"run_targeted_encoding is obfuscation/encoding_scan only, got "
            f"{request.selected!r}/{request.targeted_source!r}")
    granted = _registry.REGISTRY.granted_scopes("obfuscation", "encoding_scan")
    if request.targeted_scopes != granted:
        raise TargetedEncodingError(
            f"an obfuscation targeted request covers exactly {sorted(granted)}, got "
            f"{sorted(request.targeted_scopes)}")
    return granted


def _layer_status(layer: str, lc, capture_state: CaptureState, *,
                  ineligible_reason: "str | None",
                  budget_prevented: bool, budget_capped: bool) -> str:
    """This layer's honest ``coverage_status`` before the boundary-truncation
    check the caller applies on top.

    ``not_applicable`` -- the layer's own descriptor-eligibility gate declined
    the target. Nothing here was missed and nothing about the dump, the budget,
    or the request size would change that, so this is the boundary of what the
    layer speaks about rather than a gap in what it did.

    ``not_evaluated`` -- the layer WOULD have applied and did not get to run:
    the read returned nothing, a spent shared budget stopped it before it
    looked, or -- entropy only -- the requested range is long enough to measure
    but the dump backs fewer bytes of it than a Shannon value can be computed
    over. That last one is a gap a fuller collection closes, which is what
    separates it from a request whose own extent is under the minimum: that is
    ``not_applicable`` above, decided before this function runs.

    Otherwise ``partial`` on any gap -- a short capture, an unreconciled ledger,
    a short read, or the shared budget hitting a cap during the layer -- and
    ``complete`` only when the whole requested range was captured and the layer
    got through all of it.
    """
    if ineligible_reason is not None:
        return "not_applicable"
    if budget_prevented:
        return "not_evaluated"
    if lc.eligible_total == 0:
        return "not_evaluated"
    if lc.read_failed:
        return "not_evaluated"
    if layer == "entropy" and lc.scanned == 0 and lc.not_applicable:
        # Reachable only for a range whose own extent clears the minimum: a
        # request that does not is declined for its extent before this runs.
        # So this is always the captured prefix falling short of it.
        return "not_evaluated"
    if capture_state != CaptureState.COMPLETE:
        return "partial"
    if budget_capped:
        return "partial"
    if not lc.reconciled:
        return "partial"
    if lc.short_reads or lc.skipped_oversize_targets or lc.budget_exhausted:
        return "partial"
    return "complete"


def _search_incomplete_limitation(layer: str, detail: str) -> CoverageLimitation:
    """A ``SCAN_REGION_SEARCH_INCOMPLETE`` for one layer whose scan reached the
    requested bytes but could not search them exhaustively (a bounded window
    sample, a truncated candidate list, or an ambiguous overlapping capture)."""
    return CoverageLimitation(
        code=LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE, source="encoding_scan",
        scope=layer, detail=detail, affected_count=1)


def _layer_limitations(layer: str, lc, *, truncation_limitation,
                       budget_reason: "str | None",
                       search_incomplete: tuple = ()) -> tuple:
    """The structured gaps for one layer closure -- the same
    ``CoverageLimitation`` shapes ``report_facts.project_coverage_report``
    builds for full-scope encoding (read-failed / short-read / oversized /
    budget-exhausted / items-unaccounted, all ``scope``-tagged with the layer),
    plus the shared ``SCAN_REGION_EVALUATION_TRUNCATED`` (already built) when the
    request crossed the containing descriptor's end and one
    ``SCAN_REGION_SEARCH_INCOMPLETE`` per ``search_incomplete`` detail."""
    out = []
    if lc.read_failed_targets:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="encoding_scan",
            scope=layer, affected_count=len(lc.read_failed_targets),
            targets=tuple(lc.read_failed_targets)))
    if lc.short_read_targets:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="encoding_scan",
            scope=layer, affected_count=len(lc.short_read_targets),
            targets=tuple(lc.short_read_targets)))
    if lc.skipped_oversize_targets:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="encoding_scan",
            scope=layer, affected_count=len(lc.skipped_oversize_targets),
            targets=tuple(lc.skipped_oversize_targets)))
    if truncation_limitation is not None:
        out.append(truncation_limitation)
    unreconciled = lc.unaccounted + lc.over_accounted + lc.ledger_imbalance
    if unreconciled:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_ITEMS_UNACCOUNTED, source="encoding_scan",
            scope=layer, affected_count=unreconciled))
    if budget_reason is not None:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="encoding_scan",
            scope=layer, detail=budget_reason))
    for detail in search_incomplete:
        out.append(_search_incomplete_limitation(layer, detail))
    return tuple(out)


@dataclasses.dataclass(frozen=True)
class _BudgetSnapshot:
    """The shared budget's counters at one instant, copied out of the live
    :class:`~dumpex.hunt._budget.ScanBudget`.

    The budget is one mutable object every layer spends from in turn, so
    reading it after all three have run attributes the whole invocation's
    consumption -- and the last layer's exhaustion -- to each of them alike. A
    layer's own work is the difference between the snapshot taken immediately
    before its call and the one taken immediately after; nothing else about the
    budget is that layer's to report."""
    attempts: int
    decoded_bytes: int
    retained_bytes: int
    hits: int
    reason: "str | None"


def _snapshot(budget: ScanBudget) -> _BudgetSnapshot:
    """``budget``'s counters now, with the deadline re-checked first so a
    just-expired deadline is visible even to a layer that never polled."""
    budget.exhausted()
    return _BudgetSnapshot(
        attempts=budget.attempts, decoded_bytes=budget.bytes_read,
        retained_bytes=budget.retained_bytes, hits=budget.hits,
        reason=budget.exhausted_reason or None)


def _budget_measurements(budget: ScanBudget, before: _BudgetSnapshot,
                         after: _BudgetSnapshot, layer_reason: "str | None") -> tuple:
    """What ONE layer spent from the shared budget, against each resource's
    own limit.

    Every ``_spent`` value is that layer's own delta across its own call, so a
    layer that spent nothing reports nothing spent however much its siblings
    used. ``budget_exhausted_reason`` is likewise the reason attributed to THIS
    layer -- ``None`` for a layer that finished inside the allowance, even when
    a later layer went on to exhaust the same budget.

    All four resources are reported, including the decoded-output cap: when
    that is the limit a run hits, a reason with no consumption or ceiling
    beside it leaves an analyst unable to size a rerun."""
    return (
        _targeted.count_measurement("budget_attempts_spent",
                                    after.attempts - before.attempts),
        _targeted.count_measurement("budget_attempts_limit", budget.max_attempts),
        _targeted.bytes_measurement("budget_decoded_bytes_spent",
                                    after.decoded_bytes - before.decoded_bytes),
        _targeted.bytes_measurement("budget_decoded_bytes_limit", budget.max_bytes_read),
        _targeted.bytes_measurement("budget_retained_bytes_spent",
                                    after.retained_bytes - before.retained_bytes),
        _targeted.bytes_measurement("budget_retained_bytes_limit", budget.max_retained_bytes),
        _targeted.count_measurement("budget_hits_spent", after.hits - before.hits),
        _targeted.count_measurement("budget_hits_limit", budget.max_hits),
        _targeted.text_measurement("budget_exhausted_reason", layer_reason),
    )


def _decode_work_measurements(counts) -> tuple:
    """What each decode sub-layer actually tried, apart from what it kept.

    Zero retained hits has two causes an analyst acts on differently -- nothing
    in the range resembled a candidate, or many candidates were tried and every
    one was rejected -- and only these counts separate them. The shared budget's
    attempt total cannot: it is spent by sleep-mask and all three sub-layers
    together, so it answers a question about the invocation rather than about
    Base64, XOR, or compression."""
    return (
        _targeted.count_measurement("base64_candidates", counts.base64_candidates),
        _targeted.count_measurement("base64_attempts", counts.base64_attempts),
        _targeted.count_measurement("xor_keys_scored", counts.xor_keys_scored),
        _targeted.count_measurement("xor_text_candidates", counts.xor_text_candidates),
        _targeted.count_measurement("xor_structural_candidates",
                                    counts.xor_structural_candidates),
        _targeted.count_measurement("xor_attempts", counts.xor_attempts),
        _targeted.count_measurement("compressed_candidates", counts.compressed_candidates),
        _targeted.count_measurement("compressed_attempts", counts.compressed_attempts),
    )


def _entropy_measurements(windowed) -> tuple:
    """What the entropy layer measured, hit or no hit.

    The whole-range average and the window summary are both kept because they
    disagree exactly where it matters: a sparse allocation averages far below
    the threshold while a bounded window inside it sits far above, and only the
    second names a range an investigator can extract. ``entropy_top_window``
    repeats, in descending order, so its first entry is the range's maximum and
    its location; ``entropy_window_coverage`` says whether a window between two
    measured ones could have been missed."""
    if windowed is None:
        return ()
    out = [
        _measure_entropy("whole_range_entropy", windowed.whole_range_entropy),
        _measure_entropy("entropy_threshold", windowed.threshold),
        _targeted.bytes_measurement("entropy_window_size", windowed.window_size),
        _targeted.count_measurement("entropy_windows_total", windowed.windows_total),
        _targeted.count_measurement("entropy_windows_evaluated",
                                    windowed.windows_evaluated),
        _targeted.count_measurement("entropy_windows_above_threshold",
                                    windowed.windows_above_threshold),
        _targeted.text_measurement(
            "entropy_window_coverage",
            "exhaustive" if windowed.exhaustive else "sampled"),
    ]
    for window in windowed.top_windows:
        out.append(_measure_entropy("entropy_top_window", window.entropy,
                                    base_address=window.base_address, size=window.size))
    return tuple(out)


def _measure_entropy(name: str, value: float, *, base_address: int = None,
                     size: int = None) -> TargetedMeasurement:
    return TargetedMeasurement(
        name=name, value=value, unit="bits_per_byte",
        base_address=None if base_address is None else hex_address(base_address),
        size=size)


def _layer_measurements(layer: str, lc, *, reached: bool, read_bytes: int, sm_result,
                        ent_result, dec_result, windowed, budget, budget_relevant: bool,
                        budget_before, budget_after, budget_reason: "str | None",
                        xor_applied: bool) -> tuple:
    """One layer's own neutral measurements: how many bytes it evaluated, what
    it measured over them, which of its own bounds it reached, and what it
    retained.

    These exist so a completed layer that found nothing still says what it did.
    They are observations: none of them creates a finding, moves a score, or
    claims anything about another layer's or another hunter's coverage.

    Only ``bytes_evaluated`` is reported for a layer that never reached its
    algorithm. Everything below it describes an execution: an inapplicable
    layer claiming its window search was exhaustive and its candidate list
    complete would be describing a search that never happened, which
    contradicts the closure standing beside it.
    """
    out = [_targeted.bytes_measurement("bytes_evaluated",
                                       read_bytes if lc.scanned else 0)]
    if not reached:
        return tuple(out)
    if layer == "sleep_mask":
        out.extend([
            _targeted.count_measurement("sleep_mask_keys_recovered",
                                        len(sm_result.hits)),
            _targeted.text_measurement(
                "sleep_mask_window_coverage",
                "sampled" if lc.window_sampled else "exhaustive"),
            _targeted.text_measurement(
                "sleep_mask_candidate_list",
                "truncated" if lc.candidate_cap_hit else "complete"),
        ])
    elif layer == "entropy":
        out.extend(_entropy_measurements(windowed))
        out.append(_targeted.count_measurement("entropy_ranges_retained",
                                                len(ent_result.hits)))
    elif layer == "decode":
        out.extend(_decode_work_measurements(dec_result.counts))
        out.extend([
            _targeted.count_measurement("base64_retained", len(dec_result.base64)),
            _targeted.count_measurement("xor_retained", len(dec_result.xor)),
            _targeted.count_measurement("compressed_retained",
                                        len(dec_result.compressed)),
            # The XOR sub-layer has a descriptor gate of its own inside the
            # decode layer: a committed MEM_IMAGE range reaches Base64 and
            # decompression but never single-byte XOR, so a decode negative
            # over one is not an XOR negative.
            _targeted.text_measurement("xor_sublayer",
                                       "applied" if xor_applied else "not_applied"),
        ])
    if budget_relevant:
        out.extend(_budget_measurements(budget, budget_before, budget_after,
                                        budget_reason))
    return tuple(out)


def _not_evaluated_result(key, capture, note: str, payload=None) -> ObservationResult:
    """A not-evaluated result for the whole request.

    ``captured_bytes`` is the measured availability of the requested range,
    carried even though nothing ran: a closure that never reached its algorithm
    still knows how much of the range the dump holds, and reporting that as
    unknown would cost an investigator the one number a re-collection or a
    chunked rescan is sized from.
    """
    closures = tuple(
        ObservationClosure(source="encoding_scan", scope=layer,
                           coverage_status="not_evaluated",
                           capture_state=capture.state,
                           captured_bytes=capture.captured_bytes, diagnostics=(note,))
        for layer in TARGETED_LAYERS)
    return ObservationResult(key=key, closures=closures, payload=payload)


def run_targeted_encoding(context) -> ObservationResult:
    """Run the sleep-mask, entropy, and decode layers over
    ``context.request.target_range`` and return one
    :class:`~dumpex.hunt._observation.ObservationResult` with an independent
    closure per layer and a :class:`TargetedEncodingEvidence` payload.

    ``context`` is a targeted :class:`~dumpex.hunt._execution.HuntExecutionContext`.
    Raises :class:`TargetedEncodingError` for any other request shape, before
    any dump read.
    """
    _validate_request(context.request)

    mf = context.mf
    requested = context.request.target_range
    key = context.observation_key("obfuscation", algorithm_version=ALGORITHM_VERSION)

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

    # One read of the requested (clipped) bytes, shared by all three layers,
    # clamped to the captured prefix the dump's own segment table backs -- the
    # raw reader can over-serve past a descriptor the capture model dropped, and
    # a layer must never analyze (or retain a hit from) bytes the closure then
    # reports as uncaptured. A clamp shorter than the synthetic region's size
    # surfaces to the layers as an ordinary short read.
    buf = read_region_spanning(
        mf, eval_range.base_address, eval_range.size)[:capture.captured_bytes]
    read_bytes = len(buf)
    read_slice = None if capture.state == CaptureState.NONE else capture.read_input(read_bytes)

    def _reader(_mf, addr, size):
        if addr == eval_range.base_address:
            return buf[:size]
        return b""

    modules = get_modules(mf)
    susp_prots = get_rules(announce=False)["suspicious_protections"]
    synthetic = _targeted.SyntheticRegion.from_captured_region(
        eval_range.base_address, eval_range.size, containing)

    ineligible = _ineligible_reasons(
        containing, synthetic, eval_range.base_address, eval_range.size, modules)

    base_cfg = _base_config()
    if _BUDGET_NAME in context.budgets:
        budget = context.budgets.get(_BUDGET_NAME)
    else:
        budget = context.budgets.register(_BUDGET_NAME, _fresh_budget())

    # Per-layer budget attribution: an immutable snapshot of the shared budget
    # taken immediately before and immediately after each budget-using layer's
    # own call. A `before` reason means the layer was prevented (the budget was
    # already spent); a reason appearing only in `after` means this layer spent
    # it. The counter difference between the two is that layer's own
    # consumption -- read off the live budget afterwards, every layer would
    # report the whole invocation's spend and the last layer's exhaustion.
    sm_before = _snapshot(budget)
    sm_result = _scan_sleep_mask(
        [synthetic], modules, mf, _reader,
        dataclasses.replace(base_cfg, sleep_mask_region_max=_CAP_BYPASS),
        budget, susp_prots=susp_prots)
    sm_after = _snapshot(budget)

    # Windowed, unlike full scope: bypassing the size cap and computing ONE
    # value over an investigator-supplied range does not recover what the cap
    # hid. A sparse oversized allocation averages far below the threshold while
    # a bounded window inside it sits far above, and the skipped-target queue
    # hands over the containing target, not the sub-window -- so measuring only
    # the average asks the analyst to already know the answer.
    ent_result, windowed = scan_entropy_targeted(
        [synthetic], modules, mf, susp_prots, _reader,
        dataclasses.replace(base_cfg, entropy_scan_max=_CAP_BYPASS))

    dec_before = _snapshot(budget)
    dec_result = scan_decode_layers(
        [synthetic], modules, mf, _reader,
        dataclasses.replace(base_cfg, decode_scan_max=_CAP_BYPASS, xor_scan_max=_CAP_BYPASS),
        budget, susp_prots=susp_prots)
    dec_after = _snapshot(budget)

    # Entropy touches no budget at all, so its pair is one snapshot used twice:
    # a zero-width interval, which is exactly the work it charged.
    ent_snapshot = _snapshot(budget)
    layers = {
        "sleep_mask": (sm_result.coverage, sm_before, sm_after),
        "entropy": (ent_result.coverage, ent_snapshot, ent_snapshot),
        "decode": (dec_result.coverage, dec_before, dec_after),
    }

    # The dump's segment table places one or more requested addresses at more
    # than one file offset -- the bytes every layer analyzed are one arbitrary
    # choice among conflicting claims, so no layer's negative is authoritative.
    overlapping = capture.overlapping

    # The same structural context for every closure: the allocation the range
    # sits in, the module backing it, and what the dump holds. Carried on each
    # closure rather than once beside them, so a closure read on its own is
    # still self-explanatory -- and it is context only, never a claim that any
    # hunter evaluated that allocation or that module.
    target_context = _targeted.region_context_measurements(
        boundary, containing, capture, modules)

    closures = []
    for layer in TARGETED_LAYERS:
        lc, before, after = layers[layer]
        ineligible_reason = ineligible[layer]
        # The shared budget is only this layer's concern when the layer both
        # uses it and would structurally have applied to this region.
        budget_relevant = (layer in _BUDGET_USING_LAYERS and ineligible_reason is None)
        budget_prevented = bool(before.reason) and budget_relevant
        budget_capped = not budget_prevented and bool(after.reason) and budget_relevant
        budget_reason = after.reason if (budget_prevented or budget_capped) else None

        # `base_status` separates three things a single "did not run" would
        # collapse: a layer whose own eligibility gate declined the target
        # (not_applicable, with the gate named), a layer that would have
        # applied and was stopped (not_evaluated), and a layer that ran.
        # Whether this layer reached its algorithm gates whether the descriptor
        # boundary is even this layer's fact.
        base_status = _layer_status(
            layer, lc, capture.state, ineligible_reason=ineligible_reason,
            budget_prevented=budget_prevented, budget_capped=budget_capped)
        reached = base_status not in ("not_evaluated", "not_applicable")
        layer_truncated = boundary.truncated and reached

        # A search this layer ran only over a bounded sample or an ambiguous
        # capture cannot close the layer's coverage: its negative is "not found
        # in what was searched", not "not found after a full search". Each
        # reason becomes a structured SCAN_REGION_SEARCH_INCOMPLETE limitation
        # (and a human diagnostic).
        search_incomplete = []
        if reached and overlapping:
            search_incomplete.append("overlapping_capture")
        if reached and layer == "sleep_mask" and lc.window_sampled:
            search_incomplete.append("window_sampled")
        if reached and layer == "sleep_mask" and lc.candidate_cap_hit:
            search_incomplete.append("candidate_list_truncated")
        if reached and layer == "entropy" and windowed is not None \
                and not windowed.exhaustive:
            search_incomplete.append("entropy_window_sampled")

        status = base_status
        if layer_truncated or (search_incomplete and status == "complete"):
            status = "partial"

        truncation_limitation = (
            _targeted.evaluation_truncated_limitation(
                "encoding_scan", layer, boundary.requested_target)
            if layer_truncated else None)
        limitations = _layer_limitations(
            layer, lc, truncation_limitation=truncation_limitation,
            budget_reason=budget_reason, search_incomplete=tuple(search_incomplete))

        diagnostics = []
        if ineligible_reason is not None:
            diagnostics.append(_INAPPLICABLE_NOTES[ineligible_reason].format(layer=layer))
        if layer_truncated:
            diagnostics.append(_targeted.truncation_diagnostic(
                boundary.region_range, requested, eval_range))
        if boundary.sub_region and reached:
            diagnostics.append(_targeted.sub_region_diagnostic(
                boundary.region_range, requested))
        if "overlapping_capture" in search_incomplete:
            diagnostics.append(
                "the dump's segment table maps one or more requested virtual addresses "
                "to multiple file offsets (overlapping segments); the analyzed bytes are "
                "one arbitrary choice among conflicting claims")
        if "window_sampled" in search_incomplete:
            diagnostics.append(
                "the sleep-mask key search sampled a strided subset of windows across "
                "this range (SLEEP_MASK_MAX_WINDOWS); a negative result is not a "
                "full-search negative")
        if "candidate_list_truncated" in search_incomplete:
            diagnostics.append(
                "the sleep-mask recovered-key list was cut at SLEEP_MASK_MAX_CANDIDATES; "
                "a real key ranked below the cap would not have been validated")
        if "entropy_window_sampled" in search_incomplete:
            diagnostics.append(
                f"the entropy scan measured {windowed.windows_evaluated} of this range's "
                f"{windowed.windows_total} windows (ENTROPY_MAX_WINDOWS); a high-entropy "
                f"sub-range between two measured windows would not have been seen")
        if layer == "entropy" and windowed is not None and not ent_result.hits:
            diagnostics.append(
                f"the range averages {windowed.whole_range_entropy:.2f} bits/byte and its "
                f"highest of {windowed.windows_evaluated} measured "
                f"{windowed.window_size:#x}-byte window(s) reaches "
                f"{windowed.max_window.entropy:.2f}, both under the "
                f"{windowed.threshold:.2f} threshold"
                if windowed.max_window is not None else
                f"the range averages {windowed.whole_range_entropy:.2f} bits/byte, under "
                f"the {windowed.threshold:.2f} threshold; it holds no window long enough "
                f"to measure separately")

        budget_outcomes = ()
        if budget_relevant:
            budget_outcomes = (
                BudgetOutcome(name=_BUDGET_NAME, exhausted=bool(after.reason)),)

        measurements = target_context + _layer_measurements(
            layer, lc, reached=reached, read_bytes=read_bytes, sm_result=sm_result,
            ent_result=ent_result, dec_result=dec_result, windowed=windowed,
            budget=budget, budget_relevant=budget_relevant,
            budget_before=before, budget_after=after, budget_reason=budget_reason,
            xor_applied=containing.type == "MEM_PRIVATE")

        closures.append(ObservationClosure(
            source="encoding_scan", scope=layer, coverage_status=status,
            capture_state=capture.state, captured_bytes=capture.captured_bytes,
            read_slice=read_slice if reached else None,
            applicability_reason=ineligible_reason if status == "not_applicable" else None,
            limitations=limitations, budget_outcomes=budget_outcomes,
            measurements=measurements, diagnostics=tuple(diagnostics)))

    payload = TargetedEncodingEvidence(
        sleep_mask=sm_result, entropy=ent_result, decode=dec_result,
        containing_region=boundary.containing_target, windowed_entropy=windowed)
    return ObservationResult(key=key, closures=tuple(closures), payload=payload)


def project_targeted_report(context, result):
    """The :class:`~dumpex.hunt.encoding.domain.EncodingReport` behind one
    targeted rescan's :class:`~dumpex.output.records.HunterRecord`.

    All three layers' own hits and per-layer coverage are fed to the SAME
    ``aggregate.build_report`` full scope uses, so a targeted verdict is
    scored and classified by one authority rather than a parallel
    targeted-only rule. The shared decode/sleep-mask budget is read back off
    the invocation's ledger, so a budget the rescan actually spent is reported
    as spent.

    ``region_count`` is 1 for a rescan whose containing region resolved and 0
    otherwise: a targeted request is exactly one region-shaped scan unit, never
    the dump's region roster. The record's document-level coverage is rebuilt
    from the observation's per-layer closures (see
    :mod:`dumpex.hunt._targeted_record`).
    """
    payload = result.payload
    if payload is None:
        return _encoding.build_report(
            (), (), (), (), (), memory_info_stream=False, region_count=0,
            any_region_scanned=False)
    sm_cov, ent_cov, dec_cov = (payload.sleep_mask.coverage, payload.entropy.coverage,
                                payload.decode.coverage)
    budget = context.budgets.get(_BUDGET_NAME) if _BUDGET_NAME in context.budgets else None
    return _encoding.build_report(
        tuple(payload.sleep_mask.hits), tuple(payload.entropy.hits),
        tuple(payload.decode.base64), tuple(payload.decode.xor),
        tuple(payload.decode.compressed),
        memory_info_stream=True, region_count=1,
        any_region_scanned=bool(sm_cov.scanned or ent_cov.scanned or dec_cov.scanned),
        sleep_mask_oversized=tuple(sm_cov.skipped_oversize_targets),
        entropy_oversized=tuple(ent_cov.skipped_oversize_targets),
        decode_oversized=tuple(dec_cov.skipped_oversize_targets),
        sleep_mask_read_failed=tuple(sm_cov.read_failed_targets),
        entropy_read_failed=tuple(ent_cov.read_failed_targets),
        decode_read_failed=tuple(dec_cov.read_failed_targets),
        sleep_mask_short_read=tuple(sm_cov.short_read_targets),
        entropy_short_read=tuple(ent_cov.short_read_targets),
        decode_short_read=tuple(dec_cov.short_read_targets),
        budget_exhausted=bool(budget is not None and budget.exhausted()),
        exhausted_reason=(budget.exhausted_reason if budget is not None else ""),
        sleep_mask_unaccounted=sm_cov.unaccounted, entropy_unaccounted=ent_cov.unaccounted,
        decode_unaccounted=dec_cov.unaccounted,
        sleep_mask_over_accounted=sm_cov.over_accounted,
        entropy_over_accounted=ent_cov.over_accounted,
        decode_over_accounted=dec_cov.over_accounted,
        sleep_mask_imbalance=sm_cov.ledger_imbalance,
        entropy_imbalance=ent_cov.ledger_imbalance,
        decode_imbalance=dec_cov.ledger_imbalance)

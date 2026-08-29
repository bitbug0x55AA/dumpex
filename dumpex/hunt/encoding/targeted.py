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

The result is one :class:`~dumpex.hunt._observation.ObservationResult` with an
independent :class:`~dumpex.hunt._observation.ObservationClosure` per layer, in
the fixed order ``sleep_mask``, ``entropy``, ``decode``, and a
:class:`TargetedEncodingEvidence` payload carrying each layer's own
``LayerResult`` / ``DecodeResult`` (recovered keys, decoded payloads, hit VAs,
entropy values) plus the containing-region :class:`~dumpex.output.coverage.ScanTarget`.
One layer's negative or gap never changes another layer's closure.
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

from dumpex.hunt.encoding.config import EncodingConfig
from dumpex.hunt.encoding.models import DecodeResult, LayerResult
from dumpex.hunt.encoding.sleep_mask import _scan_sleep_mask
from dumpex.hunt.encoding.entropy import _scan_entropy
from dumpex.hunt.encoding.decoding import _is_system_dll, scan_decode_layers

__all__ = [
    "run_targeted_encoding", "TargetedEncodingEvidence", "TargetedEncodingError",
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
    licensed."""
    sleep_mask: LayerResult
    entropy: LayerResult
    decode: DecodeResult
    containing_region: object


def _base_config() -> EncodingConfig:
    """Every ``encoding.*`` tunable at its full-scope value, read through the
    ``dumpex.hunt.encoding`` module globals -- the same re-exported,
    monkeypatchable seam ``_build_encoding_report`` reads, so an override of
    ``dumpex.hunt.encoding.<CONST>`` moves full-scope and targeted together."""
    e = _encoding
    return EncodingConfig(
        entropy_private_threshold=e.ENTROPY_PRIVATE_THRESHOLD,
        entropy_rwx_threshold=e.ENTROPY_RWX_THRESHOLD, entropy_scan_max=e.ENTROPY_SCAN_MAX,
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


def _budget_reason(budget: ScanBudget) -> "str | None":
    """``budget.exhausted_reason``, forcing a deadline re-check first so a
    just-expired deadline is visible even to a layer that never polled."""
    budget.exhausted()
    return budget.exhausted_reason or None


def _budget_layer_eligible(layer: str, region, base_address: int, size: int,
                           modules) -> bool:
    """A cheap mirror of a budget-using layer scanner's own
    descriptor-eligibility gate. Used only to decide whether a spent shared
    budget actually *prevented* this layer, or the layer would never have
    applied to this region regardless -- a false ``SCAN_BUDGET_EXHAUSTED`` on a
    structurally-ineligible layer would imply a bigger-budget rerun could help
    where it never could."""
    if region.state != "MEM_COMMIT":
        return False
    module = addr_to_module(base_address, modules)
    if layer == "sleep_mask":
        return (region.type == "MEM_PRIVATE" and region.protection == "PAGE_READWRITE"
                and module is None
                and size >= _encoding.SLEEP_MASK_KEY_SIZE * _encoding.SLEEP_MASK_MIN_REPEAT)
    if layer == "decode":
        if region.type not in ("MEM_PRIVATE", "MEM_IMAGE"):
            return False
        return not (region.type == "MEM_IMAGE" and _is_system_dll(module))
    return True


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
                  budget_prevented: bool, budget_capped: bool) -> str:
    """This layer's honest ``coverage_status`` before the boundary-truncation
    check the caller applies on top.

    ``not_evaluated`` -- the region never reached the layer's algorithm: its
    eligibility gate filtered it out, the read returned nothing, a spent shared
    budget stopped the layer before it looked, or -- entropy only -- fewer than
    256 bytes were captured.

    Otherwise ``partial`` on any gap -- a short capture, an unreconciled ledger,
    a short read, or the shared budget hitting a cap during the layer -- and
    ``complete`` only when the whole requested range was captured and the layer
    got through all of it.
    """
    if budget_prevented:
        return "not_evaluated"
    if lc.eligible_total == 0:
        return "not_evaluated"
    if lc.read_failed:
        return "not_evaluated"
    if layer == "entropy" and lc.scanned == 0 and lc.not_applicable:
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


def _not_evaluated_result(key, capture_state: CaptureState, note: str,
                          payload=None) -> ObservationResult:
    closures = tuple(
        ObservationClosure(source="encoding_scan", scope=layer,
                           coverage_status="not_evaluated",
                           capture_state=capture_state, diagnostics=(note,))
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
            key, capture.state,
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

    base_cfg = _base_config()
    if _BUDGET_NAME in context.budgets:
        budget = context.budgets.get(_BUDGET_NAME)
    else:
        budget = context.budgets.register(_BUDGET_NAME, _fresh_budget())

    # Per-layer budget attribution: a snapshot of the shared budget's reason
    # before and after each budget-using layer's own call. `before` set means
    # the layer was prevented (the budget was already spent); a reason that
    # only appears in `after` means this layer spent it.
    sm_before = _budget_reason(budget)
    sm_result = _scan_sleep_mask(
        [synthetic], modules, mf, _reader,
        dataclasses.replace(base_cfg, sleep_mask_region_max=_CAP_BYPASS),
        budget, susp_prots=susp_prots)
    sm_after = _budget_reason(budget)

    ent_result = _scan_entropy(
        [synthetic], modules, mf, susp_prots, _reader,
        dataclasses.replace(base_cfg, entropy_scan_max=_CAP_BYPASS))

    dec_before = _budget_reason(budget)
    dec_result = scan_decode_layers(
        [synthetic], modules, mf, _reader,
        dataclasses.replace(base_cfg, decode_scan_max=_CAP_BYPASS, xor_scan_max=_CAP_BYPASS),
        budget, susp_prots=susp_prots)
    dec_after = _budget_reason(budget)

    layers = {
        "sleep_mask": (sm_result.coverage, sm_before, sm_after),
        "entropy": (ent_result.coverage, None, None),
        "decode": (dec_result.coverage, dec_before, dec_after),
    }

    # The dump's segment table places one or more requested addresses at more
    # than one file offset -- the bytes every layer analyzed are one arbitrary
    # choice among conflicting claims, so no layer's negative is authoritative.
    overlapping = capture.overlapping

    closures = []
    for layer in TARGETED_LAYERS:
        lc, before, after = layers[layer]
        # The shared budget is only this layer's concern when the layer both
        # uses it and would structurally have applied to this region.
        budget_relevant = (
            layer in _BUDGET_USING_LAYERS
            and _budget_layer_eligible(
                layer, containing, eval_range.base_address, eval_range.size, modules))
        budget_prevented = bool(before) and budget_relevant
        budget_capped = not budget_prevented and bool(after) and budget_relevant
        budget_reason = after if (budget_prevented or budget_capped) else None

        # `base_status` is the not-evaluated / partial / complete decision from
        # the capture and budget state alone. Whether this layer reached its
        # algorithm gates whether the descriptor boundary is even this layer's
        # fact: a layer its own eligibility filter excluded was not evaluated,
        # truncated or not.
        base_status = _layer_status(
            layer, lc, capture.state,
            budget_prevented=budget_prevented, budget_capped=budget_capped)
        reached = base_status != "not_evaluated"
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

        budget_outcomes = ()
        if budget_relevant:
            budget_outcomes = (BudgetOutcome(name=_BUDGET_NAME, exhausted=bool(after)),)

        closures.append(ObservationClosure(
            source="encoding_scan", scope=layer, coverage_status=status,
            capture_state=capture.state,
            read_slice=read_slice if status != "not_evaluated" else None,
            limitations=limitations, budget_outcomes=budget_outcomes,
            diagnostics=tuple(diagnostics)))

    payload = TargetedEncodingEvidence(
        sleep_mask=sm_result, entropy=ent_result, decode=dec_result,
        containing_region=boundary.containing_target)
    return ObservationResult(key=key, closures=tuple(closures), payload=payload)

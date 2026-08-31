"""
Layer 1 of dumpex.hunt.encoding — Shannon entropy scan.

Returns a LayerResult, never prints, never decides score/status — see
dumpex/hunt/encoding/models.py and dumpex/hunt/encoding/aggregate.py.

Two measurements of the same bytes live here. `_scan_entropy` computes one
Shannon value per eligible region, which is that region's average.
`scan_entropy_windows` additionally measures fixed, non-overlapping windows
across one range: an average over a sparse allocation is dominated by its
zero-filled majority, so a bounded encrypted payload inside a mostly-empty
multi-megabyte region sits below the threshold as one number and above it as
its own window. The window pass is what names the sub-range an investigator can
extract. Both are observations; neither scores.
"""
import math
from collections import Counter
from dataclasses import dataclass

from dumpex.core.memory import addr_to_module, prot_str, va_range_captured_bytes
from dumpex.hunt._coverage import CoverageTracker, region_scan_target
from dumpex.hunt._location import resolve_location
from dumpex.hunt.encoding.config import (
    EncodingConfig, ENTROPY_PRIVATE_THRESHOLD, ENTROPY_RWX_THRESHOLD, ENTROPY_SCAN_MAX,
    ENTROPY_MIN_INPUT,
)
from dumpex.hunt.encoding.models import EntropyHit, LayerCoverage, LayerResult, region_ref

__all__ = [
    "EntropyWindow", "WindowedEntropy", "scan_entropy_windows",
    "entropy_region_ineligible_reason", "entropy_threshold_for",
    "scan_entropy_targeted",
]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    # `+ 0.0` normalizes the -0.0 the negated sum produces for a single-symbol
    # input: a zero-filled window measures zero entropy, not negative zero.
    return -sum(c / n * math.log2(c / n) for c in counts.values()) + 0.0


def entropy_region_ineligible_reason(region, modules) -> "str | None":
    """Why this layer's descriptor-eligibility gate declines ``region``, or
    ``None`` when it accepts it.

    One statement of the gate `_scan_entropy`'s loop applies, in the vocabulary
    ``LimitationCode.TARGETED_SOURCE_NOT_APPLICABLE`` renders, so a targeted
    closure can name the filter that declined the target rather than only
    report that something did. ``region`` is a raw ``MemoryInfo``-shaped view
    (``State`` / ``Type`` / ``BaseAddress``)."""
    if prot_str(region.State) != 'MEM_COMMIT':
        return "region_not_committed"
    if prot_str(region.Type) != 'MEM_PRIVATE':
        return "region_type_ineligible"
    if addr_to_module(region.BaseAddress, modules):
        return "region_module_backed"
    return None


def entropy_threshold_for(ref, config: EncodingConfig) -> float:
    """The threshold this layer applies to ``ref`` -- the lower RWX bar for a
    region whose protection matches the rules-derived suspicious set, the
    private bar otherwise. Read off an already-resolved ``RegionRef`` so the
    scan and anything reporting on it pick the same number."""
    return config.entropy_rwx_threshold if ref.is_rwx else config.entropy_private_threshold


@dataclass(frozen=True)
class EntropyWindow:
    """One measured window: where it starts, how many bytes it covers, and the
    Shannon value over exactly those bytes."""
    base_address: int
    size: int
    entropy: float


@dataclass(frozen=True)
class WindowedEntropy:
    """What one range's window pass measured -- retained whether or not any
    window crossed the threshold, because "measured 512 windows, highest 3.1"
    and "did not measure" are different answers to the same question.

    ``whole_range_entropy`` is the single average over every byte handed to the
    pass, the value a non-windowed scan reports. ``windows_total`` is how many
    windows the range holds and ``windows_evaluated`` how many were actually
    measured; when the second is smaller the pass strided a sample and
    ``exhaustive`` is ``False``, so a window between two measured ones could
    hold a payload nobody looked at. ``top_windows`` is bounded and ordered by
    descending entropy then ascending address, so its first entry is the
    range's maximum."""
    whole_range_entropy: float
    threshold: float
    window_size: int
    windows_total: int
    windows_evaluated: int
    windows_above_threshold: int
    exhaustive: bool
    top_windows: tuple = ()

    def __post_init__(self):
        object.__setattr__(self, "top_windows", tuple(self.top_windows))

    @property
    def max_window(self) -> "EntropyWindow | None":
        """The highest-entropy window measured, or ``None`` when none was."""
        return self.top_windows[0] if self.top_windows else None


def _window_spans(length: int, base_address: int, window_size: int,
                  max_windows: int, min_input: int):
    """``(spans, windows_total, exhaustive)`` for a virtual-address range.

    Each ``span`` is ``(offset, size)``. Windows are fixed-size,
    non-overlapping, and aligned to absolute virtual-address boundaries rather
    than to offset zero: a request that starts or ends within a window therefore
    has a partial edge span. An edge below ``min_input`` is not measured because
    a Shannon value over so few bytes says nothing.

    Past ``max_windows`` the spans are selected with a deterministic stride
    rather than truncated, so a sampled pass still crosses the whole range
    instead of stopping part-way through it.
    """
    if length < min_input or window_size <= 0 or max_windows <= 0:
        return (), 0, True

    spans = []
    offset = 0
    first_size = window_size - (base_address % window_size)
    while offset < length:
        size = min(first_size if offset == 0 else window_size, length - offset)
        if size >= min_input:
            spans.append((offset, size))
        offset += size

    total = len(spans)
    if total <= 0:
        return (), 0, True
    if total <= max_windows:
        return tuple(spans), total, True
    step = (total + max_windows - 1) // max_windows
    return tuple(spans[i] for i in range(0, total, step)), total, False


def scan_entropy_windows(data: bytes, base_address: int, threshold: float,
                         config: EncodingConfig) -> WindowedEntropy:
    """Measure ``data`` (mapped at ``base_address``) both as one value and as
    bounded windows. Pure: no dump access, no coverage ledger, no hits."""
    whole = _shannon_entropy(data)
    spans, total, exhaustive = _window_spans(
        len(data), base_address, config.entropy_window_size, config.entropy_max_windows,
        config.entropy_min_input)
    measured = []
    above = 0
    for offset, size in spans:
        chunk = data[offset:offset + size]
        value = _shannon_entropy(chunk)
        if value >= threshold:
            above += 1
        measured.append(EntropyWindow(base_address=base_address + offset,
                                      size=len(chunk), entropy=value))
    # Descending value, then ascending address: two windows of equal entropy
    # rank in address order, so the same bytes always produce the same list.
    measured.sort(key=lambda w: (-w.entropy, w.base_address))
    return WindowedEntropy(
        whole_range_entropy=whole, threshold=threshold,
        window_size=config.entropy_window_size, windows_total=total,
        windows_evaluated=len(spans), windows_above_threshold=above,
        exhaustive=exhaustive,
        top_windows=tuple(measured[:config.entropy_top_windows]))


def _scan_entropy(regions, modules, mf, susp_prots, read_region, config: EncodingConfig = None) -> LayerResult:
    """
    `read_region` and `config` are passed in explicitly (rather than
    imported/read here) because dumpex.hunt.encoding's tests monkeypatch
    `encoding.read_region`/`encoding.ENTROPY_*` directly; _hunt_encoding
    passes its own (possibly-patched) module-level values through on
    every call. `config=None` defaults to this module's own constants,
    so this remains directly callable standalone.
    """
    if config is None:
        config = EncodingConfig(entropy_private_threshold=ENTROPY_PRIVATE_THRESHOLD,
                                 entropy_rwx_threshold=ENTROPY_RWX_THRESHOLD,
                                 entropy_scan_max=ENTROPY_SCAN_MAX)
    hits = []
    coverage = CoverageTracker()
    for r in regions:
        if entropy_region_ineligible_reason(r, modules) is not None:
            continue
        if r.RegionSize <= 0:
            # A zero-length region has nothing to read and no bytes anyone
            # could miss: a filter, not a coverage gap. It is also not
            # something a ScanTarget can identify -- a target has an
            # extent by definition.
            continue
        # Past every filter: this region is IN SCOPE, so every path out of
        # the iteration from here on owes the ledger a disposition.
        coverage.note_eligible(va_range_captured_bytes(mf, r.BaseAddress, r.RegionSize))
        if r.RegionSize > config.entropy_scan_max:
            coverage.note_skipped_oversize(
                region_scan_target(mf, r, config.entropy_scan_max))
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage.note_read_failed(region_scan_target(mf, r))
            continue
        if not data:
            # Nothing came back at all: no prefix to scan, so this is a
            # failed read rather than a short one -- a short read is an
            # ANNOTATION on a region that WAS scanned.
            coverage.note_read_failed(region_scan_target(mf, r))
            continue
        if len(data) < r.RegionSize:
            coverage.note_short_read(region_scan_target(mf, r))
        if len(data) < ENTROPY_MIN_INPUT:
            # Read fine, just too little data for a meaningful Shannon
            # entropy -- an outcome, not a gap.
            coverage.note_not_applicable()
            continue
        coverage.note_scanned()

        ent = _shannon_entropy(data)
        ref = region_ref(r, susp_prots)
        threshold = entropy_threshold_for(ref, config)

        if ent >= threshold:
            location = resolve_location(mf, r.BaseAddress, r.BaseAddress, r.RegionSize)
            hits.append(EntropyHit(region=ref, location=location, entropy=ent, threshold=threshold))
    return LayerResult(hits=hits, coverage=LayerCoverage.from_tracker(coverage))


def scan_entropy_targeted(regions, modules, mf, susp_prots, read_region,
                          config: EncodingConfig):
    """The entropy layer over one investigator-selected range, measured in
    windows. Returns ``(LayerResult, WindowedEntropy | None)``.

    The eligibility gate, the coverage ledger, and every disposition are
    `_scan_entropy`'s -- what differs is which values are computed and which
    become hits. The whole-range average is still measured and still decides a
    whole-range hit, so a range that would flag full-scope flags here too. When
    it stays under the threshold, the above-threshold windows do: that is the
    case a single average hides, and the bounded sub-range is the thing an
    investigator extracts. The two are mutually exclusive, so one high-entropy
    range never reports both itself and its own parts.

    ``WindowedEntropy`` is ``None`` when no region reached the window pass; it
    is the last region's when several did, which a targeted request -- exactly
    one synthetic region -- never produces.
    """
    hits = []
    coverage = CoverageTracker()
    windowed = None
    for r in regions:
        if entropy_region_ineligible_reason(r, modules) is not None:
            continue
        if r.RegionSize <= 0:
            continue
        # Past every filter: this region is IN SCOPE, so every path out of
        # the iteration from here on owes the ledger a disposition.
        coverage.note_eligible(va_range_captured_bytes(mf, r.BaseAddress, r.RegionSize))
        if r.RegionSize > config.entropy_scan_max:
            coverage.note_skipped_oversize(
                region_scan_target(mf, r, config.entropy_scan_max))
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage.note_read_failed(region_scan_target(mf, r))
            continue
        if not data:
            # Nothing came back at all: no prefix to measure, so this is a
            # failed read rather than a short one -- a short read is an
            # ANNOTATION on a region that WAS scanned.
            coverage.note_read_failed(region_scan_target(mf, r))
            continue
        if len(data) < r.RegionSize:
            coverage.note_short_read(region_scan_target(mf, r))
        if len(data) < config.entropy_min_input:
            # Read fine, just too little data for a meaningful Shannon
            # entropy -- an outcome, not a gap.
            coverage.note_not_applicable()
            continue
        coverage.note_scanned()

        ref = region_ref(r, susp_prots)
        threshold = entropy_threshold_for(ref, config)
        windowed = scan_entropy_windows(data, r.BaseAddress, threshold, config)
        if windowed.whole_range_entropy >= threshold:
            hits.append(EntropyHit(
                region=ref,
                location=resolve_location(mf, r.BaseAddress, r.BaseAddress, r.RegionSize),
                entropy=windowed.whole_range_entropy, threshold=threshold))
            continue
        # `top_windows` is ordered by descending entropy, so the first window
        # under the threshold ends the above-threshold run.
        for window in windowed.top_windows:
            if window.entropy < threshold:
                break
            hits.append(EntropyHit(
                region=ref,
                location=resolve_location(mf, window.base_address, r.BaseAddress,
                                          r.RegionSize),
                entropy=window.entropy, threshold=threshold, size=window.size))
    return LayerResult(hits=hits, coverage=LayerCoverage.from_tracker(coverage)), windowed

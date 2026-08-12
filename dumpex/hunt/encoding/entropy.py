"""
Layer 1 of dumpex.hunt.encoding — Shannon entropy scan.

Returns a LayerResult, never prints, never decides score/status — see
dumpex/hunt/encoding/models.py and dumpex/hunt/encoding/aggregate.py.
"""
import math
from collections import Counter

from dumpex.core.memory import addr_to_module, prot_str
from dumpex.hunt._coverage import CoverageTracker, region_scan_target
from dumpex.hunt._location import resolve_location
from dumpex.hunt.encoding.config import (
    EncodingConfig, ENTROPY_PRIVATE_THRESHOLD, ENTROPY_RWX_THRESHOLD, ENTROPY_SCAN_MAX,
)
from dumpex.hunt.encoding.models import EntropyHit, LayerCoverage, LayerResult, region_ref


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


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
        if prot_str(r.State) != 'MEM_COMMIT':
            continue
        if prot_str(r.Type) != 'MEM_PRIVATE':
            continue
        if addr_to_module(r.BaseAddress, modules):
            continue
        if r.RegionSize > config.entropy_scan_max:
            coverage.note_skipped_oversize(
                region_scan_target(mf, r, config.entropy_scan_max))
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage.note_read_failed(region_scan_target(mf, r))
            continue
        if len(data) < r.RegionSize:
            coverage.note_short_read(region_scan_target(mf, r))
            if not data:
                continue
        if len(data) < 256:
            continue
        coverage.note_scanned()

        ent = _shannon_entropy(data)
        ref = region_ref(r, susp_prots)
        threshold = config.entropy_rwx_threshold if ref.is_rwx else config.entropy_private_threshold

        if ent >= threshold:
            location = resolve_location(mf, r.BaseAddress, r.BaseAddress, r.RegionSize)
            hits.append(EntropyHit(region=ref, location=location, entropy=ent, threshold=threshold))
    return LayerResult(hits=hits, coverage=LayerCoverage.from_tracker(coverage))

"""
Layer 1 of dumpex.hunt.encoding — Shannon entropy scan.

Split out of encoding.py verbatim (see the package-split notes in
dumpex/hunt/encoding.py's own docstring) — no behavior change. Imported
back into dumpex.hunt.encoding, which is still the only public entry
point (_hunt_encoding).
"""
import math
from collections import Counter

from dumpex.core.memory import addr_to_module, prot_str
from dumpex.hunt._coverage import CoverageTracker
from dumpex.hunt._encoding.config import EncodingConfig

ENTROPY_PRIVATE_THRESHOLD = 7.2   # MEM_PRIVATE: likely encrypted / packed
ENTROPY_RWX_THRESHOLD     = 6.5   # MEM_PRIVATE + RWX: lower bar (combo is critical)
ENTROPY_SCAN_MAX          = 10 * 1024 * 1024   # entropy scan: skip regions > 10 MB


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _scan_entropy(regions, modules, mf, susp_prots, read_region, config: EncodingConfig = None):
    """Returns (hits, coverage) — see _scan_sleep_mask for the CoverageTracker shape.

    `read_region` and `config` are passed in explicitly (rather than
    imported/read here) because dumpex.hunt.encoding's tests monkeypatch
    `encoding.read_region`/`encoding.ENTROPY_*` directly; _hunt_encoding
    passes its own (possibly-patched) module-level values through on
    every call, so this function always sees whatever the caller
    currently has bound rather than this module's own separate constants
    (see dumpex/hunt/_encoding/config.py for why re-exporting alone isn't
    enough). `config=None` defaults to this module's own constants, so
    this remains directly callable exactly as before.
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
            coverage.note_skipped_oversize()
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage.note_read_failed()
            continue
        if len(data) < r.RegionSize:
            coverage.note_short_read()
            if not data:
                continue
        if len(data) < 256:
            continue
        coverage.note_scanned()

        ent = _shannon_entropy(data)
        p      = prot_str(r.Protect)
        is_rwx = any(s in p for s in susp_prots)
        threshold = config.entropy_rwx_threshold if is_rwx else config.entropy_private_threshold

        if ent >= threshold:
            hits.append((r, ent, threshold))
    return hits, coverage

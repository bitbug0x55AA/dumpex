"""Internal data-transfer objects for the stomping scan/correlation
pipeline. Not the public JSON shape -- aggregate.py reads these to build
the `findings` dict, unchanged in shape from before this package split.
"""
from dataclasses import dataclass, field

from dumpex.hunt._coverage import CoverageTracker


@dataclass
class VerifiedChangeCandidate:
    """One eligible section's raw on-disk-vs-memory diff result, before
    RIP correlation and display truncation are applied (see
    correlation.py / aggregate.py)."""
    module: object
    section: dict
    va_start: int
    all_ranges: list              # every diff range, up to MAX_DIFF_RANGES_SCAN
    ranges_truncated_by_scan: bool
    compared_len: int
    disk_sha256: str
    mem_sha256: str


@dataclass
class StompingScan:
    """Everything the module/section walk (memory_scan.py + disk_reference.py,
    orchestrated by __init__.py) collected."""
    protection_leads: list = field(default_factory=list)
    verified_candidates: list = field(default_factory=list)   # list[VerifiedChangeCandidate]
    identity_skipped: list = field(default_factory=list)      # (module, section, reason)
    parse_failed: list = field(default_factory=list)          # (module, pe)
    read_failed: int = 0
    coverage_counts: dict = field(default_factory=dict)


@dataclass
class IocScan:
    """Result of memory_scan.scan_ioc_strings -- the unscored, informational
    IOC-string lead scan over executable MEM_IMAGE regions.

    `coverage` is the shared dumpex.hunt._coverage.CoverageTracker rather
    than this scan's own bespoke counters: its gaps genuinely ARE just
    "region over the size cap / read failed" (exactly the generic shape
    that tracker documents itself as the right fit for), and going through
    it is what makes an oversized skip carry the region's own identity
    (skipped_oversize_targets -> dumpex.output.coverage.ScanTarget) instead
    of a bare tally nobody can act on. A skipped region that isn't
    RECORDED is a region an analyst never learns to go re-scan, while the
    console check line can still read "CLEAN — no IOC patterns in
    executable module memory"."""
    ioc_hits: list = field(default_factory=list)          # (region, module, hits, not_whitelisted)
    skipped_wl: list = field(default_factory=list)
    weak_only_skipped: list = field(default_factory=list)
    coverage: CoverageTracker = field(default_factory=CoverageTracker)

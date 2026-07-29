"""Internal data-transfer objects for the injection scan/correlation
pipeline. Not the public JSON shape -- aggregate.py reads these to build
the `findings` dict, unchanged in shape from before this package split
(see aggregate.py's own docstring for why raw Region objects are kept
as-is there rather than converted to plain dicts)."""
from dataclasses import dataclass, field


@dataclass
class HiddenPeScan:
    """Result of memory_scan.hunt_hidden_pe: every MZ-prefixed candidate
    region, plus how many regions could not be fully examined."""
    hits: list              # [{"region", "in_module_list", "pe"}, ...]
    read_failed: int = 0
    short_reads: int = 0


@dataclass
class Correlation:
    """Everything correlation.py derived from the raw scan results:
    allocation-based structural correlation plus live-execution (RIP/EIP)
    and StartAddress correlation."""
    rwx_by_alloc: dict = field(default_factory=dict)
    pe_by_alloc: dict = field(default_factory=dict)
    rwx_and_pe_alloc_bases: set = field(default_factory=set)
    suspicious_alloc_bases: set = field(default_factory=set)
    rip_hits: list = field(default_factory=list)              # [(thread_ctx, region), ...]
    rip_full_correlation: list = field(default_factory=list)  # subset of rip_hits
    start_hits: list = field(default_factory=list)             # [(thread_info, region), ...]

"""Internal data-transfer objects for the pipe scan/correlation pipeline.
Not the public JSON shape -- aggregate.py reads these to build the
`findings` dict, unchanged in shape from before this package split.
"""
from dataclasses import dataclass, field


@dataclass
class HandleScan:
    """Result of handle_scan.scan_handles: HandleDataStream entries that
    look like open pipe handles, classified by canonical name and
    known-framework naming convention."""
    handle_pipe_hits: list = field(default_factory=list)
    handle_classified: list = field(default_factory=list)     # [{"handle", "canonical_name", "framework_match"}]
    framework_handle_hits: list = field(default_factory=list)


@dataclass
class PipeNameScan:
    """Result of memory_scan.scan_pipe_names: every '\\pipe\\' string
    occurrence found via byte-pattern scan, plus the C2-context records
    gathered from the SAME regions, and the two independent budgets that
    bounded the walk."""
    private_pipes: list = field(default_factory=list)
    image_pipes: list = field(default_factory=list)
    region_c2_records: dict = field(default_factory=dict)     # region.BaseAddress -> [records]
    coverage_counts: object = None      # dumpex.hunt._coverage.CoverageTracker
    pipe_name_budget: object = None     # dumpex.hunt._budget.ScanBudget
    c2_budget: object = None            # dumpex.hunt._budget.ScanBudget


@dataclass
class CorrelationResult:
    """Everything correlation.py derived by relating HandleScan and
    PipeNameScan facts to each other and to thread state."""
    c2_hits: list = field(default_factory=list)                  # [(region, pipe_name, records), ...]
    corroborated_handles: list = field(default_factory=list)     # [{"hc","string_hit","pipe_va","nearby_c2","rip_hit"}]
    start_addr_leads: list = field(default_factory=list)         # [{"hc","string_hit","pipe_va","thread_info"}]
    framework_string_hits: list = field(default_factory=list)    # [(region, name, framework, technique, mitre), ...]
    unbacked_in_pipe_rgn: list = field(default_factory=list)     # [(thread_info, region), ...]

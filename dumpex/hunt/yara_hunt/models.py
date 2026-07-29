"""Internal data-transfer objects for the YARA scan/aggregate pipeline.
Not the public JSON shape -- aggregate.py reads these to build the
`findings` dict, unchanged in shape from before this package split.
"""
from dataclasses import dataclass, field


@dataclass
class RuleBundle:
    """Result of compiling every .yar/.yara file in a rules directory,
    plus reproducible content provenance for the exact files used (see
    dumpex/hunt/yara_hunt/__init__.py's get_yara_provenance())."""
    rule_files: list = field(default_factory=list)   # [(filename, compiled_rules), ...]
    compile_failed: int = 0
    provenance: dict = None


@dataclass
class ScanOutcome:
    """Everything scanner.py learned from walking every memory segment
    against every compiled rule file."""
    all_hits: list = field(default_factory=list)
    scanned: int = 0
    skipped: int = 0
    read_failed: int = 0
    short_reads: int = 0
    timed_out: int = 0
    match_failed: int = 0
    truncated: bool = False
    budget_exhausted: bool = False
    total_bytes_scanned: int = 0
    suppressed_module_pe: int = 0
    suppressed_scoped: int = 0
    context_unverified: int = 0
    triggered_rules: set = field(default_factory=set)
    unverified_rules: set = field(default_factory=set)


@dataclass
class RuleGroup:
    """One rule's hits, deduplicated by segment base VA, plus the display
    facts presentation.py needs -- built once by aggregate.py so it and
    the score/status computation agree on the same grouping."""
    rule_name: str
    file: str
    tags: list
    meta: dict
    seen_vas: dict            # seg_va -> hit
    rule_is_unverified: bool
    unverified_contexts: set = field(default_factory=set)

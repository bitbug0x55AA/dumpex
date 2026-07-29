"""Tunable constants for the YARA memory scanner, and the YaraConfig
bundle that threads them into scanner.py.

YARA_MAX_SEG_SCAN is this hunter's OWN segment-size cap — it no longer
imports CS Beacon's CS_MAX_SEG_SCAN. The two hunters' segment-size limits
are conceptually independent (each hunter should be free to tune its own
cap without silently affecting the other), even though both currently
default to the same 50 MB value.
"""
from dataclasses import dataclass

YARA_MATCH_TIMEOUT      = 30    # seconds, per (segment, rule-file) match() call
YARA_MAX_STRINGS_PER_MATCH = 50 # cap annotated string instances kept per match
YARA_MAX_TOTAL_HITS     = 2000  # hard cap on collected hits across the whole scan
# YARA_MATCH_TIMEOUT only bounds a SINGLE (segment, rule-file) match() call —
# a dump with many segments times many rule files can still run unboundedly
# long even with every individual call finishing well inside 30s. These two
# bound the WHOLE scan loop the same way ScanBudget bounds encoding.py's
# decode loop and CS_MAX_CANDIDATES/CS_SCAN_DEADLINE_SECONDS bound the
# scan loop in dumpex.hunt.cs_beacon: once either is hit, remaining
# segments are treated as an explicit coverage gap (reported, not
# silently dropped), never a false CLEAN.
YARA_SCAN_DEADLINE_SECONDS   = 300          # wall-clock budget for the whole scan loop
YARA_MAX_TOTAL_BYTES_SCANNED = 512 * 1024 * 1024   # cumulative segment bytes read

YARA_MAX_SEG_SCAN = 50 * 1024 * 1024   # skip segments > 50 MB -- this hunter's
                                         # own cap (see module docstring above)


@dataclass(frozen=True)
class YaraConfig:
    match_timeout: int = YARA_MATCH_TIMEOUT
    max_strings_per_match: int = YARA_MAX_STRINGS_PER_MATCH
    max_total_hits: int = YARA_MAX_TOTAL_HITS
    scan_deadline_seconds: float = YARA_SCAN_DEADLINE_SECONDS
    max_total_bytes_scanned: int = YARA_MAX_TOTAL_BYTES_SCANNED
    max_seg_scan: int = YARA_MAX_SEG_SCAN

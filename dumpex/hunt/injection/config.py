"""Tunable constants for the process injection hunter.

The PE_SCAN_* family below all bound ONE thing: the hidden-PE candidate
search (dumpex.hunt.injection.memory_scan). That search reads every
eligible region end to end and looks for the 'MZ' marker at ANY byte
offset (issue #26) rather than only at each region's base address, so it
needs explicit bounds -- a dump is attacker-supplied input, and a region
filled with 'MZ' every other byte must cost a bounded amount of reading,
parsing, and reported evidence rather than whatever that dump asks for.

Every bound is chosen to be a safety net rather than a routine working
limit: one that trips on ordinary dumps would put a coverage caveat on
nearly every run, and a caveat that fires nearly every run stops carrying
information about the runs where something was genuinely missed. Which
bound was reached is never silent -- see HiddenPeScan's own counters and
CoverageSnapshot.complete.
"""

# Bytes read per MZ candidate for structural PE validation — large
# enough for the DOS/COFF/optional headers plus a section table of typical
# size (a handful to a few dozen sections). A candidate whose section table
# extends past this just reports valid=False with a truncation reason
# (parse_pe_header) rather than growing this unboundedly for every
# MZ-prefixed hit in the dump.
PE_VALIDATE_READ_MAX = 4096

# Bytes per bulk discovery read while walking a region for candidates.
# The marker search runs over already-read bytes (bytes.find, ~0.5 ms per
# MB) rather than one read per offset, and those same bytes usually also
# cover the PE_VALIDATE_READ_MAX validation span of any candidate found
# inside them, so a whole 1 MB of region typically costs ONE read.
PE_SCAN_WINDOW = 1024 * 1024

# Read size the search falls back to when a PE_SCAN_WINDOW-sized read
# raises. A minidump's buffered reader raises for a span crossing the end
# of a captured segment while still serving smaller reads inside it, so a
# failed bulk read means "ask for less", not "this region is unreadable".
PE_SCAN_DEGRADED_READ = 0x1000

# Hard cap on read attempts (discovery reads, degraded re-reads, and
# validation reads combined) spent on ANY ONE region -- the bound on a
# malformed RegionSize, and on a region whose reads keep failing.
PE_SCAN_MAX_READS_PER_REGION = 4096

# Whole-hunt cap on bytes actually returned to the candidate search. Sized
# well past the private/mapped memory a real dump carries (a full-memory
# capture of an ordinary process is a fraction of this), so it bounds a
# pathological dump rather than shortening real ones.
PE_SCAN_TOTAL_BYTES_MAX = 2 * 1024 * 1024 * 1024

# Caps on structural VALIDATIONS (one parse_pe_header call per 'MZ' found).
# Benign memory carries roughly 16 incidental 'MZ' per MB, so scanning the
# whole byte budget above costs ~33k validations -- these leave an order of
# magnitude of headroom over that, while still bounding a region crafted to
# carry an 'MZ' every other byte (which would otherwise be ~500k
# validations per MB).
PE_SCAN_MAX_VALIDATIONS_PER_REGION = 50_000
PE_SCAN_MAX_VALIDATIONS_TOTAL = 200_000

# Caps on RETAINED evidence, so the reported finding list (and the JSON
# document built from it) stays bounded no matter how many candidates a
# dump carries. Validated PE headers are kept in preference to unvalidated
# 'MZ' prefixes: the first drive score and correlation, the second are
# informational only (see aggregate.py's own checks), and incidental 'MZ'
# bytes are common enough in ordinary memory that retaining every one of
# them would bury the hits that matter.
PE_SCAN_MAX_VALIDATED_EVIDENCE = 512
PE_SCAN_MAX_UNVALIDATED_EVIDENCE = 64

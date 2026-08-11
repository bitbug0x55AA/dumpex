"""Tunable constants for the process-hollowing hunter.

Deliberately tiny: this hunter has no per-region scan loop and no budget
(every check is anchored on the ONE address the PEB itself reports), so
the only tunables it has are the size of the single header read and how
much of that header a rendered fact quotes. They live here rather than as
literals in `memory_scan.py`/`report_facts.py` for the same reason every
other migrated hunter keeps a `config.py`: a scan-layer read size and a
presentation-layer preview length are different decisions owned by
different layers, and neither should have to import the other's module to
agree on a number.
"""

# Bytes read at the PEB's own image base for the MZ/DOS-header anchor.
# The pre-migration code wrote this as `min(64, 0x1000)` -- a page-size
# clamp that could never actually bind, since 64 < 0x1000 unconditionally.
# Recorded here as the 64 it always was, with the intent (one DOS-header's
# worth of bytes, enough for the magic plus a recognizable prefix) stated
# instead of implied.
MZ_READ_LEN = 64

# Fewer bytes than this back from the read and the MZ magic cannot be
# checked at all -- a SHORT READ (a coverage gap), never evidence that the
# header is missing. Combined with MEM_PRIVATE, treating a short read as a
# wiped header previously reached a false DETECTED.
MZ_MIN_BYTES = 2

# How many leading header bytes a rendered fact/console line quotes. Purely
# a display bound: the whole `MZ_READ_LEN`-byte read is kept on the
# evidence object, and the zero-fill comparison above uses all of it.
HEADER_PREVIEW_BYTES = 8

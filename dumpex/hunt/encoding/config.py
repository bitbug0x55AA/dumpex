"""Resource bounds for encoded-payload scanning.

Per-region limits bound individual reads and decodes; whole-hunt budgets bound
attacker-controlled cumulative bytes, candidates, work, and retained evidence.
Independent limits represent different resources and must report exhaustion as
partial coverage rather than being silently combined.
"""
from dataclasses import dataclass

ENTROPY_PRIVATE_THRESHOLD = 7.2   # MEM_PRIVATE: likely encrypted / packed
ENTROPY_RWX_THRESHOLD     = 6.5   # MEM_PRIVATE + RWX: lower bar (combo is critical)
ENTROPY_SCAN_MAX          = 10 * 1024 * 1024   # entropy scan: skip regions > 10 MB

ENTROPY_MIN_INPUT         = 256                # fewest bytes a Shannon entropy value is
                                                # computed over: below this the sample is
                                                # too small for the value to mean anything

# A single Shannon value over a whole allocation is an average, and an average
# over a sparse region is dominated by its zero-filled majority: a bounded
# encrypted payload inside a mostly-empty multi-megabyte allocation measures
# well below the threshold as one number and well above it as its own window.
# A targeted rescan therefore also measures the range in fixed, non-overlapping
# windows, which is where the sub-range an investigator can act on is named.
ENTROPY_WINDOW_SIZE       = 64 * 1024          # bytes per measured window
ENTROPY_MAX_WINDOWS       = 512                # windows measured per range; past this the
                                                # windows are strided and the coverage is
                                                # reported as sampled rather than exhaustive
ENTROPY_TOP_WINDOWS       = 5                  # highest-entropy windows retained, in
                                                # descending order -- the first is the
                                                # range's maximum

B64_MIN_LEN               = 80                 # minimum Base64 string length

XOR_SCAN_MAX              = 512 * 1024         # max region for single-byte XOR BF
XOR_SAMPLE_SIZE           = 4096               # bytes sampled before full decode (text/
                                                # keyword candidate path only -- see
                                                # XOR_STRUCTURAL_* below for the offset-
                                                # independent structural path that does NOT
                                                # sample)
XOR_SCORE_MIN             = 0.68               # printable ratio to accept a key (text/
                                                # keyword candidate path only)

XOR_STRUCTURAL_WINDOW = 128 * 1024   # bytes decoded per structural PE/shellcode candidate
                                      # once its key is derived directly from a matching
                                      # MZ+PE\0\0 (or shellcode-bootstrap) signature --
                                      # bounds parse_pe_header()'s input regardless of how
                                      # large the eligible region is. A full PE header plus
                                      # up to 96 sections' table needs at most
                                      # e_lfanew(<=0x1000, itself range-checked) + a 16-bit
                                      # optional-header size + 96*40 section-table bytes --
                                      # well under this.
                                      #
                                      # There is deliberately NO separate per-region cap on
                                      # how many structural candidates get decoded+parsed:
                                      # an earlier version had one (XOR_STRUCTURAL_MAX_
                                      # CANDIDATES), but a cap applied while candidates were
                                      # still discovered key-by-key (not offset-by-offset)
                                      # could be exhausted by decoys using low key values
                                      # before a genuine payload under a higher key was ever
                                      # reached -- silently, with 0 hits and no coverage
                                      # signal (dumpex issue #27 follow-up). Candidates are
                                      # now found in a single offset-ordered pass (see
                                      # decoding._xor_derive_pe_candidates /
                                      # _xor_derive_shellcode_candidates) and the actual
                                      # decode+parse attempt is gated solely by the shared,
                                      # whole-hunt ScanBudget's note_attempt() -- which
                                      # already surfaces exhaustion as an explicit
                                      # coverage_status="partial", not a silent drop.

DECOMPRESS_MAX_OUTPUT = 8 * 1024 * 1024   # cap decompressed output per candidate; a small
                                           # compressed blob can expand enormously (zip
                                           # bomb), and input-size limits alone don't bound
                                           # output size — 8MB is far more than needed to
                                           # classify content (PE header, IOC strings, etc).

DECODE_SCAN_MAX = 2 * 1024 * 1024   # Base64 / XOR / GZIP: skip regions > 2 MB

# ── Sleep Mask tunables (mirroring cs-analyze-processdump.py defaults) ────
SLEEP_MASK_KEY_SIZE        = 13        # XOR key length used by default CS sleep mask
SLEEP_MASK_MIN_REPEAT      = 100       # key must repeat ≥ N times to be a candidate
SLEEP_MASK_MAX_BYTE_FREQ   = 3         # reject if any single byte appears ≥ N times
                                        # in the candidate key (monotonic key filter)
SLEEP_MASK_MIN_ACBD        = 20.0      # min average consecutive byte difference
                                        # (rejects keys like 01 02 03 … or 00 00 00)
SLEEP_MASK_MAX_CANDIDATES  = 10        # max candidates to try per region
SLEEP_MASK_REGION_MAX      = 10 * 1024 * 1024   # skip regions > 10 MB
SLEEP_MASK_VALIDATE_SAMPLE = 2 * 1024 * 1024    # streaming chunk size used while
                                        # searching each candidate x rotation
                                        # combination for the validation marker
                                        # across the COMPLETE eligible region (see
                                        # _sm_marker_in_region) -- bounds how much is
                                        # decoded at once, not how much of the region
                                        # is searched. The full-region decode still
                                        # only runs for a combination that actually
                                        # found the marker. Unbounded, up to
                                        # MAX_CANDIDATES x KEY_SIZE x REGION_MAX
                                        # (10 x 13 x 10MB ~= 1.3GB) of XOR work can be
                                        # done per region in the worst case (no early
                                        # match) -- the shared ScanBudget, polled once
                                        # per chunk, is what actually bounds this.
SLEEP_MASK_VALIDATION_MARKER = b'sha256\x00'    # always present in beacon memory
SLEEP_MASK_MAX_WINDOWS      = 200_000  # hard cap on windows counted per region, across
                                        # all key_size alignment offsets. Without this, a
                                        # ~10MB region produces ~10M dict entries (one per
                                        # non-overlapping window) — real sleep-mask keys
                                        # repeat densely enough that even sampling well
                                        # below that still surfaces them as the top
                                        # candidate, so this bounds memory/CPU without
                                        # meaningfully hurting detection.

# Layers 2 (Base64) and 4 (GZIP/ZLIB) share ONE ScanBudget across the whole
# hunt (all regions combined, and now Layer 0 too) rather than each region
# getting its own independent allowance — see dumpex/hunt/_budget.py.
ENCODING_BUDGET_MAX_ATTEMPTS  = 2000              # total decode/decompress
                                                   # attempts, whole hunt
ENCODING_BUDGET_MAX_RETAINED  = 32 * 1024 * 1024  # cumulative decoded bytes
                                                   # kept in findings, whole hunt
ENCODING_BUDGET_MAX_HITS      = 500               # cumulative hits retained
ENCODING_BUDGET_TIME_SECONDS  = 60.0              # wall-clock cap, layers 0 and 2-4 combined


@dataclass(frozen=True)
class EncodingConfig:
    entropy_private_threshold: float = ENTROPY_PRIVATE_THRESHOLD
    entropy_rwx_threshold: float = ENTROPY_RWX_THRESHOLD
    entropy_scan_max: int = ENTROPY_SCAN_MAX
    entropy_min_input: int = ENTROPY_MIN_INPUT
    entropy_window_size: int = ENTROPY_WINDOW_SIZE
    entropy_max_windows: int = ENTROPY_MAX_WINDOWS
    entropy_top_windows: int = ENTROPY_TOP_WINDOWS

    b64_min_len: int = B64_MIN_LEN

    xor_scan_max: int = XOR_SCAN_MAX
    xor_sample_size: int = XOR_SAMPLE_SIZE
    xor_score_min: float = XOR_SCORE_MIN
    xor_structural_window: int = XOR_STRUCTURAL_WINDOW

    decompress_max_output: int = DECOMPRESS_MAX_OUTPUT
    decode_scan_max: int = DECODE_SCAN_MAX

    sleep_mask_key_size: int = SLEEP_MASK_KEY_SIZE
    sleep_mask_min_repeat: int = SLEEP_MASK_MIN_REPEAT
    sleep_mask_max_byte_freq: int = SLEEP_MASK_MAX_BYTE_FREQ
    sleep_mask_min_acbd: float = SLEEP_MASK_MIN_ACBD
    sleep_mask_max_candidates: int = SLEEP_MASK_MAX_CANDIDATES
    sleep_mask_region_max: int = SLEEP_MASK_REGION_MAX
    sleep_mask_validate_sample: int = SLEEP_MASK_VALIDATE_SAMPLE
    sleep_mask_validation_marker: bytes = SLEEP_MASK_VALIDATION_MARKER
    sleep_mask_max_windows: int = SLEEP_MASK_MAX_WINDOWS

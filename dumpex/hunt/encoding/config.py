"""
Single canonical home for every dumpex.hunt.encoding tunable constant, and
the EncodingConfig bundle built from them.

Why constants live HERE and not beside the code that uses them: the
original P2-03 split put each layer's tunables next to that layer's own
implementation (entropy.py owned ENTROPY_*, decoders.py owned
B64_MIN_LEN, etc.), then re-exported them into encoding.py for backward
compatibility. That meant TWO bindings of the same name existed
(encoding.B64_MIN_LEN and decoders.B64_MIN_LEN) -- monkeypatching the
re-exported copy silently stopped affecting the real one, since Python
name rebinding doesn't propagate across modules. Defining every constant
exactly once, here, removes that class of bug structurally: there is no
second copy to fall out of sync.

`dumpex/hunt/encoding/__init__.py` re-exports these (so
`encoding.B64_MIN_LEN = 999` before calling `_hunt_encoding()` still
works -- this IS still a supported override mechanism, unlike private
helper functions' call signatures, which this refactor makes no
compatibility promise about at all). Every layer function takes an
`EncodingConfig` parameter instead of reading a bare module constant
inside its own body; the constants below are used only as those
functions' default parameter values, so they remain directly callable
standalone (as existing unit tests do) without constructing a config.
"""
from dataclasses import dataclass

ENTROPY_PRIVATE_THRESHOLD = 7.2   # MEM_PRIVATE: likely encrypted / packed
ENTROPY_RWX_THRESHOLD     = 6.5   # MEM_PRIVATE + RWX: lower bar (combo is critical)
ENTROPY_SCAN_MAX          = 10 * 1024 * 1024   # entropy scan: skip regions > 10 MB

B64_MIN_LEN               = 80                 # minimum Base64 string length

XOR_SCAN_MAX              = 512 * 1024         # max region for single-byte XOR BF
XOR_SAMPLE_SIZE           = 4096               # bytes sampled before full decode
XOR_SCORE_MIN             = 0.68               # printable ratio to accept a key

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

    b64_min_len: int = B64_MIN_LEN

    xor_scan_max: int = XOR_SCAN_MAX
    xor_sample_size: int = XOR_SAMPLE_SIZE
    xor_score_min: float = XOR_SCORE_MIN

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

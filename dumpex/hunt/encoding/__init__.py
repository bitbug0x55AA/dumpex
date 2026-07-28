"""
Encoded / obfuscated payload hunter.

Detection layers (applied per memory region):

  Layer 0: CS Sleep Mask XOR decode  — frequency-analysis key recovery for
                                       Cobalt Strike beacon memory encoded by
                                       the sleep mask (PAGE_READWRITE private
                                       regions). Adapted from cs-analyze-
                                       processdump.py by Didier Stevens
                                       (public domain, https://DidierStevens.com).
                                       See dumpex/hunt/encoding/sleep_mask.py.

  Layer 1: Shannon entropy scan  — catches all encoding schemes including custom
                                   crypto, RC4, AES blobs, multi-byte XOR, etc.
                                   See dumpex/hunt/encoding/entropy.py.

  Layer 2: Base64 detection      — standard + URL-safe; minimum 80 chars (60
                                   decoded bytes) — see B64_MIN_LEN

  Layer 3: XOR single-byte BF    — MEM_PRIVATE regions ≤ 512 KB only;
                                   sample-first heuristic to avoid O(n×255)
                                   full-region cost

  Layer 4: GZIP / ZLIB           — magic-byte scan + decompress attempt

  (Layers 2-4 share one per-region read pass — see
  dumpex/hunt/encoding/decoding.py's scan_decode_layers.)

All decoded/decompressed content goes through a shared classifier
(dumpex/hunt/encoding/classification.py):
  - MZ + PE\\x00\\x00     → PE payload
  - call-$+5 bootstrap    → likely shellcode
  - printable > 85 %      → IOC string scan (IP / URL / pipe names)
  - else                  → hex prefix reported

Address semantics: every hit reports VA (process) + .dmp file offset,
consistent with the rest of Dumpex.

This is a package, not a single file: each scan layer (sleep_mask,
entropy, decoding) returns standardized data (models.py) and decides
neither score/status/verdict nor prints anything; aggregate.py is the
ONE place score/status/coverage_status/verdict_level/confidence/
lead_count/review_priority get computed; presentation.py is the ONE
place anything gets printed to the console. This __init__.py is the thin
entry point: build config, call the three scan layers, aggregate, print,
return the findings dict.

The stable contract is `_hunt_encoding` itself (imported by
dumpex/hunt/__init__.py): same signature, and the SAME meaning for every
field this hunter has ever guaranteed (status/coverage_status/
verdict_level/confidence/findings/lead_count/review_priority/score).
This is NOT the same claim as "identical JSON output, byte for byte" —
it explicitly is not, as of schema_version 1.1: `hidden_pe`/
`hidden_shellcode`/`sleep_mask`/`entropy`/`base64`/`xor`/`compressed` now
hold a single standardized dict shape (Hit.to_dict()/EntropyHit.to_dict(),
see models.py) instead of the ad hoc, differently-shaped tuples/dicts
each layer used to produce independently. That is a real, intentional
breaking change to those specific fields -- most notably, sleep_mask's
`offset` used to BE the XOR key rotation value; it is now always 0, with
rotation moved to a new `key_offset` field, matching what `offset` means
for every other layer (byte offset within the region). See
dumpex/schemas/dumpex-output-v1.1.schema.json (which formally types these
fields for the first time) and docs/OUTPUT_SCHEMA.md's versioning policy
for the full breaking-change writeup. Tunable constants (B64_MIN_LEN, XOR_*,
ENTROPY_*, SLEEP_MASK_*, ENCODING_BUDGET_*, DECODE_SCAN_MAX,
DECOMPRESS_MAX_OUTPUT) and `read_region` are re-exported here and remain
monkeypatchable (`encoding.B64_MIN_LEN = 999` before calling
`_hunt_encoding()` still changes its behavior — see
dumpex/hunt/encoding/config.py for why that requires a config object
threaded through every layer rather than each layer reading its own
separate copy of the same-named constant). Private per-layer helper
functions (`_scan_sleep_mask`, `_classify_decoded`, `_bounded_decompress`,
etc.) are NOT re-exported here and make no compatibility promise at all
— import them from their actual module
(dumpex.hunt.encoding.sleep_mask/.decoding/.classification/...) if you
need them directly, as this package's own tests do.
"""
import time
from minidump.minidumpfile import MinidumpFile

from dumpex.ui.colors import DIM
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import get_modules, get_memory_regions, read_region
from dumpex.hunt._ui import _print_hunt_header
from dumpex.hunt._budget import ScanBudget

from dumpex.hunt.encoding.config import (
    EncodingConfig,
    ENTROPY_PRIVATE_THRESHOLD, ENTROPY_RWX_THRESHOLD, ENTROPY_SCAN_MAX,
    B64_MIN_LEN, XOR_SCAN_MAX, XOR_SAMPLE_SIZE, XOR_SCORE_MIN,
    DECOMPRESS_MAX_OUTPUT, DECODE_SCAN_MAX,
    SLEEP_MASK_KEY_SIZE, SLEEP_MASK_MIN_REPEAT, SLEEP_MASK_MAX_BYTE_FREQ,
    SLEEP_MASK_MIN_ACBD, SLEEP_MASK_MAX_CANDIDATES, SLEEP_MASK_REGION_MAX,
    SLEEP_MASK_VALIDATE_SAMPLE, SLEEP_MASK_VALIDATION_MARKER, SLEEP_MASK_MAX_WINDOWS,
    ENCODING_BUDGET_MAX_ATTEMPTS, ENCODING_BUDGET_MAX_RETAINED,
    ENCODING_BUDGET_MAX_HITS, ENCODING_BUDGET_TIME_SECONDS,
)
from dumpex.hunt.encoding.sleep_mask import _scan_sleep_mask
from dumpex.hunt.encoding.entropy import _scan_entropy
from dumpex.hunt.encoding.decoding import scan_decode_layers
from dumpex.hunt.encoding.aggregate import build_report
from dumpex.hunt.encoding import presentation


def _hunt_encoding(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Scan process memory for encoded / obfuscated payloads.

    Runs five detection layers (see this package's own docstring above),
    aggregates their results into Finding objects plus score/status/
    coverage (dumpex.hunt.encoding.aggregate), prints the console report
    (dumpex.hunt.encoding.presentation), and returns the findings dict.
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    susp_prots = get_rules()["suspicious_protections"]
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)

    # config bundles every encoding.* tunable, read from THIS module's own
    # (re-exported, and therefore still monkeypatchable) globals -- see
    # dumpex/hunt/encoding/config.py for why layers can't just read their
    # own separate copies of these constants directly.
    config = EncodingConfig(
        entropy_private_threshold=ENTROPY_PRIVATE_THRESHOLD, entropy_rwx_threshold=ENTROPY_RWX_THRESHOLD,
        entropy_scan_max=ENTROPY_SCAN_MAX, b64_min_len=B64_MIN_LEN, xor_scan_max=XOR_SCAN_MAX,
        xor_sample_size=XOR_SAMPLE_SIZE, xor_score_min=XOR_SCORE_MIN,
        decompress_max_output=DECOMPRESS_MAX_OUTPUT, decode_scan_max=DECODE_SCAN_MAX,
        sleep_mask_key_size=SLEEP_MASK_KEY_SIZE, sleep_mask_min_repeat=SLEEP_MASK_MIN_REPEAT,
        sleep_mask_max_byte_freq=SLEEP_MASK_MAX_BYTE_FREQ, sleep_mask_min_acbd=SLEEP_MASK_MIN_ACBD,
        sleep_mask_max_candidates=SLEEP_MASK_MAX_CANDIDATES, sleep_mask_region_max=SLEEP_MASK_REGION_MAX,
        sleep_mask_validate_sample=SLEEP_MASK_VALIDATE_SAMPLE,
        sleep_mask_validation_marker=SLEEP_MASK_VALIDATION_MARKER, sleep_mask_max_windows=SLEEP_MASK_MAX_WINDOWS,
    )

    # One budget shared across the WHOLE hunt, layers 0 and 2-4 alike (see
    # dumpex/hunt/_budget.py) — bounds total decode/decompress attempts and
    # retained bytes, but just as importantly bounds sleep-mask's own
    # candidate-recovery/validation cost: unlike entropy's cheap linear
    # per-region scan, sleep-mask's per-region cost is genuinely large (up
    # to ~130 XOR-over-2MB combinations), so a dump with many qualifying
    # regions could otherwise make Layer 0 run for unbounded total time.
    # Layer 0 only reads exhausted()/poll() (deadline), never
    # note_attempt()/take_hit() — those remain specific to what layers 2-4
    # actually decode/retain.
    decode_budget = ScanBudget(
        max_bytes_read=ENCODING_BUDGET_MAX_RETAINED * 4,
        max_attempts=ENCODING_BUDGET_MAX_ATTEMPTS,
        max_retained_bytes=ENCODING_BUDGET_MAX_RETAINED,
        max_hits=ENCODING_BUDGET_MAX_HITS,
        deadline=time.monotonic() + ENCODING_BUDGET_TIME_SECONDS,
    )

    # Progress announcements print HERE, immediately before each layer
    # actually runs -- not after all three finish (which is what happens
    # if these live in presentation.render() instead, since that's only
    # called once every scan is done). Layer 0 in particular can run for
    # up to ENCODING_BUDGET_TIME_SECONDS (60s): without this, the CLI
    # prints nothing at all for that whole window, indistinguishable from
    # having hung, and if it DOES fail partway through, there is no
    # "currently scanning Layer N" line on screen to say which layer was
    # running when it happened. presentation.py still owns every RESULT
    # line (CLEAN/OBSERVATION/LEAD/DETECTION, the verdict) -- these three
    # lines are the one exception, since they announce work about to
    # start rather than reporting a decision already made.
    _print_hunt_header("Obfuscation Detection")

    print(DIM("  [*] Layer 0: CS Sleep Mask XOR scan (frequency analysis) …"))
    sleep_mask_result = _scan_sleep_mask(regions, modules, mf, read_region, config, decode_budget)

    print(DIM("  [*] Layer 1: Shannon entropy scan …"))
    entropy_result = _scan_entropy(regions, modules, mf, susp_prots, read_region, config)

    print(DIM("  [*] Layers 2-4: Base64 / XOR / GZIP scan …"))
    decode_result = scan_decode_layers(regions, modules, mf, read_region, config, decode_budget)

    report = build_report(mf, verbose, sleep_mask_result, entropy_result, decode_result,
                           modules, regions, susp_prots, mem_info_available, decode_budget)

    presentation.render(mf, verbose, report, susp_prots, modules)

    return report.findings

"""Encoded and obfuscated payload hunter.

Layers cover Cobalt Strike sleep-mask XOR recovery, entropy, Base64, single-byte
XOR, and bounded GZIP/ZLIB decompression. Sleep-mask analysis is adapted from
Didier Stevens' public-domain cs-analyze-processdump.py. Decoded content is
classified as PE, shellcode bootstrap, printable IOC-bearing data, or a hex
preview.

Single-byte XOR uses text heuristics and offset-independent structural search so
binary payloads outside a printable prefix are not missed. Independent layer and
whole-hunt budgets report incomplete scans as partial coverage. Hits retain both
process VA and dump-file offset.
"""
import time
from minidump.minidumpfile import MinidumpFile

from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import get_modules, get_memory_regions, read_region
from dumpex.hunt._budget import ScanBudget

from dumpex.hunt.encoding.config import (
    EncodingConfig,
    ENTROPY_PRIVATE_THRESHOLD, ENTROPY_RWX_THRESHOLD, ENTROPY_SCAN_MAX,
    B64_MIN_LEN, XOR_SCAN_MAX, XOR_SAMPLE_SIZE, XOR_SCORE_MIN,
    XOR_STRUCTURAL_WINDOW,
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
from dumpex.hunt.encoding import report_console, report_legacy


def _build_encoding_report(mf: MinidumpFile):
    """Run the five detection layers and aggregate them into an
    EncodingReport -- the ONE place this pipeline is assembled, shared
    by `_hunt_encoding()` (console path, below) and
    `collect_obfuscation_record()` (the v2.4 migration's HunterRecord-
    producing path). Prints nothing at all. Takes no `verbose` parameter:
    --verbose only ever gates what report_console.py prints from an
    already-built Report's own evidence -- it was never a scan-time or
    aggregation-time decision, so threading it through this function and
    into `build_report()` was dead plumbing.
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    susp_prots = get_rules(announce=False)["suspicious_protections"]
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)

    # config bundles every encoding.* tunable, read from THIS module's own
    # (re-exported, and therefore still monkeypatchable) globals -- see
    # dumpex/hunt/encoding/config.py for why layers can't just read their
    # own separate copies of these constants directly.
    config = EncodingConfig(
        entropy_private_threshold=ENTROPY_PRIVATE_THRESHOLD, entropy_rwx_threshold=ENTROPY_RWX_THRESHOLD,
        entropy_scan_max=ENTROPY_SCAN_MAX, b64_min_len=B64_MIN_LEN, xor_scan_max=XOR_SCAN_MAX,
        xor_sample_size=XOR_SAMPLE_SIZE, xor_score_min=XOR_SCORE_MIN,
        xor_structural_window=XOR_STRUCTURAL_WINDOW,
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

    sleep_mask_result = _scan_sleep_mask(regions, modules, mf, read_region, config, decode_budget,
                                         susp_prots=susp_prots)
    entropy_result = _scan_entropy(regions, modules, mf, susp_prots, read_region, config)
    decode_result = scan_decode_layers(regions, modules, mf, read_region, config, decode_budget,
                                        susp_prots=susp_prots)

    sm_cov, ent_cov, dec_cov = (sleep_mask_result.coverage, entropy_result.coverage,
                                decode_result.coverage)
    report = build_report(
        tuple(sleep_mask_result.hits), tuple(entropy_result.hits),
        tuple(decode_result.base64), tuple(decode_result.xor), tuple(decode_result.compressed),
        memory_info_stream=mem_info_available, region_count=len(regions),
        any_region_scanned=bool(sm_cov.scanned or ent_cov.scanned or dec_cov.scanned),
        sleep_mask_oversized=tuple(sm_cov.skipped_oversize_targets),
        entropy_oversized=tuple(ent_cov.skipped_oversize_targets),
        decode_oversized=tuple(dec_cov.skipped_oversize_targets),
        # issue #28: each layer's own read-failed/short-read targets stay
        # attributed to that layer -- summing them (the pre-fix shape)
        # loses which layer(s) actually need a targeted rescan of a given
        # region, the same reason the three *_oversized tuples above are
        # never summed either.
        sleep_mask_read_failed=tuple(sm_cov.read_failed_targets),
        entropy_read_failed=tuple(ent_cov.read_failed_targets),
        decode_read_failed=tuple(dec_cov.read_failed_targets),
        sleep_mask_short_read=tuple(sm_cov.short_read_targets),
        entropy_short_read=tuple(ent_cov.short_read_targets),
        decode_short_read=tuple(dec_cov.short_read_targets),
        budget_exhausted=decode_budget.exhausted(), exhausted_reason=decode_budget.exhausted_reason,
        # Per layer, like the target tuples above: an unreconciled region
        # is a bug in ONE layer's own loop, and summing the three here
        # would leave the structured limitation unable to name which.
        sleep_mask_unaccounted=sm_cov.unaccounted,
        entropy_unaccounted=ent_cov.unaccounted,
        decode_unaccounted=dec_cov.unaccounted,
        sleep_mask_over_accounted=sm_cov.over_accounted,
        entropy_over_accounted=ent_cov.over_accounted,
        decode_over_accounted=dec_cov.over_accounted,
        sleep_mask_imbalance=sm_cov.ledger_imbalance,
        entropy_imbalance=ent_cov.ledger_imbalance,
        decode_imbalance=dec_cov.ledger_imbalance,
    )
    return report


def _hunt_encoding(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Scan process memory for encoded / obfuscated payloads.

    Runs five detection layers (see `_build_encoding_report()`'s own
    docstring above), aggregates their results into the immutable
    `EncodingReport` (dumpex.hunt.encoding.domain/aggregate), prints the
    verdict-first console report (dumpex.hunt.encoding.report_console),
    and returns the v1.1-shaped legacy findings dict
    (dumpex.hunt.encoding.report_legacy).

    Unlike the pre-migration version, nothing prints before
    `_build_encoding_report()` returns: `report_console.render_console_lines`
    is a pure post-hoc projection of the already-built Report (see that
    module's own docstring on why the old "Layer N: ..." pre-scan
    progress announcements moved into a verbose-only summary block
    instead of printing in real time), mirroring
    dumpex.hunt.injection's own build-once, print-after shape.
    """
    report = _build_encoding_report(mf)
    return _render_encoding_console(report, verbose)


def _render_encoding_console(report, verbose: bool = False) -> dict:
    """Render the console report for an ALREADY-BUILT encoding
    `EncodingReport`, returning the same v1.1-shaped findings dict
    `_hunt_encoding()` always has."""
    report_console.print_console(report, verbose)
    return report_legacy.project_legacy_dict(report)

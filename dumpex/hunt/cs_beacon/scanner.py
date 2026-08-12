"""Segment marker search and the whole-scan budget/coverage loop.

Only collects facts — never scores, never prints. `scan_segments` walks
every captured memory segment, finds structurally-valid (sanity-checked)
beacon configs, and returns a ScanOutcome for context.py/aggregate.py to
interpret. Every resource-budget/coverage-gap rule that existed in the
single-file hunter is preserved here unchanged (see the inline comments
below for why each check is placed where it is).
"""
import time

from dumpex.hunt._coverage import CoverageTracker, segment_scan_target
from dumpex.hunt.cs_beacon.config import CSBeaconConfig
from dumpex.hunt.cs_beacon.models import Candidate, ScanOutcome
from dumpex.hunt.cs_beacon.parser import _cs_decode_and_parse_tlv, _cs_sanity_check
from dumpex.hunt.cs_beacon.config import CS_SIG_XOR69, CS_SIG_XOR2E


def select_segments(mf) -> list:
    """Prefer the 64-bit segment table, falling back to the 32-bit one."""
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        return mf.memory_segments_64.memory_segments
    if mf.memory_segments and mf.memory_segments.memory_segments:
        return mf.memory_segments.memory_segments
    return []


def _cs_scan_segment(data: bytes, seg_va: int, seg_fo: int):
    """
    Locate candidate CS beacon config markers in one memory segment.

    Strategy (from 1768.py AnalyzeEmbeddedPEFileSub): for each XOR key
    (0x69, 0x2e), search for the pre-XOR'd marker bytes.

    A generator, not a list: a segment stuffed with thousands of decoy or
    duplicate marker bytes must not force building (and holding) one giant
    candidate list before the caller gets a chance to enforce the global
    scan budget (config.max_candidates / config.scan_deadline_seconds
    below) — the caller can stop pulling from this generator the moment a
    cap is hit.

    Decoding is deliberately NOT done here — see parser._cs_decode_and_parse_tlv,
    which decodes only as many bytes as a candidate's TLV structure
    actually needs instead of eagerly XOR-decoding (and retaining) a large
    fixed window for every marker match, most of which are never a real
    config.

    Yields (xor_key, offset_in_data, hit_va, hit_file_offset).
    """
    for key, marker in ((0x69, CS_SIG_XOR69), (0x2e, CS_SIG_XOR2E)):
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx == -1:
                break
            yield key, idx, seg_va + idx, seg_fo + idx
            start = idx + 1


def scan_segments(mf, segs: list, config: CSBeaconConfig, monotonic=time.monotonic) -> ScanOutcome:
    """
    Walk every segment in `segs`, applying every whole-scan resource
    budget (deadline, candidate count, decoded bytes, total scanned
    bytes, hit count) exactly as the single-file hunter did. `monotonic`
    is threaded explicitly (not imported directly from `time` in this
    module) so a caller/test can substitute a fake clock without needing
    the global `time.monotonic` to be patched — see dumpex/hunt/_runtime.py.
    """
    coverage_counts = CoverageTracker()
    hits = []
    seen_hit_vas = set()   # O(1) dedup, not an O(n) scan of `hits` per candidate
    reader = mf.get_reader()

    total_candidates    = 0
    total_decoded_bytes = 0
    total_scanned_bytes = 0
    budget_exhausted     = False
    budget_reason         = None
    # The index (into `segs`) of the segment being processed when the
    # whole-scan budget was first exhausted (issue #28 P5 follow-up) --
    # `segs[index:]` (that segment, plus every later one never started at
    # all) becomes CS_BEACON_SCAN_BUDGET_EXHAUSTED's own `targets`, same
    # "segment mid-processing or never-started" shape
    # dumpex.hunt.yara_hunt.scanner uses for its own hit-cap/budget codes.
    budget_exhausted_stop_index = None
    # WHICH of the five independent whole-scan budgets first tripped
    # budget_exhausted (issue #28 P6 follow-up) -- "scan_deadline_seconds"/
    # "max_total_scanned_bytes"/"max_candidates"/"max_decoded_bytes"/
    # "max_hits" -- set once, alongside budget_exhausted_stop_index, by
    # whichever call site fires first (mirrors dumpex.hunt.injection.
    # memory_scan._ScanBudget.last_exhausted_kind).
    budget_exhausted_kind = None
    scan_deadline = monotonic() + config.scan_deadline_seconds

    def _mark_budget_exhausted(reason: str, kind: str, stop_index: "int | None" = None):
        # `stop_index` defaults to the CURRENT segment (still mid-
        # processing, or not started yet) -- overridden to `seg_index + 1`
        # at the one call site where `seg` has already been fully
        # candidate-scanned by the time its own deadline recheck fires
        # (only LATER segments are actually unstarted there).
        nonlocal budget_exhausted, budget_reason, budget_exhausted_stop_index, budget_exhausted_kind
        budget_exhausted = True
        budget_reason = reason
        if budget_exhausted_stop_index is None:
            budget_exhausted_stop_index = seg_index if stop_index is None else stop_index
            budget_exhausted_kind = kind

    for seg_index, seg in enumerate(segs):
        if budget_exhausted:
            break
        # Checked at the START of every segment, not just inside the
        # per-candidate loop below — a segment that contains ZERO
        # candidate markers never enters that inner loop at all, so a
        # deadline check placed only there never fires for a long run of
        # large, marker-free segments (the scan would keep reading and
        # scanning them, unbounded, regardless of the deadline having
        # already elapsed). max_total_scanned_bytes is a second,
        # independent cap for the same gap on a machine fast enough to
        # stay under the time budget while still reading an unbounded
        # amount of data.
        if monotonic() > scan_deadline:
            _mark_budget_exhausted(
                f"{total_candidates} candidate(s) examined, "
                f"{total_scanned_bytes} byte(s) scanned, "
                f"{len(hits)} hit(s) found — scan deadline reached "
                f"before all segments were examined",
                "scan_deadline_seconds")
            break
        # Checked against the PLANNED read size (total_scanned_bytes +
        # seg.size), not just the already-accumulated total — a pure
        # post-read check only fires on the NEXT segment's iteration, so
        # if the segment that pushes the total over the cap happens to be
        # the last one in the dump, no next iteration ever runs and the
        # scan silently reports "complete" despite having scanned well
        # past the budget.
        if total_scanned_bytes + seg.size > config.max_total_scanned_bytes:
            _mark_budget_exhausted(
                f"{total_scanned_bytes} byte(s) scanned across "
                f"{total_candidates} candidate(s), {len(hits)} hit(s) "
                f"found — total scanned-bytes budget exhausted",
                "max_total_scanned_bytes")
            break
        if seg.size > config.max_seg_scan:
            coverage_counts.note_skipped_oversize(
                segment_scan_target(seg, config.max_seg_scan))
            continue
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            # A read failure means this segment was never actually looked
            # at — it must not be silently indistinguishable from "read
            # fine, no hit". Tracked separately from size-based skips so a
            # negative result can say exactly what coverage gap exists.
            # The failed segment's own identity is retained (issue #28),
            # same as the oversized-skip path three lines above.
            coverage_counts.note_read_failed(segment_scan_target(seg))
            continue

        total_scanned_bytes += len(data)

        if len(data) < seg.size:
            # A short read (fewer bytes back than the segment's own
            # declared size) is NOT the same as "read fine, no hit" —
            # whatever wasn't returned was never actually examined for a
            # signature. Still scan what WAS returned (a partial read can
            # still contain a hit), but this segment must not silently
            # count toward a "complete" scan.
            coverage_counts.note_short_read(segment_scan_target(seg))
            if not data:
                continue

        for xor_key, idx, hit_va, hit_fo in _cs_scan_segment(
                data, seg.start_virtual_address, seg.start_file_address):
            total_candidates += 1
            # Resolved via elif (issue #28 P6 follow-up), not the
            # original `or` chain's three separate conditions, so the
            # WINNING resource is known without calling monotonic() any
            # more often than the original short-circuiting `or` already
            # did (elif only evaluates monotonic() when both earlier
            # conditions are False, same as `A or B or C`'s own
            # short-circuit).
            if total_candidates > config.max_candidates:
                exhausted_kind = "max_candidates"
            elif total_decoded_bytes > config.max_decoded_bytes:
                exhausted_kind = "max_decoded_bytes"
            elif monotonic() > scan_deadline:
                exhausted_kind = "scan_deadline_seconds"
            else:
                exhausted_kind = None
            if exhausted_kind is not None:
                _mark_budget_exhausted(
                    f"{total_candidates} candidate(s) examined, "
                    f"{total_decoded_bytes} byte(s) decoded, "
                    f"{len(hits)} hit(s) found before the scan "
                    f"budget was exhausted",
                    exhausted_kind)
                break
            parsed = _cs_decode_and_parse_tlv(data, idx, xor_key, config.config_decode_max)
            total_decoded_bytes += parsed['consumed']
            if parsed['complete'] and _cs_sanity_check(parsed['fields']):
                if hit_va not in seen_hit_vas:
                    seen_hit_vas.add(hit_va)
                    hits.append(Candidate(xor_key, hit_va, hit_fo, parsed['fields']))
                    if len(hits) >= config.max_hits:
                        _mark_budget_exhausted(
                            f"{total_candidates} candidate(s) examined, "
                            f"{total_decoded_bytes} byte(s) decoded, "
                            f"{len(hits)} hit(s) found — hit cap reached",
                            "max_hits")
                        break
            # Re-checked immediately after THIS candidate's decode work,
            # not only at the top of the next loop iteration — if this
            # candidate is the last one (in the last segment), no next
            # iteration ever runs, so a budget crossed only by decoding
            # this candidate would otherwise never be noticed and the
            # scan would silently report "complete".
            if total_candidates > config.max_candidates:
                exhausted_kind = "max_candidates"
            elif total_decoded_bytes > config.max_decoded_bytes:
                exhausted_kind = "max_decoded_bytes"
            elif monotonic() > scan_deadline:
                exhausted_kind = "scan_deadline_seconds"
            else:
                exhausted_kind = None
            if exhausted_kind is not None:
                _mark_budget_exhausted(
                    f"{total_candidates} candidate(s) examined, "
                    f"{total_decoded_bytes} byte(s) decoded, "
                    f"{len(hits)} hit(s) found before the scan "
                    f"budget was exhausted",
                    exhausted_kind)
                break
        if budget_exhausted:
            break
        # Re-checked after finishing this segment's candidate scan, not
        # only at the top of the next segment's iteration — a segment
        # whose read+scan alone crosses the deadline (few or zero
        # candidates, just a slow/large read) would otherwise only be
        # caught if there is a NEXT segment to re-enter the loop for.
        if monotonic() > scan_deadline:
            _mark_budget_exhausted(
                f"{total_candidates} candidate(s) examined, "
                f"{total_scanned_bytes} byte(s) scanned, "
                f"{len(hits)} hit(s) found — scan deadline reached "
                f"before all segments were examined",
                "scan_deadline_seconds", stop_index=seg_index + 1)
            break

    # `segs[index:]` -- the segment mid-processing (or, at the one
    # override site above, only strictly-later ones) when the budget was
    # exhausted -- issue #28 P5 follow-up. Can legitimately be empty (the
    # deadline discovered only after the very last segment already
    # finished cleanly), unlike yara_hunt's own equivalent targets, which
    # are always non-empty in practice.
    budget_exhausted_targets = (
        [segment_scan_target(s) for s in segs[budget_exhausted_stop_index:]]
        if budget_exhausted_stop_index is not None else [])
    # issue #28 P6 follow-up: consumed always equals the configured limit
    # (a budget is only ever attributed once fully exhausted). max(0, ...)
    # on scan_deadline_seconds: it can be configured NEGATIVE as a
    # test-only "already expired" technique, and a real budget can never
    # be negative.
    _budget_limits_by_kind = {
        "scan_deadline_seconds": max(0, int(config.scan_deadline_seconds)),
        "max_total_scanned_bytes": config.max_total_scanned_bytes,
        "max_candidates": config.max_candidates,
        "max_decoded_bytes": config.max_decoded_bytes,
        "max_hits": config.max_hits,
    }
    budget_exhausted_limit = (_budget_limits_by_kind[budget_exhausted_kind]
                                if budget_exhausted_kind is not None else None)

    return ScanOutcome(
        segment_count=len(segs),
        hits=hits,
        coverage=coverage_counts,
        budget_exhausted=budget_exhausted,
        budget_reason=budget_reason,
        budget_exhausted_targets=budget_exhausted_targets,
        budget_exhausted_kind=budget_exhausted_kind, budget_exhausted_limit=budget_exhausted_limit,
        total_candidates=total_candidates,
        total_decoded_bytes=total_decoded_bytes,
        total_scanned_bytes=total_scanned_bytes,
    )


def format_scan_note(outcome: ScanOutcome) -> str:
    """Build the "Scan complete<note>." progress-line suffix from a
    finished ScanOutcome — pure text formatting of already-known facts,
    not a scoring decision, so this stays in scanner.py rather than
    presentation.py (which only renders an already-built aggregate.Report)."""
    note = (f" ({outcome.coverage.skipped_oversize} segment(s) >50 MB skipped)"
            if outcome.coverage.skipped_oversize else "")
    if outcome.coverage.read_failed:
        note += f" ({outcome.coverage.read_failed} segment(s) failed to read)"
    if outcome.coverage.short_reads:
        note += f" ({outcome.coverage.short_reads} segment(s) short-read)"
    if outcome.budget_exhausted:
        note += f" (scan budget exhausted: {outcome.budget_reason})"
    return note

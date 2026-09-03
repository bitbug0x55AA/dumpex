"""Segment marker search and the whole-scan budget/coverage loop.

Only collects facts — never scores, never prints. `scan_segments` walks
every captured memory segment, finds structurally-valid (sanity-checked)
beacon configs, resolves each hit's enclosing MemoryInfo region ONCE (see
models.region_ref), and returns `(hits, diagnostics)` -- a tuple of frozen
`models.ConfigEvidence` plus a frozen `domain.ScanDiagnostics` -- for
context.py/aggregate.py to interpret. Every resource-budget/coverage-gap
rule that existed before this hunter's output-source migration is preserved
here unchanged (see the inline comments below for why each check is placed
where it is); only the RETURN shape changed, from a mutable `ScanOutcome`
dataclass to this frozen pair. `CoverageTracker` and every other mutable
accumulator below are local bookkeeping only -- none of them, nor the raw
`region` objects `_get_region_at` returns, ever leave this function; only
the frozen `hits`/`diagnostics` do.
"""
import math
import time

from dumpex.core.memory import _get_region_at
from dumpex.hunt._coverage import (
    CoverageTracker, budget_stop_targets, segment_scan_target,
)
from dumpex.hunt.cs_beacon.config import CSBeaconConfig
from dumpex.hunt.cs_beacon.domain import ScanDiagnostics
from dumpex.hunt.cs_beacon.models import ConfigEvidence, config_field_from_parsed, region_ref
from dumpex.hunt.cs_beacon.parser import _cs_decode_and_parse_tlv, _cs_guess_version, _cs_sanity_check
from dumpex.hunt.cs_beacon.config import CS_SIG_XOR69, CS_SIG_XOR2E


def select_segments(mf) -> list:
    """Prefer the 64-bit segment table, falling back to the 32-bit one."""
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        return mf.memory_segments_64.memory_segments
    if mf.memory_segments and mf.memory_segments.memory_segments:
        return mf.memory_segments.memory_segments
    return []


# The XOR key passes `_cs_scan_segment` makes over a segment, in the order it
# makes them. Declared once: `LAST_XOR_KEY` is derived from this tuple rather
# than restated, so the stop cursor in `scan_segments` -- whose correctness
# rests entirely on knowing which pass is last -- cannot drift from the walk it
# describes when a key is added or the order changes.
_XOR_KEY_PASSES = ((0x69, CS_SIG_XOR69), (0x2e, CS_SIG_XOR2E))

LAST_XOR_KEY = _XOR_KEY_PASSES[-1][0]


def _stop_cursor(xor_key: int, idx: int, data_len: int, *,
                 candidate_examined: bool) -> "int | None":
    """The first offset in this segment no longer guaranteed to have been
    searched when a budget ended the walk, or `None` when no offset bounds the
    gap.

    Only a stop during the LAST key's pass yields a bounding offset: during any
    earlier pass a later key has not looked at the segment at all, so nothing
    below the cursor is fully searched either.

    `candidate_examined` says whether the candidate AT `idx` was decoded and
    judged before the budget stopped the walk. When it was, `_cs_scan_segment`
    would have resumed its search at `idx + 1`, and that is the first
    unexamined offset; when the budget stopped before that candidate was
    decoded, `idx` itself is still unexamined. Reporting `idx` for a candidate
    already judged would widen the residual by one byte and stop it being
    byte-exact.
    """
    if xor_key != LAST_XOR_KEY:
        return None
    return min(idx + 1, data_len) if candidate_examined else idx


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
    for key, marker in _XOR_KEY_PASSES:
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx == -1:
                break
            yield key, idx, seg_va + idx, seg_fo + idx
            start = idx + 1


def scan_segments(mf, segs: list, config: CSBeaconConfig, regions: list,
                   monotonic=time.monotonic) -> "tuple[tuple, ScanDiagnostics]":
    """
    Walk every segment in `segs`, applying every whole-scan resource
    budget (deadline, candidate count, decoded bytes, total scanned
    bytes, hit count) exactly as before this hunter's output-source
    migration. `monotonic` is threaded explicitly (not imported directly
    from `time` in this module) so a caller/test can substitute a fake
    clock without needing the global `time.monotonic` to be patched — see
    dumpex/hunt/_runtime.py.

    `regions` (MemoryInfoListStream, already parsed by the caller) is used
    to resolve each accepted hit's enclosing region ONCE, at scan time
    (`models.region_ref`) -- the same "resolve identity once" rule
    `dumpex.hunt.hollowing.memory_scan` applies to its own `ImageBaseContext`.

    Returns `(hits, diagnostics)`: `hits` is a tuple of
    `models.ConfigEvidence` in scan order; `diagnostics` is a frozen
    `domain.ScanDiagnostics`.
    """
    # Zero-length segments are dropped once, here, rather than at each
    # place a segment is walked or sliced: they hold nothing to scan and
    # no bytes anyone could miss, and a ScanTarget cannot name one -- a
    # target has an extent by definition. Filtering at the entry keeps
    # every later use (the walk, and the budget/truncation slices that
    # turn abandoned segments into targets) working from the same set.
    segment_count = len(segs)   # every segment the dump declares, filter or no
    segs = [seg for seg in segs if seg.size > 0]
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
    # The ACTUAL amount of the winning resource consumed at the moment it
    # was attributed (issue #28 review follow-up) -- distinct from the
    # resource's own configured limit, which is all `budget_exhausted_
    # limit` below ever carries. `total_candidates`/`total_decoded_bytes`
    # are both incremented/accumulated BEFORE their own `> config.max_*`
    # check runs, so real consumption at that instant can exceed the
    # configured cap (e.g. `limit + 1` candidates); wall-clock elapsed
    # time is measured directly rather than assumed to equal the
    # configured deadline.
    budget_exhausted_consumed = None
    # Whether the first segment of `budget_exhausted_targets` had already
    # been entered when the budget tripped -- the one segment of that run
    # whose unexamined byte extent is not simply its whole capture (see
    # dumpex.hunt._coverage.budget_stop_targets).
    budget_exhausted_first_started = False
    # Where inside the current segment the marker walk had reached when a
    # budget ended it. `_cs_scan_segment` walks the buffer once per XOR key in
    # a fixed order, so once the LAST key's pass is under way every offset
    # below its cursor has been searched by every key and the rest of the
    # segment is exactly what is left. During any earlier key's pass a later
    # key has not looked at the segment at all, so no offset bounds the gap and
    # the cursor stays None.
    budget_stop_offset = None
    scan_start = monotonic()
    scan_deadline = scan_start + config.scan_deadline_seconds

    def _mark_budget_exhausted(reason: str, kind: str, consumed: int, stop_index: "int | None" = None,
                               stop_offset: "int | None" = None, stop_started: bool = True):
        # `stop_index` defaults to the CURRENT segment (still mid-
        # processing, or not started yet) -- overridden to `seg_index + 1`
        # at the one call site where `seg` has already been fully
        # candidate-scanned by the time its own deadline recheck fires
        # (only LATER segments are actually unstarted there).
        #
        # `stop_started` says which of those two the CURRENT segment is:
        # the whole-scan checks at the top of the loop run before the
        # segment is read at all, while the per-candidate checks run with
        # its marker walk already under way. Only the second can have
        # examined part of it, and only the second is therefore not
        # chargeable in full.
        nonlocal budget_exhausted, budget_reason, budget_exhausted_stop_index, budget_exhausted_kind, \
            budget_exhausted_consumed, budget_stop_offset, budget_exhausted_first_started
        budget_exhausted = True
        budget_reason = reason
        if budget_exhausted_stop_index is None:
            budget_exhausted_stop_index = seg_index if stop_index is None else stop_index
            budget_exhausted_kind = kind
            budget_exhausted_consumed = consumed
            budget_stop_offset = stop_offset
            # Overriding `stop_index` moves the run past the current
            # segment entirely, so whatever that segment's own state was,
            # the run starts at one nothing had touched.
            budget_exhausted_first_started = stop_started and stop_index is None

    def _elapsed_seconds(now: float) -> int:
        # Ceiling, and floored at 0 -- mirrors budget_exhausted_limit's own
        # max(0, int(config.scan_deadline_seconds)) floor for a test-only
        # negative deadline (an "already expired before the scan even
        # starts" technique); a real elapsed duration can never be
        # negative either way.
        return max(0, math.ceil(now - scan_start))

    def _resource_kind_and_consumed():
        """Which of the three per-candidate resources (max_candidates/
        max_decoded_bytes/scan_deadline_seconds) is exhausted RIGHT NOW,
        and the real amount of it consumed -- shared by both per-candidate
        recheck sites below so the elapsed-time calc isn't duplicated."""
        if total_candidates > config.max_candidates:
            return "max_candidates", total_candidates
        if total_decoded_bytes > config.max_decoded_bytes:
            return "max_decoded_bytes", total_decoded_bytes
        now = monotonic()
        if now > scan_deadline:
            return "scan_deadline_seconds", _elapsed_seconds(now)
        return None, None

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
        _now = monotonic()
        if _now > scan_deadline:
            _mark_budget_exhausted(
                f"{total_candidates} candidate(s) examined, "
                f"{total_scanned_bytes} byte(s) scanned, "
                f"{len(hits)} hit(s) found — scan deadline reached "
                f"before all segments were examined",
                "scan_deadline_seconds", _elapsed_seconds(_now), stop_started=False)
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
                "max_total_scanned_bytes", total_scanned_bytes, stop_started=False)
            break
        # Past both whole-scan budget checks above, so this segment IS in
        # scope and every path out of the iteration from here on owes the
        # ledger a disposition. Segments the loop `break`s before ever
        # reaching were never eligible -- `budget_exhausted_targets` is
        # what accounts for those.
        coverage_counts.note_eligible(seg.size)
        if seg.size > config.max_seg_scan:
            coverage_counts.note_skipped_oversize(
                segment_scan_target(seg, config.max_seg_scan))
            continue
        try:
            # Clipped to the segment's own declared extent, never trusted at
            # the length the reader chose to return: a segment names exactly
            # `size` bytes, and searching past that would attribute a config
            # hit -- whose VA and file offset are both derived from the
            # segment base plus the marker offset -- to bytes outside the unit
            # being scanned. A reader that returns nothing sliceable is a
            # failed read, the same as one that raises.
            data = reader.read(seg.start_virtual_address, seg.size)[:seg.size]
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

        if not data:
            # Nothing came back at all: no partial content to scan, so
            # this is a failed read rather than a short one -- a short read
            # ANNOTATES a segment that was otherwise scanned.
            coverage_counts.note_read_failed(segment_scan_target(seg))
            continue
        if len(data) < seg.size:
            # A short read (fewer bytes back than the segment's own
            # declared size) is NOT the same as "read fine, no hit" —
            # whatever wasn't returned was never actually examined for a
            # signature. Still scan what WAS returned (a partial read can
            # still contain a hit), but this segment must not silently
            # count toward a "complete" scan.
            coverage_counts.note_short_read(segment_scan_target(seg), got=len(data))
        # Recorded before the candidate scan below, not after it: that
        # scan can `break` out on an exhausted budget, and a disposition
        # placed after the loop would be skipped on exactly that path.
        coverage_counts.note_scanned()

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
            exhausted_kind, exhausted_consumed = _resource_kind_and_consumed()
            if exhausted_kind is not None:
                _mark_budget_exhausted(
                    f"{total_candidates} candidate(s) examined, "
                    f"{total_decoded_bytes} byte(s) decoded, "
                    f"{len(hits)} hit(s) found before the scan "
                    f"budget was exhausted",
                    exhausted_kind, exhausted_consumed,
                    stop_offset=_stop_cursor(xor_key, idx, len(data), candidate_examined=False))
                break
            parsed = _cs_decode_and_parse_tlv(data, idx, xor_key, config.config_decode_max)
            total_decoded_bytes += parsed['consumed']
            if parsed['complete'] and _cs_sanity_check(parsed['fields']):
                if hit_va not in seen_hit_vas:
                    seen_hit_vas.add(hit_va)
                    fields = tuple(config_field_from_parsed(fid, rec)
                                   for fid, rec in parsed['fields'].items())
                    region = _get_region_at(hit_va, regions)
                    hits.append(ConfigEvidence(
                        xor_key=xor_key, hit_va=hit_va, hit_fo=hit_fo, fields=fields,
                        cs_version=_cs_guess_version(parsed['fields']),
                        region=region_ref(region)))
                    if len(hits) >= config.max_hits:
                        _mark_budget_exhausted(
                            f"{total_candidates} candidate(s) examined, "
                            f"{total_decoded_bytes} byte(s) decoded, "
                            f"{len(hits)} hit(s) found — hit cap reached",
                            "max_hits", len(hits),
                            stop_offset=_stop_cursor(xor_key, idx, len(data), candidate_examined=True))
                        break
            # Re-checked immediately after THIS candidate's decode work,
            # not only at the top of the next loop iteration — if this
            # candidate is the last one (in the last segment), no next
            # iteration ever runs, so a budget crossed only by decoding
            # this candidate would otherwise never be noticed and the
            # scan would silently report "complete".
            exhausted_kind, exhausted_consumed = _resource_kind_and_consumed()
            if exhausted_kind is not None:
                _mark_budget_exhausted(
                    f"{total_candidates} candidate(s) examined, "
                    f"{total_decoded_bytes} byte(s) decoded, "
                    f"{len(hits)} hit(s) found before the scan "
                    f"budget was exhausted",
                    exhausted_kind, exhausted_consumed,
                    stop_offset=_stop_cursor(xor_key, idx, len(data), candidate_examined=True))
                break
        if budget_exhausted:
            break
        # Re-checked after finishing this segment's candidate scan, not
        # only at the top of the next segment's iteration — a segment
        # whose read+scan alone crosses the deadline (few or zero
        # candidates, just a slow/large read) would otherwise only be
        # caught if there is a NEXT segment to re-enter the loop for.
        _now = monotonic()
        if _now > scan_deadline:
            _mark_budget_exhausted(
                f"{total_candidates} candidate(s) examined, "
                f"{total_scanned_bytes} byte(s) scanned, "
                f"{len(hits)} hit(s) found — scan deadline reached "
                f"before all segments were examined",
                "scan_deadline_seconds", _elapsed_seconds(_now), stop_index=seg_index + 1)
            break

    # `segs[index:]` -- the segment mid-processing (or, at the one
    # override site above, only strictly-later ones) when the budget was
    # exhausted -- issue #28 P5 follow-up. Can legitimately be empty (the
    # deadline discovered only after the very last segment already
    # finished cleanly), unlike yara_hunt's own equivalent targets, which
    # are always non-empty in practice.
    budget_exhausted_targets = (
        budget_stop_targets(segs[budget_exhausted_stop_index:],
                             first_started=budget_exhausted_first_started,
                             first_examined=budget_stop_offset)
        if budget_exhausted_stop_index is not None else [])
    # max(0, ...) on scan_deadline_seconds: it can be configured NEGATIVE
    # as a test-only "already expired" technique, and a real budget can
    # never be negative. `budget_exhausted_consumed` (issue #28 review
    # follow-up) is the REAL measured consumption at the moment this
    # budget was attributed -- see `_mark_budget_exhausted`'s own
    # docstring; it is set together with `budget_exhausted_kind`, so no
    # by-kind lookup is needed for it the way there is for the limit.
    _budget_limits_by_kind = {
        "scan_deadline_seconds": max(0, int(config.scan_deadline_seconds)),
        "max_total_scanned_bytes": config.max_total_scanned_bytes,
        "max_candidates": config.max_candidates,
        "max_decoded_bytes": config.max_decoded_bytes,
        "max_hits": config.max_hits,
    }
    budget_exhausted_limit = (_budget_limits_by_kind[budget_exhausted_kind]
                                if budget_exhausted_kind is not None else None)

    diagnostics = ScanDiagnostics(
        segment_count=segment_count,
        total_candidates=total_candidates,
        total_decoded_bytes=total_decoded_bytes,
        total_scanned_bytes=total_scanned_bytes,
        skipped_oversize_targets=tuple(coverage_counts.skipped_oversize_targets),
        read_failed_targets=tuple(coverage_counts.read_failed_targets),
        short_read_targets=tuple(coverage_counts.short_read_targets),
        budget_exhausted=budget_exhausted,
        budget_reason=budget_reason,
        budget_exhausted_targets=tuple(budget_exhausted_targets),
        budget_exhausted_kind=budget_exhausted_kind,
        budget_exhausted_limit=budget_exhausted_limit,
        budget_exhausted_consumed=budget_exhausted_consumed,
        budget_stop_offset=budget_stop_offset,
        scanned=coverage_counts.scanned,
        eligible_total=coverage_counts.total,
        eligible_bytes=coverage_counts.eligible_bytes,
        not_applicable=coverage_counts.not_applicable,
        budget_skipped=coverage_counts.budget_skipped,
        unaccounted=coverage_counts.unaccounted,
        over_accounted=coverage_counts.over_accounted,
    )
    return tuple(hits), diagnostics

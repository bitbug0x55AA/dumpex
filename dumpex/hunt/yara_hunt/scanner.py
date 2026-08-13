"""Segment × rule-file YARA match loop: reads each memory segment, runs
every compiled rule file against it, normalizes matches, and applies the
whole-scan budgets (deadline, total bytes, hit cap). Only collects facts
— never scores, never prints.
"""
import math
import time
from minidump.minidumpfile import MinidumpFile
from dumpex.hunt._coverage import segment_scan_target
from dumpex.hunt.yara_hunt.config import YaraConfig, SCOPE_PRIVATE_OR_UNBACKED
from dumpex.hunt.yara_hunt.models import ScanOutcome
from dumpex.hunt.yara_hunt import context as context_mod


def select_segments(mf) -> list:
    """Prefer the 64-bit segment table, falling back to the 32-bit one."""
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        return mf.memory_segments_64.memory_segments
    if mf.memory_segments and mf.memory_segments.memory_segments:
        return mf.memory_segments.memory_segments
    return []


def scan_segments(mf: MinidumpFile, segs: list, rule_files: list, modules: list, regions: list,
                   modules_available: bool, mem_info_available: bool,
                   config: YaraConfig, monotonic=time.monotonic) -> ScanOutcome:
    """
    Walk every segment in `segs`, matching each against every compiled
    rule file in `rule_files`, applying every whole-scan resource budget
    (deadline, total bytes scanned, hit count) exactly as the single-file
    hunter did. `monotonic` is threaded explicitly (not imported directly
    from `time` in this module) so a caller/test can substitute a fake
    clock without needing the global `time.monotonic` to be patched — see
    dumpex/hunt/_runtime.py.
    """
    reader = mf.get_reader()

    all_hits     = []
    skipped_targets = []   # ScanTarget per oversized segment -- see ScanOutcome
    read_failed  = 0
    read_failed_targets = []   # ScanTarget per failed segment -- issue #28
    short_reads  = 0   # read succeeded but returned fewer bytes than seg.size —
    short_read_targets = []   # ScanTarget per short-read segment -- issue #28
                       # whatever wasn't returned was never actually scanned,
                       # so this must not be indistinguishable from a clean
                       # full-segment scan (mirrors the same check in
                       # dumpex.hunt.cs_beacon).
    scanned      = 0
    timed_out    = 0
    # ScanTarget per TIMED-OUT CALL, not deduplicated per segment (issue
    # #28 P4 follow-up) -- `timed_out` itself counts calls, not segments
    # (unlike read_failed/short_reads, which dedupe to one per region/
    # segment; see this variable's own rendered text, "N match() call(s)
    # timed out"), so a segment whose search timed out against two
    # different rule files contributes its ScanTarget to this list TWICE,
    # keeping len(timed_out_targets) == timed_out exactly (the invariant
    # dumpex.output.coverage._require_optional_targets_matching_count
    # enforces) rather than silently changing what `timed_out` has always
    # counted.
    timed_out_targets = []
    match_failed = 0   # non-timeout exception from compiled.match() — the
                       # (segment, rule-file) pair was never actually
                       # evaluated and must not be indistinguishable from
                       # "evaluated, no match"
    match_failed_targets = []   # ScanTarget per FAILED CALL -- see timed_out_targets' own comment
    truncated    = False   # hit config.max_total_hits before finishing the scan
    budget_exhausted   = False   # hit the whole-scan time/byte budget before
                                  # finishing every segment
    # The index (into `segs`) of the segment being processed when
    # `truncated`/`budget_exhausted` first became True -- issue #28 P5
    # follow-up. `segs[index:]` (the segment mid-processing when the stop
    # happened, plus every later one never started at all) becomes that
    # gap's own `targets`; set at most once each (the FIRST stop is what
    # actually ended the scan -- a later flag flip on the SAME segment
    # still names that same segment, never a later, unreached one).
    truncated_stop_index = None
    budget_exhausted_stop_index = None
    # WHICH of the two independent whole-scan budgets (issue #28 P6
    # follow-up) first tripped budget_exhausted -- "scan_deadline_seconds"
    # (wall clock) or "max_total_bytes_scanned" (bytes read) -- set once,
    # alongside budget_exhausted_stop_index, by whichever call site fires
    # first (mirrors dumpex.hunt.injection.memory_scan._ScanBudget.
    # last_exhausted_kind).
    budget_exhausted_kind = None
    # The ACTUAL amount of the winning resource consumed at the moment it
    # was attributed (issue #28 review follow-up) -- distinct from that
    # resource's own configured limit (`budget_exhausted_limit` below):
    # wall-clock elapsed time is measured directly rather than assumed to
    # equal the configured deadline, and the post-read defensive backstop
    # on `total_bytes_scanned` can genuinely exceed `max_total_bytes_
    # scanned` (a reader returning more than the segment's declared size).
    budget_exhausted_consumed = None

    def _mark_truncated():
        nonlocal truncated, truncated_stop_index
        truncated = True
        if truncated_stop_index is None:
            truncated_stop_index = seg_index

    def _mark_budget_exhausted(kind: str, consumed: int, current_segment_affected: bool = True):
        # `current_segment_affected=False` (issue #28 P6 follow-up) is
        # used at the two call sites INSIDE the rule_files loop where the
        # deadline is discovered only AFTER the current (segment,
        # rule_file) pairing's own work already completed (a successful
        # match() call whose results are about to be processed regardless,
        # or a failed call already reflected via match_failed/timed_out) --
        # at those sites the CURRENT segment has nothing left unexamined
        # unless a LATER rule_file for it was also skipped, so naming it
        # here too would be a false positive (see those call sites' own
        # comments for the exact reasoning).
        nonlocal budget_exhausted, budget_exhausted_stop_index, budget_exhausted_kind, \
            budget_exhausted_consumed
        budget_exhausted = True
        if budget_exhausted_stop_index is None:
            budget_exhausted_stop_index = seg_index if current_segment_affected else seg_index + 1
            budget_exhausted_kind = kind
            budget_exhausted_consumed = consumed

    total_bytes_scanned = 0
    scan_start = monotonic()
    scan_deadline = scan_start + config.scan_deadline_seconds

    def _elapsed_seconds(now: float) -> int:
        # Ceiling, floored at 0 -- mirrors budget_exhausted_limit's own
        # max(0, int(config.scan_deadline_seconds)) floor for a test-only
        # negative deadline; a real elapsed duration can never be
        # negative either way.
        return max(0, math.ceil(now - scan_start))
    suppressed_module_pe = 0   # PE_In_Private_Memory hits suppressed because
                               # the match address resolved to a known module
                               # or a MEM_IMAGE region
    suppressed_scoped    = 0   # hits from a dumpex_scope="private_or_unbacked"
                               # rule (see config.SCOPE_PRIVATE_OR_UNBACKED)
                               # suppressed for the same reason
    context_unverified   = 0   # PE_In_Private_Memory / scoped-rule hits that
                               # could not be classified at all: neither
                               # ModuleList nor MemoryInfo is present (or, for
                               # a scoped rule, the resolved region is neither
                               # module-backed nor executable) — no way to
                               # tell a legitimate module hit from a
                               # genuinely private/unbacked one
    triggered_rules  = set()   # rule names with at least one confidently
                                # classified hit — drives score/DETECTED
    unverified_rules = set()   # rule names whose hits were ALL context_unverified

    for seg_index, seg in enumerate(segs):
        if truncated:
            break
        _now = monotonic()
        if _now > scan_deadline:
            # Remaining segments are an explicit coverage gap, not silently
            # dropped -- see the "budget_exhausted" coverage key below.
            _mark_budget_exhausted("scan_deadline_seconds", _elapsed_seconds(_now))
            break
        if total_bytes_scanned > config.max_total_bytes_scanned:
            _mark_budget_exhausted("max_total_bytes_scanned", total_bytes_scanned)
            break
        if seg.size > config.max_seg_scan:
            skipped_targets.append(segment_scan_target(seg, config.max_seg_scan))
            continue
        if total_bytes_scanned + seg.size > config.max_total_bytes_scanned:
            # Checked against the segment's declared size BEFORE reading —
            # the budget is meant to bound total work done, not just be
            # noticed after the fact. Checking only after the read (below)
            # would still let one full max_seg_scan-sized segment (up to
            # 50 MB) be read past the cap before it's detected.
            _mark_budget_exhausted("max_total_bytes_scanned", total_bytes_scanned)
            break
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            # A segment that fails to read was never actually scanned — it
            # must not be silently indistinguishable from "scanned, clean".
            # The segment's own identity is retained (issue #28), the same
            # way an oversized-skip target already is above.
            read_failed += 1
            read_failed_targets.append(segment_scan_target(seg))
            continue
        total_bytes_scanned += len(data)
        if total_bytes_scanned > config.max_total_bytes_scanned:
            # Defensive backstop for the (normally impossible) case of a
            # reader returning more than the segment's declared size -- the
            # real enforcement is the predictive check above.
            _mark_budget_exhausted("max_total_bytes_scanned", total_bytes_scanned)
        if len(data) < seg.size:
            # A short read is NOT "read fine, no hit" -- whatever wasn't
            # returned was never actually examined for a signature. Still
            # scan what WAS returned (a partial read can still contain a
            # hit), but this segment must not silently count toward a
            # "complete" scan.
            short_reads += 1
            short_read_targets.append(segment_scan_target(seg))
            if not data:
                continue
        scanned += 1

        for rule_index, (fname, compiled) in enumerate(rule_files):
            remaining = scan_deadline - monotonic()
            if remaining <= 0:
                # Checked HERE, not just between segments -- a single
                # segment scanned against many rule files (each individually
                # inside config.match_timeout) could otherwise blow past the
                # whole-scan deadline without it ever being noticed, since
                # there might be no further segment iteration left to catch
                # it either. This rule_index's own file (and everything
                # after it) is unconditionally unexamined here -- unlike
                # the two sites below, there is no "already handled, so
                # maybe nothing is really missing" case to consider.
                _mark_budget_exhausted("scan_deadline_seconds",
                                       _elapsed_seconds(scan_deadline - remaining))
                break
            try:
                # Bounded by whichever is smaller: the per-call timeout, or
                # whatever's left of the WHOLE-scan deadline. Using a flat
                # config.match_timeout here regardless of how much global
                # budget remained let the single LAST match() call of the
                # scan run up to a further 30s past scan_deadline with
                # nothing left afterward to notice it happened (no next
                # rule file, no next segment) -- tightening the call's own
                # timeout stops it from overrunning in the first place,
                # rather than only detecting it after the fact. int(...) is
                # required (yara-python's timeout is whole seconds, and 0
                # means "no timeout" in libyara, not "expire immediately"),
                # so this floors at 1s rather than passing 0.
                call_timeout = max(1, min(config.match_timeout, int(remaining)))
                matches = compiled.match(data=data, timeout=call_timeout)
            except Exception as e:
                # yara-python raises yara.TimeoutError specifically; match on
                # the exception class name rather than message text, which
                # isn't a stable contract across yara-python versions. Any
                # OTHER exception (a crafted/corrupt segment tripping a YARA
                # internal error, a module error, etc.) must still be
                # accounted for — silently `continue`-ing here previously
                # left this (segment, rule-file) pair unrepresented in any
                # counter, so a scan that hit nothing else came back CLEAN
                # even though this pair was never actually evaluated.
                if "timeout" in type(e).__name__.lower():
                    timed_out += 1
                    timed_out_targets.append(segment_scan_target(seg))
                else:
                    match_failed += 1
                    match_failed_targets.append(segment_scan_target(seg))
                _now = monotonic()
                if _now > scan_deadline:
                    # This (segment, rule_file) pair's own outcome is
                    # ALREADY fully accounted for above (timed_out/
                    # match_failed) -- issue #28 P6 follow-up: the CURRENT
                    # segment is only genuinely still "affected" (worth
                    # naming as a budget_exhausted target) if a LATER
                    # rule_file for it never ran; when this was that
                    # segment's own last rule_file, only later segments
                    # (if any) belong in `targets`. `budget_exhausted`
                    # itself still becomes True either way -- the
                    # wall-clock deadline genuinely was exceeded, and that
                    # remains worth recording even on a scan's very last
                    # pairing, where `targets` naturally comes out empty
                    # (`segs[len(segs):]`) rather than a manufactured one.
                    _mark_budget_exhausted("scan_deadline_seconds", _elapsed_seconds(_now),
                                           current_segment_affected=rule_index < len(rule_files) - 1)
                    break
                continue

            _now = monotonic()
            if _now > scan_deadline:
                # Re-checked immediately after the call returns (not only
                # at the top of the next iteration) -- even a call that
                # completed within its own tightened call_timeout can still
                # be the one that pushes elapsed time past scan_deadline,
                # and this may be the last rule file / last segment with no
                # further iteration left to notice it otherwise.
                #
                # This call's OWN matches are still processed below
                # regardless (nothing from this pairing is lost) -- issue
                # #28 P6 follow-up: the CURRENT segment is only genuinely
                # still "affected" if a LATER rule_file for it never runs;
                # `budget_exhausted` itself still becomes True either way
                # (the wall-clock deadline genuinely was exceeded), with
                # `targets` naturally coming out empty on the scan's very
                # last pairing rather than naming an already-fully-handled
                # segment.
                _mark_budget_exhausted("scan_deadline_seconds", _elapsed_seconds(_now),
                                       current_segment_affected=rule_index < len(rule_files) - 1)

            for match in matches:
                if len(all_hits) >= config.max_total_hits:
                    _mark_truncated()
                    break

                hit_context_unverified = False
                hit_memory_context = None
                # PE_In_Private_Memory predates the meta-driven scope
                # mechanism below and keeps its own bespoke, unchanged
                # classifier for backward compatibility with rule files/
                # tests that don't carry dumpex_scope meta — every OTHER
                # scoped rule is dispatched purely by meta, not by name,
                # so adding a new scoped rule never needs a scanner.py
                # change (see config.SCOPE_PRIVATE_OR_UNBACKED).
                if match.rule == "PE_In_Private_Memory":
                    addr = seg.start_virtual_address
                    suppressed, unverified, ctx_value = context_mod.classify_pe_in_private_memory_hit(
                        addr, modules, regions, modules_available, mem_info_available)
                    hit_memory_context = ctx_value

                    if suppressed:
                        suppressed_module_pe += 1
                        continue

                    if unverified:
                        context_unverified += 1
                        hit_context_unverified = True
                elif match.meta.get("dumpex_scope") == SCOPE_PRIVATE_OR_UNBACKED:
                    addr = seg.start_virtual_address
                    suppressed, unverified, ctx_value = context_mod.classify_scoped_hit(
                        addr, modules, regions, modules_available, mem_info_available)
                    hit_memory_context = ctx_value

                    if suppressed:
                        suppressed_scoped += 1
                        continue

                    if unverified:
                        context_unverified += 1
                        hit_context_unverified = True

                if hit_context_unverified:
                    unverified_rules.add(match.rule)
                else:
                    triggered_rules.add(match.rule)

                # Annotate each matched string with its absolute VA + file offset,
                # capped so one match with pathologically many instances can't
                # blow up memory/output.
                annotated_strings = []
                for s in match.strings:
                    if len(annotated_strings) >= config.max_strings_per_match:
                        break
                    # yara-python ≥4.3: s is a yara.StringMatch with .instances
                    # yara-python <4.3:  s is a tuple (offset, name, data)
                    if hasattr(s, 'instances'):
                        for inst in s.instances:
                            if len(annotated_strings) >= config.max_strings_per_match:
                                break
                            off     = inst.offset
                            matched = inst.matched_data
                            abs_va  = seg.start_virtual_address + off
                            fo      = seg.start_file_address + off
                            annotated_strings.append({
                                "var":       s.identifier,
                                "offset":    off,
                                "va":        abs_va,
                                "fo":        fo,
                                "data":      matched,
                            })
                    else:
                        off, varname, matched = s
                        abs_va = seg.start_virtual_address + off
                        fo     = seg.start_file_address + off
                        annotated_strings.append({
                            "var":    varname,
                            "offset": off,
                            "va":     abs_va,
                            "fo":     fo,
                            "data":   matched,
                        })

                all_hits.append({
                    "rule":     match.rule,
                    "file":     fname,
                    "tags":     match.tags,
                    "meta":     match.meta,
                    "seg_va":   seg.start_virtual_address,
                    "seg_fo":   seg.start_file_address,
                    "seg_size": seg.size,
                    "strings":  annotated_strings,
                    "context_unverified": hit_context_unverified,
                    "memory_context": hit_memory_context,
                })
            if truncated or budget_exhausted:
                break

    # `segs[index:]` -- the segment mid-processing when the stop happened,
    # plus every later segment never started at all -- issue #28 P5
    # follow-up (see truncated_stop_index/budget_exhausted_stop_index's
    # own comment above for why this is segment-granularity, not a byte
    # remainder like injection's own PE_HEADER_SCAN_TRUNCATED target).
    truncated_targets = ([segment_scan_target(s) for s in segs[truncated_stop_index:]]
                          if truncated_stop_index is not None else [])
    budget_exhausted_targets = (
        [segment_scan_target(s) for s in segs[budget_exhausted_stop_index:]]
        if budget_exhausted_stop_index is not None else [])
    # issue #28 P6 follow-up: `truncated`'s own budget is always
    # max_total_hits (no ambiguity), and its own consumed count always
    # equals the limit exactly (the check that sets it, `len(all_hits) >=
    # config.max_total_hits`, fires the first time the two are equal, never
    # after they could have diverged) -- `budget_exhausted`'s own kind (and,
    # per issue #28 review follow-up, its own REAL consumed amount) was
    # already resolved at whichever `_mark_budget_exhausted()` call fired
    # first, so only the limit needs looking up here.
    truncated_budget_limit = config.max_total_hits if truncated else None
    # max(0, ...): scan_deadline_seconds can be configured NEGATIVE as a
    # test-only "already expired before the scan even starts" technique
    # (e.g. YaraConfig(scan_deadline_seconds=-1)) -- a real budget can
    # never be negative, so a negative deadline is reported as the
    # smallest real one, 0 seconds allowed, not the literal configured
    # value.
    _budget_limits_by_kind = {
        "scan_deadline_seconds": max(0, int(config.scan_deadline_seconds)),
        "max_total_bytes_scanned": config.max_total_bytes_scanned,
    }
    budget_exhausted_limit = (_budget_limits_by_kind[budget_exhausted_kind]
                                if budget_exhausted_kind is not None else None)

    return ScanOutcome(
        all_hits=all_hits, scanned=scanned, skipped_targets=skipped_targets,
        read_failed=read_failed, read_failed_targets=read_failed_targets,
        short_reads=short_reads, short_read_targets=short_read_targets,
        timed_out=timed_out, timed_out_targets=timed_out_targets,
        match_failed=match_failed, match_failed_targets=match_failed_targets,
        truncated=truncated, truncated_targets=truncated_targets,
        truncated_budget_limit=truncated_budget_limit,
        budget_exhausted=budget_exhausted, budget_exhausted_targets=budget_exhausted_targets,
        budget_exhausted_kind=budget_exhausted_kind, budget_exhausted_limit=budget_exhausted_limit,
        budget_exhausted_consumed=budget_exhausted_consumed,
        total_bytes_scanned=total_bytes_scanned, suppressed_module_pe=suppressed_module_pe,
        suppressed_scoped=suppressed_scoped,
        context_unverified=context_unverified, triggered_rules=triggered_rules,
        unverified_rules=unverified_rules,
    )


def _format_size(n: int) -> str:
    """
    Format a byte count EXACTLY, never by rounding down to a unit it isn't
    a whole multiple of — `n // (1024*1024)` silently reports "0 MB" for a
    512 KiB cap and "1 MB" for a 1.5 MiB one, both wrong. Falls back to
    the next-smaller exact unit rather than ever losing precision.
    """
    if n % (1024 * 1024) == 0:
        return f"{n // (1024 * 1024)} MB"
    if n % 1024 == 0:
        return f"{n // 1024} KB"
    return f"{n} bytes"


def format_scan_note(outcome: ScanOutcome, config: YaraConfig) -> str:
    """Build the "Scan complete<note>." progress-line suffix from a
    finished ScanOutcome — pure text formatting of already-known facts,
    not a scoring decision, so this stays in scanner.py rather than
    presentation.py (which only renders an already-built aggregate.Report)."""
    note = (f" ({outcome.skipped} segment(s) >{_format_size(config.max_seg_scan)} skipped)"
            if outcome.skipped else "")
    if outcome.read_failed:
        note += f" ({outcome.read_failed} segment(s) failed to read)"
    if outcome.short_reads:
        note += f" ({outcome.short_reads} segment(s) short-read)"
    if outcome.timed_out:
        note += f" ({outcome.timed_out} match() call(s) timed out after {config.match_timeout}s)"
    if outcome.match_failed:
        note += f" ({outcome.match_failed} match() call(s) failed)"
    if outcome.truncated:
        note += f" — TRUNCATED at {config.max_total_hits} hits, scan did not complete"
    if outcome.budget_exhausted and outcome.budget_exhausted_targets:
        note += (f" — scan budget exhausted "
                  f"({config.scan_deadline_seconds}s/{config.max_total_bytes_scanned} "
                  f"bytes), remaining segments not scanned")
    elif outcome.budget_exhausted:
        # issue #28 review follow-up: the deadline was only noticed after
        # the scan's very last pairing already finished cleanly -- every
        # segment WAS examined, so this must not claim otherwise.
        note += (f" (scan deadline of {config.scan_deadline_seconds}s exceeded only after "
                  f"the last segment/rule-file pairing finished; no segments left unscanned)")
    return note

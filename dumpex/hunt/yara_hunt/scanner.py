"""Segment × rule-file YARA match loop: reads each memory segment, runs
every compiled rule file against it, normalizes matches, and applies the
whole-scan budgets (deadline, total bytes, hit cap). Only collects facts
— never scores, never prints.
"""
import time
from minidump.minidumpfile import MinidumpFile
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
    skipped      = 0
    read_failed  = 0
    short_reads  = 0   # read succeeded but returned fewer bytes than seg.size —
                       # whatever wasn't returned was never actually scanned,
                       # so this must not be indistinguishable from a clean
                       # full-segment scan (mirrors the same check in
                       # dumpex.hunt.cs_beacon).
    scanned      = 0
    timed_out    = 0
    match_failed = 0   # non-timeout exception from compiled.match() — the
                       # (segment, rule-file) pair was never actually
                       # evaluated and must not be indistinguishable from
                       # "evaluated, no match"
    truncated    = False   # hit config.max_total_hits before finishing the scan
    budget_exhausted   = False   # hit the whole-scan time/byte budget before
                                  # finishing every segment
    total_bytes_scanned = 0
    scan_deadline = monotonic() + config.scan_deadline_seconds
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

    for seg in segs:
        if truncated:
            break
        if (monotonic() > scan_deadline
                or total_bytes_scanned > config.max_total_bytes_scanned):
            # Remaining segments are an explicit coverage gap, not silently
            # dropped -- see the "budget_exhausted" coverage key below.
            budget_exhausted = True
            break
        if seg.size > config.max_seg_scan:
            skipped += 1
            continue
        if total_bytes_scanned + seg.size > config.max_total_bytes_scanned:
            # Checked against the segment's declared size BEFORE reading —
            # the budget is meant to bound total work done, not just be
            # noticed after the fact. Checking only after the read (below)
            # would still let one full max_seg_scan-sized segment (up to
            # 50 MB) be read past the cap before it's detected.
            budget_exhausted = True
            break
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            # A segment that fails to read was never actually scanned — it
            # must not be silently indistinguishable from "scanned, clean".
            read_failed += 1
            continue
        total_bytes_scanned += len(data)
        if total_bytes_scanned > config.max_total_bytes_scanned:
            # Defensive backstop for the (normally impossible) case of a
            # reader returning more than the segment's declared size -- the
            # real enforcement is the predictive check above.
            budget_exhausted = True
        if len(data) < seg.size:
            # A short read is NOT "read fine, no hit" -- whatever wasn't
            # returned was never actually examined for a signature. Still
            # scan what WAS returned (a partial read can still contain a
            # hit), but this segment must not silently count toward a
            # "complete" scan.
            short_reads += 1
            if not data:
                continue
        scanned += 1

        for fname, compiled in rule_files:
            remaining = scan_deadline - monotonic()
            if remaining <= 0:
                # Checked HERE, not just between segments -- a single
                # segment scanned against many rule files (each individually
                # inside config.match_timeout) could otherwise blow past the
                # whole-scan deadline without it ever being noticed, since
                # there might be no further segment iteration left to catch
                # it either.
                budget_exhausted = True
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
                else:
                    match_failed += 1
                if monotonic() > scan_deadline:
                    budget_exhausted = True
                    break
                continue

            if monotonic() > scan_deadline:
                # Re-checked immediately after the call returns (not only
                # at the top of the next iteration) -- even a call that
                # completed within its own tightened call_timeout can still
                # be the one that pushes elapsed time past scan_deadline,
                # and this may be the last rule file / last segment with no
                # further iteration left to notice it otherwise.
                budget_exhausted = True

            for match in matches:
                if len(all_hits) >= config.max_total_hits:
                    truncated = True
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

    return ScanOutcome(
        all_hits=all_hits, scanned=scanned, skipped=skipped, read_failed=read_failed,
        short_reads=short_reads, timed_out=timed_out, match_failed=match_failed,
        truncated=truncated, budget_exhausted=budget_exhausted,
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
    if outcome.budget_exhausted:
        note += (f" — scan budget exhausted "
                  f"({config.scan_deadline_seconds}s/{config.max_total_bytes_scanned} "
                  f"bytes), remaining segments not scanned")
    return note

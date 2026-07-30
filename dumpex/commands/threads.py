"""--threads command."""
import ntpath
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import get_modules, get_thread_infos, addr_to_module
from dumpex.core.pe_utils import _filetime_to_str, _dumpflags_str, _duration_100ns_to_str
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.output.records import (
    ThreadRecord, hex_address,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)

_NEITHER_STREAM_REASON = "Neither ThreadListStream nor ThreadInfoListStream present in this dump"
_DEGRADED_REASON = (
    "ThreadInfoListStream not present; StartAddress/CreateTime/ExitTime/"
    "KernelTime/UserTime unavailable (TID/SuspendCount/Priority/TEB only)"
)
_MODULES_UNAVAILABLE_REASON = (
    "ModuleListStream not present; thread backing-module classification unavailable "
    "(cannot confirm whether a start address is backed by a known module)"
)


def _missing_from_info_reason(n: int) -> str:
    return (f"{n} thread(s) present in ThreadListStream but missing from "
            f"ThreadInfoListStream (StartAddress/CreateTime/ExitTime/KernelTime/"
            f"UserTime unavailable for those)")


def _missing_from_base_reason(n: int) -> str:
    return (f"{n} thread(s) present in ThreadInfoListStream but missing from "
            f"ThreadListStream (SuspendCount/Priority/TEB unavailable for those)")


class _RawThreadInfo:
    """
    Stand-in for a MINIDUMP_THREAD_INFO record, built from the base
    ThreadListStream when the optional ThreadInfoListStream isn't present
    in the dump. StartAddress/CreateTime/ExitTime/KernelTime/UserTime/
    ExitStatus/DumpFlags don't exist on the raw MINIDUMP_THREAD structure,
    so they stay None here rather than being guessed at.
    """
    __slots__ = ("ThreadId", "StartAddress", "CreateTime", "ExitTime",
                 "KernelTime", "UserTime", "ExitStatus", "DumpFlags")

    def __init__(self, tid):
        self.ThreadId     = tid
        self.StartAddress = None
        self.CreateTime    = None
        self.ExitTime      = None
        self.KernelTime    = None
        self.UserTime      = None
        self.ExitStatus    = None
        self.DumpFlags     = None


def collect_threads(mf):
    """
    Pure data, no printing. Returns (records, coverage_status,
    coverage_reasons, degraded, has_times) -- degraded/has_times are
    extra rendering context specific to this command (whether
    ThreadInfoListStream was present, and whether any thread reports
    timing fields at all), consumed only by render_threads_console;
    cli.py only ever sees the first three (see cmd_threads below).

    ThreadListStream and ThreadInfoListStream are two independent,
    independently-optional streams describing the same threads. Neither
    stream's mere PRESENCE tells you the two actually agree on which
    TIDs exist -- a dump can have both streams and still have a TID in
    one that's absent from the other (a stream that's present but
    reports fewer threads than the other, or a genuinely inconsistent
    capture). Building the record set from ONE stream's TID list alone
    would silently drop threads the other stream knows about, and would
    report 'complete' coverage for a dump where the two streams actually
    disagree. Records are built from the UNION of both streams' TIDs;
    whichever stream is missing a given TID has its own fields filled in
    via _RawThreadInfo's None placeholders for that thread specifically,
    and the mismatch count is a coverage_reason -- not silently absorbed
    into either "complete" or a single all-or-nothing 'degraded' flag.
    """
    base_threads_present = bool(mf.threads)
    info_stream_present  = bool(mf.thread_info)
    modules_available    = bool(mf.modules)

    threads_by_tid = {t.ThreadId: t for t in (mf.threads.threads if mf.threads else [])}
    real_infos_by_tid = {ti.ThreadId: ti for ti in get_thread_infos(mf)}
    modules = get_modules(mf)

    if not base_threads_present and not info_stream_present:
        # Neither stream exists at all -- there is no thread data of any
        # kind to report, not "0 threads, fully evaluated."
        coverage_status = derive_coverage_status(evaluated=False, complete=False)
        return [], coverage_status, [_NEITHER_STREAM_REASON], False, False

    # Whole-stream absence (the common, expected "not captured with
    # MiniDumpWithThreadInfo" case) is still tracked separately from a
    # per-TID mismatch between two streams that ARE both present, since
    # it gets its own specific, more actionable console message below.
    degraded = not info_stream_present and base_threads_present

    all_tids = list(threads_by_tid.keys())
    for tid in real_infos_by_tid:
        if tid not in threads_by_tid:
            all_tids.append(tid)

    missing_from_info = 0   # TID in ThreadListStream, absent from ThreadInfoListStream
    missing_from_base = 0   # TID in ThreadInfoListStream, absent from ThreadListStream
    # (ti, is_placeholder) pairs -- is_placeholder marks a _RawThreadInfo
    # synthesized because this specific TID has no ThreadInfoListStream
    # entry (whether because the whole stream is absent, or just this
    # one TID is missing from an otherwise-present stream). Tracked
    # per-record, not as a single dump-wide flag: a merged result can
    # freely mix real entries and placeholders, and a placeholder must
    # never be rendered as if it were a real "no timestamp recorded"
    # answer -- see has_times' per-record use below.
    entries = []
    for tid in all_tids:
        ti = real_infos_by_tid.get(tid)
        if ti is None:
            if info_stream_present and not degraded:
                # ThreadInfoListStream exists (and isn't entirely absent)
                # but doesn't cover this specific TID -- a genuine
                # per-thread gap, counted once via the whole-stream
                # 'degraded' reason instead when the stream is absent
                # altogether.
                missing_from_info += 1
            ti = _RawThreadInfo(tid)
            entries.append((ti, True))
            continue
        if tid not in threads_by_tid and info_stream_present:
            missing_from_base += 1
        entries.append((ti, False))

    # Dump-wide: does ThreadInfoListStream carry meaningful timing data
    # at all (some minidump producers leave CreateTime/ExitTime zeroed
    # even when the stream itself is present)? Only checked over REAL
    # entries -- a placeholder's CreateTime is always None and must not
    # be able to suppress this for the whole result on its own, nor
    # (see the per-record gating below) borrow a "yes" from unrelated
    # real threads elsewhere in the same result.
    has_times = any(getattr(ti, "CreateTime", None) for ti, is_placeholder in entries
                     if not is_placeholder)

    records = []
    for ti, is_placeholder in entries:
        sa  = ti.StartAddress   # may be None in degraded mode — do not coerce to 0

        module_context = None   # start address itself unknown -- module context is moot
        mod = None
        if sa is not None:
            mod = addr_to_module(sa, modules)
            if mod is not None:
                module_context = MODULE_CONTEXT_RESOLVED
            elif modules_available:
                # ModuleListStream WAS available and this address genuinely
                # isn't in it -- a real, confirmed finding (this tool's own
                # injection/hollowing hunters treat an unbacked thread start
                # address as a suspicious indicator).
                module_context = MODULE_CONTEXT_UNREGISTERED
            else:
                # ModuleListStream itself is missing -- we simply cannot
                # tell either way. Must never be indistinguishable from
                # MODULE_CONTEXT_UNREGISTERED above, which IS a signal.
                module_context = MODULE_CONTEXT_UNAVAILABLE

        raw           = threads_by_tid.get(ti.ThreadId)
        suspend_count = getattr(raw, "SuspendCount", None) if raw else None
        priority      = getattr(raw, "Priority", None) if raw else None
        teb           = getattr(raw, "Teb", None) if raw else None

        flag_tag    = _dumpflags_str(getattr(ti, "DumpFlags", None))
        exit_status = getattr(ti, "ExitStatus", None)
        exited      = flag_tag == "[EXITED]"

        # A placeholder never gets a create_time/exit_time value, no
        # matter what has_times says about the rest of the result -- it
        # has no real ThreadInfoListStream entry at all, which is not
        # the same claim as "this stream reports no timestamp."
        create_time = (_filetime_to_str(getattr(ti, "CreateTime", 0) or 0)
                       if (has_times and not is_placeholder) else None)
        exit_time   = (_filetime_to_str(getattr(ti, "ExitTime", 0) or 0)
                       if (has_times and not is_placeholder and exited) else None)

        records.append(ThreadRecord(
            tid=ti.ThreadId,
            start_address=hex_address(sa) if sa is not None else None,
            # ntpath.basename, not os.path.basename -- module paths are
            # Windows paths regardless of the host OS this tool runs on
            # (see dumpex.hunt.stomping.memory_scan._module_basename).
            backing_module=ntpath.basename(mod.name) if mod else None,
            module_context=module_context,
            flags=[flag_tag.strip("[]")] if flag_tag else [],
            create_time=create_time,
            exit_time=exit_time,
            exit_status=exit_status,
            kernel_time_100ns=getattr(ti, "KernelTime", None),
            user_time_100ns=getattr(ti, "UserTime", None),
            suspend_count=suspend_count,
            priority=priority,
            teb=hex_address(teb) if teb else None,
        ))

    gaps = []
    if degraded:
        gaps.append(_DEGRADED_REASON)
    if missing_from_info:
        gaps.append(_missing_from_info_reason(missing_from_info))
    if missing_from_base:
        gaps.append(_missing_from_base_reason(missing_from_base))
    if not modules_available:
        gaps.append(_MODULES_UNAVAILABLE_REASON)

    coverage_status = derive_coverage_status(evaluated=True, complete=not gaps)
    return records, coverage_status, gaps, degraded, has_times


def render_threads_console(records, degraded: bool, has_times: bool,
                            coverage_reasons: list = None) -> None:
    if degraded:
        print(YELLOW(
            "  [~] ThreadInfoListStream not present in this dump — falling back to the\n"
            "      base ThreadListStream. StartAddress / CreateTime / ExitTime / Kernel-\n"
            "      UserTime are NOT available in this mode (only TID / SuspendCount /\n"
            "      Priority / TEB, from the raw thread record).\n"))

    # Every OTHER coverage gap (a per-TID mismatch between the two thread
    # streams, or a missing ModuleListStream) gets a plain warning line --
    # the degraded banner above already covers its own specific reason,
    # so it's skipped here to avoid printing the same fact twice.
    for reason in (coverage_reasons or []):
        if reason == _DEGRADED_REASON:
            continue
        print(YELLOW(f"  [~] {reason}\n"))

    for rec in records:
        flag_tag = f"[{rec.flags[0]}]" if rec.flags else ""
        exited   = "EXITED" in rec.flags

        tid_str = f"0x{rec.tid:x}"
        if flag_tag == "[DUMPER]":
            tid_str = CYAN(tid_str) + f" {CYAN(flag_tag)}"
        elif exited:
            tid_str = DIM(tid_str) + f" {DIM(flag_tag)}"
        elif flag_tag:
            tid_str = YELLOW(tid_str) + f" {YELLOW(flag_tag)}"

        print(f"\n  {BOLD('TID')}              {tid_str}")
        if rec.start_address is None:
            backed = DIM("(unknown — requires ThreadInfoListStream)")
            print(f"  {'StartAddress':<16} {DIM('unavailable')}  ← {backed}")
        else:
            if rec.module_context == MODULE_CONTEXT_RESOLVED:
                backed = DIM(rec.backing_module)
            elif rec.module_context == MODULE_CONTEXT_UNREGISTERED:
                # Confirmed: ModuleListStream was available and this
                # address genuinely isn't backed by any known module.
                backed = RED("⚠  NOT IN ANY MODULE")
            else:
                # MODULE_CONTEXT_UNAVAILABLE -- ModuleListStream itself
                # missing; must not read as the confirmed anomaly above.
                backed = YELLOW("(module data unavailable — ModuleListStream missing)")
            print(f"  {'StartAddress':<16} {rec.start_address}  ← {backed}")
        if rec.suspend_count is not None:
            # SuspendCount > 0 has legitimate benign explanations (thread
            # pool management, a debugger attach, a thread not yet resumed
            # after CreateThread) as well as injection-prep ones — report
            # it as notable, not as a definitive verdict either way.
            susp_str = (YELLOW(f"{rec.suspend_count}  (non-zero — can indicate injection prep, "
                               f"debugging, or benign suspension; not conclusive alone)")
                        if rec.suspend_count > 0 else str(rec.suspend_count))
            print(f"  {'SuspendCount':<16} {susp_str}")
        if rec.priority is not None:
            print(f"  {'Priority':<16} {rec.priority}")
        if rec.teb:
            print(f"  {'TEB':<16} {rec.teb}")
        if rec.create_time is not None:
            # Gated on THIS record's own create_time, not the dump-wide
            # has_times flag -- a merged result can mix real
            # ThreadInfoListStream entries with placeholder threads that
            # have none at all, and a placeholder must never print
            # "Exited: (still running)" as if that had been confirmed.
            print(f"  {'Created':<16} {rec.create_time}")
            if exited:
                print(f"  {'Exited':<16} {YELLOW(rec.exit_time)}")
                if rec.exit_status is not None:
                    code_str = f"0x{rec.exit_status:x}"
                    label    = YELLOW(code_str) if rec.exit_status else DIM(code_str + " (clean)")
                    print(f"  {'ExitStatus':<16} {label}")
            else:
                print(f"  {'Exited':<16} {DIM('(still running)')}")
        if rec.kernel_time_100ns is not None:
            print(f"  {'KernelTime':<16} {_duration_100ns_to_str(rec.kernel_time_100ns)}")
        if rec.user_time_100ns is not None:
            print(f"  {'UserTime':<16} {_duration_100ns_to_str(rec.user_time_100ns)}")

    if not has_times and not degraded:
        print(f"\n  {DIM('[~] CreateTime/ExitTime not available — dump was produced without ThreadInfoList stream.')}")

    print(f"\n{GREEN(f'[+] {len(records)} thread(s).')}")


def cmd_threads(mf):
    records, coverage_status, coverage_reasons, degraded, has_times = collect_threads(mf)
    render_threads_console(records, degraded, has_times, coverage_reasons)
    return records, coverage_status, coverage_reasons

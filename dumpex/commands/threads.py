"""--threads command."""
import os
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import get_modules, get_thread_infos, addr_to_module
from dumpex.core.pe_utils import _filetime_to_str, _dumpflags_str, _duration_100ns_to_str
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.output.records import ThreadRecord, hex_address

_DEGRADED_REASON = (
    "ThreadInfoListStream not present; StartAddress/CreateTime/ExitTime/"
    "KernelTime/UserTime unavailable (TID/SuspendCount/Priority/TEB only)"
)


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
    """
    threads_by_tid = {t.ThreadId: t for t in (mf.threads.threads if mf.threads else [])}
    infos   = get_thread_infos(mf)
    modules = get_modules(mf)

    # ThreadInfoListStream is an optional MiniDumpWriteDump capture flag
    # (MiniDumpWithThreadInfo) — its absence is common, not corruption.
    # Falling straight through to "0 thread(s)" when the base ThreadListStream
    # actually has entries would misreport a dump that simply wasn't captured
    # with that extra stream as having no threads at all.
    degraded = not infos and bool(threads_by_tid)
    if degraded:
        infos = [_RawThreadInfo(tid) for tid in threads_by_tid]

    has_times = any(getattr(ti, "CreateTime", None) for ti in infos)

    records = []
    for ti in infos:
        sa  = ti.StartAddress   # may be None in degraded mode — do not coerce to 0
        mod = None if sa is None else addr_to_module(sa, modules)

        raw           = threads_by_tid.get(ti.ThreadId)
        suspend_count = getattr(raw, "SuspendCount", None) if raw else None
        priority      = getattr(raw, "Priority", None) if raw else None
        teb           = getattr(raw, "Teb", None) if raw else None

        flag_tag    = _dumpflags_str(getattr(ti, "DumpFlags", None))
        exit_status = getattr(ti, "ExitStatus", None)
        exited      = flag_tag == "[EXITED]"

        create_time = (_filetime_to_str(getattr(ti, "CreateTime", 0) or 0)
                       if has_times else None)
        exit_time   = (_filetime_to_str(getattr(ti, "ExitTime", 0) or 0)
                       if (has_times and exited) else None)

        records.append(ThreadRecord(
            tid=ti.ThreadId,
            start_address=hex_address(sa) if sa is not None else None,
            backing_module=os.path.basename(mod.name) if mod else None,
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

    coverage_status = derive_coverage_status(evaluated=True, complete=not degraded)
    coverage_reasons = [_DEGRADED_REASON] if degraded else []
    return records, coverage_status, coverage_reasons, degraded, has_times


def render_threads_console(records, degraded: bool, has_times: bool) -> None:
    if degraded:
        print(YELLOW(
            "  [~] ThreadInfoListStream not present in this dump — falling back to the\n"
            "      base ThreadListStream. StartAddress / CreateTime / ExitTime / Kernel-\n"
            "      UserTime are NOT available in this mode (only TID / SuspendCount /\n"
            "      Priority / TEB, from the raw thread record).\n"))

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
            backed = DIM(rec.backing_module) if rec.backing_module else RED("⚠  NOT IN ANY MODULE")
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
        if has_times:
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
    render_threads_console(records, degraded, has_times)
    return records, coverage_status, coverage_reasons

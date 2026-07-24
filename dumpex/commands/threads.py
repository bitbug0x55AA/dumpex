"""--threads command."""
import os
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import get_modules, get_thread_infos, addr_to_module
from dumpex.core.pe_utils import _filetime_to_str, _dumpflags_str, _duration_100ns_to_str


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


def cmd_threads(mf):
    threads  = {t.ThreadId: t for t in (mf.threads.threads if mf.threads else [])}
    infos    = get_thread_infos(mf)
    modules  = get_modules(mf)

    # ThreadInfoListStream is an optional MiniDumpWriteDump capture flag
    # (MiniDumpWithThreadInfo) — its absence is common, not corruption.
    # Falling straight through to "0 thread(s)" when the base ThreadListStream
    # actually has entries would misreport a dump that simply wasn't captured
    # with that extra stream as having no threads at all.
    degraded = not infos and bool(threads)
    if degraded:
        infos = [_RawThreadInfo(tid) for tid in threads]

    has_times = any(getattr(ti, "CreateTime", None) for ti in infos)
    rows      = []

    if degraded:
        print(YELLOW(
            "  [~] ThreadInfoListStream not present in this dump — falling back to the\n"
            "      base ThreadListStream. StartAddress / CreateTime / ExitTime / Kernel-\n"
            "      UserTime are NOT available in this mode (only TID / SuspendCount /\n"
            "      Priority / TEB, from the raw thread record).\n"))

    for ti in infos:
        sa = ti.StartAddress   # may be None in degraded mode — do not coerce to 0
        if sa is None:
            backed = DIM("(unknown — requires ThreadInfoListStream)")
            mod    = None
        else:
            mod    = addr_to_module(sa, modules)
            backed = DIM(os.path.basename(mod.name)) if mod else RED("⚠  NOT IN ANY MODULE")

        raw           = threads.get(ti.ThreadId)
        suspend_count = getattr(raw, "SuspendCount", None) if raw else None
        priority      = getattr(raw, "Priority", None) if raw else None
        teb           = getattr(raw, "Teb", None) if raw else None

        flag_tag    = _dumpflags_str(getattr(ti, "DumpFlags", None))
        exit_status = getattr(ti, "ExitStatus", None)
        exited      = flag_tag == "[EXITED]"

        create_time = _filetime_to_str(getattr(ti, "CreateTime", 0) or 0)
        exit_time   = _filetime_to_str(getattr(ti, "ExitTime",   0) or 0)
        kernel_time = getattr(ti, "KernelTime", None)
        user_time   = getattr(ti, "UserTime",   None)

        tid_str = f"0x{ti.ThreadId:x}"
        if flag_tag == "[DUMPER]":
            tid_str = CYAN(tid_str) + f" {CYAN(flag_tag)}"
        elif exited:
            tid_str = DIM(tid_str) + f" {DIM(flag_tag)}"
        elif flag_tag:
            tid_str = YELLOW(tid_str) + f" {YELLOW(flag_tag)}"

        print(f"\n  {BOLD('TID')}              {tid_str}")
        if sa is None:
            print(f"  {'StartAddress':<16} {DIM('unavailable')}  ← {backed}")
        else:
            print(f"  {'StartAddress':<16} 0x{sa:x}  ← {backed}")
        if suspend_count is not None:
            # SuspendCount > 0 has legitimate benign explanations (thread
            # pool management, a debugger attach, a thread not yet resumed
            # after CreateThread) as well as injection-prep ones — report
            # it as notable, not as a definitive verdict either way.
            susp_str = (YELLOW(f"{suspend_count}  (non-zero — can indicate injection prep, "
                               f"debugging, or benign suspension; not conclusive alone)")
                        if suspend_count > 0 else str(suspend_count))
            print(f"  {'SuspendCount':<16} {susp_str}")
        if priority is not None:
            print(f"  {'Priority':<16} {priority}")
        if teb:
            print(f"  {'TEB':<16} 0x{teb:x}")
        if has_times:
            print(f"  {'Created':<16} {create_time}")
            if exited:
                print(f"  {'Exited':<16} {YELLOW(exit_time)}")
                if exit_status is not None:
                    code_str = f"0x{exit_status:x}"
                    label    = YELLOW(code_str) if exit_status else DIM(code_str + " (clean)")
                    print(f"  {'ExitStatus':<16} {label}")
            else:
                print(f"  {'Exited':<16} {DIM('(still running)')}")
        if kernel_time is not None:
            print(f"  {'KernelTime':<16} {_duration_100ns_to_str(kernel_time)}")
        if user_time is not None:
            print(f"  {'UserTime':<16} {_duration_100ns_to_str(user_time)}")

        rows.append({
            "tid":            f"0x{ti.ThreadId:x}",
            "start_address":  f"0x{sa:x}" if sa is not None else "",
            "backing_module": os.path.basename(mod.name) if mod else "",
            "flags":          flag_tag,
            "create_time":    create_time if has_times else "",
            "exit_time":      exit_time   if (has_times and exited) else "",
            "exit_status":    f"0x{exit_status:x}" if exit_status is not None else "",
            "kernel_time":    kernel_time if kernel_time is not None else "",
            "user_time":      user_time if user_time is not None else "",
            "suspend_count":  suspend_count if suspend_count is not None else "",
            "priority":       priority if priority is not None else "",
            "teb":            f"0x{teb:x}" if teb else "",
        })

    if not has_times and not degraded:
        print(f"\n  {DIM('[~] CreateTime/ExitTime not available — dump was produced without ThreadInfoList stream.')}")

    print(f"\n{GREEN(f'[+] {len(infos)} thread(s).')}")
    return rows

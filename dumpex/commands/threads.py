"""--threads command."""
import os
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import get_modules, get_thread_infos, addr_to_module
from dumpex.core.pe_utils import _filetime_to_str, _dumpflags_str

def cmd_threads(mf):
    threads  = {t.ThreadId: t for t in (mf.threads.threads if mf.threads else [])}
    infos    = get_thread_infos(mf)
    modules  = get_modules(mf)
    has_times = any(getattr(ti, "CreateTime", 0) for ti in infos)
    rows      = []

    for ti in infos:
        sa     = ti.StartAddress or 0
        mod    = addr_to_module(sa, modules)
        backed = DIM(os.path.basename(mod.name)) if mod else RED("⚠  NOT IN ANY MODULE")

        flag_tag    = _dumpflags_str(getattr(ti, "DumpFlags", None))
        exit_status = getattr(ti, "ExitStatus", None)
        exited      = flag_tag == "[EXITED]"

        create_time = _filetime_to_str(getattr(ti, "CreateTime", 0))
        exit_time   = _filetime_to_str(getattr(ti, "ExitTime",   0))
        kernel_time = getattr(ti, "KernelTime", 0)
        user_time   = getattr(ti, "UserTime",   0)

        tid_str = f"0x{ti.ThreadId:x}"
        if flag_tag == "[DUMPER]":
            tid_str = CYAN(tid_str) + f" {CYAN(flag_tag)}"
        elif exited:
            tid_str = DIM(tid_str) + f" {DIM(flag_tag)}"
        elif flag_tag:
            tid_str = YELLOW(tid_str) + f" {YELLOW(flag_tag)}"

        print(f"\n  {BOLD('TID')}              {tid_str}")
        print(f"  {'StartAddress':<16} 0x{sa:x}  ← {backed}")
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
        print(f"  {'KernelTime':<16} {kernel_time}")
        print(f"  {'UserTime':<16} {user_time}")

        rows.append({
            "tid":            f"0x{ti.ThreadId:x}",
            "start_address":  f"0x{sa:x}",
            "backing_module": os.path.basename(mod.name) if mod else "",
            "flags":          flag_tag,
            "create_time":    create_time if has_times else "",
            "exit_time":      exit_time   if (has_times and exited) else "",
            "exit_status":    f"0x{exit_status:x}" if exit_status is not None else "",
            "kernel_time":    kernel_time,
            "user_time":      user_time,
        })

    if not has_times:
        print(f"\n  {DIM('[~] CreateTime/ExitTime not available — dump was produced without ThreadInfoList stream.')}")

    print(f"\n{GREEN(f'[+] {len(infos)} thread(s).')}")
    return rows


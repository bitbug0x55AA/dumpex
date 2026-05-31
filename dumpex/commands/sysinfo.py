"""--sysinfo and --pid commands."""
import os
import datetime
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import get_modules, get_thread_infos, va_to_file_offset

def cmd_sysinfo(mf: MinidumpFile):
    import datetime

    si  = mf.sysinfo
    mi  = mf.misc_info
    peb = mf.peb

    # Hostname from environment variables
    hostname = "(unknown)"
    username = "(unknown)"
    if peb and peb.environment_variables:
        for env in peb.environment_variables:
            name = env.get("name", "") if isinstance(env, dict) else env[0]
            val  = env.get("value", "") if isinstance(env, dict) else env[1]
            if name.upper() == "COMPUTERNAME":
                hostname = val
            if name.upper() == "USERNAME":
                username = val

    print(f"\n{BOLD('═══ SYSTEM INFO ═══')}")

    # ── OS ──────────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Operating System')}")
    if si:
        os_name = si.OperatingSystem or "Windows (unknown version)"
        build   = si.BuildNumber if si.BuildNumber is not None else "?"
        major   = si.MajorVersion if si.MajorVersion is not None else "?"
        minor   = si.MinorVersion if si.MinorVersion is not None else "?"
        csd     = f" {si.CSDVersion}" if si.CSDVersion else ""
        arch    = si.ProcessorArchitecture.name if si.ProcessorArchitecture else "?"
        ptype   = si.ProductType.name if si.ProductType else "?"
        print(f"    {'OS':<22} {os_name}{csd}")
        print(f"    {'Version':<22} {major}.{minor}.{build}")
        print(f"    {'Architecture':<22} {arch}")
        print(f"    {'Product Type':<22} {ptype}")
    else:
        print(f"    {DIM('(sysinfo stream not available)')}")

    # ── Host ────────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Host')}")
    print(f"    {'Hostname':<22} {hostname}")
    print(f"    {'Username':<22} {username}")

    # ── Process ─────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Process')}")
    if mi and mi.ProcessId:
        print(f"    {'PID':<22} {mi.ProcessId} (0x{mi.ProcessId:x})")
    if mi and mi.ProcessCreateTime:
        try:
            ts = datetime.datetime.fromtimestamp(mi.ProcessCreateTime, tz=datetime.timezone.utc)
            print(f"    {'Process Start (UTC)':<22} {ts.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception:
            print(f"    {'Process Start':<22} {mi.ProcessCreateTime}")
    if mi and mi.ProcessUserTime is not None:
        print(f"    {'CPU User Time':<22} {mi.ProcessUserTime}s")
    if mi and mi.ProcessKernelTime is not None:
        print(f"    {'CPU Kernel Time':<22} {mi.ProcessKernelTime}s")
    if peb:
        print(f"    {'Image Path':<22} {peb.image_path or '(none)'}")
        print(f"    {'Command Line':<22} {peb.command_line or '(none)'}")
        print(f"    {'Working Dir':<22} {peb.current_directory or '(none)'}")
        print(f"    {'BeingDebugged':<22} {peb.being_debugged}")

    # ── CPU ─────────────────────────────────────────────────────────────
    if si:
        print(f"\n  {BOLD('CPU')}")
        print(f"    {'Processors':<22} {si.NumberOfProcessors}")
        if si.VendorId:
            try:
                vendor = bytes(si.VendorId).decode("ascii", errors="replace").rstrip("\x00")
                print(f"    {'Vendor':<22} {vendor}")
            except Exception:
                pass
        if mi and mi.ProcessorCurrentMhz:
            print(f"    {'Current MHz':<22} {mi.ProcessorCurrentMhz}")
        if mi and mi.ProcessorMaxMhz:
            print(f"    {'Max MHz':<22} {mi.ProcessorMaxMhz}")

    # ── Dump metadata ────────────────────────────────────────────────────
    print(f"\n  {BOLD('Dump File')}")
    print(f"    {'File':<22} {os.path.basename(mf.filename)}")
    thread_count = len(mf.threads.threads) if mf.threads else 0
    module_count = len(mf.modules.modules) if mf.modules else 0
    if mf.threads:
        print(f"    {'Threads in dump':<22} {thread_count}")
    if mf.modules:
        print(f"    {'Modules in dump':<22} {module_count}")
    print()

    proc_start = None
    if mi and mi.ProcessCreateTime:
        try:
            proc_start = datetime.datetime.fromtimestamp(
                mi.ProcessCreateTime, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            proc_start = str(mi.ProcessCreateTime)

    pid_val = mi.ProcessId if mi and mi.ProcessId else None
    return {
        "dump_file":         os.path.basename(mf.filename),
        "hostname":          hostname,
        "username":          username,
        "os":                (si.OperatingSystem or "") if si else "",
        "os_version":        (f"{si.MajorVersion}.{si.MinorVersion}.{si.BuildNumber}"
                              if si and all(x is not None for x in
                              [si.MajorVersion, si.MinorVersion, si.BuildNumber]) else ""),
        "architecture":      (si.ProcessorArchitecture.name if si and si.ProcessorArchitecture else ""),
        "product_type":      (si.ProductType.name if si and si.ProductType else ""),
        "pid":               pid_val,
        "pid_hex":           f"0x{pid_val:x}" if pid_val else "",
        "process_start_utc": proc_start or "",
        "image_path":        (peb.image_path or "") if peb else "",
        "command_line":      (peb.command_line or "") if peb else "",
        "processors":        (si.NumberOfProcessors if si else ""),
        "threads_in_dump":   thread_count,
        "modules_in_dump":   module_count,
    }


def cmd_pid(mf: MinidumpFile):
    """
    Report the Process ID recorded in the minidump.

    Tries multiple streams in priority order so the result is as reliable
    as possible even when a dump was produced by a non-standard tool:

      1. MINIDUMP_MISC_INFO  – most authoritative; written by MiniDumpWriteDump
      2. Thread list         – all threads share the same owning PID on Windows;
                               reported as a cross-check when MiscInfo is absent
      3. Exception stream    – contains ThreadId; used purely as a last resort
         (gives TID, not PID, so it is labelled accordingly)
    """
    pid      = None
    source   = None
    warnings = []

    # ── 1. MiscInfo (most reliable) ──────────────────────────────────────
    mi = mf.misc_info
    if mi and getattr(mi, "ProcessId", None):
        pid    = mi.ProcessId
        source = "MINIDUMP_MISC_INFO (ProcessId field)"

    # ── 2. Thread list cross-check / fallback ────────────────────────────
    #    minidump-python exposes thread.ThreadId but NOT thread.ProcessId
    #    directly; however, we can cross-check that MiscInfo PID is plausible
    #    by confirming threads exist.  When MiscInfo is missing we report the
    #    thread count as evidence and surface any TID that might help.
    threads = mf.threads.threads if mf.threads else []
    if threads and pid is None:
        tids = [t.ThreadId for t in threads]
        warnings.append(
            f"MiscInfo stream absent — PID not directly recoverable from thread list.\n"
            f"    {len(tids)} thread(s) found: "
            + ", ".join(f"0x{t:x}" for t in tids[:8])
            + (" …" if len(tids) > 8 else "")
        )

    # ── 3. Exception stream – last resort (gives TID, not PID) ───────────
    exc = getattr(mf, "exception", None)
    exc_tid = None
    if exc and pid is None:
        try:
            exc_tid = exc.ThreadId
        except AttributeError:
            pass
        if exc_tid:
            warnings.append(
                f"Exception stream present: faulting TID = 0x{exc_tid:x} "
                f"(this is a Thread ID, not a Process ID)"
            )

    # ── Output ────────────────────────────────────────────────────────────
    print(f"\n{BOLD('═══ PROCESS ID ═══')}")

    if pid is not None:
        print(f"  {'PID (decimal)':<26} {GREEN(str(pid))}")
        print(f"  {'PID (hex)':<26} {GREEN(f'0x{pid:x}')}")
        print(f"  {'Source':<26} {DIM(source)}")
        if threads:
            print(f"  {'Threads in dump':<26} {len(threads)}")
    else:
        print(f"  {YELLOW('[!] ProcessId not found in MiscInfo stream.')}")

    for w in warnings:
        print(f"\n  {YELLOW('[~]')} {w}")

    if pid is None and not warnings:
        print(f"  {RED('[!] Could not determine PID — dump may lack MiscInfo, thread list, and exception stream.')}")

    print()
    return {
        "pid":          pid,
        "pid_hex":      f"0x{pid:x}" if pid is not None else "",
        "source":       source or "",
        "thread_count": len(threads),
        "exc_tid":      f"0x{exc_tid:x}" if exc_tid else "",
        "warnings":     warnings,
    }


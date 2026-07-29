"""--sysinfo and --pid commands."""
import os
import datetime
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.output.records import ProcessInfoRecord

def _os_display_name(si) -> str:
    """
    Return a corrected OS name for `si`, fixing the upstream minidump
    library's guess_os(): its build-number table predates Windows 11, so it
    falls through to the generic "MajorVersion==10, MinorVersion==0,
    ProductType==WORKSTATION" branch and always reports "Windows 10" —
    even though Windows 11 keeps the same 10.0.x NT version and is only
    distinguishable by BuildNumber >= 22000.
    """
    os_name = si.OperatingSystem or "Windows (unknown version)"
    ptype   = si.ProductType.name if si.ProductType else None
    if (os_name == "Windows 10" and si.MajorVersion == 10 and si.MinorVersion == 0
            and ptype == "VER_NT_WORKSTATION"
            and isinstance(si.BuildNumber, int) and si.BuildNumber >= 22000):
        return "Windows 11"
    return os_name


# ── --sysinfo ────────────────────────────────────────────────────────────

def collect_sysinfo(mf: MinidumpFile):
    """
    Pure data, no printing. Returns (records, coverage_status,
    coverage_reasons) -- records is a single-element list (see the v2
    migration plan's "always a records array" convention, even for a
    one-record result). 'partial' coverage when the sysinfo/misc-info/PEB
    streams are individually missing.
    """
    si  = mf.sysinfo
    mi  = mf.misc_info
    peb = mf.peb

    hostname = None
    username = None
    if peb and peb.environment_variables:
        for env in peb.environment_variables:
            name = env.get("name", "") if isinstance(env, dict) else env[0]
            val  = env.get("value", "") if isinstance(env, dict) else env[1]
            if name.upper() == "COMPUTERNAME":
                hostname = val
            if name.upper() == "USERNAME":
                username = val

    proc_start = None
    if mi and mi.ProcessCreateTime:
        try:
            proc_start = datetime.datetime.fromtimestamp(
                mi.ProcessCreateTime, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            proc_start = str(mi.ProcessCreateTime)

    cpu_vendor = None
    if si and si.VendorId:
        try:
            cpu_vendor = bytes(si.VendorId).decode("ascii", errors="replace").rstrip("\x00")
        except Exception:
            cpu_vendor = None

    record = ProcessInfoRecord(
        pid=(mi.ProcessId if mi and mi.ProcessId else None),
        dump_file=os.path.basename(mf.filename),
        hostname=hostname,
        username=username,
        os=(_os_display_name(si) if si else None),
        os_version=(f"{si.MajorVersion}.{si.MinorVersion}.{si.BuildNumber}"
                    if si and all(x is not None for x in
                    [si.MajorVersion, si.MinorVersion, si.BuildNumber]) else None),
        architecture=(si.ProcessorArchitecture.name if si and si.ProcessorArchitecture else None),
        product_type=(si.ProductType.name if si and si.ProductType else None),
        process_start_utc=proc_start,
        image_path=(peb.image_path or None) if peb else None,
        command_line=(peb.command_line or None) if peb else None,
        current_directory=(peb.current_directory or None) if peb else None,
        processors=(si.NumberOfProcessors if si else None),
        cpu_vendor=cpu_vendor,
        cpu_current_mhz=(mi.ProcessorCurrentMhz if mi and mi.ProcessorCurrentMhz else None),
        cpu_max_mhz=(mi.ProcessorMaxMhz if mi and mi.ProcessorMaxMhz else None),
        process_user_time_seconds=(mi.ProcessUserTime if mi and mi.ProcessUserTime is not None else None),
        process_kernel_time_seconds=(mi.ProcessKernelTime if mi and mi.ProcessKernelTime is not None else None),
        thread_count=(len(mf.threads.threads) if mf.threads else 0),
        module_count=(len(mf.modules.modules) if mf.modules else 0),
    )

    missing = []
    if not si:
        missing.append("SystemInfoStream not present")
    if not mi:
        missing.append("MiscInfo stream not present")
    if not peb:
        missing.append("PEB not available (requires sysinfo + thread list)")
    coverage_status = derive_coverage_status(evaluated=True, complete=not missing)
    return [record], coverage_status, missing, bool(peb), bool(mf.threads), bool(mf.modules)


def render_sysinfo_console(record: ProcessInfoRecord, peb_present: bool,
                            threads_present: bool, modules_present: bool) -> None:
    print(f"\n{BOLD('═══ SYSTEM INFO ═══')}")

    # ── OS ──────────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Operating System')}")
    if record.os is not None:
        print(f"    {'OS':<22} {record.os}")
        print(f"    {'Version':<22} {record.os_version or '?'}")
        print(f"    {'Architecture':<22} {record.architecture or '?'}")
        print(f"    {'Product Type':<22} {record.product_type or '?'}")
    else:
        print(f"    {DIM('(sysinfo stream not available)')}")

    # ── Host ────────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Host')}")
    print(f"    {'Hostname':<22} {record.hostname or '(unknown)'}")
    print(f"    {'Username':<22} {record.username or '(unknown)'}")

    # ── Process ─────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Process')}")
    if record.pid is not None:
        print(f"    {'PID':<22} {record.pid} (0x{record.pid:x})")
    if record.process_start_utc:
        print(f"    {'Process Start (UTC)':<22} {record.process_start_utc}")
    if record.process_user_time_seconds is not None:
        print(f"    {'CPU User Time':<22} {record.process_user_time_seconds}s")
    if record.process_kernel_time_seconds is not None:
        print(f"    {'CPU Kernel Time':<22} {record.process_kernel_time_seconds}s")
    if peb_present:
        print(f"    {'Image Path':<22} {record.image_path or '(none)'}")
        print(f"    {'Command Line':<22} {record.command_line or '(none)'}")
        print(f"    {'Working Dir':<22} {record.current_directory or '(none)'}")

    # ── CPU ─────────────────────────────────────────────────────────────
    if record.os is not None:
        print(f"\n  {BOLD('CPU')}")
        print(f"    {'Processors':<22} {record.processors}")
        if record.cpu_vendor:
            print(f"    {'Vendor':<22} {record.cpu_vendor}")
        if record.cpu_current_mhz:
            print(f"    {'Current MHz':<22} {record.cpu_current_mhz}")
        if record.cpu_max_mhz:
            print(f"    {'Max MHz':<22} {record.cpu_max_mhz}")

    # ── Dump metadata ────────────────────────────────────────────────────
    print(f"\n  {BOLD('Dump File')}")
    print(f"    {'File':<22} {record.dump_file}")
    if threads_present:
        print(f"    {'Threads in dump':<22} {record.thread_count}")
    if modules_present:
        print(f"    {'Modules in dump':<22} {record.module_count}")
    print()


def cmd_sysinfo(mf: MinidumpFile):
    records, coverage_status, coverage_reasons, peb_present, threads_present, modules_present = \
        collect_sysinfo(mf)
    render_sysinfo_console(records[0], peb_present, threads_present, modules_present)
    return records, coverage_status, coverage_reasons


# ── --pid ────────────────────────────────────────────────────────────────

def collect_pid(mf: MinidumpFile):
    """
    Report the Process ID recorded in the minidump.

    Tries multiple streams in priority order so the result is as reliable
    as possible even when a dump was produced by a non-standard tool:

      1. MINIDUMP_MISC_INFO  – most authoritative; written by MiniDumpWriteDump
      2. Thread list         – all threads share the same owning PID on Windows;
                               reported as a cross-check when MiscInfo is absent
      3. Exception stream    – contains ThreadId; used purely as a last resort
         (gives TID, not PID, so it is labelled accordingly)

    Pure data, no printing. Returns (records, coverage_status,
    coverage_reasons) -- 'complete' only when MiscInfo directly supplied
    the PID; any fallback path is 'partial' (reuses the same human-
    readable explanations the console has always shown, now surfaced as
    coverage_reasons instead of only being printed).
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

    record = ProcessInfoRecord(
        pid=pid,
        source=source,
        thread_count=len(threads),
        exc_tid=exc_tid,
    )
    coverage_status = derive_coverage_status(evaluated=True, complete=(pid is not None))
    return [record], coverage_status, warnings


def render_pid_console(record: ProcessInfoRecord, coverage_reasons: list) -> None:
    print(f"\n{BOLD('═══ PROCESS ID ═══')}")

    if record.pid is not None:
        print(f"  {'PID (decimal)':<26} {GREEN(str(record.pid))}")
        print(f"  {'PID (hex)':<26} {GREEN(f'0x{record.pid:x}')}")
        print(f"  {'Source':<26} {DIM(record.source)}")
        if record.thread_count:
            print(f"  {'Threads in dump':<26} {record.thread_count}")
    else:
        print(f"  {YELLOW('[!] ProcessId not found in MiscInfo stream.')}")

    for w in coverage_reasons:
        print(f"\n  {YELLOW('[~]')} {w}")

    if record.pid is None and not coverage_reasons:
        print(f"  {RED('[!] Could not determine PID — dump may lack MiscInfo, thread list, and exception stream.')}")

    print()


def cmd_pid(mf: MinidumpFile):
    records, coverage_status, coverage_reasons = collect_pid(mf)
    render_pid_console(records[0], coverage_reasons)
    return records, coverage_status, coverage_reasons

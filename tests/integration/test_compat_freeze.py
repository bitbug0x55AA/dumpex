"""
Table-driven compatibility-freeze suite for the six recon commands.

For every legal source-state scenario (absent / present_empty / present --
SourceState.FAILED is explicitly N/A for all six of these commands, see
dumpex.output.coverage's SourceState docstring: none of their mf.<stream>
accesses are wrapped in a try/except, so a read failure propagates as a
fatal exception rather than becoming a SOURCE_FAILED observation), this
asserts all four output surfaces at once, through one real cli.main()
invocation per scenario:

  - process exit code
  - console text (everything printed BEFORE the two dynamic "JSON/CSV
    written -> <tmp path> (... sha256=...)" trailer lines, which embed a
    per-run tmp path and hash and are therefore deliberately excluded)
  - the full `result` object written to --json (kind/execution_status/
    coverage/summary/data.records -- not `meta`, which carries the dump's
    real absolute path/size/sha256 and per-run timestamps)
  - the full --csv file content, byte for byte

Every expected value below was captured by actually running the code
(not hand-guessed) and cross-checked against the existing per-command
unit/integration tests before being frozen here -- this suite's job is to
catch any FUTURE unintended drift in any of these four surfaces, not to
re-derive correctness from scratch. A change to any of these four blocks
for an existing scenario is a compatibility break and must be a deliberate,
reviewed decision, not an incidental side effect of an unrelated edit.
"""
import json
import os
import sys
import tempfile

import pytest

import dumpex.cli as cli
from tests.fixtures.fakes import (
    FakeMF, Region, Module, Thread, ThreadInfo, Ctx, FakeStream, Peb, MiscInfo,
    SysInfo, ExceptionStream,
)


def _make_dump_file() -> str:
    fd, path = tempfile.mkstemp(suffix=".dmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"synthetic dump content")
    return path


def _console_before_write_confirmations(full_console: str) -> str:
    idx = full_console.find("  [\u00b7] JSON written")
    return full_console[:idx] if idx != -1 else full_console


def _run(monkeypatch, tmp_path, argv, mf):
    dump_path = _make_dump_file()
    try:
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_json = str(tmp_path / "out.json")
        out_csv = str(tmp_path / "out.csv")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, *argv, "--json", out_json, "--csv", out_csv])
        exit_code = 0
        try:
            cli.main()
        except SystemExit as exc:
            exit_code = exc.code
        doc = json.loads(open(out_json, encoding="utf-8").read())
        csv_text = open(out_csv, encoding="utf-8").read()
        return exit_code, doc, csv_text
    finally:
        os.remove(dump_path)


# ── scenario builders (fresh FakeMF per invocation) ───────────────────────

def _list_absent(): return FakeMF()

def _list_present_empty():
    mf = FakeMF(); mf.memory_info = FakeStream([], "infos"); return mf

def _list_present():
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    return mf

def _modules_absent(): return FakeMF()

def _modules_present_empty():
    mf = FakeMF(); mf.modules = FakeStream([], "modules"); return mf

def _modules_present():
    mf = FakeMF()
    mf.modules = FakeStream([Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")],
                             "modules")
    return mf

def _peb_absent(): return FakeMF()

def _peb_present():
    mf = FakeMF(); mf.peb = Peb(0x140000000, r"C:\test.exe"); return mf

def _threads_all_absent(): return FakeMF()

def _threads_degraded():
    mf = FakeMF(); mf.threads = FakeStream([Thread(1, Ctx(0))], "threads"); return mf

def _threads_present_empty():
    mf = FakeMF()
    mf.threads     = FakeStream([], "threads")
    mf.thread_info = FakeStream([], "infos")
    mf.modules     = FakeStream([], "modules")
    return mf

def _threads_complete():
    mf = FakeMF()
    mf.threads     = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    mf.modules     = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
    return mf

def _pid_all_absent(): return FakeMF()

def _pid_complete():
    mf = FakeMF(); mf.misc_info = MiscInfo(process_id=4321); return mf

def _pid_thread_fallback():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0)), Thread(10, Ctx(0))], "threads")
    return mf

def _pid_exception_fallback():
    mf = FakeMF()
    mf.threads   = FakeStream([Thread(9, Ctx(0))], "threads")
    mf.exception = ExceptionStream(9)
    return mf

def _sysinfo_all_absent(): return FakeMF()

def _sysinfo_complete():
    mf = FakeMF()
    mf.sysinfo    = SysInfo()
    mf.misc_info  = MiscInfo(process_id=1234)
    mf.peb        = Peb(0x140000000, r"C:\test.exe")
    mf.threads    = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules    = FakeStream([Module(0, 0, "a")], "modules")
    return mf


# ── frozen scenarios ───────────────────────────────────────────────────
# (name, argv, mf_builder, exit_code, console, result, csv)

SCENARIOS = [
    (
        "list_absent", ["--list"], _list_absent, 4,
        '  [~] MemoryInfoListStream not present in this dump\n\n'
        'Address                  Size           State          Protection                       Type\n'
        '────────────────────────────────────────────────────────────────────────────────────────────────────\n'
        '\n[+] 0 region(s) shown.\n',
        {"kind": "memory_regions", "execution_status": "completed",
         "coverage": {"status": "not_evaluated",
                      "reasons": ["MemoryInfoListStream not present in this dump"]},
         "summary": {"count": 0}, "data": {"records": []}},
        '## memory_regions / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'memory_regions,completed,not_evaluated,MemoryInfoListStream not present in this dump,0\n\n\n',
    ),
    (
        "list_present_empty", ["--list"], _list_present_empty, 0,
        '\nAddress                  Size           State          Protection                       Type\n'
        '────────────────────────────────────────────────────────────────────────────────────────────────────\n'
        '\n[+] 0 region(s) shown.\n',
        {"kind": "memory_regions", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 0}, "data": {"records": []}},
        '## memory_regions / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'memory_regions,completed,complete,,0\n\n\n',
    ),
    (
        "list_present", ["--list"], _list_present, 0,
        '\nAddress                  Size           State          Protection                       Type\n'
        '────────────────────────────────────────────────────────────────────────────────────────────────────\n'
        '0x0000000000001000       0x2000         MEM_COMMIT     PAGE_EXECUTE_READWRITE           MEM_PRIVATE\n'
        '\n[+] 1 region(s) shown.\n',
        {"kind": "memory_regions", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 1},
         "data": {"records": [{"base_address": "0x0000000000001000", "size": 8192,
                                "state": "MEM_COMMIT", "protect": "PAGE_EXECUTE_READWRITE",
                                "type": "MEM_PRIVATE", "suspicious": True}]}},
        '## memory_regions / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'memory_regions,completed,complete,,1\n\n\n'
        '## memory_regions / records\nbase_address,size,state,protect,type,suspicious\n\n'
        '0x0000000000001000,8192,MEM_COMMIT,PAGE_EXECUTE_READWRITE,MEM_PRIVATE,True\n\n\n',
    ),
    (
        "modules_absent", ["--modules"], _modules_absent, 4,
        '  [~] ModuleListStream not present in this dump\n\n[+] 0 module(s).\n',
        {"kind": "modules", "execution_status": "completed",
         "coverage": {"status": "not_evaluated",
                      "reasons": ["ModuleListStream not present in this dump"]},
         "summary": {"count": 0}, "data": {"records": []}},
        '## modules / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'modules,completed,not_evaluated,ModuleListStream not present in this dump,0\n\n\n',
    ),
    (
        "modules_present_empty", ["--modules"], _modules_present_empty, 0,
        '\n[+] 0 module(s).\n',
        {"kind": "modules", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 0}, "data": {"records": []}},
        '## modules / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'modules,completed,complete,,0\n\n\n',
    ),
    (
        "modules_present", ["--modules"], _modules_present, 0,
        '\n  ntdll.dll\n  Full path          C:\\Windows\\System32\\ntdll.dll\n'
        '  Base \u2192 End         0x0000000140000000 \u2192 0x0000000140005000  (size 0x5000)\n'
        '  Compiled (UTC)     (not set)\n\n[+] 1 module(s).\n',
        {"kind": "modules", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 1},
         "data": {"records": [{"name": "ntdll.dll",
                                "full_path": "C:\\Windows\\System32\\ntdll.dll",
                                "base_address": "0x0000000140000000",
                                "end_address": "0x0000000140005000", "size": 20480,
                                "compiled_utc": "(not set)", "file_version": None,
                                "checksum": None, "anomaly_flags": []}]}},
        '## modules / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'modules,completed,complete,,1\n\n\n'
        '## modules / records\nname,full_path,base_address,end_address,size,compiled_utc,'
        'file_version,checksum,anomaly_flags\n\n'
        'ntdll.dll,C:\\Windows\\System32\\ntdll.dll,0x0000000140000000,0x0000000140005000,'
        '20480,(not set),,,[]\n\n\n',
    ),
    (
        "peb_absent", ["--peb"], _peb_absent, 4,
        '[!] PEB could not be parsed (missing sysinfo or thread list in dump)\n',
        {"kind": "peb", "execution_status": "completed",
         "coverage": {"status": "not_evaluated",
                      "reasons": ["PEB could not be parsed (missing sysinfo or thread list in dump)"]},
         "summary": {"count": 1},
         "data": {"records": [{"peb_address": None, "image_base_address": None,
                                "being_debugged": None, "image_path": None,
                                "command_line": None, "window_title": None, "dll_path": None,
                                "current_directory": None, "standard_input": None,
                                "standard_output": None, "standard_error": None,
                                "environment_variables": None}]}},
        '## peb / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'peb,completed,not_evaluated,PEB could not be parsed (missing sysinfo or thread list in dump),1\n\n\n'
        '## peb / records\npeb_address,image_base_address,being_debugged,image_path,command_line,'
        'window_title,dll_path,current_directory,standard_input,standard_output,standard_error\n\n'
        ',,,,,,,,,,\n\n\n',
    ),
    (
        "peb_present", ["--peb"], _peb_present, 0,
        '\n\u2550\u2550\u2550 PEB \u2550\u2550\u2550\n  PEB Address              0x0000000000000000\n'
        '  BeingDebugged            False\n  ImageBaseAddress         0x0000000140000000\n'
        '  ImagePath                C:\\test.exe\n  CommandLine              (none)\n'
        '  WindowTitle              (none)\n  DllPath                  (none)\n'
        '  CurrentDirectory         (none)\n  StandardInput            None\n'
        '  StandardOutput           None\n  StandardError            None\n',
        {"kind": "peb", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 1},
         "data": {"records": [{"peb_address": "0x0000000000000000",
                                "image_base_address": "0x0000000140000000",
                                "being_debugged": False, "image_path": "C:\\test.exe",
                                "command_line": None, "window_title": None, "dll_path": None,
                                "current_directory": None, "standard_input": None,
                                "standard_output": None, "standard_error": None,
                                "environment_variables": None}]}},
        '## peb / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'peb,completed,complete,,1\n\n\n'
        '## peb / records\npeb_address,image_base_address,being_debugged,image_path,command_line,'
        'window_title,dll_path,current_directory,standard_input,standard_output,standard_error\n\n'
        '0x0000000000000000,0x0000000140000000,False,C:\\test.exe,,,,,,,\n\n\n',
    ),
    (
        "threads_all_absent", ["--threads"], _threads_all_absent, 4,
        '  [~] Neither ThreadListStream nor ThreadInfoListStream present in this dump\n\n\n'
        '  [~] CreateTime/ExitTime not available in the captured ThreadInfo data.\n\n[+] 0 thread(s).\n',
        {"kind": "threads", "execution_status": "completed",
         "coverage": {"status": "not_evaluated",
                      "reasons": ["Neither ThreadListStream nor ThreadInfoListStream present in this dump"]},
         "summary": {"count": 0}, "data": {"records": []}},
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'threads,completed,not_evaluated,Neither ThreadListStream nor ThreadInfoListStream '
        'present in this dump,0\n\n\n',
    ),
    (
        "threads_degraded", ["--threads"], _threads_degraded, 3,
        '  [~] ThreadInfoListStream not present in this dump \u2014 falling back to the\n'
        '      base ThreadListStream. StartAddress / CreateTime / ExitTime / Kernel-\n'
        '      UserTime are NOT available in this mode (only TID / SuspendCount /\n'
        '      Priority / TEB, from the raw thread record).\n\n'
        '  [~] ModuleListStream not present; thread backing-module classification unavailable '
        '(cannot confirm whether a start address is backed by a known module)\n\n\n'
        '  TID              0x1\n'
        '  StartAddress     unavailable  \u2190 (unknown \u2014 requires ThreadInfoListStream)\n\n'
        '[+] 1 thread(s).\n',
        {"kind": "threads", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": [
                          "ThreadInfoListStream not present; StartAddress/CreateTime/ExitTime/"
                          "KernelTime/UserTime unavailable (TID/SuspendCount/Priority/TEB only)",
                          "ModuleListStream not present; thread backing-module classification "
                          "unavailable (cannot confirm whether a start address is backed by a "
                          "known module)"]},
         "summary": {"count": 1},
         "data": {"records": [{"tid": 1, "start_address": None, "backing_module": None,
                                "module_context": None, "flags": [], "create_time": None,
                                "exit_time": None, "exit_status": None,
                                "kernel_time_100ns": None, "user_time_100ns": None,
                                "suspend_count": None, "priority": None, "teb": None}]}},
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'threads,completed,partial,ThreadInfoListStream not present; StartAddress/CreateTime/'
        'ExitTime/KernelTime/UserTime unavailable (TID/SuspendCount/Priority/TEB only); '
        'ModuleListStream not present; thread backing-module classification unavailable '
        '(cannot confirm whether a start address is backed by a known module),1\n\n\n'
        '## threads / records\ntid,start_address,backing_module,module_context,flags,create_time,'
        'exit_time,exit_status,kernel_time_100ns,user_time_100ns,suspend_count,priority,teb\n\n'
        '1,,,,[],,,,,,,,\n\n\n',
    ),
    (
        "threads_present_empty", ["--threads"], _threads_present_empty, 0,
        '\n  [~] CreateTime/ExitTime not available in the captured ThreadInfo data.\n\n[+] 0 thread(s).\n',
        {"kind": "threads", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 0}, "data": {"records": []}},
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'threads,completed,complete,,0\n\n\n',
    ),
    (
        "threads_complete", ["--threads"], _threads_complete, 0,
        '\n  TID              0x1\n  StartAddress     0x000000007ffe0000  \u2190 legit.dll\n\n'
        '  [~] CreateTime/ExitTime not available in the captured ThreadInfo data.\n\n[+] 1 thread(s).\n',
        {"kind": "threads", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 1},
         "data": {"records": [{"tid": 1, "start_address": "0x000000007ffe0000",
                                "backing_module": "legit.dll", "module_context": "resolved",
                                "flags": [], "create_time": None, "exit_time": None,
                                "exit_status": None, "kernel_time_100ns": None,
                                "user_time_100ns": None, "suspend_count": None,
                                "priority": None, "teb": None}]}},
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'threads,completed,complete,,1\n\n\n'
        '## threads / records\ntid,start_address,backing_module,module_context,flags,create_time,'
        'exit_time,exit_status,kernel_time_100ns,user_time_100ns,suspend_count,priority,teb\n\n'
        '1,0x000000007ffe0000,legit.dll,resolved,[],,,,,,,,\n\n\n',
    ),
    (
        "pid_all_absent", ["--pid"], _pid_all_absent, 4,
        '\n\u2550\u2550\u2550 PROCESS ID \u2550\u2550\u2550\n  [!] ProcessId not found in MiscInfo stream.\n\n'
        '  [~] MiscInfo, thread list, and exception stream are all absent from this dump; '
        'PID could not be evaluated\n\n',
        {"kind": "pid", "execution_status": "completed",
         "coverage": {"status": "not_evaluated",
                      "reasons": ["MiscInfo, thread list, and exception stream are all absent "
                                  "from this dump; PID could not be evaluated"]},
         "summary": {"count": 1},
         "data": {"records": [{"pid": None, "source": None, "thread_count": None,
                                "exc_tid": None}]}},
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'pid,completed,not_evaluated,"MiscInfo, thread list, and exception stream are all '
        'absent from this dump; PID could not be evaluated",1\n\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n\n,,,\n\n\n',
    ),
    (
        "pid_complete", ["--pid"], _pid_complete, 0,
        '\n\u2550\u2550\u2550 PROCESS ID \u2550\u2550\u2550\n  PID (decimal)              4321\n'
        '  PID (hex)                  0x10e1\n'
        '  Source                     MINIDUMP_MISC_INFO (ProcessId field)\n\n',
        {"kind": "pid", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 1},
         "data": {"records": [{"pid": 4321, "source": "MINIDUMP_MISC_INFO (ProcessId field)",
                                "thread_count": None, "exc_tid": None}]}},
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'pid,completed,complete,,1\n\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n\n'
        '4321,MINIDUMP_MISC_INFO (ProcessId field),,\n\n\n',
    ),
    (
        "pid_thread_fallback", ["--pid"], _pid_thread_fallback, 3,
        '\n\u2550\u2550\u2550 PROCESS ID \u2550\u2550\u2550\n  [!] ProcessId not found in MiscInfo stream.\n\n'
        '  [~] MiscInfo stream absent \u2014 PID not directly recoverable from thread list.\n'
        '    2 thread(s) found: 0x9, 0xa\n\n',
        {"kind": "pid", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["MiscInfo stream absent \u2014 PID not directly recoverable "
                                  "from thread list.\n    2 thread(s) found: 0x9, 0xa"]},
         "summary": {"count": 1},
         "data": {"records": [{"pid": None, "source": None, "thread_count": 2,
                                "exc_tid": None}]}},
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'pid,completed,partial,"MiscInfo stream absent \u2014 PID not directly recoverable from '
        'thread list.\n    2 thread(s) found: 0x9, 0xa",1\n\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n\n,,2,\n\n\n',
    ),
    (
        "pid_exception_fallback", ["--pid"], _pid_exception_fallback, 3,
        '\n\u2550\u2550\u2550 PROCESS ID \u2550\u2550\u2550\n  [!] ProcessId not found in MiscInfo stream.\n\n'
        '  [~] MiscInfo stream absent \u2014 PID not directly recoverable from thread list.\n'
        '    1 thread(s) found: 0x9\n\n'
        '  [~] Exception stream present: faulting TID = 0x9 (this is a Thread ID, not a '
        'Process ID)\n\n',
        {"kind": "pid", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["MiscInfo stream absent \u2014 PID not directly recoverable "
                                  "from thread list.\n    1 thread(s) found: 0x9",
                                  "Exception stream present: faulting TID = 0x9 (this is a "
                                  "Thread ID, not a Process ID)"]},
         "summary": {"count": 1},
         "data": {"records": [{"pid": None, "source": None, "thread_count": 1,
                                "exc_tid": 9}]}},
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'pid,completed,partial,"MiscInfo stream absent \u2014 PID not directly recoverable from '
        'thread list.\n    1 thread(s) found: 0x9; Exception stream present: faulting TID = '
        '0x9 (this is a Thread ID, not a Process ID)",1\n\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n\n,,1,9\n\n\n',
    ),
    (
        "sysinfo_all_absent", ["--sysinfo"], _sysinfo_all_absent, 3,
        '\n\u2550\u2550\u2550 SYSTEM INFO \u2550\u2550\u2550\n  [~] SystemInfoStream not present\n'
        '  [~] MiscInfo stream not present\n  [~] PEB not available (requires sysinfo + '
        'thread list)\n  [~] ThreadListStream not present (thread_count unavailable)\n'
        '  [~] ModuleListStream not present (module_count unavailable)\n\n'
        '  Operating System\n    (sysinfo stream not available)\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n'
        '  Process\n\n  Dump File\n    File                   test.dmp\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["SystemInfoStream not present", "MiscInfo stream not present",
                                  "PEB not available (requires sysinfo + thread list)",
                                  "ThreadListStream not present (thread_count unavailable)",
                                  "ModuleListStream not present (module_count unavailable)"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "hostname": None, "username": None,
                                "os": None, "os_version": None, "architecture": None,
                                "product_type": None, "pid": None, "process_start_utc": None,
                                "image_path": None, "command_line": None,
                                "current_directory": None, "processors": None,
                                "cpu_vendor": None, "cpu_current_mhz": None,
                                "cpu_max_mhz": None, "process_user_time_seconds": None,
                                "process_kernel_time_seconds": None, "thread_count": None,
                                "module_count": None}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'sysinfo,completed,partial,SystemInfoStream not present; MiscInfo stream not present; '
        'PEB not available (requires sysinfo + thread list); ThreadListStream not present '
        '(thread_count unavailable); ModuleListStream not present (module_count unavailable),1\n\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n\n'
        'test.dmp,,,,,,,,,,,,,,,,,,,\n\n\n',
    ),
    (
        "sysinfo_complete", ["--sysinfo"], _sysinfo_complete, 0,
        '\n\u2550\u2550\u2550 SYSTEM INFO \u2550\u2550\u2550\n\n  Operating System\n'
        '    OS                     Windows 10\n    Version                10.0.19041\n'
        '    Architecture           PROCESSOR_ARCHITECTURE_AMD64\n'
        '    Product Type           VER_NT_WORKSTATION\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n'
        '  Process\n    PID                    1234 (0x4d2)\n'
        '    Image Path             C:\\test.exe\n    Command Line           (none)\n'
        '    Working Dir            (none)\n\n  CPU\n    Processors             4\n'
        '    Vendor                 GenuineIntel\n\n  Dump File\n'
        '    File                   test.dmp\n    Threads in dump        1\n'
        '    Modules in dump        1\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "hostname": None, "username": None,
                                "os": "Windows 10", "os_version": "10.0.19041",
                                "architecture": "PROCESSOR_ARCHITECTURE_AMD64",
                                "product_type": "VER_NT_WORKSTATION", "pid": 1234,
                                "process_start_utc": None, "image_path": "C:\\test.exe",
                                "command_line": None, "current_directory": None,
                                "processors": 4, "cpu_vendor": "GenuineIntel",
                                "cpu_current_mhz": None, "cpu_max_mhz": None,
                                "process_user_time_seconds": None,
                                "process_kernel_time_seconds": None, "thread_count": 1,
                                "module_count": 1}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n\n'
        'sysinfo,completed,complete,,1\n\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n\n'
        'test.dmp,,,Windows 10,10.0.19041,PROCESSOR_ARCHITECTURE_AMD64,VER_NT_WORKSTATION,'
        '1234,,C:\\test.exe,,,4,GenuineIntel,,,,,1,1\n\n\n',
    ),
]


@pytest.mark.parametrize(
    "name,argv,mf_builder,exit_code,console,result,csv",
    SCENARIOS, ids=[s[0] for s in SCENARIOS],
)
def test_compat_freeze(monkeypatch, tmp_path, capsys, name, argv, mf_builder, exit_code,
                        console, result, csv):
    actual_exit, doc, csv_text = _run(monkeypatch, tmp_path, argv, mf_builder())
    actual_console = _console_before_write_confirmations(capsys.readouterr().out)

    assert actual_exit == exit_code, f"{name}: exit code drifted"
    assert doc["meta"]["schema_version"] == "2.0"
    assert doc["result"] == result, f"{name}: JSON result drifted"
    assert doc["artifacts"] == [], f"{name}: artifacts drifted"
    assert doc["diagnostics"] == {"warnings": [], "errors": []}, f"{name}: diagnostics drifted"
    assert csv_text == csv, f"{name}: CSV drifted"
    assert actual_console == console, f"{name}: console drifted"

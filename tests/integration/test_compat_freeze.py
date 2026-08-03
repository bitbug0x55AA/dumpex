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
  - the FULL console text, normalized (see _normalize_console)
  - the FULL --json document (meta + result + artifacts + diagnostics),
    normalized (see _normalize_doc) -- not a subset of `result` with
    `meta` skipped: meta.execution.command/options, meta.evidence's
    role/file_name/size_bytes/sha256, meta.tool.name, and the exact set
    of meta.runtime keys are all asserted for real. Only genuinely
    non-reproducible leaf VALUES (wall-clock timestamps, the per-test tmp
    directory, the installed dumpex/library version strings) are
    substituted with a placeholder -- never an entire section skipped.
  - the full --csv file content, byte for byte

Genuinely dynamic values are made reproducible, not skipped, wherever
that's actually possible:
  - wall-clock time: dumpex.cli's and dumpex.output.collector's `datetime`
    modules are monkeypatched to a fixed instant, making
    meta.execution.started_at/finished_at/duration_seconds fully
    deterministic instead of merely normalized.
  - the dump file: a fixed name ("sample.dmp") and fixed byte content
    make meta.evidence[0].file_name/size_bytes/sha256 fully deterministic
    too -- only meta.evidence[0].path (which embeds pytest's per-test
    unique tmp directory) is placeholdered.
  - the CSV file's write-confirmation console line ("... row(s) ...
    bytes  sha256=...") is asserted EXACTLY, computed via hashlib from
    the very `csv` string frozen below -- CSV content embeds no path or
    timestamp, so it's fully reproducible, unlike the JSON write line
    (whose file embeds meta.evidence[0].path, i.e. the per-test tmp
    directory), which is placeholdered.

Every expected value below was captured by actually running the code
(not hand-guessed) and cross-checked against the existing per-command
unit/integration tests before being frozen here -- this suite's job is to
catch any FUTURE unintended drift in any of these four surfaces, not to
re-derive correctness from scratch. A change to any of these four blocks
for an existing scenario is a compatibility break and must be a deliberate,
reviewed decision, not an incidental side effect of an unrelated edit.
"""
import datetime
import hashlib
import json
import os
import re
import sys

import pytest

import dumpex.cli as cli
import dumpex.output.collector as collector_mod
from tests.fixtures.fakes import (
    FakeMF, Region, Module, Thread, ThreadInfo, Ctx, FakeStream, Peb, MiscInfo,
    SysInfo, ExceptionStream,
)

DUMP_BYTES = b"synthetic dump content"
DUMP_SHA256 = hashlib.sha256(DUMP_BYTES).hexdigest()
DUMP_SIZE = len(DUMP_BYTES)

_FIXED_RUNTIME_KEYS = {"python_version", "minidump_version", "yara_version", "pyyaml_version"}

_CMD_LABEL = {"--list": "list", "--modules": "modules", "--threads": "threads",
              "--peb": "peb", "--pid": "pid", "--sysinfo": "sysinfo"}
_CMD_OPTIONS = {"--list": {"verbose": False, "filter": None}}   # every other command: {"verbose": False}


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, tzinfo=tz)


_real_timezone = datetime.timezone
_real_timedelta = datetime.timedelta


class _FrozenDateTimeModule:
    """Stand-in for the whole `datetime` module -- cli.py/collector.py
    both `import datetime` (the module, not `from datetime import
    datetime`), so monkeypatching just the class's `.now` classmethod in
    place isn't an option; the module name itself is replaced instead."""
    datetime = _FixedDateTime
    timezone = _real_timezone
    timedelta = _real_timedelta


def _normalize_doc(doc: dict, dump_path_abs: str) -> dict:
    """Mutates and returns `doc`: replaces the one meta leaf value that's
    still genuinely irreproducible across test runs/environments (the
    absolute dump path, which embeds pytest's per-test tmp directory; the
    installed dumpex/library version strings, which legitimately vary by
    environment and are not this feature's concern) with a placeholder --
    every other field is asserted against its real value by the caller."""
    meta = doc["meta"]
    evidence = meta["evidence"][0]
    assert evidence["path"] == dump_path_abs, "dump path in meta.evidence drifted unexpectedly"
    evidence["path"] = "<DUMP_PATH>"
    assert "version" in meta["tool"]
    meta["tool"]["version"] = "<VERSION>"
    assert set(meta["runtime"]) == _FIXED_RUNTIME_KEYS, "meta.runtime key set drifted"
    meta["runtime"] = {k: "<VERSION>" for k in meta["runtime"]}
    return doc


_JSON_LINE_SIZE_HASH_RE = re.compile(
    r"(JSON written \u2192 <TMP_DIR>[^\n(]*\()\d+ bytes  sha256=[0-9a-f]{64}(\))")


def _normalize_console(text: str, tmp_dir: str) -> str:
    text = text.replace(tmp_dir, "<TMP_DIR>")
    # Only the JSON line's size/hash is inherently irreproducible: the
    # JSON file's bytes embed meta.evidence[0].path, which differs
    # whenever the tmp dir differs. The CSV line is NOT normalized here --
    # CSV content embeds no path or timestamp, so it's fully
    # deterministic and asserted exactly by the caller instead.
    return _JSON_LINE_SIZE_HASH_RE.sub(r"\1<SIZE> bytes  sha256=<HASH>\2", text)


def _csv_write_line(result: dict, csv_text: str, tmp_dir_placeholder: str) -> str:
    # "summary" is always exactly 1 row; "records" contributes
    # len(records) rows (entirely omitted, not zero rows, when empty) --
    # matches collector.py's own total_rows accounting exactly. None of
    # this suite's scenarios hit the third possible table
    # ("environment_variables", peb-only, only when non-empty).
    total_rows = 1 + len(result["data"]["records"])
    csv_bytes = csv_text.encode("utf-8")
    return (f"  [\u00b7] CSV  written \u2192 {tmp_dir_placeholder}{os.sep}out.csv  "
            f"({total_rows} row(s) across all tables, {len(csv_bytes)} bytes  "
            f"sha256={hashlib.sha256(csv_bytes).hexdigest()})\n")


def _run(monkeypatch, tmp_path, argv, mf):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    dump_path = str(tmp_path / "sample.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(DUMP_BYTES)
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    out_json = str(tmp_path / "out.json")
    out_csv = str(tmp_path / "out.csv")
    monkeypatch.setattr(sys, "argv",
                         ["dumpex", dump_path, *argv, "--json", out_json, "--csv", out_csv,
                          "--force"])
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    doc = json.loads(open(out_json, encoding="utf-8").read())
    csv_text = open(out_csv, encoding="utf-8").read()
    return exit_code, doc, csv_text, os.path.abspath(dump_path)


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

def _threads_tid_mismatch():
    # Both streams genuinely present, but partially disagree on which
    # TIDs exist: 2 (of 3) in ThreadListStream absent from
    # ThreadInfoListStream, 1 (of the merged set) present in
    # ThreadInfoListStream absent from ThreadListStream -- exercises
    # SOURCE_KEY_MISMATCH, distinct from either stream's SOURCE_ABSENT.
    mf = FakeMF()
    mf.threads     = FakeStream([Thread(1, Ctx(0)), Thread(2, Ctx(0)), Thread(3, Ctx(0))],
                                 "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000), ThreadInfo(4, 0x7fff0000)], "infos")
    mf.modules     = FakeStream([], "modules")
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

def _pid_no_usable_fallback():
    # mf.threads is present as a stream object but reports zero threads --
    # neither fallback branch fires on its own, exercising the
    # PID_NO_USABLE_FALLBACK safety-net code.
    mf = FakeMF(); mf.threads = FakeStream([], "threads"); return mf

def _sysinfo_all_absent(): return FakeMF()

def _sysinfo_full():
    mf = FakeMF()
    mf.sysinfo    = SysInfo()
    mf.misc_info  = MiscInfo(process_id=1234)
    mf.peb        = Peb(0x140000000, r"C:\test.exe")
    mf.threads    = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules    = FakeStream([Module(0, 0, "a")], "modules")
    return mf

def _sysinfo_complete(): return _sysinfo_full()

def _sysinfo_missing_sysinfo_only():
    mf = _sysinfo_full(); mf.sysinfo = None; return mf

def _sysinfo_missing_misc_info_only():
    mf = _sysinfo_full(); mf.misc_info = None; return mf

def _sysinfo_missing_peb_only():
    mf = _sysinfo_full(); mf.peb = None; return mf

def _sysinfo_missing_threads_only():
    mf = _sysinfo_full(); mf.threads = None; return mf

def _sysinfo_missing_modules_only():
    mf = _sysinfo_full(); mf.modules = None; return mf


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
        '## memory_regions / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'memory_regions,completed,not_evaluated,MemoryInfoListStream not present in this dump,0\n\n',
    ),
    (
        "list_present_empty", ["--list"], _list_present_empty, 0,
        '\nAddress                  Size           State          Protection                       Type\n'
        '────────────────────────────────────────────────────────────────────────────────────────────────────\n'
        '\n[+] 0 region(s) shown.\n',
        {"kind": "memory_regions", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 0}, "data": {"records": []}},
        '## memory_regions / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'memory_regions,completed,complete,,0\n\n',
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
        '## memory_regions / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'memory_regions,completed,complete,,1\n\n'
        '## memory_regions / records\nbase_address,size,state,protect,type,suspicious\n'
        '0x0000000000001000,8192,MEM_COMMIT,PAGE_EXECUTE_READWRITE,MEM_PRIVATE,True\n\n',
    ),
    (
        "modules_absent", ["--modules"], _modules_absent, 4,
        '  [~] ModuleListStream not present in this dump\n\n[+] 0 module(s).\n',
        {"kind": "modules", "execution_status": "completed",
         "coverage": {"status": "not_evaluated",
                      "reasons": ["ModuleListStream not present in this dump"]},
         "summary": {"count": 0}, "data": {"records": []}},
        '## modules / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'modules,completed,not_evaluated,ModuleListStream not present in this dump,0\n\n',
    ),
    (
        "modules_present_empty", ["--modules"], _modules_present_empty, 0,
        '\n[+] 0 module(s).\n',
        {"kind": "modules", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 0}, "data": {"records": []}},
        '## modules / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'modules,completed,complete,,0\n\n',
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
        '## modules / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'modules,completed,complete,,1\n\n'
        '## modules / records\nname,full_path,base_address,end_address,size,compiled_utc,'
        'file_version,checksum,anomaly_flags\n'
        'ntdll.dll,C:\\Windows\\System32\\ntdll.dll,0x0000000140000000,0x0000000140005000,'
        '20480,(not set),,,[]\n\n',
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
        '## peb / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'peb,completed,not_evaluated,PEB could not be parsed (missing sysinfo or thread list in dump),1\n\n'
        '## peb / records\npeb_address,image_base_address,being_debugged,image_path,command_line,'
        'window_title,dll_path,current_directory,standard_input,standard_output,standard_error\n'
        ',,,,,,,,,,\n\n',
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
        '## peb / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'peb,completed,complete,,1\n\n'
        '## peb / records\npeb_address,image_base_address,being_debugged,image_path,command_line,'
        'window_title,dll_path,current_directory,standard_input,standard_output,standard_error\n'
        '0x0000000000000000,0x0000000140000000,False,C:\\test.exe,,,,,,,\n\n',
    ),
    (
        "threads_all_absent", ["--threads"], _threads_all_absent, 4,
        '  [~] Neither ThreadListStream nor ThreadInfoListStream present in this dump\n\n\n'
        '  [~] CreateTime/ExitTime not available in the captured ThreadInfo data.\n\n[+] 0 thread(s).\n',
        {"kind": "threads", "execution_status": "completed",
         "coverage": {"status": "not_evaluated",
                      "reasons": ["Neither ThreadListStream nor ThreadInfoListStream present in this dump"]},
         "summary": {"count": 0}, "data": {"records": []}},
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'threads,completed,not_evaluated,Neither ThreadListStream nor ThreadInfoListStream '
        'present in this dump,0\n\n',
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
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'threads,completed,partial,ThreadInfoListStream not present; StartAddress/CreateTime/'
        'ExitTime/KernelTime/UserTime unavailable (TID/SuspendCount/Priority/TEB only); '
        'ModuleListStream not present; thread backing-module classification unavailable '
        '(cannot confirm whether a start address is backed by a known module),1\n\n'
        '## threads / records\ntid,start_address,backing_module,module_context,flags,create_time,'
        'exit_time,exit_status,kernel_time_100ns,user_time_100ns,suspend_count,priority,teb\n'
        '1,,,,[],,,,,,,,\n\n',
    ),
    (
        "threads_present_empty", ["--threads"], _threads_present_empty, 0,
        '\n  [~] CreateTime/ExitTime not available in the captured ThreadInfo data.\n\n[+] 0 thread(s).\n',
        {"kind": "threads", "execution_status": "completed",
         "coverage": {"status": "complete", "reasons": []},
         "summary": {"count": 0}, "data": {"records": []}},
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'threads,completed,complete,,0\n\n',
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
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'threads,completed,complete,,1\n\n'
        '## threads / records\ntid,start_address,backing_module,module_context,flags,create_time,'
        'exit_time,exit_status,kernel_time_100ns,user_time_100ns,suspend_count,priority,teb\n'
        '1,0x000000007ffe0000,legit.dll,resolved,[],,,,,,,,\n\n',
    ),
    (
        "threads_tid_mismatch", ["--threads"], _threads_tid_mismatch, 3,
        '  [~] 2 thread(s) present in ThreadListStream but missing from ThreadInfoListStream '
        '(StartAddress/CreateTime/ExitTime/KernelTime/UserTime unavailable for those)\n\n'
        '  [~] 1 thread(s) present in ThreadInfoListStream but missing from ThreadListStream '
        '(SuspendCount/Priority/TEB unavailable for those)\n\n\n'
        '  TID              0x1\n  StartAddress     0x000000007ffe0000  ← ⚠  NOT IN ANY MODULE\n\n'
        '  TID              0x2\n  StartAddress     unavailable  ← (unknown — requires '
        'ThreadInfoListStream)\n\n'
        '  TID              0x3\n  StartAddress     unavailable  ← (unknown — requires '
        'ThreadInfoListStream)\n\n'
        '  TID              0x4\n  StartAddress     0x000000007fff0000  ← ⚠  NOT IN ANY MODULE\n\n'
        '  [~] CreateTime/ExitTime not available in the captured ThreadInfo data.\n\n[+] 4 thread(s).\n',
        {"kind": "threads", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["2 thread(s) present in ThreadListStream but missing from "
                                  "ThreadInfoListStream (StartAddress/CreateTime/ExitTime/"
                                  "KernelTime/UserTime unavailable for those)",
                                  "1 thread(s) present in ThreadInfoListStream but missing from "
                                  "ThreadListStream (SuspendCount/Priority/TEB unavailable for "
                                  "those)"]},
         "summary": {"count": 4},
         "data": {"records": [
             {"tid": 1, "start_address": "0x000000007ffe0000", "backing_module": None,
              "module_context": "unregistered", "flags": [], "create_time": None,
              "exit_time": None, "exit_status": None, "kernel_time_100ns": None,
              "user_time_100ns": None, "suspend_count": None, "priority": None, "teb": None},
             {"tid": 2, "start_address": None, "backing_module": None, "module_context": None,
              "flags": [], "create_time": None, "exit_time": None, "exit_status": None,
              "kernel_time_100ns": None, "user_time_100ns": None, "suspend_count": None,
              "priority": None, "teb": None},
             {"tid": 3, "start_address": None, "backing_module": None, "module_context": None,
              "flags": [], "create_time": None, "exit_time": None, "exit_status": None,
              "kernel_time_100ns": None, "user_time_100ns": None, "suspend_count": None,
              "priority": None, "teb": None},
             {"tid": 4, "start_address": "0x000000007fff0000", "backing_module": None,
              "module_context": "unregistered", "flags": [], "create_time": None,
              "exit_time": None, "exit_status": None, "kernel_time_100ns": None,
              "user_time_100ns": None, "suspend_count": None, "priority": None, "teb": None},
         ]}},
        '## threads / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'threads,completed,partial,2 thread(s) present in ThreadListStream but missing from '
        'ThreadInfoListStream (StartAddress/CreateTime/ExitTime/KernelTime/UserTime unavailable '
        'for those); 1 thread(s) present in ThreadInfoListStream but missing from '
        'ThreadListStream (SuspendCount/Priority/TEB unavailable for those),4\n\n'
        '## threads / records\ntid,start_address,backing_module,module_context,flags,create_time,'
        'exit_time,exit_status,kernel_time_100ns,user_time_100ns,suspend_count,priority,teb\n'
        '1,0x000000007ffe0000,,unregistered,[],,,,,,,,\n'
        '2,,,,[],,,,,,,,\n'
        '3,,,,[],,,,,,,,\n'
        '4,0x000000007fff0000,,unregistered,[],,,,,,,,\n\n',
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
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'pid,completed,not_evaluated,"MiscInfo, thread list, and exception stream are all '
        'absent from this dump; PID could not be evaluated",1\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n,,,\n\n',
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
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'pid,completed,complete,,1\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n'
        '4321,MINIDUMP_MISC_INFO (ProcessId field),,\n\n',
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
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'pid,completed,partial,"MiscInfo stream absent \u2014 PID not directly recoverable from '
        'thread list.\n    2 thread(s) found: 0x9, 0xa",1\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n,,2,\n\n',
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
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'pid,completed,partial,"MiscInfo stream absent \u2014 PID not directly recoverable from '
        'thread list.\n    1 thread(s) found: 0x9; Exception stream present: faulting TID = '
        '0x9 (this is a Thread ID, not a Process ID)",1\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n,,1,9\n\n',
    ),
    (
        "pid_no_usable_fallback", ["--pid"], _pid_no_usable_fallback, 3,
        '\n═══ PROCESS ID ═══\n  [!] ProcessId not found in MiscInfo stream.\n\n'
        '  [~] PID not found in MINIDUMP_MISC_INFO, and no usable cross-check data was '
        'available from the thread list or exception stream\n\n',
        {"kind": "pid", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["PID not found in MINIDUMP_MISC_INFO, and no usable "
                                  "cross-check data was available from the thread list or "
                                  "exception stream"]},
         "summary": {"count": 1},
         "data": {"records": [{"pid": None, "source": None, "thread_count": 0,
                                "exc_tid": None}]}},
        '## pid / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'pid,completed,partial,"PID not found in MINIDUMP_MISC_INFO, and no usable cross-check '
        'data was available from the thread list or exception stream",1\n\n'
        '## pid / records\npid,source,thread_count,exc_tid\n,,0,\n\n',
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
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,SystemInfoStream not present; MiscInfo stream not present; '
        'PEB not available (requires sysinfo + thread list); ThreadListStream not present '
        '(thread_count unavailable); ModuleListStream not present (module_count unavailable),1\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n'
        'test.dmp,,,,,,,,,,,,,,,,,,,\n\n',
    ),
    (
        "sysinfo_missing_sysinfo_only", ["--sysinfo"], _sysinfo_missing_sysinfo_only, 3,
        '\n═══ SYSTEM INFO ═══\n  [~] SystemInfoStream not present\n\n'
        '  Operating System\n    (sysinfo stream not available)\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n'
        '  Process\n    PID                    1234 (0x4d2)\n'
        '    Image Path             C:\\test.exe\n    Command Line           (none)\n'
        '    Working Dir            (none)\n\n  Dump File\n'
        '    File                   test.dmp\n    Threads in dump        1\n'
        '    Modules in dump        1\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial", "reasons": ["SystemInfoStream not present"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "hostname": None, "username": None,
                                "os": None, "os_version": None, "architecture": None,
                                "product_type": None, "pid": 1234, "process_start_utc": None,
                                "image_path": "C:\\test.exe", "command_line": None,
                                "current_directory": None, "processors": None,
                                "cpu_vendor": None, "cpu_current_mhz": None,
                                "cpu_max_mhz": None, "process_user_time_seconds": None,
                                "process_kernel_time_seconds": None, "thread_count": 1,
                                "module_count": 1}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,SystemInfoStream not present,1\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n'
        'test.dmp,,,,,,,1234,,C:\\test.exe,,,,,,,,,1,1\n\n',
    ),
    (
        "sysinfo_missing_misc_info_only", ["--sysinfo"], _sysinfo_missing_misc_info_only, 3,
        '\n═══ SYSTEM INFO ═══\n  [~] MiscInfo stream not present\n\n'
        '  Operating System\n    OS                     Windows 10\n'
        '    Version                10.0.19041\n'
        '    Architecture           PROCESSOR_ARCHITECTURE_AMD64\n'
        '    Product Type           VER_NT_WORKSTATION\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n'
        '  Process\n    Image Path             C:\\test.exe\n'
        '    Command Line           (none)\n    Working Dir            (none)\n\n'
        '  CPU\n    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '  Dump File\n    File                   test.dmp\n    Threads in dump        1\n'
        '    Modules in dump        1\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial", "reasons": ["MiscInfo stream not present"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "hostname": None, "username": None,
                                "os": "Windows 10", "os_version": "10.0.19041",
                                "architecture": "PROCESSOR_ARCHITECTURE_AMD64",
                                "product_type": "VER_NT_WORKSTATION", "pid": None,
                                "process_start_utc": None, "image_path": "C:\\test.exe",
                                "command_line": None, "current_directory": None,
                                "processors": 4, "cpu_vendor": "GenuineIntel",
                                "cpu_current_mhz": None, "cpu_max_mhz": None,
                                "process_user_time_seconds": None,
                                "process_kernel_time_seconds": None, "thread_count": 1,
                                "module_count": 1}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,MiscInfo stream not present,1\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n'
        'test.dmp,,,Windows 10,10.0.19041,PROCESSOR_ARCHITECTURE_AMD64,VER_NT_WORKSTATION,,,'
        'C:\\test.exe,,,4,GenuineIntel,,,,,1,1\n\n',
    ),
    (
        "sysinfo_missing_peb_only", ["--sysinfo"], _sysinfo_missing_peb_only, 3,
        '\n═══ SYSTEM INFO ═══\n  [~] PEB not available (requires sysinfo + thread list)\n\n'
        '  Operating System\n    OS                     Windows 10\n'
        '    Version                10.0.19041\n'
        '    Architecture           PROCESSOR_ARCHITECTURE_AMD64\n'
        '    Product Type           VER_NT_WORKSTATION\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n'
        '  Process\n    PID                    1234 (0x4d2)\n\n'
        '  CPU\n    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '  Dump File\n    File                   test.dmp\n    Threads in dump        1\n'
        '    Modules in dump        1\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["PEB not available (requires sysinfo + thread list)"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "hostname": None, "username": None,
                                "os": "Windows 10", "os_version": "10.0.19041",
                                "architecture": "PROCESSOR_ARCHITECTURE_AMD64",
                                "product_type": "VER_NT_WORKSTATION", "pid": 1234,
                                "process_start_utc": None, "image_path": None,
                                "command_line": None, "current_directory": None,
                                "processors": 4, "cpu_vendor": "GenuineIntel",
                                "cpu_current_mhz": None, "cpu_max_mhz": None,
                                "process_user_time_seconds": None,
                                "process_kernel_time_seconds": None, "thread_count": 1,
                                "module_count": 1}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,PEB not available (requires sysinfo + thread list),1\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n'
        'test.dmp,,,Windows 10,10.0.19041,PROCESSOR_ARCHITECTURE_AMD64,VER_NT_WORKSTATION,1234,'
        ',,,,4,GenuineIntel,,,,,1,1\n\n',
    ),
    (
        "sysinfo_missing_threads_only", ["--sysinfo"], _sysinfo_missing_threads_only, 3,
        '\n═══ SYSTEM INFO ═══\n  [~] ThreadListStream not present (thread_count unavailable)\n\n'
        '  Operating System\n    OS                     Windows 10\n'
        '    Version                10.0.19041\n'
        '    Architecture           PROCESSOR_ARCHITECTURE_AMD64\n'
        '    Product Type           VER_NT_WORKSTATION\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n'
        '  Process\n    PID                    1234 (0x4d2)\n'
        '    Image Path             C:\\test.exe\n    Command Line           (none)\n'
        '    Working Dir            (none)\n\n'
        '  CPU\n    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '  Dump File\n    File                   test.dmp\n    Modules in dump        1\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["ThreadListStream not present (thread_count unavailable)"]},
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
                                "process_kernel_time_seconds": None, "thread_count": None,
                                "module_count": 1}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,ThreadListStream not present (thread_count unavailable),1\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n'
        'test.dmp,,,Windows 10,10.0.19041,PROCESSOR_ARCHITECTURE_AMD64,VER_NT_WORKSTATION,1234,'
        ',C:\\test.exe,,,4,GenuineIntel,,,,,,1\n\n',
    ),
    (
        "sysinfo_missing_modules_only", ["--sysinfo"], _sysinfo_missing_modules_only, 3,
        '\n═══ SYSTEM INFO ═══\n  [~] ModuleListStream not present (module_count unavailable)\n\n'
        '  Operating System\n    OS                     Windows 10\n'
        '    Version                10.0.19041\n'
        '    Architecture           PROCESSOR_ARCHITECTURE_AMD64\n'
        '    Product Type           VER_NT_WORKSTATION\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n'
        '  Process\n    PID                    1234 (0x4d2)\n'
        '    Image Path             C:\\test.exe\n    Command Line           (none)\n'
        '    Working Dir            (none)\n\n'
        '  CPU\n    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '  Dump File\n    File                   test.dmp\n    Threads in dump        1\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["ModuleListStream not present (module_count unavailable)"]},
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
                                "module_count": None}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,ModuleListStream not present (module_count unavailable),1\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n'
        'test.dmp,,,Windows 10,10.0.19041,PROCESSOR_ARCHITECTURE_AMD64,VER_NT_WORKSTATION,1234,'
        ',C:\\test.exe,,,4,GenuineIntel,,,,,1,\n\n',
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
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,complete,,1\n\n'
        '## sysinfo / records\ndump_file,hostname,username,os,os_version,architecture,'
        'product_type,pid,process_start_utc,image_path,command_line,current_directory,'
        'processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,process_user_time_seconds,'
        'process_kernel_time_seconds,thread_count,module_count\n'
        'test.dmp,,,Windows 10,10.0.19041,PROCESSOR_ARCHITECTURE_AMD64,VER_NT_WORKSTATION,'
        '1234,,C:\\test.exe,,,4,GenuineIntel,,,,,1,1\n\n',
    ),
]


# ── frozen coverage.sources/coverage.limitations, keyed by scenario name ──
# Kept separate from SCENARIOS above (rather than folded into each
# scenario's `result` literal) so the console/CSV/exit-code table added
# first stays untouched -- these two structured fields were added later,
# once coverage.py grew to_dict() methods and collector.py started
# forwarding them onto the wire (see dumpex.output.envelope.Result).
# Every value captured by actually running the scenario's own mf_builder
# through collect_*() -- not hand-derived -- then merged onto `result`
# in test_compat_freeze() below.

def _src(state, count=None, detail=None):
    return {"state": state, "record_count": count, "detail": detail}


def _lim(code, source, **kw):
    d = {"scope": None, "affected_count": None, "unavailable_fields": [],
         "available_fields": [], "counterpart_source": None, "related_sources": [],
         "related_tids": [], "thread_id": None, "detail": None}
    d.update(kw)
    d["code"] = code
    d["source"] = source
    return d


_COVERAGE_SOURCES_AND_LIMITATIONS = {
    "list_absent": (
        {"memory_info": _src("absent")},
        [_lim("SOURCE_ABSENT", "memory_info", scope="dump")],
    ),
    "list_present_empty": ({"memory_info": _src("present_empty", 0)}, []),
    "list_present": ({"memory_info": _src("present", 1)}, []),
    "modules_absent": (
        {"modules": _src("absent")},
        [_lim("SOURCE_ABSENT", "modules", scope="dump")],
    ),
    "modules_present_empty": ({"modules": _src("present_empty", 0)}, []),
    "modules_present": ({"modules": _src("present", 1)}, []),
    "peb_absent": (
        {"peb": _src("absent")},
        [_lim("PEB_UNAVAILABLE", "peb", scope="dump")],
    ),
    "peb_present": ({"peb": _src("present", 1)}, []),
    "threads_all_absent": (
        {"threads": _src("absent"), "thread_info": _src("absent"), "modules": _src("absent")},
        [_lim("SOURCE_GROUP_ABSENT", "threads", scope="dump",
              related_sources=["threads", "thread_info"])],
    ),
    "threads_degraded": (
        {"threads": _src("present", 1), "thread_info": _src("absent"), "modules": _src("absent")},
        [_lim("SOURCE_ABSENT", "thread_info", scope="dump",
              unavailable_fields=["StartAddress", "CreateTime", "ExitTime", "KernelTime",
                                   "UserTime"],
              available_fields=["TID", "SuspendCount", "Priority", "TEB"]),
         _lim("MODULE_CLASSIFICATION_UNAVAILABLE", "modules", scope="dump")],
    ),
    "threads_present_empty": (
        {"threads": _src("present_empty", 0), "thread_info": _src("present_empty", 0),
         "modules": _src("present_empty", 0)},
        [],
    ),
    "threads_complete": (
        {"threads": _src("present", 1), "thread_info": _src("present", 1),
         "modules": _src("present", 1)},
        [],
    ),
    "threads_tid_mismatch": (
        {"threads": _src("present", 3), "thread_info": _src("present", 2),
         "modules": _src("present_empty", 0)},
        [_lim("SOURCE_KEY_MISMATCH", "thread_info", scope="thread", affected_count=2,
              unavailable_fields=["StartAddress", "CreateTime", "ExitTime", "KernelTime",
                                   "UserTime"],
              counterpart_source="threads"),
         _lim("SOURCE_KEY_MISMATCH", "threads", scope="thread", affected_count=1,
              unavailable_fields=["SuspendCount", "Priority", "TEB"],
              counterpart_source="thread_info")],
    ),
    "pid_all_absent": (
        {"misc_info": _src("absent"), "threads": _src("absent"), "exception": _src("absent")},
        [_lim("PID_SOURCES_ABSENT", "misc_info", scope="dump",
              related_sources=["misc_info", "threads", "exception"])],
    ),
    "pid_complete": (
        {"misc_info": _src("present", 1), "threads": _src("absent"), "exception": _src("absent")},
        [],
    ),
    "pid_thread_fallback": (
        {"misc_info": _src("absent"), "threads": _src("present", 2), "exception": _src("absent")},
        [_lim("PID_THREAD_LIST_FALLBACK", "misc_info", counterpart_source="threads",
              related_tids=[9, 10])],
    ),
    "pid_exception_fallback": (
        {"misc_info": _src("absent"), "threads": _src("present", 1),
         "exception": _src("present", 1)},
        [_lim("PID_THREAD_LIST_FALLBACK", "misc_info", counterpart_source="threads",
              related_tids=[9]),
         _lim("PID_EXCEPTION_TID_FALLBACK", "exception", thread_id=9)],
    ),
    "pid_no_usable_fallback": (
        {"misc_info": _src("absent"), "threads": _src("present_empty", 0),
         "exception": _src("absent")},
        [_lim("PID_NO_USABLE_FALLBACK", "misc_info")],
    ),
    "sysinfo_all_absent": (
        {"sysinfo": _src("absent"), "misc_info": _src("absent"), "peb": _src("absent"),
         "threads": _src("absent"), "modules": _src("absent")},
        [_lim("SYSINFO_SYSTEM_INFO_UNAVAILABLE", "sysinfo", scope="dump"),
         _lim("SYSINFO_MISC_INFO_UNAVAILABLE", "misc_info", scope="dump"),
         _lim("SYSINFO_PEB_UNAVAILABLE", "peb", scope="dump"),
         _lim("SYSINFO_THREADS_UNAVAILABLE", "threads", scope="dump"),
         _lim("SYSINFO_MODULES_UNAVAILABLE", "modules", scope="dump")],
    ),
    "sysinfo_missing_sysinfo_only": (
        {"sysinfo": _src("absent"), "misc_info": _src("present", 1), "peb": _src("present", 1),
         "threads": _src("present", 1), "modules": _src("present", 1)},
        [_lim("SYSINFO_SYSTEM_INFO_UNAVAILABLE", "sysinfo", scope="dump")],
    ),
    "sysinfo_missing_misc_info_only": (
        {"sysinfo": _src("present", 1), "misc_info": _src("absent"), "peb": _src("present", 1),
         "threads": _src("present", 1), "modules": _src("present", 1)},
        [_lim("SYSINFO_MISC_INFO_UNAVAILABLE", "misc_info", scope="dump")],
    ),
    "sysinfo_missing_peb_only": (
        {"sysinfo": _src("present", 1), "misc_info": _src("present", 1), "peb": _src("absent"),
         "threads": _src("present", 1), "modules": _src("present", 1)},
        [_lim("SYSINFO_PEB_UNAVAILABLE", "peb", scope="dump")],
    ),
    "sysinfo_missing_threads_only": (
        {"sysinfo": _src("present", 1), "misc_info": _src("present", 1),
         "peb": _src("present", 1), "threads": _src("absent"), "modules": _src("present", 1)},
        [_lim("SYSINFO_THREADS_UNAVAILABLE", "threads", scope="dump")],
    ),
    "sysinfo_missing_modules_only": (
        {"sysinfo": _src("present", 1), "misc_info": _src("present", 1),
         "peb": _src("present", 1), "threads": _src("present", 1), "modules": _src("absent")},
        [_lim("SYSINFO_MODULES_UNAVAILABLE", "modules", scope="dump")],
    ),
    "sysinfo_complete": (
        {"sysinfo": _src("present", 1), "misc_info": _src("present", 1),
         "peb": _src("present", 1), "threads": _src("present", 1),
         "modules": _src("present", 1)},
        [],
    ),
}


def _expected_meta(argv0: str) -> dict:
    return {
        "schema_version": "2.4",
        "tool": {"name": "dumpex", "version": "<VERSION>"},
        "execution": {
            "started_at": "2024-01-01T00:00:00Z",
            "finished_at": "2024-01-01T00:00:00Z",
            "duration_seconds": 0.0,
            "command": _CMD_LABEL[argv0],
            "options": _CMD_OPTIONS.get(argv0, {"verbose": False}),
            "case_id": None,
            "analyst": None,
        },
        "evidence": [{"id": "primary", "role": "primary", "file_name": "sample.dmp",
                      "path": "<DUMP_PATH>", "size_bytes": DUMP_SIZE, "sha256": DUMP_SHA256}],
        "runtime": {k: "<VERSION>" for k in _FIXED_RUNTIME_KEYS},
    }


@pytest.mark.parametrize(
    "name,argv,mf_builder,exit_code,console,result,csv",
    SCENARIOS, ids=[s[0] for s in SCENARIOS],
)
def test_compat_freeze(monkeypatch, tmp_path, capsys, name, argv, mf_builder, exit_code,
                        console, result, csv):
    actual_exit, doc, csv_text, dump_path_abs = _run(monkeypatch, tmp_path, argv, mf_builder())
    actual_console = _normalize_console(capsys.readouterr().out, str(tmp_path))
    _normalize_doc(doc, dump_path_abs)

    sources, limitations = _COVERAGE_SOURCES_AND_LIMITATIONS[name]
    result = dict(result)
    result["coverage"] = dict(result["coverage"], sources=sources, limitations=limitations)

    expected_doc = {"meta": _expected_meta(argv[0]), "result": result,
                     "artifacts": [], "diagnostics": {"warnings": [], "errors": []}}
    expected_console = console + "  [·] JSON written → <TMP_DIR>" + os.sep \
        + "out.json  (<SIZE> bytes  sha256=<HASH>)\n" + _csv_write_line(result, csv, "<TMP_DIR>")

    assert actual_exit == exit_code, f"{name}: exit code drifted"
    assert doc == expected_doc, f"{name}: JSON document drifted"
    assert csv_text == csv, f"{name}: CSV drifted"
    assert actual_console == expected_console, f"{name}: console drifted"


def test_compat_freeze_corrupted_dump_exits_1_writes_no_structured_output(
        monkeypatch, tmp_path, capsys):
    """The one scenario every other row in this suite can't cover: a dump
    that fails to PARSE at all. Deliberately does NOT monkeypatch
    cli.open_dump -- the real dumpex.core.memory.open_dump() runs against
    our fixed (deliberately non-minidump) DUMP_BYTES, hits
    MinidumpFile.parse()'s real exception path, and must exit 1 before
    ever reaching a V2Output construction, writing neither --json nor
    --csv at all (a half-written structured-output file for a run that
    never produced a result would be worse than none). The exact
    exception class/message is the `minidump` library's own -- asserted
    by structural markers (prefix/suffix), not the full interpolated
    string, so a library version bump doesn't spuriously fail this test
    over wording dumpex itself doesn't own."""
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    dump_path = str(tmp_path / "sample.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(DUMP_BYTES)   # not a real minidump -- MinidumpFile.parse() must reject it
    out_json = str(tmp_path / "out.json")
    out_csv = str(tmp_path / "out.csv")
    monkeypatch.setattr(sys, "argv",
                         ["dumpex", dump_path, "--list", "--json", out_json, "--csv", out_csv])

    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == 1
    assert not os.path.exists(out_json), "a failed parse must not leave a partial JSON file"
    assert not os.path.exists(out_csv), "a failed parse must not leave a partial CSV file"

    console = capsys.readouterr().out
    assert f"[!] Could not parse {dump_path} as a minidump file:" in console
    assert ("The file may be corrupted, truncated, or not a Windows minidump "
            "(.dmp) at all.") in console

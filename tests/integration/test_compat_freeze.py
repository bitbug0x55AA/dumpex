"""
Table-driven compatibility-freeze suite for four of dumpex's recon
commands (--list/--modules/--threads/--sysinfo). `--pid`/`--peb` were
removed in issue #43's atomic v2.13 cutover (see
docs/recon_process_sysinfo_handles_contract.md §7.2) -- their golden
scenarios were removed from this suite in the same change, and #44 owns
adding fresh compatibility fixtures for their replacements (--process/
--handles/--profile).

For every legal source-state scenario (absent / present_empty / present --
SourceState.FAILED is explicitly N/A for all four of these commands, see
dumpex.output.coverage's SourceState docstring: none of their mf.<stream>
accesses are wrapped in a try/except, so a read failure propagates as a
fatal exception rather than becoming a SOURCE_FAILED observation), this
asserts all three output surfaces at once, through one real cli.main()
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
Every expected value below was captured by actually running the code
(not hand-guessed) and cross-checked against the existing per-command
unit/integration tests before being frozen here -- this suite's job is to
catch any FUTURE unintended drift in any of these three surfaces, not to
re-derive correctness from scratch. A change to any of these three blocks
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
from dumpex.output.envelope import SCHEMA_VERSION
from tests.fixtures.fakes import (
    FakeMF, FakeHeader, Region, Module, Thread, ThreadInfo, Ctx, FakeStream, Peb, MiscInfo,
    SysInfo, wire_environment_walk, EnvReader, UnconstructibleEnvReader,
)


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")

DUMP_BYTES = b"synthetic dump content"
DUMP_SHA256 = hashlib.sha256(DUMP_BYTES).hexdigest()
DUMP_SIZE = len(DUMP_BYTES)

_FIXED_RUNTIME_KEYS = {"python_version", "minidump_version", "yara_version", "pyyaml_version"}

_CMD_LABEL = {"--list": "list", "--modules": "modules", "--threads": "threads",
              "--sysinfo": "sysinfo"}
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
    # whenever the tmp dir differs.
    return _JSON_LINE_SIZE_HASH_RE.sub(r"\1<SIZE> bytes  sha256=<HASH>\2", text)


def _run(monkeypatch, tmp_path, argv, mf):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    dump_path = str(tmp_path / "sample.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(DUMP_BYTES)
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    out_json = str(tmp_path / "out.json")
    monkeypatch.setattr(sys, "argv",
                         ["dumpex", dump_path, *argv, "--json", out_json,
                          "--force"])
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    doc = json.loads(open(out_json, encoding="utf-8").read())
    return exit_code, doc, os.path.abspath(dump_path)


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

def _sysinfo_all_absent(): return _assert_sysinfo_reachable_via_open_dump(FakeMF())


def _assert_peb_reachable_via_open_dump(mf):
    """dumpex/core/memory.py's phase 3b only ever builds mf.peb under the
    same sysinfo+threads precondition the installed library's own
    __parse_peb() needs -- a scenario builder that leaves mf.peb present
    while either is absent describes a state a real open_dump() can never
    actually produce (see docs/recon_process_sysinfo_handles_contract.md
    §4.3.3's duplicate-absence-suppression rule, which relies on exactly
    this invariant)."""
    if mf.peb is not None:
        assert mf.sysinfo is not None and mf.threads is not None, (
            "mf.peb is present but sysinfo/threads is not -- open_dump() can never "
            "produce this combination (see dumpex/core/memory.py phase 3b)")


def _assert_env_walk_reachable_via_open_dump(mf):
    """A real open_dump() output's mf.get_reader() always constructs a
    fresh MinidumpFileReader, whose __init__ unconditionally dereferences
    mf.modules.modules -- if mf.modules is None, that raises before any
    pointer is ever read (dumpex/core/process_info.py's walk_environment_
    block() folds this into "pointer_unreadable", per issue #41's own P1
    fix). A scenario builder that wires a successful environment walk (an
    EnvReader, via wire_environment_walk()) while leaving mf.modules None
    describes a state a real open_dump() can never actually produce --
    checked by isinstance rather than a bare `mf._reader is not None` so
    an mf.modules-absent scenario intentionally wired with
    UnconstructibleEnvReader (which fails the exact way a real
    open_dump() output would) is never mistaken for the bug this guards
    against."""
    if isinstance(mf._reader, EnvReader):
        assert mf.modules is not None, (
            "mf._reader is wired for a successful environment walk but mf.modules is "
            "None -- open_dump() can never produce this combination (MinidumpFileReader"
            ".__init__ needs mf.modules.modules)")


def _assert_sysinfo_reachable_via_open_dump(mf):
    """Called by every _sysinfo_* builder below so a future edit can't
    silently drift back into freezing a golden no real open_dump() output
    could ever produce -- see the two assertions' own docstrings."""
    _assert_peb_reachable_via_open_dump(mf)
    _assert_env_walk_reachable_via_open_dump(mf)
    return mf


def _sysinfo_full():
    mf = FakeMF()
    # MinidumpHeader.TimeDateStamp -- the source of --sysinfo's
    # dump_time_utc. A real open_dump() always has a parsed header by the
    # time any command runs (phase 1 exits 1 otherwise), so every sysinfo
    # golden below freezes a real timestamp rather than the null a
    # header-less fake would produce. 1723598105 == 2024-08-14 01:15:05 UTC.
    mf.header     = FakeHeader(1723598105)
    mf.sysinfo    = SysInfo()   # SysInfo()'s own default is PROCESSOR_ARCHITECTURE.AMD64
    mf.misc_info  = MiscInfo(process_id=1234)
    mf.peb        = Peb(0x140000000, r"C:\test.exe", current_directory=r"C:\work")
    mf.threads    = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules    = FakeStream([Module(0, 0, "a")], "modules")
    # A real, non-empty environment block -- COMPUTERNAME/USERNAME so
    # hostname/username derive from it (issue #41 §4.2), not from
    # peb.environment_variables.
    env_data = (_utf16("COMPUTERNAME=HOST1") + b"\x00\x00"
                + _utf16("USERNAME=alice") + b"\x00\x00"
                + b"\x00\x00")
    wire_environment_walk(mf, env_data)
    return _assert_sysinfo_reachable_via_open_dump(mf)

def _sysinfo_complete(): return _sysinfo_full()

def _sysinfo_missing_sysinfo_only():
    # sysinfo missing implies peb missing too (see
    # _assert_peb_reachable_via_open_dump's own docstring) -- a real
    # open_dump() never builds one without the other.
    mf = _sysinfo_full(); mf.sysinfo = None; mf.peb = None
    return _assert_sysinfo_reachable_via_open_dump(mf)

def _sysinfo_missing_misc_info_only():
    mf = _sysinfo_full(); mf.misc_info = None
    return _assert_sysinfo_reachable_via_open_dump(mf)

def _sysinfo_missing_peb_only():
    mf = _sysinfo_full(); mf.peb = None
    return _assert_sysinfo_reachable_via_open_dump(mf)

def _sysinfo_missing_threads_only():
    # threads missing implies peb missing too -- see
    # _sysinfo_missing_sysinfo_only's own comment above.
    mf = _sysinfo_full(); mf.threads = None; mf.peb = None
    return _assert_sysinfo_reachable_via_open_dump(mf)

def _sysinfo_missing_modules_only():
    # modules missing implies the environment walk fails too -- see
    # _assert_env_walk_reachable_via_open_dump's own docstring: a real
    # MinidumpFileReader can't be constructed without mf.modules. The
    # fake reader wire_environment_walk() wired into _sysinfo_full() is
    # replaced with UnconstructibleEnvReader, which fails through
    # mf.get_reader() the exact way open_dump() output would (same
    # AttributeError text, not a FakeMF-specific message).
    mf = _sysinfo_full(); mf.modules = None
    mf._reader = UnconstructibleEnvReader(mf.modules)
    return _assert_sysinfo_reachable_via_open_dump(mf)


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
        "sysinfo_all_absent", ["--sysinfo"], _sysinfo_all_absent, 3,
        '\n═══ DUMP ═══\n  [~] ThreadListStream not present (thread_count unavailable)\n'
        '  [~] ModuleListStream not present (module_count unavailable)\n'
        '    File                   test.dmp\n    Size                   25 bytes\n'
        '    SHA-256                5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509\n'
        '\n═══ SYSTEM INFO ═══\n  [~] SystemInfoStream not present\n'
        '  [~] MiscInfo stream not present\n\n  Operating System\n'
        '    (sysinfo stream not available)\n\n  Host\n    Hostname               (unknown)\n'
        '    Username               (unknown)\n\n═══ ENVIRONMENT ═══\n'
        '  [~] PEB not available (requires sysinfo + thread list)\n'
        '    Current Directory      (unknown)\n    Environment Variables  (unavailable)\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["ThreadListStream not present (thread_count unavailable)", "ModuleListStream not present (module_count unavailable)", "SystemInfoStream not present", "MiscInfo stream not present", "PEB not available (requires sysinfo + thread list)"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "dump_file_size_bytes": 25, "dump_sha256": "5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509", "dump_time_utc": None, "hostname": None, "username": None, "os": None, "os_version": None, "architecture": None, "product_type": None, "processors": None, "cpu_vendor": None, "cpu_current_mhz": None, "cpu_max_mhz": None, "thread_count": None, "module_count": None, "current_directory": None, "environment_variables": None}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,ThreadListStream not present (thread_count unavailable); ModuleListStream not present (module_count unavailable); SystemInfoStream not present; MiscInfo stream not present; PEB not available (requires sysinfo + thread list),1\n'
        '\n## sysinfo / records\n'
        'dump_file,dump_file_size_bytes,dump_sha256,dump_time_utc,hostname,username,os,os_version,architecture,product_type,processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,thread_count,module_count,current_directory,environment_variables\n'
        'test.dmp,25,5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509,,,,,,,,,,,,,,,\n'
        '\n',
    ),
    (
        "sysinfo_missing_sysinfo_only", ["--sysinfo"], _sysinfo_missing_sysinfo_only, 3,
        '\n═══ DUMP ═══\n    File                   test.dmp\n'
        '    Size                   25 bytes\n'
        '    SHA-256                5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509\n'
        '    Dump Time              2024-08-14 01:15:05 UTC\n    Threads in dump        1\n'
        '    Modules in dump        1\n\n═══ SYSTEM INFO ═══\n'
        '  [~] SystemInfoStream not present\n\n  Operating System\n'
        '    (sysinfo stream not available)\n\n  Host\n    Hostname               (unknown)\n'
        '    Username               (unknown)\n\n═══ ENVIRONMENT ═══\n'
        '  [~] PEB not available (requires sysinfo + thread list)\n'
        '    Current Directory      (unknown)\n    Environment Variables  (unavailable)\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["SystemInfoStream not present", "PEB not available (requires sysinfo + thread list)"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "dump_file_size_bytes": 25, "dump_sha256": "5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509", "dump_time_utc": "2024-08-14 01:15:05 UTC", "hostname": None, "username": None, "os": None, "os_version": None, "architecture": None, "product_type": None, "processors": None, "cpu_vendor": None, "cpu_current_mhz": None, "cpu_max_mhz": None, "thread_count": 1, "module_count": 1, "current_directory": None, "environment_variables": None}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,SystemInfoStream not present; PEB not available (requires sysinfo + thread list),1\n'
        '\n## sysinfo / records\n'
        'dump_file,dump_file_size_bytes,dump_sha256,dump_time_utc,hostname,username,os,os_version,architecture,product_type,processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,thread_count,module_count,current_directory,environment_variables\n'
        'test.dmp,25,5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509,2024-08-14 01:15:05 UTC,,,,,,,,,,,1,1,,\n'
        '\n',
    ),
    (
        "sysinfo_missing_misc_info_only", ["--sysinfo"], _sysinfo_missing_misc_info_only, 3,
        '\n═══ DUMP ═══\n    File                   test.dmp\n'
        '    Size                   25 bytes\n'
        '    SHA-256                5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509\n'
        '    Dump Time              2024-08-14 01:15:05 UTC\n    Threads in dump        1\n'
        '    Modules in dump        1\n\n═══ SYSTEM INFO ═══\n'
        '  [~] MiscInfo stream not present\n\n  Operating System\n'
        '    OS                     Windows 10\n    Version                10.0.19041\n'
        '    Architecture           AMD64\n    Product Type           VER_NT_WORKSTATION\n\n'
        '  Host\n    Hostname               HOST1\n    Username               alice\n\n  CPU\n'
        '    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '═══ ENVIRONMENT ═══\n    Current Directory      C:\\work\n'
        '    Environment Variables  2 captured (--verbose or --json to view)\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["MiscInfo stream not present"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "dump_file_size_bytes": 25, "dump_sha256": "5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509", "dump_time_utc": "2024-08-14 01:15:05 UTC", "hostname": "HOST1", "username": "alice", "os": "Windows 10", "os_version": "10.0.19041", "architecture": "AMD64", "product_type": "VER_NT_WORKSTATION", "processors": 4, "cpu_vendor": "GenuineIntel", "cpu_current_mhz": None, "cpu_max_mhz": None, "thread_count": 1, "module_count": 1, "current_directory": "C:\\work", "environment_variables": [{"name": "COMPUTERNAME", "value": "HOST1"}, {"name": "USERNAME", "value": "alice"}]}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,MiscInfo stream not present,1\n\n## sysinfo / records\n'
        'dump_file,dump_file_size_bytes,dump_sha256,dump_time_utc,hostname,username,os,os_version,architecture,product_type,processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,thread_count,module_count,current_directory,environment_variables\n'
        'test.dmp,25,5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509,2024-08-14 01:15:05 UTC,HOST1,alice,Windows 10,10.0.19041,AMD64,VER_NT_WORKSTATION,4,GenuineIntel,,,1,1,C:\\work,"[{\'name\': \'COMPUTERNAME\', \'value\': \'HOST1\'}, {\'name\': \'USERNAME\', \'value\': \'alice\'}]"\n'
        '\n',
    ),
    (
        "sysinfo_missing_peb_only", ["--sysinfo"], _sysinfo_missing_peb_only, 3,
        '\n═══ DUMP ═══\n    File                   test.dmp\n'
        '    Size                   25 bytes\n'
        '    SHA-256                5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509\n'
        '    Dump Time              2024-08-14 01:15:05 UTC\n    Threads in dump        1\n'
        '    Modules in dump        1\n\n═══ SYSTEM INFO ═══\n\n  Operating System\n'
        '    OS                     Windows 10\n    Version                10.0.19041\n'
        '    Architecture           AMD64\n    Product Type           VER_NT_WORKSTATION\n\n'
        '  Host\n    Hostname               HOST1\n    Username               alice\n\n  CPU\n'
        '    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '═══ ENVIRONMENT ═══\n  [~] PEB not available (requires sysinfo + thread list)\n'
        '    Current Directory      (unknown)\n'
        '    Environment Variables  2 captured (--verbose or --json to view)\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["PEB not available (requires sysinfo + thread list)"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "dump_file_size_bytes": 25, "dump_sha256": "5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509", "dump_time_utc": "2024-08-14 01:15:05 UTC", "hostname": "HOST1", "username": "alice", "os": "Windows 10", "os_version": "10.0.19041", "architecture": "AMD64", "product_type": "VER_NT_WORKSTATION", "processors": 4, "cpu_vendor": "GenuineIntel", "cpu_current_mhz": None, "cpu_max_mhz": None, "thread_count": 1, "module_count": 1, "current_directory": None, "environment_variables": [{"name": "COMPUTERNAME", "value": "HOST1"}, {"name": "USERNAME", "value": "alice"}]}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,PEB not available (requires sysinfo + thread list),1\n\n'
        '## sysinfo / records\n'
        'dump_file,dump_file_size_bytes,dump_sha256,dump_time_utc,hostname,username,os,os_version,architecture,product_type,processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,thread_count,module_count,current_directory,environment_variables\n'
        'test.dmp,25,5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509,2024-08-14 01:15:05 UTC,HOST1,alice,Windows 10,10.0.19041,AMD64,VER_NT_WORKSTATION,4,GenuineIntel,,,1,1,,"[{\'name\': \'COMPUTERNAME\', \'value\': \'HOST1\'}, {\'name\': \'USERNAME\', \'value\': \'alice\'}]"\n'
        '\n',
    ),
    (
        "sysinfo_missing_threads_only", ["--sysinfo"], _sysinfo_missing_threads_only, 3,
        '\n═══ DUMP ═══\n  [~] ThreadListStream not present (thread_count unavailable)\n'
        '    File                   test.dmp\n    Size                   25 bytes\n'
        '    SHA-256                5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509\n'
        '    Dump Time              2024-08-14 01:15:05 UTC\n    Modules in dump        1\n\n'
        '═══ SYSTEM INFO ═══\n\n  Operating System\n    OS                     Windows 10\n'
        '    Version                10.0.19041\n    Architecture           AMD64\n'
        '    Product Type           VER_NT_WORKSTATION\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n  CPU\n'
        '    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '═══ ENVIRONMENT ═══\n  [~] PEB not available (requires sysinfo + thread list)\n'
        '    Current Directory      (unknown)\n    Environment Variables  (unavailable)\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["ThreadListStream not present (thread_count unavailable)", "PEB not available (requires sysinfo + thread list)"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "dump_file_size_bytes": 25, "dump_sha256": "5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509", "dump_time_utc": "2024-08-14 01:15:05 UTC", "hostname": None, "username": None, "os": "Windows 10", "os_version": "10.0.19041", "architecture": "AMD64", "product_type": "VER_NT_WORKSTATION", "processors": 4, "cpu_vendor": "GenuineIntel", "cpu_current_mhz": None, "cpu_max_mhz": None, "thread_count": None, "module_count": 1, "current_directory": None, "environment_variables": None}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,ThreadListStream not present (thread_count unavailable); PEB not available (requires sysinfo + thread list),1\n'
        '\n## sysinfo / records\n'
        'dump_file,dump_file_size_bytes,dump_sha256,dump_time_utc,hostname,username,os,os_version,architecture,product_type,processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,thread_count,module_count,current_directory,environment_variables\n'
        'test.dmp,25,5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509,2024-08-14 01:15:05 UTC,,,Windows 10,10.0.19041,AMD64,VER_NT_WORKSTATION,4,GenuineIntel,,,,1,,\n'
        '\n',
    ),
    (
        "sysinfo_missing_modules_only", ["--sysinfo"], _sysinfo_missing_modules_only, 3,
        '\n═══ DUMP ═══\n  [~] ModuleListStream not present (module_count unavailable)\n'
        '    File                   test.dmp\n    Size                   25 bytes\n'
        '    SHA-256                5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509\n'
        '    Dump Time              2024-08-14 01:15:05 UTC\n    Threads in dump        1\n\n'
        '═══ SYSTEM INFO ═══\n\n  Operating System\n    OS                     Windows 10\n'
        '    Version                10.0.19041\n    Architecture           AMD64\n'
        '    Product Type           VER_NT_WORKSTATION\n\n  Host\n'
        '    Hostname               (unknown)\n    Username               (unknown)\n\n  CPU\n'
        '    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '═══ ENVIRONMENT ═══\n'
        '  [~] environment block pointers could not be read: memory reader unavailable: \'NoneType\' object has no attribute \'modules\'\n'
        '    Current Directory      C:\\work\n    Environment Variables  (unavailable)\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "partial",
                      "reasons": ["ModuleListStream not present (module_count unavailable)", "environment block pointers could not be read: memory reader unavailable: 'NoneType' object has no attribute 'modules'"]},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "dump_file_size_bytes": 25, "dump_sha256": "5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509", "dump_time_utc": "2024-08-14 01:15:05 UTC", "hostname": None, "username": None, "os": "Windows 10", "os_version": "10.0.19041", "architecture": "AMD64", "product_type": "VER_NT_WORKSTATION", "processors": 4, "cpu_vendor": "GenuineIntel", "cpu_current_mhz": None, "cpu_max_mhz": None, "thread_count": 1, "module_count": None, "current_directory": "C:\\work", "environment_variables": None}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,partial,ModuleListStream not present (module_count unavailable); environment block pointers could not be read: memory reader unavailable: \'NoneType\' object has no attribute \'modules\',1\n'
        '\n## sysinfo / records\n'
        'dump_file,dump_file_size_bytes,dump_sha256,dump_time_utc,hostname,username,os,os_version,architecture,product_type,processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,thread_count,module_count,current_directory,environment_variables\n'
        'test.dmp,25,5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509,2024-08-14 01:15:05 UTC,,,Windows 10,10.0.19041,AMD64,VER_NT_WORKSTATION,4,GenuineIntel,,,1,,C:\\work,\n'
        '\n',
    ),
    (
        "sysinfo_complete", ["--sysinfo"], _sysinfo_complete, 0,
        '\n═══ DUMP ═══\n    File                   test.dmp\n'
        '    Size                   25 bytes\n'
        '    SHA-256                5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509\n'
        '    Dump Time              2024-08-14 01:15:05 UTC\n    Threads in dump        1\n'
        '    Modules in dump        1\n\n═══ SYSTEM INFO ═══\n\n  Operating System\n'
        '    OS                     Windows 10\n    Version                10.0.19041\n'
        '    Architecture           AMD64\n    Product Type           VER_NT_WORKSTATION\n\n'
        '  Host\n    Hostname               HOST1\n    Username               alice\n\n  CPU\n'
        '    Processors             4\n    Vendor                 GenuineIntel\n\n'
        '═══ ENVIRONMENT ═══\n    Current Directory      C:\\work\n'
        '    Environment Variables  2 captured (--verbose or --json to view)\n\n',
        {"kind": "sysinfo", "execution_status": "completed",
         "coverage": {"status": "complete",
                      "reasons": []},
         "summary": {"count": 1},
         "data": {"records": [{"dump_file": "test.dmp", "dump_file_size_bytes": 25, "dump_sha256": "5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509", "dump_time_utc": "2024-08-14 01:15:05 UTC", "hostname": "HOST1", "username": "alice", "os": "Windows 10", "os_version": "10.0.19041", "architecture": "AMD64", "product_type": "VER_NT_WORKSTATION", "processors": 4, "cpu_vendor": "GenuineIntel", "cpu_current_mhz": None, "cpu_max_mhz": None, "thread_count": 1, "module_count": 1, "current_directory": "C:\\work", "environment_variables": [{"name": "COMPUTERNAME", "value": "HOST1"}, {"name": "USERNAME", "value": "alice"}]}]}},
        '## sysinfo / summary\nkind,execution_status,coverage_status,coverage_reasons,count\n'
        'sysinfo,completed,complete,,1\n\n## sysinfo / records\n'
        'dump_file,dump_file_size_bytes,dump_sha256,dump_time_utc,hostname,username,os,os_version,architecture,product_type,processors,cpu_vendor,cpu_current_mhz,cpu_max_mhz,thread_count,module_count,current_directory,environment_variables\n'
        'test.dmp,25,5ab9667424b5f6af9c187e32671245bdbe969c16667f04ffa2a3eaa2786c3509,2024-08-14 01:15:05 UTC,HOST1,alice,Windows 10,10.0.19041,AMD64,VER_NT_WORKSTATION,4,GenuineIntel,,,1,1,C:\\work,"[{\'name\': \'COMPUTERNAME\', \'value\': \'HOST1\'}, {\'name\': \'USERNAME\', \'value\': \'alice\'}]"\n'
        '\n',
    ),
]


# ── frozen coverage.sources/coverage.limitations, keyed by scenario name ──
# Kept separate from SCENARIOS above (rather than folded into each
# scenario's `result` literal) so the console/exit-code table added
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
         "related_tids": [], "thread_id": None, "detail": None, "targets": [],
         "budget_limit": None, "budget_consumed": None}
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
    # --sysinfo's seven sources, and its limitations in §4.7's SECTION
    # order -- DUMP (dump_file, threads, modules), then SYSTEM INFO
    # (sysinfo, misc_info), then ENVIRONMENT (environment_block, peb).
    # "dump_file" is `present` throughout: conftest's
    # _fake_dump_file_on_disk backs FakeMF.filename with a real file, so
    # every scenario below establishes the dump's size and SHA-256, which
    # is the only state a real open_dump() can hand a command.
    "sysinfo_all_absent": (
        {"dump_file": _src("present", 1),
         "sysinfo": _src("absent"), "misc_info": _src("absent"), "peb": _src("absent"),
         "threads": _src("absent"), "modules": _src("absent"),
         "environment_block": _src("absent")},
        [_lim("SYSINFO_THREADS_UNAVAILABLE", "threads", scope="dump"),
         _lim("SYSINFO_MODULES_UNAVAILABLE", "modules", scope="dump"),
         _lim("SYSINFO_SYSTEM_INFO_UNAVAILABLE", "sysinfo", scope="dump"),
         _lim("SYSINFO_MISC_INFO_UNAVAILABLE", "misc_info", scope="dump"),
         _lim("SYSINFO_PEB_UNAVAILABLE", "peb", scope="dump")],
    ),
    "sysinfo_missing_sysinfo_only": (
        # sysinfo absent implies peb absent too via a real open_dump()
        # (dumpex/core/memory.py's phase 3b only builds peb under the
        # same sysinfo+threads precondition the environment walk's own
        # "unsupported" state requires) -- the builder nulls both, so
        # this is a genuinely reachable state: environment_block's
        # "unsupported" suppression applies (no limitation of its own).
        {"dump_file": _src("present", 1),
         "sysinfo": _src("absent"), "misc_info": _src("present", 1), "peb": _src("absent"),
         "threads": _src("present", 1), "modules": _src("present", 1),
         "environment_block": _src("absent")},
        [_lim("SYSINFO_SYSTEM_INFO_UNAVAILABLE", "sysinfo", scope="dump"),
         _lim("SYSINFO_PEB_UNAVAILABLE", "peb", scope="dump")],
    ),
    "sysinfo_missing_misc_info_only": (
        {"dump_file": _src("present", 1),
         "sysinfo": _src("present", 1), "misc_info": _src("absent"), "peb": _src("present", 1),
         "threads": _src("present", 1), "modules": _src("present", 1),
         "environment_block": _src("present", 2)},
        [_lim("SYSINFO_MISC_INFO_UNAVAILABLE", "misc_info", scope="dump")],
    ),
    "sysinfo_missing_peb_only": (
        {"dump_file": _src("present", 1),
         "sysinfo": _src("present", 1), "misc_info": _src("present", 1), "peb": _src("absent"),
         "threads": _src("present", 1), "modules": _src("present", 1),
         "environment_block": _src("present", 2)},
        [_lim("SYSINFO_PEB_UNAVAILABLE", "peb", scope="dump")],
    ),
    "sysinfo_missing_threads_only": (
        # threads absent implies peb absent too -- see
        # sysinfo_missing_sysinfo_only's own comment above.
        {"dump_file": _src("present", 1),
         "sysinfo": _src("present", 1), "misc_info": _src("present", 1),
         "peb": _src("absent"), "threads": _src("absent"), "modules": _src("present", 1),
         "environment_block": _src("absent")},
        [_lim("SYSINFO_THREADS_UNAVAILABLE", "threads", scope="dump"),
         _lim("SYSINFO_PEB_UNAVAILABLE", "peb", scope="dump")],
    ),
    "sysinfo_missing_modules_only": (
        # modules absent implies the environment walk fails too (a real
        # MinidumpFileReader can't be constructed without mf.modules) --
        # see _assert_env_walk_reachable_via_open_dump's own docstring.
        {"dump_file": _src("present", 1),
         "sysinfo": _src("present", 1), "misc_info": _src("present", 1),
         "peb": _src("present", 1), "threads": _src("present", 1), "modules": _src("absent"),
         "environment_block": _src("failed", detail="memory reader unavailable: "
                                    "'NoneType' object has no attribute 'modules'")},
        [_lim("SYSINFO_MODULES_UNAVAILABLE", "modules", scope="dump"),
         _lim("ENVIRONMENT_BLOCK_UNREADABLE", "environment_block",
              detail="memory reader unavailable: 'NoneType' object has no attribute "
                     "'modules'")],
    ),
    "sysinfo_complete": (
        {"dump_file": _src("present", 1),
         "sysinfo": _src("present", 1), "misc_info": _src("present", 1),
         "peb": _src("present", 1), "threads": _src("present", 1),
         "modules": _src("present", 1), "environment_block": _src("present", 2)},
        [],
    ),
}


def _expected_meta(argv0: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
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


# issue #41 changed --sysinfo's live SysInfoRecord shape (removed pid/
# process_start_utc/image_path/command_line/process_user_time_seconds/
# process_kernel_time_seconds; added current_directory/environment_variables,
# plus a new console ENVIRONMENT section replacing the removed Process
# section). The "sysinfo_*" scenarios below were refreshed in the SAME
# change (not deferred to #43): _sysinfo_full() now wires a real
# TEB->PEB->ProcessParameters->Environment walk (tests.fixtures.fakes.
# wire_environment_walk()) with a genuine PROCESSOR_ARCHITECTURE.AMD64
# sysinfo, so "sysinfo_complete" reaches an actually-complete, exit-0
# result with real captured environment entries -- not a fixture artifact
# blessed as correct. #43's own job stays only the CURRENT_SCHEMA/v2.13
# file cutover (see test_json_schema_v2.py's still-deferred xfails).
@pytest.mark.parametrize(
    "name,argv,mf_builder,exit_code,console,result,_csv",
    SCENARIOS, ids=[s[0] for s in SCENARIOS],
)
def test_compat_freeze(monkeypatch, tmp_path, capsys, name, argv, mf_builder, exit_code,
                        console, result, _csv):
    mf = mf_builder()
    if name.startswith("sysinfo"):
        # Structural backstop, not just per-builder discipline: every
        # _sysinfo_* builder is SUPPOSED to call
        # _assert_sysinfo_reachable_via_open_dump() itself (a builder
        # that forgets to is exactly the class of bug this file's own
        # "sysinfo_*" golden regenerations have hit repeatedly), but
        # asserting it again here means a future builder that omits the
        # call still can't slip an unreachable state past this suite.
        _assert_sysinfo_reachable_via_open_dump(mf)
    actual_exit, doc, dump_path_abs = _run(monkeypatch, tmp_path, argv, mf)
    actual_console = _normalize_console(capsys.readouterr().out, str(tmp_path))
    _normalize_doc(doc, dump_path_abs)

    sources, limitations = _COVERAGE_SOURCES_AND_LIMITATIONS[name]
    result = dict(result)
    result["coverage"] = dict(result["coverage"], sources=sources, limitations=limitations)

    expected_doc = {"meta": _expected_meta(argv[0]), "result": result,
                     "artifacts": [], "diagnostics": {"warnings": [], "errors": []}}
    expected_console = console + "  [·] JSON written → <TMP_DIR>" + os.sep \
        + "out.json  (<SIZE> bytes  sha256=<HASH>)\n"

    assert actual_exit == exit_code, f"{name}: exit code drifted"
    assert doc == expected_doc, f"{name}: JSON document drifted"
    assert actual_console == expected_console, f"{name}: console drifted"


# ── reachability guards: prove they actually catch drift ─────────────────
# Both assertions exist so a future edit to a _sysinfo_* builder can't
# silently re-freeze a golden no real open_dump() output could produce
# (see each assertion's own docstring for the underlying invariant).

def test_assert_peb_reachable_via_open_dump_catches_peb_without_sysinfo():
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe")   # sysinfo/threads left absent
    with pytest.raises(AssertionError, match="open_dump\\(\\) can never produce"):
        _assert_peb_reachable_via_open_dump(mf)


def test_assert_env_walk_reachable_via_open_dump_catches_reader_without_modules():
    mf = FakeMF()
    mf.sysinfo = SysInfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    wire_environment_walk(mf, b"\x00\x00\x00\x00")   # wires mf._reader
    mf.modules = None
    with pytest.raises(AssertionError, match="open_dump\\(\\) can never produce"):
        _assert_env_walk_reachable_via_open_dump(mf)


def test_compat_freeze_corrupted_dump_exits_1_writes_no_structured_output(
        monkeypatch, tmp_path, capsys):
    """The one scenario every other row in this suite can't cover: a dump
    that fails to PARSE at all. Deliberately does NOT monkeypatch
    cli.open_dump -- the real dumpex.core.memory.open_dump() runs against
    our fixed (deliberately non-minidump) DUMP_BYTES, hits
    MinidumpFile.parse()'s real exception path, and must exit 1 before
    ever reaching a V2Output construction, writing no --json output (a half-written structured-output file for a run that
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
    monkeypatch.setattr(sys, "argv",
                         ["dumpex", dump_path, "--list", "--json", out_json])

    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == 1
    assert not os.path.exists(out_json), "a failed parse must not leave a partial JSON file"

    console = capsys.readouterr().out
    assert f"[!] Could not parse {dump_path} as a minidump file:" in console
    assert ("The file may be corrupted, truncated, or not a Windows minidump "
            "(.dmp) at all.") in console

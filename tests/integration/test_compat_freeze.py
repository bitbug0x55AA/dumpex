"""
Table-driven compatibility-freeze suite for four of dumpex's recon
commands (--list/--modules/--threads/--sysinfo), plus a second table
(RECON_V213_SCENARIOS, near the bottom of this file) doing the same
full-console/full-JSON freeze for --process/--handles/--profile: complete/
partial/not_evaluated coverage for all three; default vs. --verbose;
#98's handle folding and Identity Verification block (agreement,
conflict, ambiguous-candidate, and unavailable-checks states); #102's
Access-mask decode over both a decodable and a genuinely unreadable
(evidence-lost) object name; the \\KnownDlls note; named/ordinal/
unavailable verbose IAT entries; and --profile's full stream-state
vocabulary (parsed/present_empty/unparsed/failed/indeterminate, including
an unrecognized numeric stream type) with a genuine available/limited/
unavailable capability mix. `--pid`/`--peb`
were removed in issue #43's atomic v2.13 cutover (see
docs/developer/recon_process_sysinfo_handles_contract.md §7.2) -- their golden
scenarios were removed from this suite in the same change. The three
replacements also get broader CLI-level compatibility coverage (every
exit code, --txt, --redact-paths, more source-state combinations) in
tests/integration/test_cli_v2_routing.py, which this second table does
not attempt to duplicate.

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
              "--sysinfo": "sysinfo", "--process": "process", "--handles": "handles",
              "--profile": "profile"}
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
    actually produce (see docs/developer/recon_process_sysinfo_handles_contract.md
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


# Every scenario in BOTH tables below reports this same aggregate, and
# that is the assertion, not a placeholder: none of these seven recon
# commands has a coverage gap that costs capturable memory. An absent
# stream, a stream present but incomplete, a thread list that disagrees
# with its counterpart -- each makes coverage `partial` while missing no
# bytes a re-collection would recover, and the aggregate must say exactly
# zero rather than invent a gap to match the status word.
_NO_MISSED_BYTES = {"state": "exact", "bytes": 0, "complete": True,
                     "quantified_gaps": 0, "unquantified_gaps": 0,
                     "distinct_ranges": 0}


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
    result["coverage"] = dict(result["coverage"], sources=sources, limitations=limitations,
                               missed_bytes=_NO_MISSED_BYTES)

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


# ── --process/--handles/--profile compatibility-freeze suite ──────────────
# The three v2.13 replacements for --pid/--peb (issue #43) get their own
# golden table here, at the same full-console/full-JSON rigor as the four
# commands above -- this file's own top-of-module docstring used to say
# their compatibility fixtures were still owed to #44; this closes that gap
# for the states that most exercise table layout, folding counts, and help
# text: complete/partial/not_evaluated coverage for all three commands;
# default vs. --verbose console projections; #98's handle folding, #98's
# Identity Verification block (agreement, conflict, and unavailable-checks
# states); #102's Access-mask decode; the \KnownDlls explanatory note;
# named/ordinal/unavailable verbose IAT entries; and #95's full stream-
# state vocabulary (parsed/present_empty/unparsed/failed/indeterminate,
# including an unrecognized numeric type) with a genuine available/
# limited/unavailable capability mix; and, for --handles, a genuinely
# unreadable (not merely unnamed) object name driving partial coverage.
# Every state above is exercised through the exact same real mf-level
# fixture builders tests/unit/test_process_cmd.py,
# test_process_identity_snapshot.py, and test_handles_cmd.py already use
# at the unit level, reused here rather than re-derived, so this suite's
# job is only to freeze the exact rendered text they produce, not to
# re-establish correctness from scratch.
#
# Reuses this module's own _run()/_normalize_console()/_normalize_doc()/
# _FrozenDateTimeModule harness. Unlike SCENARIOS above, each entry's
# `result` dict already includes `coverage.sources`/`coverage.limitations`
# verbatim (captured from a real run, not hand-derived) -- there is no
# separate _COVERAGE_SOURCES_AND_LIMITATIONS split to keep in sync.

from minidump.constants import MINIDUMP_STREAM_TYPE as _MINIDUMP_STREAM_TYPE
from tests.fixtures.fakes import Handle as _Handle, build_pe_header as _build_pe_header, \
    TEXT_SECTION_RX as _TEXT_SECTION_RX
from tests.unit.test_process_cmd import (
    _complete_mf as _process_complete_mf, _mf as _process_mf_builder,
    _patch_data_directories as _process_patch_data_directories,
    _descriptor as _process_descriptor, _TERMINATOR as _PROCESS_IAT_TERMINATOR,
    _cstr as _process_cstr, _pad as _process_pad, _thunk64 as _process_thunk64,
    IMAGE_BASE as _PROCESS_IMAGE_BASE,
)
from tests.unit.test_handles_cmd import _mf_with as _handles_mf_with, BAD_RVA as _HANDLES_BAD_RVA


def _process_not_evaluated(): return FakeMF()

def _process_complete(): return _process_complete_mf()

def _handles_absent(): return FakeMF()

def _handles_present_empty():
    mf = FakeMF(); mf.handles = FakeStream([], "handles"); return mf

def _handles_fold():
    # Two anonymous Event handles (object_name RVA genuinely 0, not a
    # failed read) plus one named File -- goes through the real byte-level
    # parser (test_handles_cmd.py's own _mf_with), not the simplified
    # Handle() fake: a bare `Handle(h, t, None)` has no ObjectNameRva at
    # all, which collect_handles() reads as "unreadable" (evidence lost),
    # not "unnamed" (positively no name) -- see dumpex/commands/handles.py
    # §5.2.1. Only the real parser distinguishes the two, and only
    # "unnamed" rows are foldable.
    return _handles_mf_with([
        {"handle": 0x10, "type_name": "Event", "object_name": None},
        {"handle": 0x11, "type_name": "Event", "object_name": None},
        {"handle": 0x20, "type_name": "File",
         "object_name": r"\Device\HarddiskVolume1\notes.txt", "granted_access": 0x0012019F},
    ])

def _handles_known_dlls():
    mf = FakeMF()
    mf.handles = FakeStream([_Handle(0x30, "Directory", r"\KnownDlls")], "handles")
    return mf

def _profile_not_evaluated(): return FakeMF()

class _FakeMinidumpHeader:
    """Minimal stand-in for the dump's own header -- only `.Flags`
    (MINIDUMP_TYPE), the one field collect_profile() reads from it."""
    def __init__(self, flags=0):
        self.Flags = flags

def _profile_complete_sparse():
    mf = FakeMF()
    mf.header = _FakeMinidumpHeader(0)
    mf.sysinfo = SysInfo()
    return mf

def _process_partial():
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=100, process_create_time=1786670105)
    mf.peb = Peb(None, r"C:\test.exe")   # image_base_address=None, command_line=None
    return mf

def _process_unavailable_checks():
    # PEB/MiscInfo present with a structurally valid, import-free image at
    # the PEB base, but ModuleListStream entirely absent -- every
    # ModuleList-dependent Identity Verification check must read "[--]
    # could not be evaluated", never an agreement or a conflict.
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(_PROCESS_IMAGE_BASE, r"C:\Samples\malware.exe",
              command_line=r"C:\Samples\malware.exe")
    header = _build_pe_header([_TEXT_SECTION_RX], image_base=_PROCESS_IMAGE_BASE, size_of_image=0x6000)
    header = _process_patch_data_directories(header, {1: (0, 0), 12: (0, 0)})   # no imports
    memory = {_PROCESS_IMAGE_BASE: header}
    return _process_mf_builder(misc_info=misc, peb=peb, memory=memory)   # modules=None -> absent

def _process_conflict_and_iat():
    # A module registered at a DIFFERENT base than the PEB's own image
    # base (an identity conflict, [!!]) plus a two-entry IAT: one ordinal
    # import and one OriginalFirstThunk==0 "unavailable" import -- the two
    # verbose-only IAT entry shapes not otherwise exercised in this suite.
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(_PROCESS_IMAGE_BASE, r"C:\Samples\malware.exe",
              command_line=r"C:\Samples\malware.exe")
    other_base = 0x00007ff700000000
    conflicting_mod = Module(other_base, 0x6000, r"C:\Windows\Temp\malware.exe")

    import_dir_rva, dll_name_rva1, int_rva1 = 0x2000, 0x4000, 0x5000
    first_thunk_rva1, first_thunk_rva2 = 0x3000, 0x3010

    header = _build_pe_header([_TEXT_SECTION_RX], image_base=_PROCESS_IMAGE_BASE, size_of_image=0x7000)
    header = _process_patch_data_directories(header, {1: (import_dir_rva, 60), 12: (0x3000, 32)})

    descr_ordinal = _process_descriptor(int_rva1, dll_name_rva1, first_thunk_rva1)
    descr_unavailable = _process_descriptor(0, 0, first_thunk_rva2)   # OriginalFirstThunk == 0

    memory = {
        _PROCESS_IMAGE_BASE: header,
        _PROCESS_IMAGE_BASE + import_dir_rva:
            descr_ordinal + descr_unavailable + _PROCESS_IAT_TERMINATOR,
        _PROCESS_IMAGE_BASE + dll_name_rva1: _process_pad(_process_cstr("ADVAPI32.dll")),
        # IMAGE_ORDINAL_FLAG64 | ordinal 12 -- imported by ordinal, no name.
        _PROCESS_IMAGE_BASE + int_rva1: _process_thunk64(0x8000000000000000 | 12) + _process_thunk64(0),
        _PROCESS_IMAGE_BASE + first_thunk_rva1: _process_thunk64(0x00007ffb0000000C) + _process_thunk64(0),
        _PROCESS_IMAGE_BASE + first_thunk_rva2: _process_thunk64(0x00007ffb00000099) + _process_thunk64(0),
    }
    return _process_mf_builder(misc_info=misc, peb=peb, modules=[conflicting_mod], memory=memory)


class _ProfileDirLocation:
    def __init__(self, rva=0, data_size=0):
        self.Rva = rva
        self.DataSize = data_size

class _ProfileDirectory:
    def __init__(self, stream_type, rva=0, data_size=0):
        self.StreamType = stream_type
        self.Location = _ProfileDirLocation(rva, data_size)

def _profile_mixed():
    # One dump exercising every stream-inventory state at once (parsed,
    # present_empty, unparsed x2 -- a recognized-but-undispatched type and
    # an unrecognized numeric type, failed, and a duplicate/indeterminate
    # pair) plus a genuine mix of capability statuses (available, limited,
    # unavailable) -- #95's own "every new profile state" surface in one
    # coherent, plausible dump rather than eight near-identical scenarios.
    mf = FakeMF()
    mf.header = _FakeMinidumpHeader(0)
    mf.directories = [
        _ProfileDirectory(_MINIDUMP_STREAM_TYPE.SystemInfoStream),
        _ProfileDirectory(_MINIDUMP_STREAM_TYPE.ThreadListStream),
        _ProfileDirectory(_MINIDUMP_STREAM_TYPE.ModuleListStream),
        _ProfileDirectory(_MINIDUMP_STREAM_TYPE.ModuleListStream),   # duplicate -> indeterminate
        _ProfileDirectory(_MINIDUMP_STREAM_TYPE.FunctionTableStream),   # recognized, undispatched
        _ProfileDirectory(9999),   # unrecognized numeric type
        _ProfileDirectory(_MINIDUMP_STREAM_TYPE.HandleDataStream),
        _ProfileDirectory(_MINIDUMP_STREAM_TYPE.MemoryInfoListStream),
    ]
    mf.sysinfo = SysInfo()
    mf.threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")   # thread_info absent -> limited
    mf.handles = FakeStream([], "handles")   # present_empty -> handle capabilities available
    mf._dumpex_stream_failures = {
        _MINIDUMP_STREAM_TYPE.MemoryInfoListStream: "ValueError: layout drift",
    }
    return mf

def _handles_partial():
    # A descriptor whose ObjectNameRva points past the end of the captured
    # stream body -- a genuinely UNREADABLE name (evidence lost), not
    # merely unnamed -- drives object_name_status="unreadable" and the
    # command's own partial coverage in one real, parser-level fixture.
    return _handles_mf_with([{"handle": 0x10, "type_name": "File", "object_name": _HANDLES_BAD_RVA}])

def _process_identity_ambiguous():
    # Two modules share the process name, neither registered at the PEB's
    # own image base -- module_claim.name_matched_candidate_ambiguous, the
    # one identity state the rest of this table doesn't reach.
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(_PROCESS_IMAGE_BASE, r"C:\Samples\malware.exe",
              command_line=r"C:\Samples\malware.exe")
    mod1 = Module(0x00007ff700000000, 0x2000, r"C:\Windows\Temp\malware.exe")
    mod2 = Module(0x00007ff800000000, 0x2000, r"C:\ProgramData\malware.exe")

    header = _build_pe_header([_TEXT_SECTION_RX], image_base=_PROCESS_IMAGE_BASE, size_of_image=0x6000)
    header = _process_patch_data_directories(header, {1: (0, 0), 12: (0, 0)})   # no imports
    memory = {_PROCESS_IMAGE_BASE: header}
    return _process_mf_builder(misc_info=misc, peb=peb, modules=[mod1, mod2], memory=memory)


# (name, argv, mf_builder, exit_code, console, result) -- console excludes
# the trailing "JSON written" line, appended by the test itself (same
# convention as SCENARIOS above); result is the COMPLETE result dict
# (coverage.sources/limitations included), captured from a real run.
RECON_V213_SCENARIOS = [
    (
        'process_not_evaluated', ['--process'], _process_not_evaluated, 4,
        '\n═══ PROCESS ═══\n  [~] no usable process identity evidence available (MiscInfo and the PEB supplied no usable PID, start time, path, command line, or image base)\n\n  Process Name           (unknown)\n  PID                    (unknown)\n  Path                   (unknown)\n  Command Line           (unknown)\n  Start Time (UTC)       (unknown)\n  Image Base             (unknown)\n\n  Import Address Table\n    (unavailable -- see coverage below)\n\n  Identity\n',
        {'kind': 'process', 'execution_status': 'completed', 'coverage': {'status': 'not_evaluated', 'reasons': ['no usable process identity evidence available (MiscInfo and the PEB supplied no usable PID, start time, path, command line, or image base)'], 'sources': {'process_identity': {'state': 'absent', 'record_count': None, 'detail': None}, 'misc_info': {'state': 'absent', 'record_count': None, 'detail': None}, 'peb': {'state': 'absent', 'record_count': None, 'detail': None}, 'modules': {'state': 'absent', 'record_count': None, 'detail': None}, 'main_image': {'state': 'absent', 'record_count': None, 'detail': None}, 'iat': {'state': 'absent', 'record_count': None, 'detail': None}}, 'limitations': [{'code': 'PROCESS_SOURCES_ABSENT', 'source': 'process_identity', 'scope': 'dump', 'affected_count': None, 'unavailable_fields': [], 'available_fields': [], 'counterpart_source': None, 'related_sources': [], 'related_tids': [], 'thread_id': None, 'detail': None, 'targets': [], 'budget_limit': None, 'budget_consumed': None}]}, 'summary': {'count': 1}, 'data': {'records': [{'process_name': None, 'pid': None, 'process_path': None, 'command_line': None, 'process_start_utc': None, 'image_base_address': None, 'iat': {'table_present': None, 'table_va': None, 'table_size': None, 'import_directory_present': None, 'import_directory_va': None, 'import_directory_size': None, 'has_entries': False, 'dll_count': 0, 'entry_count': 0, 'entries': [], 'diagnostics': []}, 'identity_evidence': {'misc_info_claim': {'pid': None, 'process_create_time_utc': None, 'raw_pid': None, 'raw_process_create_time': None}, 'peb_claim': {'image_base_address': None, 'image_path': None, 'name': None, 'raw_image_base_address': None, 'raw_image_path': None, 'raw_command_line': None}, 'module_claim': {'match_state': 'unavailable', 'base_address': None, 'name': None, 'path': None, 'name_matched_candidate': None, 'name_matched_candidate_ambiguous': False}, 'main_image_pe': {'checked': False, 'valid': None, 'reason': None}, 'selected_path_source': None, 'diagnostics': []}}]}},
    ),
    (
        'process_complete', ['--process'], _process_complete, 0,
        '\n═══ PROCESS ═══\n\n  Process Name           malware.exe\n  PID                    4242 (0x1092)\n  Path                   C:\\Samples\\malware.exe\n  Command Line           "C:\\Samples\\malware.exe" -k\n  Start Time (UTC)       2026-08-14 01:15:05 UTC\n  Image Base             0x00007ff600010000\n\n  Import Address Table\n    1 import(s) across 1 DLL(s)\n\n  Identity\n',
        {'kind': 'process', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'process_identity': {'state': 'present', 'record_count': 5, 'detail': None}, 'misc_info': {'state': 'present', 'record_count': 1, 'detail': None}, 'peb': {'state': 'present', 'record_count': 1, 'detail': None}, 'modules': {'state': 'present', 'record_count': 1, 'detail': None}, 'main_image': {'state': 'present', 'record_count': 1, 'detail': None}, 'iat': {'state': 'present', 'record_count': 1, 'detail': None}}, 'limitations': []}, 'summary': {'count': 1}, 'data': {'records': [{'process_name': 'malware.exe', 'pid': 4242, 'process_path': 'C:\\Samples\\malware.exe', 'command_line': '"C:\\Samples\\malware.exe" -k', 'process_start_utc': '2026-08-14 01:15:05 UTC', 'image_base_address': '0x00007ff600010000', 'iat': {'table_present': True, 'table_va': '0x00007ff600013000', 'table_size': 16, 'import_directory_present': True, 'import_directory_va': '0x00007ff600012000', 'import_directory_size': 40, 'has_entries': True, 'dll_count': 1, 'entry_count': 1, 'entries': [{'dll': 'KERNEL32.dll', 'import_by': 'name', 'symbol': 'CreateFileW', 'ordinal': None, 'iat_slot_va': '0x00007ff600013000', 'resolved_target_va': '0x00007ffb12345678', 'slot_in_bounds': True}], 'diagnostics': []}, 'identity_evidence': {'misc_info_claim': {'pid': 4242, 'process_create_time_utc': '2026-08-14 01:15:05 UTC', 'raw_pid': None, 'raw_process_create_time': None}, 'peb_claim': {'image_base_address': '0x00007ff600010000', 'image_path': 'C:\\Samples\\malware.exe', 'name': 'malware.exe', 'raw_image_base_address': None, 'raw_image_path': None, 'raw_command_line': None}, 'module_claim': {'match_state': 'resolved', 'base_address': '0x00007ff600010000', 'name': 'malware.exe', 'path': 'C:\\Samples\\malware.exe', 'name_matched_candidate': None, 'name_matched_candidate_ambiguous': False}, 'main_image_pe': {'checked': True, 'valid': True, 'reason': None}, 'selected_path_source': 'peb', 'diagnostics': []}}]}},
    ),
    (
        'process_complete_verbose', ['--process', '--verbose'], _process_complete, 0,
        '\n═══ PROCESS ═══\n\n  Process Name           malware.exe\n  PID                    4242 (0x1092)\n  Path                   C:\\Samples\\malware.exe\n  Command Line           "C:\\Samples\\malware.exe" -k\n  Start Time (UTC)       2026-08-14 01:15:05 UTC\n  Image Base             0x00007ff600010000\n\n  Import Address Table\n    1 import(s) across 1 DLL(s)\n\n    Each row reads IAT Slot VA -> Resolved Target VA.\n    The slot is the address where the import pointer is stored; the target is the\n    address stored in that slot in the captured process memory.\n\n    DLL                       Imported API                  IAT Slot VA           Resolved Target VA\n    KERNEL32.dll              CreateFileW                   0x00007ff600013000    0x00007ffb12345678\n\n  Identity\n\n  Identity Verification                            [--verbose only]\n    Selected path    C:\\Samples\\malware.exe\n    Selected name    malware.exe\n    Source           PEB (ProcessParameters.ImagePathName)\n    Image base       0x00007ff600010000 (source: PEB)\n\n    [OK] PEB image base is registered in ModuleList\n         0x00007ff600010000 -> malware.exe\n    [OK] PEB and ModuleList process names agree\n    [OK] a valid PE header was found at the PEB image base\n    [OK] no competing module shares this process name\n\n    Raw claims       PEB                              ModuleList\n    path             C:\\Samples\\malware.exe           C:\\Samples\\malware.exe\n    name             malware.exe                      malware.exe\n    image base       0x00007ff600010000               0x00007ff600010000 (resolved)\n\n  Extended PEB\n    PEB Address        0x0000000000000000\n    BeingDebugged      False\n    WindowTitle        (none)\n    DllPath            (none)\n    StandardInput      (unknown)\n    StandardOutput     (unknown)\n    StandardError      (unknown)\n',
        {'kind': 'process', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'process_identity': {'state': 'present', 'record_count': 5, 'detail': None}, 'misc_info': {'state': 'present', 'record_count': 1, 'detail': None}, 'peb': {'state': 'present', 'record_count': 1, 'detail': None}, 'modules': {'state': 'present', 'record_count': 1, 'detail': None}, 'main_image': {'state': 'present', 'record_count': 1, 'detail': None}, 'iat': {'state': 'present', 'record_count': 1, 'detail': None}}, 'limitations': []}, 'summary': {'count': 1}, 'data': {'records': [{'process_name': 'malware.exe', 'pid': 4242, 'process_path': 'C:\\Samples\\malware.exe', 'command_line': '"C:\\Samples\\malware.exe" -k', 'process_start_utc': '2026-08-14 01:15:05 UTC', 'image_base_address': '0x00007ff600010000', 'iat': {'table_present': True, 'table_va': '0x00007ff600013000', 'table_size': 16, 'import_directory_present': True, 'import_directory_va': '0x00007ff600012000', 'import_directory_size': 40, 'has_entries': True, 'dll_count': 1, 'entry_count': 1, 'entries': [{'dll': 'KERNEL32.dll', 'import_by': 'name', 'symbol': 'CreateFileW', 'ordinal': None, 'iat_slot_va': '0x00007ff600013000', 'resolved_target_va': '0x00007ffb12345678', 'slot_in_bounds': True}], 'diagnostics': []}, 'identity_evidence': {'misc_info_claim': {'pid': 4242, 'process_create_time_utc': '2026-08-14 01:15:05 UTC', 'raw_pid': None, 'raw_process_create_time': None}, 'peb_claim': {'image_base_address': '0x00007ff600010000', 'image_path': 'C:\\Samples\\malware.exe', 'name': 'malware.exe', 'raw_image_base_address': None, 'raw_image_path': None, 'raw_command_line': None}, 'module_claim': {'match_state': 'resolved', 'base_address': '0x00007ff600010000', 'name': 'malware.exe', 'path': 'C:\\Samples\\malware.exe', 'name_matched_candidate': None, 'name_matched_candidate_ambiguous': False}, 'main_image_pe': {'checked': True, 'valid': True, 'reason': None}, 'selected_path_source': 'peb', 'diagnostics': []}, 'peb_extended': {'peb_address': '0x0000000000000000', 'being_debugged': False, 'window_title': None, 'dll_path': None, 'standard_input': None, 'standard_output': None, 'standard_error': None}}]}},
    ),
    (
        'handles_absent', ['--handles'], _handles_absent, 4,
        '\n═══ HANDLES ═══\n  HandleDataStream not present in this dump\n\n  [~] HandleDataStream not present in this dump (not captured with handle data)\n\n',
        {'kind': 'handles', 'execution_status': 'completed', 'coverage': {'status': 'not_evaluated', 'reasons': ['HandleDataStream not present in this dump (not captured with handle data)'], 'sources': {'handles': {'state': 'absent', 'record_count': None, 'detail': None}, 'handle_records': {'state': 'absent', 'record_count': None, 'detail': None}}, 'limitations': [{'code': 'HANDLES_UNAVAILABLE', 'source': 'handle_records', 'scope': 'dump', 'affected_count': None, 'unavailable_fields': [], 'available_fields': [], 'counterpart_source': None, 'related_sources': [], 'related_tids': [], 'thread_id': None, 'detail': None, 'targets': [], 'budget_limit': None, 'budget_consumed': None}]}, 'summary': {'count': 0, 'by_type': {}}, 'data': {'records': []}},
    ),
    (
        'handles_present_empty', ['--handles'], _handles_present_empty, 0,
        '\n═══ HANDLES ═══\n  0 handle(s) captured\n\n',
        {'kind': 'handles', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'handles': {'state': 'present_empty', 'record_count': 0, 'detail': None}, 'handle_records': {'state': 'present_empty', 'record_count': 0, 'detail': None}}, 'limitations': []}, 'summary': {'count': 0, 'by_type': {}}, 'data': {'records': []}},
    ),
    (
        'handles_default_folds', ['--handles'], _handles_fold, 0,
        "\n═══ HANDLES ═══\n  3 handle(s) captured\n  By type: Event 2, File 1\n\n  Handle              Type            Access      Cnt  Ptr  Object\n  0x0000000000000020  File            0x0012019f    1    1  \\Device\\HarddiskVolume1\\notes.txt\n      └─ Rights   FileGenericRead · FileGenericWrite\n  Rights decode each row's own Access mask against its recorded object type -- the same bit means\n  different things for a File, a Process and a Token. A long list splits into Type (rights that\n  object type defines) and Standard (the rights every type shares). They are an observation about\n  what the handle permitted, never evidence that it was used.\n\n  Aliases used\n    Each display name maps to one Windows SDK, WDK or native constant, and what that constant\n    contains depends on the object type it was read against.\n      File  FileGenericRead  = ReadData · ReadEa · ReadAttributes · ReadControl · Synchronize\n      File  FileGenericWrite = WriteData · AppendData · WriteEa · WriteAttributes · ReadControl ·\n                               Synchronize\n\n  2 anonymous handle(s) not shown (no object name recorded): Event 2\n  These rows are captured evidence and are complete in structured output -- use --verbose to show all.\n\n",
        {'kind': 'handles', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'handles': {'state': 'present', 'record_count': 3, 'detail': None}, 'handle_records': {'state': 'present', 'record_count': 3, 'detail': None}}, 'limitations': []}, 'summary': {'count': 3, 'by_type': {'Event': 2, 'File': 1}}, 'data': {'records': [{'handle': '0x0000000000000010', 'type_name': 'Event', 'type_name_status': 'ok', 'object_name': None, 'object_name_status': 'unnamed', 'attributes': 0, 'granted_access': 0, 'handle_count': 1, 'pointer_count': 1}, {'handle': '0x0000000000000011', 'type_name': 'Event', 'type_name_status': 'ok', 'object_name': None, 'object_name_status': 'unnamed', 'attributes': 0, 'granted_access': 0, 'handle_count': 1, 'pointer_count': 1}, {'handle': '0x0000000000000020', 'type_name': 'File', 'type_name_status': 'ok', 'object_name': '\\Device\\HarddiskVolume1\\notes.txt', 'object_name_status': 'ok', 'attributes': 0, 'granted_access': 1180063, 'handle_count': 1, 'pointer_count': 1}]}},
    ),
    (
        'handles_verbose_shows_all', ['--handles', '--verbose'], _handles_fold, 0,
        "\n═══ HANDLES ═══\n  3 handle(s) captured\n  By type: Event 2, File 1\n\n  Handle              Type            Access      Cnt  Ptr  Object\n  0x0000000000000010  Event           0x00000000    1    1  (unnamed)\n      └─ Rights   (no rights)\n  0x0000000000000011  Event           0x00000000    1    1  (unnamed)\n      └─ Rights   (no rights)\n  0x0000000000000020  File            0x0012019f    1    1  \\Device\\HarddiskVolume1\\notes.txt\n      └─ Rights   FileGenericRead · FileGenericWrite\n  (unnamed) = the descriptor records no name; (unreadable) = a name was recorded but the bounded read failed\n  Rights decode each row's own Access mask against its recorded object type -- the same bit means\n  different things for a File, a Process and a Token. A long list splits into Type (rights that\n  object type defines) and Standard (the rights every type shares). They are an observation about\n  what the handle permitted, never evidence that it was used.\n\n  Aliases used\n    Each display name maps to one Windows SDK, WDK or native constant, and what that constant\n    contains depends on the object type it was read against.\n      File  FileGenericRead  = ReadData · ReadEa · ReadAttributes · ReadControl · Synchronize\n      File  FileGenericWrite = WriteData · AppendData · WriteEa · WriteAttributes · ReadControl ·\n                               Synchronize\n\n",
        {'kind': 'handles', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'handles': {'state': 'present', 'record_count': 3, 'detail': None}, 'handle_records': {'state': 'present', 'record_count': 3, 'detail': None}}, 'limitations': []}, 'summary': {'count': 3, 'by_type': {'Event': 2, 'File': 1}}, 'data': {'records': [{'handle': '0x0000000000000010', 'type_name': 'Event', 'type_name_status': 'ok', 'object_name': None, 'object_name_status': 'unnamed', 'attributes': 0, 'granted_access': 0, 'handle_count': 1, 'pointer_count': 1}, {'handle': '0x0000000000000011', 'type_name': 'Event', 'type_name_status': 'ok', 'object_name': None, 'object_name_status': 'unnamed', 'attributes': 0, 'granted_access': 0, 'handle_count': 1, 'pointer_count': 1}, {'handle': '0x0000000000000020', 'type_name': 'File', 'type_name_status': 'ok', 'object_name': '\\Device\\HarddiskVolume1\\notes.txt', 'object_name_status': 'ok', 'attributes': 0, 'granted_access': 1180063, 'handle_count': 1, 'pointer_count': 1}]}},
    ),
    (
        'handles_known_dlls', ['--handles', '--verbose'], _handles_known_dlls, 0,
        "\n═══ HANDLES ═══\n  1 handle(s) captured\n  By type: Directory 1\n\n  Handle              Type            Access      Cnt  Ptr  Object\n  0x0000000000000030  Directory       0x0012019f    1    1  \\KnownDlls\n      └─ Type     Query · Traverse · CreateObject · CreateSubdirectory · UnknownBits(0x00000190)\n         Standard ReadControl · Synchronize\n  Rights decode each row's own Access mask against its recorded object type -- the same bit means\n  different things for a File, a Process and a Token. A long list splits into Type (rights that\n  object type defines) and Standard (the rights every type shares). They are an observation about\n  what the handle permitted, never evidence that it was used.\n\n  Object name notes\n    \\KnownDlls (Directory)\n      NT Object Manager directory of pre-mapped system DLL sections. This\n      descriptor records the directory name only -- the section objects inside\n      it are not captured by it.\n\n",
        {'kind': 'handles', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'handles': {'state': 'present', 'record_count': 1, 'detail': None}, 'handle_records': {'state': 'present', 'record_count': 1, 'detail': None}}, 'limitations': []}, 'summary': {'count': 1, 'by_type': {'Directory': 1}}, 'data': {'records': [{'handle': '0x0000000000000030', 'type_name': 'Directory', 'type_name_status': 'ok', 'object_name': '\\KnownDlls', 'object_name_status': 'ok', 'attributes': None, 'granted_access': 1180063, 'handle_count': 1, 'pointer_count': 1}]}},
    ),
    (
        'profile_not_evaluated', ['--profile'], _profile_not_evaluated, 4,
        '\n═══ PROFILE ═══\n  no defensible capability profile could be constructed\n\n  [~] dump header/directory table could not be established; no defensible capability profile can be constructed\n\n',
        {'kind': 'profile', 'execution_status': 'completed', 'coverage': {'status': 'not_evaluated', 'reasons': ['dump header/directory table could not be established; no defensible capability profile can be constructed'], 'sources': {'profile_directory': {'state': 'absent', 'record_count': None, 'detail': None}}, 'limitations': [{'code': 'PROFILE_DIRECTORY_UNAVAILABLE', 'source': 'profile_directory', 'scope': 'dump', 'affected_count': None, 'unavailable_fields': [], 'available_fields': [], 'counterpart_source': None, 'related_sources': [], 'related_tids': [], 'thread_id': None, 'detail': None, 'targets': [], 'budget_limit': None, 'budget_consumed': None}]}, 'summary': {'stream_count': 0, 'capability_summary': {'available': 0, 'limited': 0, 'unavailable': 0}}, 'data': {'records': []}},
    ),
    (
        'profile_complete_sparse', ['--profile'], _profile_complete_sparse, 0,
        '\n═══ PROFILE ═══\n  0 directory entries inventoried\n\n  Basic\n    Architecture             AMD64\n    Full memory (flag)       no\n    Captured memory content  (unknown)\n    Raw MINIDUMP_TYPE flags  0x0\n    Recognized flags         (none)\n\n  Streams\n\n  Analysis capabilities\n    Memory-region analysis           unavailable\n        - MemoryInfoListStream is not present in this dump\n    Module analysis                  unavailable\n        - ModuleListStream is not present in this dump\n    Injection-artifact analysis      unavailable\n        - MemoryInfoListStream is not present in this dump\n        - ThreadInfoListStream is not present in this dump\n    Thread analysis                  unavailable\n        - ThreadListStream is not present in this dump\n        - ThreadInfoListStream is not present in this dump\n    Handle analysis                  unavailable\n        - HandleDataStream is not present in this dump\n    Injector-handle assessment       unavailable\n        - HandleDataStream is not present in this dump\n\n',
        {'kind': 'profile', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'sysinfo': {'state': 'present', 'record_count': 1, 'detail': None}, 'modules': {'state': 'absent', 'record_count': None, 'detail': None}, 'threads': {'state': 'absent', 'record_count': None, 'detail': None}, 'thread_info': {'state': 'absent', 'record_count': None, 'detail': None}, 'memory_info': {'state': 'absent', 'record_count': None, 'detail': None}, 'handles': {'state': 'absent', 'record_count': None, 'detail': None}, 'memory_content': {'state': 'absent', 'record_count': None, 'detail': None}, 'profile_directory': {'state': 'present', 'record_count': 1, 'detail': None}}, 'limitations': []}, 'summary': {'stream_count': 0, 'capability_summary': {'available': 0, 'limited': 0, 'unavailable': 6}}, 'data': {'records': [{'architecture': 'AMD64', 'raw_flags': 0, 'recognized_flags': [], 'unrecognized_flag_bits': 0, 'memory_capture': {'full_memory_flag_set': False, 'memory64_list_present': False, 'memory_list_present': False, 'captured_segment_count': None, 'captured_bytes_total': None}, 'streams': [], 'capabilities': [{'capability_id': 'memory_region_analysis', 'status': 'unavailable', 'required_source_groups': [['memory_info']], 'required_sources': ['memory_info'], 'optional_sources': [], 'limitations': [{'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'memory_info', 'detail': 'MemoryInfoListStream is not present in this dump'}]}, {'capability_id': 'module_analysis', 'status': 'unavailable', 'required_source_groups': [['modules']], 'required_sources': ['modules'], 'optional_sources': [], 'limitations': [{'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'modules', 'detail': 'ModuleListStream is not present in this dump'}]}, {'capability_id': 'injection_artifact_analysis', 'status': 'unavailable', 'required_source_groups': [['memory_info', 'thread_info']], 'required_sources': ['memory_info', 'thread_info'], 'optional_sources': ['modules', 'threads', 'memory_content'], 'limitations': [{'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'memory_info', 'detail': 'MemoryInfoListStream is not present in this dump'}, {'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'thread_info', 'detail': 'ThreadInfoListStream is not present in this dump'}]}, {'capability_id': 'thread_analysis', 'status': 'unavailable', 'required_source_groups': [['threads', 'thread_info']], 'required_sources': ['threads', 'thread_info'], 'optional_sources': ['modules'], 'limitations': [{'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'threads', 'detail': 'ThreadListStream is not present in this dump'}, {'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'thread_info', 'detail': 'ThreadInfoListStream is not present in this dump'}]}, {'capability_id': 'handle_analysis', 'status': 'unavailable', 'required_source_groups': [['handles']], 'required_sources': ['handles'], 'optional_sources': [], 'limitations': [{'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'handles', 'detail': 'HandleDataStream is not present in this dump'}]}, {'capability_id': 'injector_handle_assessment', 'status': 'unavailable', 'required_source_groups': [['handles']], 'required_sources': ['handles'], 'optional_sources': ['threads'], 'limitations': [{'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'handles', 'detail': 'HandleDataStream is not present in this dump'}]}]}]}},
    ),
    (
        'process_partial', ['--process'], _process_partial, 3,
        '\n═══ PROCESS ═══\n  [~] PEB present but CommandLine is empty\n  [~] PEB present but ImageBaseAddress is not set\n\n  Process Name           test.exe\n  PID                    100 (0x64)\n  Path                   C:\\test.exe\n  Command Line           (unknown)\n  Start Time (UTC)       2026-08-14 01:15:05 UTC\n  Image Base             (unknown)\n\n  Import Address Table\n    (unavailable -- see coverage below)\n\n  Identity\n',
        {'kind': 'process', 'execution_status': 'completed', 'coverage': {'status': 'partial', 'reasons': ['PEB present but CommandLine is empty', 'PEB present but ImageBaseAddress is not set'], 'sources': {'process_identity': {'state': 'present', 'record_count': 3, 'detail': None}, 'misc_info': {'state': 'present', 'record_count': 1, 'detail': None}, 'peb': {'state': 'present', 'record_count': 1, 'detail': None}, 'modules': {'state': 'absent', 'record_count': None, 'detail': None}, 'main_image': {'state': 'absent', 'record_count': None, 'detail': None}, 'iat': {'state': 'absent', 'record_count': None, 'detail': None}}, 'limitations': [{'code': 'PROCESS_COMMAND_LINE_UNAVAILABLE', 'source': 'peb', 'scope': None, 'affected_count': None, 'unavailable_fields': [], 'available_fields': [], 'counterpart_source': None, 'related_sources': [], 'related_tids': [], 'thread_id': None, 'detail': None, 'targets': [], 'budget_limit': None, 'budget_consumed': None}, {'code': 'PROCESS_IMAGE_BASE_UNAVAILABLE', 'source': 'peb', 'scope': None, 'affected_count': None, 'unavailable_fields': [], 'available_fields': [], 'counterpart_source': None, 'related_sources': [], 'related_tids': [], 'thread_id': None, 'detail': None, 'targets': [], 'budget_limit': None, 'budget_consumed': None}]}, 'summary': {'count': 1}, 'data': {'records': [{'process_name': 'test.exe', 'pid': 100, 'process_path': 'C:\\test.exe', 'command_line': None, 'process_start_utc': '2026-08-14 01:15:05 UTC', 'image_base_address': None, 'iat': {'table_present': None, 'table_va': None, 'table_size': None, 'import_directory_present': None, 'import_directory_va': None, 'import_directory_size': None, 'has_entries': False, 'dll_count': 0, 'entry_count': 0, 'entries': [], 'diagnostics': []}, 'identity_evidence': {'misc_info_claim': {'pid': 100, 'process_create_time_utc': '2026-08-14 01:15:05 UTC', 'raw_pid': None, 'raw_process_create_time': None}, 'peb_claim': {'image_base_address': None, 'image_path': 'C:\\test.exe', 'name': 'test.exe', 'raw_image_base_address': None, 'raw_image_path': None, 'raw_command_line': None}, 'module_claim': {'match_state': 'unavailable', 'base_address': None, 'name': None, 'path': None, 'name_matched_candidate': None, 'name_matched_candidate_ambiguous': False}, 'main_image_pe': {'checked': False, 'valid': None, 'reason': None}, 'selected_path_source': 'peb', 'diagnostics': []}}]}},
    ),
    (
        'process_verbose_unavailable_identity_checks', ['--process', '--verbose'], _process_unavailable_checks, 0,
        '\n═══ PROCESS ═══\n\n  Process Name           malware.exe\n  PID                    4242 (0x1092)\n  Path                   C:\\Samples\\malware.exe\n  Command Line           C:\\Samples\\malware.exe\n  Start Time (UTC)       2026-08-14 01:15:05 UTC\n  Image Base             0x00007ff600010000\n\n  Import Address Table\n    (none -- this image declares no imports)\n\n  Identity\n\n  Identity Verification                            [--verbose only]\n    Selected path    C:\\Samples\\malware.exe\n    Selected name    malware.exe\n    Source           PEB (ProcessParameters.ImagePathName)\n    Image base       0x00007ff600010000 (source: PEB)\n\n    [--] PEB image base could not be compared with ModuleList\n         ModuleListStream is absent or failed, or no image base normalized\n    [--] PEB and ModuleList process names could not be compared\n         one of the two names was not recovered\n    [OK] a valid PE header was found at the PEB image base\n    [--] no ModuleList corroboration was available for this identity\n\n    Raw claims       PEB                              ModuleList\n    path             C:\\Samples\\malware.exe           (none)\n    name             malware.exe                      (none)\n    image base       0x00007ff600010000               (none) (unavailable)\n\n  Extended PEB\n    PEB Address        0x0000000000000000\n    BeingDebugged      False\n    WindowTitle        (none)\n    DllPath            (none)\n    StandardInput      (unknown)\n    StandardOutput     (unknown)\n    StandardError      (unknown)\n',
        {'kind': 'process', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'process_identity': {'state': 'present', 'record_count': 5, 'detail': None}, 'misc_info': {'state': 'present', 'record_count': 1, 'detail': None}, 'peb': {'state': 'present', 'record_count': 1, 'detail': None}, 'modules': {'state': 'absent', 'record_count': None, 'detail': None}, 'main_image': {'state': 'present', 'record_count': 1, 'detail': None}, 'iat': {'state': 'present_empty', 'record_count': 0, 'detail': None}}, 'limitations': []}, 'summary': {'count': 1}, 'data': {'records': [{'process_name': 'malware.exe', 'pid': 4242, 'process_path': 'C:\\Samples\\malware.exe', 'command_line': 'C:\\Samples\\malware.exe', 'process_start_utc': '2026-08-14 01:15:05 UTC', 'image_base_address': '0x00007ff600010000', 'iat': {'table_present': False, 'table_va': None, 'table_size': None, 'import_directory_present': False, 'import_directory_va': None, 'import_directory_size': None, 'has_entries': False, 'dll_count': 0, 'entry_count': 0, 'entries': [], 'diagnostics': []}, 'identity_evidence': {'misc_info_claim': {'pid': 4242, 'process_create_time_utc': '2026-08-14 01:15:05 UTC', 'raw_pid': None, 'raw_process_create_time': None}, 'peb_claim': {'image_base_address': '0x00007ff600010000', 'image_path': 'C:\\Samples\\malware.exe', 'name': 'malware.exe', 'raw_image_base_address': None, 'raw_image_path': None, 'raw_command_line': None}, 'module_claim': {'match_state': 'unavailable', 'base_address': None, 'name': None, 'path': None, 'name_matched_candidate': None, 'name_matched_candidate_ambiguous': False}, 'main_image_pe': {'checked': True, 'valid': True, 'reason': None}, 'selected_path_source': 'peb', 'diagnostics': []}, 'peb_extended': {'peb_address': '0x0000000000000000', 'being_debugged': False, 'window_title': None, 'dll_path': None, 'standard_input': None, 'standard_output': None, 'standard_error': None}}]}},
    ),
    (
        'process_verbose_conflict_and_iat_variety', ['--process', '--verbose'], _process_conflict_and_iat, 0,
        '\n═══ PROCESS ═══\n\n  Process Name           malware.exe\n  PID                    4242 (0x1092)\n  Path                   C:\\Samples\\malware.exe\n  Command Line           C:\\Samples\\malware.exe\n  Start Time (UTC)       2026-08-14 01:15:05 UTC\n  Image Base             0x00007ff600010000\n\n  Import Address Table\n    2 import(s) across 2 DLL(s)\n\n    Each row reads IAT Slot VA -> Resolved Target VA.\n    The slot is the address where the import pointer is stored; the target is the\n    address stored in that slot in the captured process memory.\n\n    DLL                       Imported API                  IAT Slot VA           Resolved Target VA\n    ADVAPI32.dll              ordinal #12                   0x00007ff600013000    0x00007ffb0000000c\n    (unknown)                 (unavailable)                 0x00007ff600013010    0x00007ffb00000099\n\n  Identity\n    [!] a module named malware.exe is loaded at 0x00007ff700000000, not the PEB-reported image base 0x00007ff600010000\n\n  Identity Verification                            [--verbose only]\n    Selected path    C:\\Samples\\malware.exe\n    Selected name    malware.exe\n    Source           PEB (ProcessParameters.ImagePathName)\n    Image base       0x00007ff600010000 (source: PEB)\n\n    [!!] no module is registered at the PEB image base\n         a module named malware.exe is registered at 0x00007ff700000000 instead\n    [--] PEB and ModuleList process names could not be compared\n         one of the two names was not recovered\n    [OK] a valid PE header was found at the PEB image base\n    [OK] no competing module shares this process name\n\n    Raw claims       PEB                              ModuleList\n    path             C:\\Samples\\malware.exe           (none)\n    name             malware.exe                      (none)\n    image base       0x00007ff600010000               (none) (unregistered)\n\n  Extended PEB\n    PEB Address        0x0000000000000000\n    BeingDebugged      False\n    WindowTitle        (none)\n    DllPath            (none)\n    StandardInput      (unknown)\n    StandardOutput     (unknown)\n    StandardError      (unknown)\n',
        {'kind': 'process', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'process_identity': {'state': 'present', 'record_count': 5, 'detail': None}, 'misc_info': {'state': 'present', 'record_count': 1, 'detail': None}, 'peb': {'state': 'present', 'record_count': 1, 'detail': None}, 'modules': {'state': 'present', 'record_count': 1, 'detail': None}, 'main_image': {'state': 'present', 'record_count': 1, 'detail': None}, 'iat': {'state': 'present', 'record_count': 2, 'detail': None}}, 'limitations': []}, 'summary': {'count': 1}, 'data': {'records': [{'process_name': 'malware.exe', 'pid': 4242, 'process_path': 'C:\\Samples\\malware.exe', 'command_line': 'C:\\Samples\\malware.exe', 'process_start_utc': '2026-08-14 01:15:05 UTC', 'image_base_address': '0x00007ff600010000', 'iat': {'table_present': True, 'table_va': '0x00007ff600013000', 'table_size': 32, 'import_directory_present': True, 'import_directory_va': '0x00007ff600012000', 'import_directory_size': 60, 'has_entries': True, 'dll_count': 2, 'entry_count': 2, 'entries': [{'dll': 'ADVAPI32.dll', 'import_by': 'ordinal', 'symbol': None, 'ordinal': 12, 'iat_slot_va': '0x00007ff600013000', 'resolved_target_va': '0x00007ffb0000000c', 'slot_in_bounds': True}, {'dll': None, 'import_by': 'unavailable', 'symbol': None, 'ordinal': None, 'iat_slot_va': '0x00007ff600013010', 'resolved_target_va': '0x00007ffb00000099', 'slot_in_bounds': True}], 'diagnostics': []}, 'identity_evidence': {'misc_info_claim': {'pid': 4242, 'process_create_time_utc': '2026-08-14 01:15:05 UTC', 'raw_pid': None, 'raw_process_create_time': None}, 'peb_claim': {'image_base_address': '0x00007ff600010000', 'image_path': 'C:\\Samples\\malware.exe', 'name': 'malware.exe', 'raw_image_base_address': None, 'raw_image_path': None, 'raw_command_line': None}, 'module_claim': {'match_state': 'unregistered', 'base_address': None, 'name': None, 'path': None, 'name_matched_candidate': {'base_address': '0x00007ff700000000', 'name': 'malware.exe', 'path': 'C:\\Windows\\Temp\\malware.exe'}, 'name_matched_candidate_ambiguous': False}, 'main_image_pe': {'checked': True, 'valid': True, 'reason': None}, 'selected_path_source': 'peb', 'diagnostics': [{'code': 'PROCESS_MODULE_BASE_CONFLICT', 'severity': 'warning', 'message': 'a module named malware.exe is loaded at 0x00007ff700000000, not the PEB-reported image base 0x00007ff600010000', 'affected_count': None, 'details': {'name': 'malware.exe', 'module_base': '0x00007ff700000000', 'peb_base': '0x00007ff600010000'}}]}, 'peb_extended': {'peb_address': '0x0000000000000000', 'being_debugged': False, 'window_title': None, 'dll_path': None, 'standard_input': None, 'standard_output': None, 'standard_error': None}}]}},
    ),
    (
        'profile_mixed_states', ['--profile'], _profile_mixed, 3,
        '\n═══ PROFILE ═══\n  8 directory entries inventoried\n\n  Basic\n    Architecture             AMD64\n    Full memory (flag)       no\n    Captured memory content  (unknown)\n    Raw MINIDUMP_TYPE flags  0x0\n    Recognized flags         (none)\n\n  Streams\n    SystemInfoStream             parsed\n    ThreadListStream             parsed [1]\n    ModuleListStream             present (ambiguous -- duplicate entry)\n        stream type 4 appears at 2 directory index(es): [2, 3]; dumpex retains only one shared parse outcome per stream type, so which entry it reflects cannot be determined\n    ModuleListStream             present (ambiguous -- duplicate entry)\n        stream type 4 appears at 2 directory index(es): [2, 3]; dumpex retains only one shared parse outcome per stream type, so which entry it reflects cannot be determined\n    FunctionTableStream          present (not parsed by dumpex)\n    (unknown type 9999)          present (not parsed by dumpex)\n    HandleDataStream             present (empty) [0]\n    MemoryInfoListStream         present (parse failed)\n        ValueError: layout drift\n\n  Analysis capabilities\n    Memory-region analysis           unavailable\n        - MemoryInfoListStream is present in this dump but could not be parsed\n    Module analysis                  unavailable\n        - ModuleListStream has duplicate directory entries; its parse outcome cannot be attributed to one entry with confidence\n    Injection-artifact analysis      unavailable\n        - MemoryInfoListStream is present in this dump but could not be parsed\n        - ThreadInfoListStream is not present in this dump\n    Thread analysis                  limited\n        - ThreadInfoListStream is not present in this dump, but a different required-group member for this capability already is -- treated as a degraded (not blocking) gap\n        - ModuleListStream has duplicate directory entries; its parse outcome cannot be attributed to one entry with confidence (optional corroborating evidence)\n    Handle analysis                  available\n    Injector-handle assessment       available\n\n  [~] 1 stream type has duplicate directory entries whose individual parser state could not be attributed with confidence -- see the affected entries\' own "indeterminate" state\n\n',
        {'kind': 'profile', 'execution_status': 'completed', 'coverage': {'status': 'partial', 'reasons': ['1 stream type has duplicate directory entries whose individual parser state could not be attributed with confidence -- see the affected entries\' own "indeterminate" state'], 'sources': {'sysinfo': {'state': 'present', 'record_count': 1, 'detail': None}, 'modules': {'state': 'failed', 'record_count': None, 'detail': 'this stream type has duplicate directory entries; its parse outcome cannot be attributed with confidence -- see the stream inventory\'s own "indeterminate" entries'}, 'threads': {'state': 'present', 'record_count': 1, 'detail': None}, 'thread_info': {'state': 'absent', 'record_count': None, 'detail': None}, 'memory_info': {'state': 'failed', 'record_count': None, 'detail': 'ValueError: layout drift'}, 'handles': {'state': 'present_empty', 'record_count': 0, 'detail': None}, 'memory_content': {'state': 'absent', 'record_count': None, 'detail': None}, 'profile_directory': {'state': 'present', 'record_count': 1, 'detail': None}}, 'limitations': [{'code': 'PROFILE_STREAM_STATE_AMBIGUOUS', 'source': 'profile_directory', 'scope': None, 'affected_count': 1, 'unavailable_fields': [], 'available_fields': [], 'counterpart_source': None, 'related_sources': [], 'related_tids': [], 'thread_id': None, 'detail': None, 'targets': [], 'budget_limit': None, 'budget_consumed': None}]}, 'summary': {'stream_count': 8, 'capability_summary': {'available': 2, 'limited': 1, 'unavailable': 3}}, 'data': {'records': [{'architecture': 'AMD64', 'raw_flags': 0, 'recognized_flags': [], 'unrecognized_flag_bits': 0, 'memory_capture': {'full_memory_flag_set': False, 'memory64_list_present': False, 'memory_list_present': False, 'captured_segment_count': None, 'captured_bytes_total': None}, 'streams': [{'directory_index': 0, 'stream_type_id': 7, 'stream_type_name': 'SystemInfoStream', 'parser_state': 'parsed', 'record_count': None, 'detail': None}, {'directory_index': 1, 'stream_type_id': 3, 'stream_type_name': 'ThreadListStream', 'parser_state': 'parsed', 'record_count': 1, 'detail': None}, {'directory_index': 2, 'stream_type_id': 4, 'stream_type_name': 'ModuleListStream', 'parser_state': 'indeterminate', 'record_count': None, 'detail': 'stream type 4 appears at 2 directory index(es): [2, 3]; dumpex retains only one shared parse outcome per stream type, so which entry it reflects cannot be determined'}, {'directory_index': 3, 'stream_type_id': 4, 'stream_type_name': 'ModuleListStream', 'parser_state': 'indeterminate', 'record_count': None, 'detail': 'stream type 4 appears at 2 directory index(es): [2, 3]; dumpex retains only one shared parse outcome per stream type, so which entry it reflects cannot be determined'}, {'directory_index': 4, 'stream_type_id': 13, 'stream_type_name': 'FunctionTableStream', 'parser_state': 'unparsed', 'record_count': None, 'detail': None}, {'directory_index': 5, 'stream_type_id': 9999, 'stream_type_name': None, 'parser_state': 'unparsed', 'record_count': None, 'detail': None}, {'directory_index': 6, 'stream_type_id': 12, 'stream_type_name': 'HandleDataStream', 'parser_state': 'present_empty', 'record_count': 0, 'detail': None}, {'directory_index': 7, 'stream_type_id': 16, 'stream_type_name': 'MemoryInfoListStream', 'parser_state': 'failed', 'record_count': None, 'detail': 'ValueError: layout drift'}], 'capabilities': [{'capability_id': 'memory_region_analysis', 'status': 'unavailable', 'required_source_groups': [['memory_info']], 'required_sources': ['memory_info'], 'optional_sources': [], 'limitations': [{'code': 'REQUIRED_SOURCE_FAILED', 'source': 'memory_info', 'detail': 'MemoryInfoListStream is present in this dump but could not be parsed'}]}, {'capability_id': 'module_analysis', 'status': 'unavailable', 'required_source_groups': [['modules']], 'required_sources': ['modules'], 'optional_sources': [], 'limitations': [{'code': 'REQUIRED_SOURCE_INDETERMINATE', 'source': 'modules', 'detail': 'ModuleListStream has duplicate directory entries; its parse outcome cannot be attributed to one entry with confidence'}]}, {'capability_id': 'injection_artifact_analysis', 'status': 'unavailable', 'required_source_groups': [['memory_info', 'thread_info']], 'required_sources': ['memory_info', 'thread_info'], 'optional_sources': ['modules', 'threads', 'memory_content'], 'limitations': [{'code': 'REQUIRED_SOURCE_FAILED', 'source': 'memory_info', 'detail': 'MemoryInfoListStream is present in this dump but could not be parsed'}, {'code': 'REQUIRED_SOURCE_ABSENT', 'source': 'thread_info', 'detail': 'ThreadInfoListStream is not present in this dump'}]}, {'capability_id': 'thread_analysis', 'status': 'limited', 'required_source_groups': [['threads', 'thread_info']], 'required_sources': ['threads', 'thread_info'], 'optional_sources': ['modules'], 'limitations': [{'code': 'REQUIRED_GROUP_MEMBER_ABSENT', 'source': 'thread_info', 'detail': 'ThreadInfoListStream is not present in this dump, but a different required-group member for this capability already is -- treated as a degraded (not blocking) gap'}, {'code': 'OPTIONAL_SOURCE_INDETERMINATE', 'source': 'modules', 'detail': 'ModuleListStream has duplicate directory entries; its parse outcome cannot be attributed to one entry with confidence (optional corroborating evidence)'}]}, {'capability_id': 'handle_analysis', 'status': 'available', 'required_source_groups': [['handles']], 'required_sources': ['handles'], 'optional_sources': [], 'limitations': []}, {'capability_id': 'injector_handle_assessment', 'status': 'available', 'required_source_groups': [['handles']], 'required_sources': ['handles'], 'optional_sources': ['threads'], 'limitations': []}]}]}},
    ),
    (
        'handles_partial', ['--handles'], _handles_partial, 3,
        "\n═══ HANDLES ═══\n  1 handle(s) captured\n  By type: File 1\n\n  Handle              Type            Access      Cnt  Ptr  Object\n  0x0000000000000010  File            0x00000000    1    1  (unreadable)\n      └─ Rights   (no rights)\n  (unnamed) = the descriptor records no name; (unreadable) = a name was recorded but the bounded read failed\n  Rights decode each row's own Access mask against its recorded object type -- the same bit means\n  different things for a File, a Process and a Token. A long list splits into Type (rights that\n  object type defines) and Standard (the rights every type shares). They are an observation about\n  what the handle permitted, never evidence that it was used.\n\n  [~] 1 handle(s) have a type or object name that could not be read or decoded\n\n",
        {'kind': 'handles', 'execution_status': 'completed', 'coverage': {'status': 'partial', 'reasons': ['1 handle(s) have a type or object name that could not be read or decoded'], 'sources': {'handles': {'state': 'present', 'record_count': 1, 'detail': None}, 'handle_records': {'state': 'present', 'record_count': 1, 'detail': None}}, 'limitations': [{'code': 'HANDLE_STRING_READ_FAILED', 'source': 'handles', 'scope': None, 'affected_count': 1, 'unavailable_fields': [], 'available_fields': [], 'counterpart_source': None, 'related_sources': [], 'related_tids': [], 'thread_id': None, 'detail': None, 'targets': [], 'budget_limit': None, 'budget_consumed': None}]}, 'summary': {'count': 1, 'by_type': {'File': 1}}, 'data': {'records': [{'handle': '0x0000000000000010', 'type_name': 'File', 'type_name_status': 'ok', 'object_name': None, 'object_name_status': 'unreadable', 'attributes': 0, 'granted_access': 0, 'handle_count': 1, 'pointer_count': 1}]}},
    ),
    (
        'process_identity_ambiguous', ['--process', '--verbose'], _process_identity_ambiguous, 0,
        '\n═══ PROCESS ═══\n\n  Process Name           malware.exe\n  PID                    4242 (0x1092)\n  Path                   C:\\Samples\\malware.exe\n  Command Line           C:\\Samples\\malware.exe\n  Start Time (UTC)       2026-08-14 01:15:05 UTC\n  Image Base             0x00007ff600010000\n\n  Import Address Table\n    (none -- this image declares no imports)\n\n  Identity\n    [!] a module named malware.exe is loaded at 0x00007ff700000000, not the PEB-reported image base 0x00007ff600010000\n    [i] 2 modules share the name malware.exe; only the first is reported\n\n  Identity Verification                            [--verbose only]\n    Selected path    C:\\Samples\\malware.exe\n    Selected name    malware.exe\n    Source           PEB (ProcessParameters.ImagePathName)\n    Image base       0x00007ff600010000 (source: PEB)\n\n    [!!] no module is registered at the PEB image base\n         a module named malware.exe is registered at 0x00007ff700000000 instead\n    [--] PEB and ModuleList process names could not be compared\n         one of the two names was not recovered\n    [OK] a valid PE header was found at the PEB image base\n    [!!] more than one module shares this process name; only the first is reported\n         compare --modules for every module carrying this name\n\n    Raw claims       PEB                              ModuleList\n    path             C:\\Samples\\malware.exe           (none)\n    name             malware.exe                      (none)\n    image base       0x00007ff600010000               (none) (unregistered)\n\n  Extended PEB\n    PEB Address        0x0000000000000000\n    BeingDebugged      False\n    WindowTitle        (none)\n    DllPath            (none)\n    StandardInput      (unknown)\n    StandardOutput     (unknown)\n    StandardError      (unknown)\n',
        {'kind': 'process', 'execution_status': 'completed', 'coverage': {'status': 'complete', 'reasons': [], 'sources': {'process_identity': {'state': 'present', 'record_count': 5, 'detail': None}, 'misc_info': {'state': 'present', 'record_count': 1, 'detail': None}, 'peb': {'state': 'present', 'record_count': 1, 'detail': None}, 'modules': {'state': 'present', 'record_count': 2, 'detail': None}, 'main_image': {'state': 'present', 'record_count': 1, 'detail': None}, 'iat': {'state': 'present_empty', 'record_count': 0, 'detail': None}}, 'limitations': []}, 'summary': {'count': 1}, 'data': {'records': [{'process_name': 'malware.exe', 'pid': 4242, 'process_path': 'C:\\Samples\\malware.exe', 'command_line': 'C:\\Samples\\malware.exe', 'process_start_utc': '2026-08-14 01:15:05 UTC', 'image_base_address': '0x00007ff600010000', 'iat': {'table_present': False, 'table_va': None, 'table_size': None, 'import_directory_present': False, 'import_directory_va': None, 'import_directory_size': None, 'has_entries': False, 'dll_count': 0, 'entry_count': 0, 'entries': [], 'diagnostics': []}, 'identity_evidence': {'misc_info_claim': {'pid': 4242, 'process_create_time_utc': '2026-08-14 01:15:05 UTC', 'raw_pid': None, 'raw_process_create_time': None}, 'peb_claim': {'image_base_address': '0x00007ff600010000', 'image_path': 'C:\\Samples\\malware.exe', 'name': 'malware.exe', 'raw_image_base_address': None, 'raw_image_path': None, 'raw_command_line': None}, 'module_claim': {'match_state': 'unregistered', 'base_address': None, 'name': None, 'path': None, 'name_matched_candidate': {'base_address': '0x00007ff700000000', 'name': 'malware.exe', 'path': 'C:\\Windows\\Temp\\malware.exe'}, 'name_matched_candidate_ambiguous': True}, 'main_image_pe': {'checked': True, 'valid': True, 'reason': None}, 'selected_path_source': 'peb', 'diagnostics': [{'code': 'PROCESS_MODULE_BASE_CONFLICT', 'severity': 'warning', 'message': 'a module named malware.exe is loaded at 0x00007ff700000000, not the PEB-reported image base 0x00007ff600010000', 'affected_count': None, 'details': {'name': 'malware.exe', 'module_base': '0x00007ff700000000', 'peb_base': '0x00007ff600010000'}}, {'code': 'PROCESS_MODULE_NAME_AMBIGUOUS', 'severity': 'info', 'message': '2 modules share the name malware.exe; only the first is reported', 'affected_count': None, 'details': {'name': 'malware.exe', 'count': 2}}]}, 'peb_extended': {'peb_address': '0x0000000000000000', 'being_debugged': False, 'window_title': None, 'dll_path': None, 'standard_input': None, 'standard_output': None, 'standard_error': None}}]}},
    ),
]


@pytest.mark.parametrize(
    "name,argv,mf_builder,exit_code,console,result",
    RECON_V213_SCENARIOS, ids=[s[0] for s in RECON_V213_SCENARIOS],
)
def test_recon_v213_compat_freeze(monkeypatch, tmp_path, capsys, name, argv, mf_builder,
                                   exit_code, console, result):
    mf = mf_builder()
    actual_exit, doc, dump_path_abs = _run(monkeypatch, tmp_path, argv, mf)
    actual_console = _normalize_console(capsys.readouterr().out, str(tmp_path))
    _normalize_doc(doc, dump_path_abs)

    expected_meta = _expected_meta(argv[0])
    # _CMD_OPTIONS' shared default assumes verbose=False -- true for every
    # OTHER scenario in this suite, but several of this file's own recon
    # scenarios genuinely pass --verbose and must see it reflected here.
    if "--verbose" in argv:
        expected_meta["execution"]["options"]["verbose"] = True
    result = dict(result)
    result["coverage"] = dict(result["coverage"], missed_bytes=_NO_MISSED_BYTES)
    expected_doc = {"meta": expected_meta, "result": result,
                     "artifacts": [], "diagnostics": {"warnings": [], "errors": []}}
    expected_console = console + "  [·] JSON written → <TMP_DIR>" + os.sep \
        + "out.json  (<SIZE> bytes  sha256=<HASH>)\n"

    assert actual_exit == exit_code, f"{name}: exit code drifted"
    assert doc == expected_doc, f"{name}: JSON document drifted"
    assert actual_console == expected_console, f"{name}: console drifted"

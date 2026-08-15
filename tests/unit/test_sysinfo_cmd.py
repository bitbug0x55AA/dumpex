"""Unit tests for dumpex.commands.sysinfo's collect/render split
(cmd_sysinfo and cmd_pid).

--sysinfo (issue #41 / docs/recon_process_sysinfo_handles_contract.md §4):
SysInfoRecord no longer carries the process identity/runtime fields owned
by --process, and instead reports current_directory/environment_variables
via the independent, bounded environment-block walk (dumpex.core.
process_info.walk_environment_block(), issue #38). tests.fixtures.fakes.
SysInfo's ProcessorArchitecture defaults to the real minidump
PROCESSOR_ARCHITECTURE.AMD64 enum member, and
tests.fixtures.fakes.wire_environment_walk() supplies the buffered-reader
layer FakeMF itself doesn't (its get_reader() returns self._reader
directly), so a genuine walk works through the shared fixtures alone --
no local reader fake needed here."""
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

from tests.fixtures.fakes import (
    SysInfo, MiscInfo, ExceptionStream, Peb, Thread, Ctx, Module,
    FakeStream, FakeMF, wire_environment_walk,
)

from dumpex.commands.sysinfo import (
    collect_sysinfo, render_sysinfo_console, cmd_sysinfo, sysinfo_source_present,
    collect_pid, render_pid_console, cmd_pid,
)
from dumpex.output.coverage import (
    LimitationCode, CoverageReport, CoverageLimitation, SourceObservation, SourceState,
    COVERAGE_PARTIAL, render_limitation,
)
from dumpex.output.records import SysInfoRecord


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


_wire_environment_walk = wire_environment_walk   # local alias, pre-existing call sites unchanged


def _amd64_sysinfo(**kwargs) -> SysInfo:
    return SysInfo(**kwargs)   # SysInfo()'s own default IS PROCESSOR_ARCHITECTURE.AMD64 now


# ── --sysinfo ────────────────────────────────────────────────────────────
# collect_sysinfo() returns a dumpex.output.command_result.CommandResult
# (migrated onto the shared coverage core in dumpex.output.coverage);
# accessed via attributes, never unpacked as a tuple. peb_present/
# threads_present/modules_present -- extra rendering context this command
# needs -- are derived via sysinfo_source_present() rather than returned
# separately.

def test_collect_sysinfo_normal_is_complete():
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe", current_directory=r"C:\work")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules = FakeStream([Module(0, 0, "a")], "modules")
    env_data = (_utf16("COMPUTERNAME=HOST1") + b"\x00\x00"
                + _utf16("USERNAME=alice") + b"\x00\x00"
                + b"\x00\x00")
    _wire_environment_walk(mf, env_data)

    result = collect_sysinfo(mf)
    assert result.coverage.status == "complete"
    assert result.coverage.reasons == []
    rec = result.records[0]
    assert rec.os == "Windows 10"
    assert rec.thread_count == 1
    assert rec.module_count == 1
    assert rec.hostname == "HOST1"
    assert rec.username == "alice"
    assert rec.current_directory == r"C:\work"
    assert rec.environment_variables == (
        {"name": "COMPUTERNAME", "value": "HOST1"},
        {"name": "USERNAME", "value": "alice"},
    )
    assert result.summary == {"count": 1}


def test_collect_sysinfo_hostname_username_empty_value_becomes_none():
    # P2 regression: §1.4 -- "The empty string is never emitted. A
    # source string that is empty ... becomes null." A captured
    # COMPUTERNAME=/USERNAME= with nothing after the `=` is real,
    # preserved evidence in environment_variables (raw block content),
    # but the DERIVED hostname/username fields must still be null, not
    # "".
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    env_data = (_utf16("COMPUTERNAME=") + b"\x00\x00"
                + _utf16("USERNAME=") + b"\x00\x00"
                + b"\x00\x00")
    _wire_environment_walk(mf, env_data)

    result = collect_sysinfo(mf)
    rec = result.records[0]
    assert rec.hostname is None
    assert rec.username is None
    assert rec.environment_variables == (
        {"name": "COMPUTERNAME", "value": ""},
        {"name": "USERNAME", "value": ""},
    )


def test_collect_sysinfo_hostname_duplicate_last_entry_empty_becomes_none():
    # "Last match wins" applies even when the last duplicate is empty --
    # consistent with every other duplicate-name case, and still null,
    # never "".
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    env_data = (_utf16("COMPUTERNAME=HOST1") + b"\x00\x00"
                + _utf16("COMPUTERNAME=") + b"\x00\x00"
                + b"\x00\x00")
    _wire_environment_walk(mf, env_data)

    result = collect_sysinfo(mf)
    rec = result.records[0]
    assert rec.hostname is None
    assert rec.environment_variables == (
        {"name": "COMPUTERNAME", "value": "HOST1"},
        {"name": "COMPUTERNAME", "value": ""},
    )


def test_collect_sysinfo_removed_process_fields_are_gone():
    # §4.1: pid/process_start_utc/image_path/command_line/
    # process_user_time_seconds/process_kernel_time_seconds moved to
    # --process or were dropped outright -- neither the dataclass nor
    # its to_dict() output may carry them any more.
    rec = SysInfoRecord()
    for removed in ("pid", "process_start_utc", "image_path", "command_line",
                     "process_user_time_seconds", "process_kernel_time_seconds"):
        assert not hasattr(rec, removed)
        assert removed not in rec.to_dict()
    assert "current_directory" in rec.to_dict()
    assert "environment_variables" in rec.to_dict()


def test_collect_sysinfo_missing_streams_is_partial():
    result = collect_sysinfo(FakeMF())
    assert result.coverage.status == "partial"
    # sysinfo, misc_info, peb, threads, modules all missing; environment
    # walk state is "unsupported" (sysinfo/threads both absent), which
    # emits no limitation of its own (§4.3.3 duplicate-absence
    # suppression) -- unchanged five-reason list, in the pre-#41 order.
    assert result.coverage.reasons == [
        "SystemInfoStream not present",
        "MiscInfo stream not present",
        "PEB not available (requires sysinfo + thread list)",
        "ThreadListStream not present (thread_count unavailable)",
        "ModuleListStream not present (module_count unavailable)",
    ]
    assert sysinfo_source_present(result.coverage, "peb") is False
    rec = result.records[0]
    assert rec.os is None
    assert rec.hostname is None   # never "" or "(unknown)"
    assert rec.thread_count is None   # never 0 when the stream itself is absent
    assert rec.module_count is None
    assert rec.current_directory is None
    assert rec.environment_variables is None

    codes = [l.code for l in result.coverage.limitations]
    assert codes == [
        LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE,
        LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE,
        LimitationCode.SYSINFO_PEB_UNAVAILABLE,
        LimitationCode.SYSINFO_THREADS_UNAVAILABLE,
        LimitationCode.SYSINFO_MODULES_UNAVAILABLE,
    ]


def test_collect_sysinfo_unsupported_with_peb_present_is_a_contradiction_not_silent():
    # P3 regression: the "unsupported" state's own suppression (no
    # limitation, since SYSINFO_PEB_UNAVAILABLE should already explain
    # it) relies on open_dump()'s own phase 3b never building a peb
    # without sysinfo+threads (dumpex/core/memory.py) -- provably true
    # for any real dump, but not for an mf assembled directly (as here).
    # When mf.peb is unexpectedly present anyway, collect_sysinfo() must
    # still surface a limitation rather than silently leaving
    # environment_variables: null with nothing in coverage.reasons to
    # explain it.
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe")   # sysinfo/threads left absent

    result = collect_sysinfo(mf)
    assert result.coverage.status == "partial"
    rec = result.records[0]
    assert rec.environment_variables is None
    assert result.coverage.sources["environment_block"].state == SourceState.FAILED
    # Domain language only -- never a bare Python attribute name -- since
    # a SourceObservation.detail is user-facing text.
    assert "mf.peb" not in result.coverage.sources["environment_block"].detail
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    # A dedicated code, not ENVIRONMENT_BLOCK_UNREADABLE -- that code's
    # fixed message describes a pointer read that was attempted and
    # failed; no pointer read is ever attempted here.
    assert limitation.code == LimitationCode.ENVIRONMENT_PRECONDITION_INCONSISTENT


def test_collect_sysinfo_windows_11_misdetection_fix():
    mf = FakeMF()
    mf.sysinfo = SysInfo(build_number=22631, operating_system="Windows 10")
    result = collect_sysinfo(mf)
    assert result.records[0].os == "Windows 11"


def test_collect_sysinfo_current_directory_normalized():
    mf = FakeMF()
    mf.peb = Peb(0x140000000, r"C:\test.exe", current_directory="  C:\\work\\ \x00\x00")
    result = collect_sysinfo(mf)
    assert result.records[0].current_directory == "C:\\work\\"


def test_collect_sysinfo_current_directory_none_when_peb_absent():
    result = collect_sysinfo(FakeMF())
    assert result.records[0].current_directory is None


def test_collect_sysinfo_current_directory_none_when_peb_offsets_untrustworthy():
    # P2 regression: PEB.from_minidump() treats every non-INTEL
    # architecture (ARM64 included) as x64 and reads ProcessParameters's
    # scalar fields -- current_directory among them -- at potentially
    # wrong offsets, the exact same untrustworthy parse
    # ENVIRONMENT_ARCHITECTURE_UNSUPPORTED already refuses to trust for
    # the environment block. A peb.current_directory value read through
    # those same offsets must not be published as if it were reliable.
    mf = FakeMF()
    si = SysInfo()
    si.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AARCH64
    mf.sysinfo = si
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.peb = Peb(0x140000000, r"C:\test.exe", current_directory=r"C:\maybe-wrong-offsets")

    result = collect_sysinfo(mf)
    assert result.records[0].current_directory is None
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED
    # P2 regression (round 2): the suppression itself must be a visible
    # coverage fact -- not just a silently-nulled field with no reason
    # given, which would read as "PEB present, but nothing recorded".
    assert limitation.unavailable_fields == ("current_directory",)
    assert "current_directory unavailable" in render_limitation(limitation)


def test_collect_sysinfo_architecture_unsupported_does_not_claim_current_directory_when_peb_absent():
    # P3 regression: when mf.peb is None, current_directory is null
    # because there is no PEB at all -- SYSINFO_PEB_UNAVAILABLE's own
    # fact -- not because ENVIRONMENT_ARCHITECTURE_UNSUPPORTED suppressed
    # an untrustworthy value that was never there to suppress. The two
    # limitations must never both claim to explain the same single gap
    # (§4.3.3's duplicate-absence-suppression rule).
    mf = FakeMF()
    si = SysInfo()
    si.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AARCH64
    mf.sysinfo = si
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    # mf.peb deliberately left None.

    result = collect_sysinfo(mf)
    assert result.records[0].current_directory is None
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED
    assert limitation.unavailable_fields == ()
    assert "current_directory" not in render_limitation(limitation)
    codes = [l.code for l in result.coverage.limitations]
    assert LimitationCode.SYSINFO_PEB_UNAVAILABLE in codes   # the actual explanation


# ── environment_variables: independent bounded walk (§4.3) ───────────────

def test_collect_sysinfo_environment_present_empty_is_captured_empty():
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, b"\x00\x00\x00\x00")   # verified empty block

    result = collect_sysinfo(mf)
    rec = result.records[0]
    assert rec.environment_variables == ()
    assert rec.hostname is None
    assert rec.username is None
    env_codes = [l.code for l in result.coverage.limitations if l.source == "environment_block"]
    assert env_codes == []   # a captured-empty block is not a limitation


def test_collect_sysinfo_environment_duplicate_special_and_empty_entries_preserved():
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    env_data = (_utf16("A=1") + b"\x00\x00"
                + _utf16("A=2") + b"\x00\x00"          # duplicate name
                + _utf16("=C:=C:\\Work") + b"\x00\x00"  # special =-prefixed entry
                + _utf16("EMPTY=") + b"\x00\x00"        # empty value
                + b"\x00\x00")
    _wire_environment_walk(mf, env_data)

    result = collect_sysinfo(mf)
    rec = result.records[0]
    assert rec.environment_variables == (
        {"name": "A", "value": "1"},
        {"name": "A", "value": "2"},
        {"name": "=C:", "value": "C:\\Work"},
        {"name": "EMPTY", "value": ""},
    )


def test_collect_sysinfo_survives_unavailable_memory_reader():
    # P1 regression: mf.get_reader() (real MinidumpFile) constructs a
    # fresh MinidumpFileReader every call, whose __init__ unconditionally
    # dereferences mf.modules.modules and mf.memory_segments_64/
    # mf.memory_segments -- either being None (a stream open_dump()'s own
    # per-stream isolation can legitimately leave absent/failed) raises
    # AttributeError with no guard of its own. collect_sysinfo() must
    # degrade to a FAILED environment_block source, never crash the whole
    # command -- and every OTHER completeness check (modules included)
    # must still fire normally. FakeMF's default _reader=None reproduces
    # the same "reader construction/access itself fails" surface (a
    # different concrete exception, same failure point) without needing
    # a real MinidumpFile.
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.threads.threads[0].Teb = 0x7FF000000000   # value irrelevant -- never reached
    # mf.modules deliberately left None -- both the crash surface this
    # test is guarding, and SYSINFO_MODULES_UNAVAILABLE's own trigger.

    result = collect_sysinfo(mf)   # must not raise
    assert result.coverage.status == "partial"
    rec = result.records[0]
    assert rec.environment_variables is None
    assert result.coverage.sources["environment_block"].state == SourceState.FAILED

    codes = [l.code for l in result.coverage.limitations]
    assert LimitationCode.ENVIRONMENT_BLOCK_UNREADABLE in codes
    assert LimitationCode.SYSINFO_MODULES_UNAVAILABLE in codes   # unrelated checks still fire


def test_collect_sysinfo_environment_architecture_unsupported_is_partial():
    mf = FakeMF()
    si = SysInfo()
    si.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AARCH64   # neither AMD64 nor INTEL
    mf.sysinfo = si
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")

    result = collect_sysinfo(mf)
    assert result.coverage.status == "partial"
    rec = result.records[0]
    assert rec.environment_variables is None
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED
    assert limitation.detail


def test_collect_sysinfo_environment_pointer_unreadable_is_partial():
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, b"\x00\x00\x00\x00", wire_teb_pointer=False)

    result = collect_sysinfo(mf)
    assert result.coverage.status == "partial"
    rec = result.records[0]
    assert rec.environment_variables is None
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_BLOCK_UNREADABLE
    assert limitation.detail
    assert result.coverage.sources["environment_block"].state == SourceState.FAILED


def test_collect_sysinfo_environment_unparseable_is_partial():
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, b"\x00\x00")   # only two captured zero bytes

    result = collect_sysinfo(mf)
    assert result.coverage.status == "partial"
    rec = result.records[0]
    assert rec.environment_variables is None
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE
    # P3 regression: §4.3.3 requires a FAILED source to always carry a
    # non-null detail, even for walk_environment_block()'s own
    # genuinely-ambiguous "only two captured zero bytes" sub-case (which
    # itself returns detail=None).
    assert result.coverage.sources["environment_block"].detail


def test_collect_sysinfo_environment_unparseable_undecodable_first_entry():
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    # A lone UTF-16 high surrogate (0xD800) -- undecodable on its own --
    # as the very first entry, immediately terminated.
    _wire_environment_walk(mf, bytes([0x00, 0xD8]) + b"\x00\x00")

    result = collect_sysinfo(mf)
    assert result.records[0].environment_variables is None
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE
    detail = result.coverage.sources["environment_block"].detail
    assert detail and detail != "undecodable_entry"   # P3: never a bare machine token
    assert "decoded" in detail


def test_collect_sysinfo_environment_unparseable_captured_segment_ends_mid_first_entry():
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, _utf16("AB"))   # no terminator, segment ends here

    result = collect_sysinfo(mf)
    assert result.records[0].environment_variables is None
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE
    detail = result.coverage.sources["environment_block"].detail
    assert detail and detail != "captured_segment"   # P3: never a bare machine token
    assert "captured memory ended" in detail


def test_collect_sysinfo_environment_unparseable_bytes_budget_reached_mid_first_entry(monkeypatch):
    import dumpex.commands.sysinfo as sysinfo_module
    monkeypatch.setattr(sysinfo_module, "MAX_ENV_BYTES", 4)

    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, _utf16("ABCDEF"))   # 12 bytes available, budget caps read at 4

    result = collect_sysinfo(mf)
    assert result.records[0].environment_variables is None
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE
    detail = result.coverage.sources["environment_block"].detail
    assert detail and detail != "environment_bytes"   # P3: never a bare machine token
    assert "byte budget" in detail


def test_collect_sysinfo_environment_partial_truncated_keeps_entries_found_so_far():
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    # One full entry, then an unterminated string running off the end of
    # the (deliberately short) captured segment -- "captured_segment".
    env_data = _utf16("A=1") + b"\x00\x00" + _utf16("B=UNTERMINATED")
    _wire_environment_walk(mf, env_data)

    result = collect_sysinfo(mf)
    assert result.coverage.status == "partial"
    rec = result.records[0]
    assert rec.environment_variables == ({"name": "A", "value": "1"},)
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED
    assert limitation.affected_count == 1
    assert limitation.scope == "captured_segment"
    assert limitation.budget_limit is None
    assert limitation.budget_consumed is None


def test_collect_sysinfo_environment_partial_truncated_entries_budget_scope(monkeypatch):
    import dumpex.commands.sysinfo as sysinfo_module
    monkeypatch.setattr(sysinfo_module, "MAX_ENV_ENTRIES", 1)

    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, _utf16("A=1") + b"\x00\x00")   # one entry hits the max_entries=1 cap

    result = collect_sysinfo(mf)
    assert result.coverage.status == "partial"
    rec = result.records[0]
    assert rec.environment_variables == ({"name": "A", "value": "1"},)
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED
    assert limitation.scope == "environment_entries"
    assert limitation.budget_limit == 1
    assert limitation.budget_consumed == 1


def test_collect_sysinfo_environment_partial_truncated_bytes_budget_scope(monkeypatch):
    import dumpex.commands.sysinfo as sysinfo_module
    monkeypatch.setattr(sysinfo_module, "MAX_ENV_BYTES", 10)

    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    # First entry ("A=1\0", 8 bytes) is fully captured; a second entry
    # then starts but the 10-byte budget cuts it off after one code unit.
    env_data = _utf16("A=1") + b"\x00\x00" + _utf16("BCDEF")
    _wire_environment_walk(mf, env_data)

    result = collect_sysinfo(mf)
    assert result.coverage.status == "partial"
    rec = result.records[0]
    assert rec.environment_variables == ({"name": "A", "value": "1"},)
    limitation = next(l for l in result.coverage.limitations if l.source == "environment_block")
    assert limitation.code == LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED
    assert limitation.scope == "environment_bytes"
    assert limitation.budget_limit == 10
    assert limitation.budget_consumed == 10


def test_collect_sysinfo_environment_ordering_precedes_peb_reason():
    # §4.7: any hand-built environment limitation is inserted immediately
    # before the `peb` completeness check.
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, b"\x00\x00", wire_teb_pointer=False)

    result = collect_sysinfo(mf)
    codes = [l.code for l in result.coverage.limitations]
    assert codes.index(LimitationCode.ENVIRONMENT_BLOCK_UNREADABLE) \
        < codes.index(LimitationCode.SYSINFO_PEB_UNAVAILABLE)


def test_collect_sysinfo_environment_serializes_as_plain_dicts():
    # No process_info.EnvironmentEntry (or any other parser object) may
    # leak through SysInfoRecord.to_dict().
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, _utf16("A=1") + b"\x00\x00" + b"\x00\x00")

    result = collect_sysinfo(mf)
    doc = result.records[0].to_dict()
    assert doc["environment_variables"] == [{"name": "A", "value": "1"}]
    for entry in doc["environment_variables"]:
        assert type(entry) is dict
        assert set(entry) == {"name", "value"}


# ── console rendering ──────────────────────────────────────────────────

def test_render_sysinfo_console_does_not_crash(capsys):
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe", current_directory=r"C:\work")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules = FakeStream([Module(0, 0, "a")], "modules")
    _wire_environment_walk(mf, _utf16("A=1") + b"\x00\x00" + b"\x00\x00")
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "SYSTEM INFO" in out
    assert "Threads in dump" in out
    assert "ENVIRONMENT" in out
    assert "Current Directory" in out
    assert r"C:\work" in out
    assert "1 captured (--verbose or --json to view)" in out


def test_render_sysinfo_console_reasons_render_exactly_once_in_frozen_order(capsys):
    # P2 regression: §4.7 is frozen text -- "this is the order of
    # coverage.limitations AND OF THE CONSOLE'S [~] LINES ... an analyst
    # should see 'environment block pointers could not be read: X' and
    # only then 'PEB not available', not the other way round." Every
    # limitation must render EXACTLY ONCE, at the console position
    # matching its own place in that order: coverage.limitations is
    # split into three segments around the environment_block-sourced
    # entry (before it -> top SYSTEM INFO block, it itself -> only
    # inside the ENVIRONMENT section, after it -> immediately following
    # that section) -- never both at the top AND locally (a prior round
    # mistakenly did that), and never reordered to dodge the duplicate.
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, b"\x00\x00", wire_teb_pointer=False)   # pointer_unreadable
    # mf.peb/misc_info/modules absent too, so SYSINFO_PEB_UNAVAILABLE/
    # SYSINFO_MODULES_UNAVAILABLE land AFTER the environment limitation
    # per §4.7's frozen order -- exactly the ordering this test guards.
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out

    expected_order = [render_limitation(l) for l in result.coverage.limitations]
    assert len(expected_order) > 1   # the ordering/no-duplicate claim needs 2+ reasons to be meaningful
    all_lines = out.splitlines()
    printed_order = [line.split("[~] ", 1)[1] for line in all_lines if "[~]" in line]
    assert printed_order == expected_order   # every reason exactly once, in coverage.limitations' order

    env_text = "environment block pointers could not be read"
    env_line_index = next(i for i, line in enumerate(all_lines) if env_text in line)
    environment_header_index = next(i for i, line in enumerate(all_lines) if "ENVIRONMENT" in line)
    dump_file_header_index = next(i for i, line in enumerate(all_lines) if "Dump File" in line)
    assert environment_header_index < env_line_index < dump_file_header_index


def test_render_sysinfo_console_has_no_process_section(capsys):
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, b"\x00\x00\x00\x00")
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "PROCESS" not in out
    assert "PID" not in out
    assert "Command Line" not in out
    assert "Image Path" not in out


def test_render_sysinfo_console_verbose_prints_entries(capsys):
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, _utf16("A=1") + b"\x00\x00" + b"\x00\x00")
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage, verbose=True)
    out = capsys.readouterr().out
    assert "A=1" in out


def test_render_sysinfo_console_not_verbose_hides_entries(capsys):
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, _utf16("SECRET_TOKEN=abc123") + b"\x00\x00" + b"\x00\x00")
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "SECRET_TOKEN" not in out
    assert "1 captured (--verbose or --json to view)" in out


def test_render_sysinfo_console_partial_missing_streams_does_not_crash(capsys):
    result = collect_sysinfo(FakeMF())
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "SYSTEM INFO" in out
    assert "sysinfo stream not available" in out
    assert "Threads in dump" not in out    # threads absent -- gated field must not print
    assert "Modules in dump" not in out    # modules absent -- gated field must not print
    assert "(unavailable)" in out          # environment: unsupported -> unavailable text


def test_render_sysinfo_console_architecture_unsupported_text(capsys):
    mf = FakeMF()
    si = SysInfo()
    si.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AARCH64   # neither AMD64 nor INTEL
    mf.sysinfo = si
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "(not supported for this architecture)" in out


def test_render_sysinfo_console_unparseable_text(capsys):
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, b"\x00\x00")
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "(unparseable -- see coverage below)" in out


# ── [P1 review fix] FAILED must not be treated as "present" ──────────────
# None of collect_sysinfo's five original sources have a path today that
# produces SourceState.FAILED (none of mf.sysinfo/misc_info/peb/threads/
# modules access is wrapped in a try/except), but sysinfo_source_present()
# must still handle it correctly per the coverage model's own vocabulary --
# constructed directly here rather than through collect_sysinfo().

def test_sysinfo_source_present_false_for_failed_source():
    coverage = CoverageReport(
        status=COVERAGE_PARTIAL,
        sources={"peb": SourceObservation(name="peb", state=SourceState.FAILED)},
        limitations=[CoverageLimitation(
            code=LimitationCode.SOURCE_FAILED, source="peb", detail="parse boom")],
    )
    assert sysinfo_source_present(coverage, "peb") is False


def test_render_sysinfo_console_failed_peb_prints_reason_not_gated_fields(capsys):
    coverage = CoverageReport(
        status=COVERAGE_PARTIAL,
        sources={
            "peb":     SourceObservation(name="peb", state=SourceState.FAILED),
            "threads": SourceObservation(name="threads", state=SourceState.ABSENT),
            "modules": SourceObservation(name="modules", state=SourceState.ABSENT),
            "environment_block": SourceObservation(name="environment_block", state=SourceState.ABSENT),
        },
        limitations=[CoverageLimitation(
            code=LimitationCode.SOURCE_FAILED, source="peb", detail="parse boom")],
    )
    render_sysinfo_console(SysInfoRecord(), coverage)
    out = capsys.readouterr().out
    assert "PEB present but could not be read: parse boom" in out
    assert "Current Directory" in out   # ENVIRONMENT section still renders


def test_cmd_sysinfo_returns_command_result(capsys):
    result = cmd_sysinfo(FakeMF())
    assert len(result.records) == 1
    assert result.coverage.status == "partial"
    capsys.readouterr()


# ── --pid ──────────────────────────────────────────────────────────────
# collect_pid() returns a dumpex.output.command_result.CommandResult
# (migrated onto the shared coverage core in dumpex.output.coverage);
# accessed via attributes, never unpacked as a tuple.

def test_collect_pid_via_misc_info_is_complete():
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=4321)
    result = collect_pid(mf)
    assert result.coverage.status == "complete"
    assert result.coverage.reasons == []
    rec = result.records[0]
    assert rec.pid == 4321
    assert rec.source == "MINIDUMP_MISC_INFO (ProcessId field)"


def test_collect_pid_fallback_to_thread_list_is_partial():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0)), Thread(10, Ctx(0))], "threads")
    result = collect_pid(mf)
    assert result.coverage.status == "partial"
    assert result.coverage.reasons
    assert "thread list" in result.coverage.reasons[0]
    rec = result.records[0]
    assert rec.pid is None
    assert rec.thread_count == 2

    # Structured: the reducer never inferred this -- it's business logic
    # collect_pid itself decided, so it must be a hand-built
    # PID_THREAD_LIST_FALLBACK carrying the raw TIDs, not a free-text blob.
    limitation = result.coverage.limitations[0]
    assert limitation.code == LimitationCode.PID_THREAD_LIST_FALLBACK
    assert limitation.source == "misc_info"
    assert limitation.counterpart_source == "threads"
    assert limitation.related_tids == (9, 10)


def test_collect_pid_fallback_to_exception_stream():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0))], "threads")
    mf.exception = ExceptionStream(9)
    result = collect_pid(mf)
    assert result.coverage.status == "partial"
    assert len(result.coverage.reasons) == 2   # thread-list warning + exception-stream warning
    assert result.records[0].exc_tid == 9
    assert isinstance(result.records[0].exc_tid, int)

    codes = [l.code for l in result.coverage.limitations]
    assert codes == [LimitationCode.PID_THREAD_LIST_FALLBACK, LimitationCode.PID_EXCEPTION_TID_FALLBACK]
    exc_limitation = result.coverage.limitations[1]
    assert exc_limitation.source == "exception"
    assert exc_limitation.thread_id == 9


def test_collect_pid_nothing_available():
    # None of MiscInfo/thread list/exception stream present at all --
    # nothing to even attempt a fallback with.
    result = collect_pid(FakeMF())
    assert result.coverage.status == "not_evaluated"
    assert result.coverage.reasons and "could not be evaluated" in result.coverage.reasons[0]
    rec = result.records[0]
    assert rec.pid is None
    assert rec.thread_count is None   # never 0 when ThreadListStream itself is absent

    limitation = result.coverage.limitations[0]
    assert limitation.code == LimitationCode.PID_SOURCES_ABSENT


def test_collect_pid_partial_status_never_has_empty_reasons():
    # mf.threads is present as a stream object but reports zero threads,
    # and there's no exception stream -- neither fallback branch appends
    # a warning on its own, so this exercises the safety-net reason.
    mf = FakeMF()
    mf.threads = FakeStream([], "threads")
    result = collect_pid(mf)
    assert result.coverage.status == "partial"
    assert result.coverage.reasons   # must never be empty for a non-complete status
    assert result.coverage.limitations[0].code == LimitationCode.PID_NO_USABLE_FALLBACK


def test_collect_pid_threads_present_but_misc_info_absent_is_partial():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    result = collect_pid(mf)
    assert result.coverage.status == "partial"   # a real (if weaker) source was available
    assert result.records[0].thread_count == 1


def test_render_pid_console_not_evaluated_prints_the_stable_reason(capsys):
    result = collect_pid(FakeMF())
    render_pid_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "ProcessId not found" in out
    assert "could not be evaluated" in out


def test_render_pid_console_complete_via_misc_info(capsys):
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=4321)
    result = collect_pid(mf)
    render_pid_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "4321" in out
    assert "0x10e1" in out   # hex(4321)
    assert "MINIDUMP_MISC_INFO" in out
    assert "[~]" not in out   # complete -- no warning lines


def test_render_pid_console_partial_fallback_prints_warning(capsys):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(9, Ctx(0))], "threads")
    result = collect_pid(mf)
    render_pid_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "ProcessId not found" in out
    assert "thread list" in out


def test_cmd_pid_returns_command_result(capsys):
    mf = FakeMF()
    mf.misc_info = MiscInfo(process_id=100)
    result = cmd_pid(mf)
    assert result.records[0].pid == 100
    assert result.coverage.status == "complete"
    capsys.readouterr()

"""Unit tests for dumpex.commands.sysinfo's collect/render split
(cmd_sysinfo).

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

import hashlib
import re

import pytest

from tests.fixtures.fakes import (
    SysInfo, MiscInfo, Peb, Thread, Ctx, Module,
    FakeStream, FakeMF, FakeHeader, FAKE_DUMP_BYTES, wire_environment_walk,
)

from dumpex.commands.sysinfo import (
    collect_sysinfo, render_sysinfo_console, cmd_sysinfo, sysinfo_source_present,
    _format_size, _render_environment_entries,
)
from dumpex.ui import colors
from dumpex.ui.console_layout import strip_ansi
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
    # suppression) -- five reasons, in §4.7's SECTION order: the DUMP
    # section's two (threads/modules) first, then SYSTEM INFO's two, then
    # ENVIRONMENT's peb. No dump-file reason: FakeMF.filename is backed by
    # a real file (conftest's _fake_dump_file_on_disk), so size/SHA-256
    # are established.
    assert result.coverage.reasons == [
        "ThreadListStream not present (thread_count unavailable)",
        "ModuleListStream not present (module_count unavailable)",
        "SystemInfoStream not present",
        "MiscInfo stream not present",
        "PEB not available (requires sysinfo + thread list)",
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
        LimitationCode.SYSINFO_THREADS_UNAVAILABLE,
        LimitationCode.SYSINFO_MODULES_UNAVAILABLE,
        LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE,
        LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE,
        LimitationCode.SYSINFO_PEB_UNAVAILABLE,
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


# ── the DUMP section's own evidence (§4.2: size / SHA-256 / dump time) ──


def test_collect_sysinfo_reports_the_dump_files_own_size_and_sha256():
    # The one --sysinfo field group that goes back to disk instead of
    # reading an already-parsed mf. Asserted against a digest computed
    # here from the fixture's own bytes, not a hex string pasted in: a
    # pasted constant would still "pass" if collect_sysinfo hashed the
    # wrong file, or hashed nothing and returned a cached value.
    result = collect_sysinfo(FakeMF())
    rec = result.records[0]
    assert rec.dump_file_size_bytes == len(FAKE_DUMP_BYTES)
    assert rec.dump_sha256 == hashlib.sha256(FAKE_DUMP_BYTES).hexdigest()
    # Establishing them is not a coverage gap.
    assert sysinfo_source_present(result.coverage, "dump_file") is True
    assert not [l for l in result.coverage.limitations if l.source == "dump_file"]


def test_collect_sysinfo_unreadable_dump_file_is_a_limitation_not_a_silent_null(tmp_path):
    # A file that vanished between open_dump() and now. Both fields go
    # null TOGETHER (a size without a digest identifies nothing), and the
    # gap is stated rather than left as an unexplained null.
    mf = FakeMF()
    mf.filename = str(tmp_path / "gone.dmp")
    result = collect_sysinfo(mf)
    rec = result.records[0]
    assert rec.dump_file_size_bytes is None
    assert rec.dump_sha256 is None
    assert rec.dump_file == "gone.dmp"   # the basename never depended on reading the file

    assert result.coverage.status == "partial"
    assert result.coverage.sources["dump_file"].state is SourceState.FAILED
    assert sysinfo_source_present(result.coverage, "dump_file") is False
    limitation = next(l for l in result.coverage.limitations if l.source == "dump_file")
    assert limitation.code == LimitationCode.SYSINFO_DUMP_FILE_UNREADABLE
    # The OS's own error text is carried through, so an analyst can tell a
    # deleted file from a permissions problem from an unmounted share.
    assert "FileNotFoundError" in limitation.detail
    # §4.7's section order puts the DUMP section's reasons first.
    assert result.coverage.limitations[0] is limitation


def test_collect_sysinfo_unreadable_dump_file_does_not_cost_the_other_fields():
    # Isolation: one unreadable evidence file must not blank out
    # everything the already-parsed dump object still knows.
    # An embedded NUL: os.stat() rejects it with ValueError rather than
    # OSError, so this also pins that the guard covers both.
    mf = FakeMF()
    mf.filename = "\0not-a-valid-path\0"
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, _utf16("COMPUTERNAME=HOST1") + b"\x00\x00" + b"\x00\x00")
    rec = collect_sysinfo(mf).records[0]
    assert rec.dump_sha256 is None
    assert rec.os == "Windows 10"           # SystemInfoStream still read
    assert rec.hostname == "HOST1"          # environment walk still ran
    assert rec.thread_count == 1


def test_collect_sysinfo_dump_time_from_header_time_date_stamp():
    mf = FakeMF()
    mf.header = FakeHeader(1723598105)
    assert collect_sysinfo(mf).records[0].dump_time_utc == "2024-08-14 01:15:05 UTC"


@pytest.mark.parametrize("stamp", [
    0,                # the producer never filled the field in
    -1,               # below UINT32 range
    0x1_0000_0000,    # above UINT32 range
    True,             # a bool is not a timestamp, even though it is an int
    "1723598105",     # wrong type entirely
    None,
])
def test_collect_sysinfo_dump_time_is_none_for_an_uncertifiable_stamp(stamp):
    # Same "present but not certifiable -> null" rule cpu_vendor follows,
    # and deliberately NOT a limitation: nothing failed to be evaluated,
    # the dump simply carries no usable timestamp.
    mf = FakeMF()
    mf.header = FakeHeader(stamp)
    result = collect_sysinfo(mf)
    assert result.records[0].dump_time_utc is None
    assert not [l for l in result.coverage.limitations if l.source == "dump_file"]


def test_collect_sysinfo_dump_time_is_none_without_a_header():
    # Hand-assembled mf objects need not carry a header; "no header" and
    # "unset TimeDateStamp" are the same answer and must not raise.
    assert collect_sysinfo(FakeMF()).records[0].dump_time_utc is None


@pytest.mark.parametrize("size,expected", [
    (0, "0 bytes"),
    (1023, "1023 bytes"),          # below 1 KiB: exact count only, no unit
    (1024, "1.0 KiB (1024 bytes)"),
    (59969536, "57.2 MiB (59969536 bytes)"),
    (2254857216, "2.1 GiB (2254857216 bytes)"),
])
def test_format_size_never_replaces_the_exact_byte_count(size, expected):
    # The approximation is a prefix, never a substitute: a size is
    # evidence an analyst cross-checks against a file listing, and
    # "2.1 GiB" matches nothing.
    rendered = _format_size(size)
    assert rendered == expected
    assert str(size) in rendered


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
    # matching its own place in that order. §4.6 now states that order as
    # SECTION order -- each limitation prints under the section owning the
    # field it explains (DUMP: threads/modules, SYSTEM INFO: sysinfo/
    # misc_info, ENVIRONMENT: environment_block/peb) -- and
    # collect_sysinfo declares its completeness_checks in that same order,
    # so the two are still one sequence. Never printed both at the top AND
    # locally (a prior round mistakenly did that), and never reordered to
    # dodge the duplicate.
    mf = FakeMF()
    mf.sysinfo = _amd64_sysinfo()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    _wire_environment_walk(mf, b"\x00\x00", wire_teb_pointer=False)   # pointer_unreadable
    # mf.peb/misc_info/modules absent too, so SYSINFO_MODULES_UNAVAILABLE
    # lands in the DUMP section, SYSINFO_MISC_INFO_UNAVAILABLE in SYSTEM
    # INFO, and SYSINFO_PEB_UNAVAILABLE after the environment limitation
    # in ENVIRONMENT -- exactly the ordering this test guards.
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out

    expected_order = [render_limitation(l) for l in result.coverage.limitations]
    assert len(expected_order) > 1   # the ordering/no-duplicate claim needs 2+ reasons to be meaningful
    all_lines = out.splitlines()
    printed_order = [line.split("[~] ", 1)[1] for line in all_lines if "[~]" in line]
    assert printed_order == expected_order   # every reason exactly once, in coverage.limitations' order

    def _line_index(needle):
        return next(i for i, line in enumerate(all_lines) if needle in line)

    # The environment reason renders inside the ENVIRONMENT section, and
    # the PEB reason -- ordered after it -- still renders after it, on the
    # console as well as on the wire.
    assert (_line_index("═══ ENVIRONMENT ═══")
            < _line_index("environment block pointers could not be read")
            < _line_index("PEB not available"))
    # The modules reason belongs to the DUMP section, which is now the
    # FIRST section: it must render there, not above the OS table.
    assert (_line_index("═══ DUMP ═══")
            < _line_index("ModuleListStream not present")
            < _line_index("═══ SYSTEM INFO ═══"))


def _sysinfo_console(capsys, **render_kwargs) -> str:
    mf = FakeMF()
    mf.header = FakeHeader(1723598105)
    mf.sysinfo = _amd64_sysinfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe", current_directory=r"C:\work")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules = FakeStream([Module(0, 0, "a")], "modules")
    _wire_environment_walk(mf, _utf16("A=1") + b"\x00\x00" + b"\x00\x00")
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage, **render_kwargs)
    return capsys.readouterr().out


def test_render_sysinfo_console_has_three_peer_sections_in_order(capsys):
    # The reported defect: ENVIRONMENT used to be a `  ═══ ENVIRONMENT ═══`
    # banner sitting between SYSTEM INFO's own subsections, so CPU and
    # Dump File -- printed after it, and structurally its PEERS -- read as
    # if they belonged to it. A banner is how a terminal reader segments
    # output; indentation is not. All three banners must therefore be
    # peers at column 0, in DUMP -> SYSTEM INFO -> ENVIRONMENT order.
    lines = _sysinfo_console(capsys).splitlines()
    banners = [line for line in lines if "═══" in line]
    assert banners == ["═══ DUMP ═══", "═══ SYSTEM INFO ═══", "═══ ENVIRONMENT ═══"]


def test_render_sysinfo_console_cpu_belongs_to_system_info_not_environment(capsys):
    # Issue 1 of the report: the CPU block describes the machine, so it
    # must sit inside SYSTEM INFO, above the ENVIRONMENT banner -- not
    # after it, where it reads as environment data.
    lines = _sysinfo_console(capsys).splitlines()

    def idx(needle):
        return next(i for i, line in enumerate(lines) if needle in line)

    assert idx("═══ SYSTEM INFO ═══") < idx("  CPU") < idx("═══ ENVIRONMENT ═══")
    # ... and alongside its sibling subsections, not orphaned after them.
    assert idx("Operating System") < idx("Host") < idx("  CPU")


def test_render_sysinfo_console_dump_section_leads_and_carries_file_identity(capsys):
    # Issue 2 + 3 of the report: dump-file facts get their own leading
    # section rather than trailing the environment dump, and that section
    # now also answers "which artifact is this, exactly?" -- digest and
    # dump time included.
    out = _sysinfo_console(capsys)
    lines = out.splitlines()
    assert lines[0] == ""                      # the leading blank line every command prints
    assert lines[1] == "═══ DUMP ═══"           # ... then DUMP, before anything else

    dump_block = out.split("═══ DUMP ═══", 1)[1].split("═══ SYSTEM INFO ═══", 1)[0]
    assert "File                   test.dmp" in dump_block
    assert f"Size                   {_format_size(len(FAKE_DUMP_BYTES))}" in dump_block
    assert hashlib.sha256(FAKE_DUMP_BYTES).hexdigest() in dump_block
    assert "Dump Time              2024-08-14 01:15:05 UTC" in dump_block
    assert "Threads in dump        1" in dump_block
    assert "Modules in dump        1" in dump_block


def test_render_sysinfo_console_omits_dump_identity_lines_it_could_not_establish(capsys):
    # A gated field prints nothing rather than "(unknown)" -- the reason
    # is already on a [~] line for size/SHA-256, and a dump with no
    # TimeDateStamp has nothing to explain.
    result = collect_sysinfo(FakeMF())          # no header, so no dump time
    render_sysinfo_console(result.records[0], result.coverage)
    out = capsys.readouterr().out
    assert "Dump Time" not in out
    assert "SHA-256" in out                      # the file itself IS readable here


def test_render_sysinfo_console_verbose_list_prints_after_every_other_section(capsys):
    # ENVIRONMENT goes last specifically because --verbose can make it
    # hundreds of lines long; anything printed after it is invisible.
    out = _sysinfo_console(capsys, verbose=True)
    entry_line = next(i for i, line in enumerate(out.splitlines())
                      if strip_ansi(line).split() == ["A", "1"])
    banners = [i for i, line in enumerate(out.splitlines()) if "═══" in line]
    assert banners == sorted(banners) and len(banners) == 3
    assert banners[-1] < entry_line, "the verbose listing must come after every banner"


# ── --verbose environment listing (§4.6.1) ──────────────────────────────


def _env_lines(capsys, pairs, **kwargs) -> list:
    _render_environment_entries([{"name": n, "value": v} for n, v in pairs], **kwargs)
    return [strip_ansi(line) for line in capsys.readouterr().out.splitlines()]


def test_environment_listing_aligns_every_value_to_one_column(capsys):
    # The readability complaint: names run 2-30 characters, so a flat
    # `name=value` list gives the eye no column to follow.
    pairs = [("A", "1"), ("ALLUSERSPROFILE", r"C:\ProgramData"),
             ("NUMBER_OF_PROCESSORS", "8")]
    lines = _env_lines(capsys, pairs)
    columns = {line.index(value) for line, (_, value) in zip(lines, pairs)}
    assert len(columns) == 1, f"values start at differing columns: {sorted(columns)}"


def test_environment_listing_alignment_survives_colour(capsys, monkeypatch):
    # Regression guard for the `f"{CYAN(name):<20}"` mistake: padding a
    # COLOURED string makes the ANSI escape count toward the field width,
    # so the column silently breaks whenever stdout is a TTY -- i.e. for
    # every real user and no test.
    monkeypatch.setattr(colors, "USE_COLOR", True)
    pairs = [("A", "1"), ("ALLUSERSPROFILE", r"C:\ProgramData")]
    _render_environment_entries([{"name": n, "value": v} for n, v in pairs])
    raw = capsys.readouterr().out
    assert "\x1b[" in raw, "colour was not actually applied, so this proves nothing"

    lines = [strip_ansi(line) for line in raw.splitlines()]
    columns = {line.index(value) for line, (_, value) in zip(lines, pairs)}
    assert len(columns) == 1, f"colour broke the column: {sorted(columns)}"


def test_environment_listing_breaks_a_path_after_its_semicolons(capsys):
    # The other half of the complaint: `Path` runs far past the terminal
    # and hard-wraps at column 0, destroying the block.
    value = ";".join([r"C:\Windows\system32", r"C:\Windows",
                      r"C:\Windows\System32\Wbem",
                      r"C:\Program Files\nodejs\\"])
    lines = [l for l in _env_lines(capsys, [("Path", value)]) if l.strip()]
    assert len(lines) > 1, "a value far wider than the terminal must wrap"
    # Every wrapped line but the last ends on the separator, so a reader
    # can see the entry continues.
    for line in lines[:-1]:
        assert line.rstrip().endswith(";")


def test_environment_listing_wrap_is_lossless(capsys):
    # Soft wrapping, never truncation: §4.5 keeps these values unredacted
    # because they are evidence. Reassembling the printed lines must
    # reproduce the value exactly -- no ellipsis, no dropped separator.
    value = ";".join(f"C:\\dir{i}\\sub" for i in range(40))
    lines = [l for l in _env_lines(capsys, [("Path", value)]) if l.strip()]
    reassembled = "".join(line.strip() if i else line.split("Path", 1)[1].strip()
                          for i, line in enumerate(lines))
    assert reassembled == value


def test_environment_listing_never_splits_a_console_safe_escape(capsys):
    # console_safe() renders a control byte as the literal text `\x0a`.
    # Wrapping through the middle of that would show `\x0` on one line and
    # `a` on the next -- the analyst would read a different byte than the
    # dump contained.
    value = "".join(f"\x01\x02{i:03d}" for i in range(60))
    lines = [l for l in _env_lines(capsys, [("CTRL", value)]) if l.strip()]
    assert len(lines) > 1
    for line in lines:
        # A trailing partial escape is what a naive character-grid wrap
        # would produce; a complete one always has its two hex digits.
        assert not re.search(r"\\x[0-9a-f]?$", line.rstrip())
        assert not re.search(r"\\$", line.rstrip())


def test_environment_listing_escapes_untrusted_names_and_values(capsys):
    # These are bytes the process was started with. A newline in one must
    # never produce a line an analyst reads as dumpex's own output.
    lines = _env_lines(capsys, [("EVIL\nNAME", "v"),
                                ("OK", "x\n  [~] environment block fully captured")])
    assert not any(line.strip().startswith("[~]") for line in lines)
    assert any("\\x0a" in line for line in lines)


def test_environment_listing_gives_an_over_long_name_its_own_line(capsys):
    # One pathological, attacker-controlled name must not shove the value
    # column right for all forty entries -- nor be truncated, since the
    # name is evidence too.
    long_name = "X" * 90
    lines = [l for l in _env_lines(capsys, [(long_name, "v"), ("SHORT", "w")]) if l.strip()]
    assert lines[0].strip() == long_name
    assert lines[1].strip() == "v"
    assert lines[2].index("w") < 60, "the ordinary entry kept a sane value column"


def test_environment_listing_marks_a_captured_but_empty_value(capsys):
    # `NAME=` with nothing after it is real evidence (the block WAS
    # walked); printing the name with trailing blank space would read as a
    # rendering bug instead.
    line = _env_lines(capsys, [("EMPTY", "")])[0]
    assert line.split() == ["EMPTY", "(empty)"]


def test_environment_listing_width_is_deterministic_off_a_terminal(capsys):
    # capsys-captured stdout is never a TTY, which is exactly the
    # condition resolve_width() pins to FALLBACK_WIDTH -- console goldens
    # and this suite must not depend on the terminal a run happens in.
    value = ";".join(f"seg{i}" for i in range(60))
    assert _env_lines(capsys, [("P", value)]) == _env_lines(capsys, [("P", value)])
    narrow = _env_lines(capsys, [("P", value)], width=80)
    wide = _env_lines(capsys, [("P", value)], width=120)
    assert len(narrow) > len(wide), "an explicit width must still be honoured"


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
    # Two aligned columns since §4.6.1, not the old flat `name=value`.
    assert [line.split() for line in out.splitlines()].count(["A", "1"]) == 1


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

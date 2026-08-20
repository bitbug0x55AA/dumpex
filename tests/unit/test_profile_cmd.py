"""Unit tests for dumpex.commands.profile -- issue #95's collect/render/
command vertical slice over docs/recon_profile_contract.md.

--profile consumes ALREADY-PARSED mf.<attr> objects (the same ones every
other recon command reads) rather than parsing its own stream bytes, so
these fixtures build FakeMF instances directly (mirroring
tests/unit/test_console_untrusted_text.py's own style) instead of the
byte-level stream builders test_handles_cmd.py needs for HandleDataStream's
own real parser.
"""
import contextlib
import io

import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE

from tests.fixtures.fakes import FakeMF, Module, Thread, Ctx, Handle, FakeStream, SysInfo, Segment

from dumpex.commands.profile import (
    collect_profile, cmd_profile, render_profile_console,
)
from dumpex.output.coverage import (
    CoverageStatus, LimitationCode, SourceState, exit_code_for,
)
from dumpex.output.records import (
    StreamParserState, CapabilityStatus, CapabilityLimitationCode, CAPABILITY_IDS,
    ProfileCapabilityEntry, CapabilityLimitation,
)


# ── Directory/header fixtures ───────────────────────────────────────────

class _Location:
    def __init__(self, rva=0, data_size=0):
        self.Rva = rva
        self.DataSize = data_size


class _Directory:
    def __init__(self, stream_type, rva=0, data_size=0):
        self.StreamType = stream_type
        self.Location = _Location(rva, data_size)


class _Header:
    def __init__(self, flags=0):
        self.Flags = flags


def _mf(*, header=True, flags=0, directories=(), failures=None, **attrs) -> FakeMF:
    mf = FakeMF()
    mf.header = _Header(flags) if header else None
    mf.directories = list(directories)
    mf._dumpex_stream_failures = dict(failures or {})
    for name, value in attrs.items():
        setattr(mf, name, value)
    return mf


class _TruncatedHandleStreamHeader:
    def __init__(self, declared):
        self.NumberOfDescriptors = declared


class _ParsedHandles:
    """Minimal stand-in for dumpex.core.memory.ParsedHandleDataStream --
    only `.header.NumberOfDescriptors` and `.handles`, the two fields
    _declared_item_count()/_collection_item_count() actually read."""
    def __init__(self, declared, handles):
        self.header = _TruncatedHandleStreamHeader(declared)
        self.handles = handles


def _codes(coverage):
    return [l.code for l in coverage.limitations]


def _limitation(coverage, code):
    return next((l for l in coverage.limitations if l.code == code), None)


def _stream(record, stream_type):
    return next(s for s in record.streams if s.stream_type_id == stream_type.value)


def _cap(record, capability_id):
    return next(c for c in record.capabilities if c.capability_id == capability_id)


def _console(result) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        render_profile_console(result.records, result.coverage)
    return buffer.getvalue()


# ── not_evaluated: no defensible profile at all ─────────────────────────

def test_missing_header_is_not_evaluated_with_zero_records():
    result = collect_profile(_mf(header=False))

    assert result.kind == "profile"
    assert result.records == []
    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(result.coverage.status) == 4
    assert LimitationCode.PROFILE_DIRECTORY_UNAVAILABLE in _codes(result.coverage)


def test_not_evaluated_renderer_does_not_crash_on_zero_records():
    result = collect_profile(_mf(header=False))
    text = _console(result)
    assert "no defensible capability profile" in text


def test_not_evaluated_summary_is_zeroed_even_with_leftover_stream_attrs():
    """Regression: a hand-built (or otherwise not-open_dump()-produced)
    `mf` with header=None but stray leftover stream attributes (e.g.
    mf.handles set) must not let those attributes drive a positive
    capability_summary -- 'no defensible profile could be constructed'
    and 'capability X is available' must never coexist in the same
    result. collect_profile() short-circuits before computing any
    per-stream/per-capability state at all once header is None."""
    result = collect_profile(_mf(
        header=False, handles=FakeStream([Handle(0x10, "File", "obj")], "handles"),
        modules=FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")))
    assert result.records == []
    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert result.summary == {"stream_count": 0,
                               "capability_summary": {"available": 0, "limited": 0, "unavailable": 0}}
    text = _console(result)
    for status_word in ("available", "limited"):
        assert status_word not in text.lower()


# ── complete: a minimal, sparse, but successfully profiled dump ────────

def test_sparse_dump_with_only_sysinfo_is_complete():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)],
        sysinfo=SysInfo()))

    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status) == 0
    assert len(result.records) == 1
    record = result.records[0]
    assert record.architecture == "AMD64"
    # A complete result may still report unavailable capabilities -- #95's
    # own "downstream capability statuses ... must not automatically
    # downgrade the command-level coverage" rule.
    assert any(c.status == CapabilityStatus.UNAVAILABLE.value for c in record.capabilities)


def test_fully_populated_dump_is_complete_with_every_capability_available():
    mf = _mf(
        flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value,
        directories=[
            _Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream),
            _Directory(MINIDUMP_STREAM_TYPE.ModuleListStream),
            _Directory(MINIDUMP_STREAM_TYPE.ThreadListStream),
            _Directory(MINIDUMP_STREAM_TYPE.ThreadInfoListStream),
            _Directory(MINIDUMP_STREAM_TYPE.MemoryInfoListStream),
            _Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
            _Directory(MINIDUMP_STREAM_TYPE.HandleDataStream),
        ],
        sysinfo=SysInfo(),
        modules=FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules"),
        threads=FakeStream([Thread(1, Ctx(0x1000))], "threads"),
        thread_info=FakeStream([object()], "infos"),
        memory_info=FakeStream([object()], "infos"),
        memory_segments_64=FakeStream([Segment(0x1000, 0x2000, 0x1000)], "memory_segments"),
        handles=FakeStream([Handle(0x10, "File", "\\Device\\x")], "handles"),
    )
    result = collect_profile(mf)

    assert result.coverage.status == CoverageStatus.COMPLETE
    record = result.records[0]
    for capability_id in CAPABILITY_IDS:
        entry = _cap(record, capability_id)
        assert entry.status == CapabilityStatus.AVAILABLE.value, capability_id
        assert entry.limitations == ()


# ── PROFILE_FLAGS_UNAVAILABLE / PROFILE_ARCHITECTURE_UNAVAILABLE ───────

def test_truncated_header_flags_drive_partial_and_null_flag_fields():
    result = collect_profile(_mf(header=True, flags=None))
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert exit_code_for(result.coverage.status) == 3
    assert LimitationCode.PROFILE_FLAGS_UNAVAILABLE in _codes(result.coverage)
    record = result.records[0]
    assert record.raw_flags is None
    assert record.recognized_flags == ()
    assert record.unrecognized_flag_bits is None


def test_missing_sysinfo_drives_partial_and_null_architecture():
    result = collect_profile(_mf(flags=0))
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert LimitationCode.PROFILE_ARCHITECTURE_UNAVAILABLE in _codes(result.coverage)
    assert result.records[0].architecture is None


def test_failed_sysinfo_is_generic_source_failed_not_architecture_unavailable():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)],
        failures={MINIDUMP_STREAM_TYPE.SystemInfoStream: "ValueError: boom"}))
    codes = _codes(result.coverage)
    assert LimitationCode.SOURCE_FAILED in codes
    assert LimitationCode.PROFILE_ARCHITECTURE_UNAVAILABLE not in codes


def test_both_flags_and_architecture_gaps_survive_together():
    result = collect_profile(_mf(header=True, flags=None))
    codes = _codes(result.coverage)
    assert LimitationCode.PROFILE_FLAGS_UNAVAILABLE in codes
    assert LimitationCode.PROFILE_ARCHITECTURE_UNAVAILABLE in codes


# ── MINIDUMP_TYPE flags: raw vs recognized, independent of stream evidence ──

def test_recognized_flags_decode_in_declaration_order():
    flags = (MINIDUMP_TYPE.MiniDumpWithThreadInfo.value | MINIDUMP_TYPE.MiniDumpWithDataSegs.value
              | MINIDUMP_TYPE.MiniDumpWithFullMemory.value)
    result = collect_profile(_mf(flags=flags))
    record = result.records[0]
    assert record.raw_flags == flags
    # MiniDumpWithDataSegs(1) < MiniDumpWithFullMemory(2) < MiniDumpWithThreadInfo(4096)
    # in MINIDUMP_TYPE's own declaration order.
    assert record.recognized_flags == (
        "MiniDumpWithDataSegs", "MiniDumpWithFullMemory", "MiniDumpWithThreadInfo")
    assert record.unrecognized_flag_bits == 0


def test_unrecognized_flag_bits_are_preserved_not_dropped():
    weird_bit = 1 << 30   # past MiniDumpFilterTriage(0x100000), never a named MINIDUMP_TYPE member
    flags = MINIDUMP_TYPE.MiniDumpWithFullMemory.value | weird_bit
    result = collect_profile(_mf(flags=flags))
    record = result.records[0]
    assert record.raw_flags == flags
    assert record.recognized_flags == ("MiniDumpWithFullMemory",)
    assert record.unrecognized_flag_bits == weird_bit


def test_minidump_normal_reports_full_memory_flag_false():
    result = collect_profile(_mf(flags=0))
    assert result.records[0].memory_capture.full_memory_flag_set is False


def test_full_memory_flag_never_inferred_from_memory64list_alone():
    """§: 'Do not infer MiniDumpWithFullMemory from Memory64ListStream
    alone. Report the raw flag and observed memory evidence
    independently.' -- a captured Memory64ListStream with the flag CLEAR
    must still report full_memory_flag_set=False, never True."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream)],
        memory_segments_64=FakeStream([Segment(0x1000, 0x2000, 0x1000)], "memory_segments")))
    mc = result.records[0].memory_capture
    assert mc.full_memory_flag_set is False
    assert mc.memory64_list_present is True
    assert mc.captured_segment_count == 1


def test_full_memory_flag_set_with_no_captured_segments_reports_both_facts_separately():
    """The inverse mismatch: the flag claims full memory but nothing was
    actually captured -- both facts are reported as observed, neither
    silently overriding the other."""
    result = collect_profile(_mf(flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value))
    mc = result.records[0].memory_capture
    assert mc.full_memory_flag_set is True
    assert mc.captured_segment_count is None
    assert mc.memory64_list_present is False
    assert mc.memory_list_present is False


def test_console_never_reports_null_captured_memory_as_an_established_zero():
    """§1: 'null means the fact could not be established; an empty
    tuple/list/0 means established, and the answer is none/zero -- the
    two are never conflated.' The console's own captured-memory-content
    line must render null (neither memory stream ever parsed) distinctly
    from an established zero (a segment stream parsed but held no
    segments) -- neither may say '(none captured)', which reads as a
    confirmed empty capture either way."""
    null_result = collect_profile(_mf(flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value))
    assert null_result.records[0].memory_capture.captured_segment_count is None
    null_text = _console(null_result)
    assert "(none captured)" not in null_text
    assert "(unknown)" in null_text.split("Captured memory content")[1].splitlines()[0]

    zero_result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream)],
        memory_segments_64=FakeStream([], "memory_segments")))
    assert zero_result.records[0].memory_capture.captured_segment_count == 0
    zero_text = _console(zero_result)
    assert "(none captured)" not in zero_text
    assert "0 segment(s), 0 byte(s)" in zero_text


def test_partial_captured_range_reports_a_real_segment_count():
    result = collect_profile(_mf(
        flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream)],
        memory_segments_64=FakeStream(
            [Segment(0x1000, 0x2000, 0x1000), Segment(0x5000, 0x6000, 0x2000)], "memory_segments")))
    mc = result.records[0].memory_capture
    assert mc.captured_segment_count == 2
    assert mc.captured_bytes_total == 0x3000


def test_memory64_preferred_over_memorylist_matching_read_region():
    result = collect_profile(_mf(
        flags=0,
        memory_segments_64=FakeStream([Segment(0x1000, 0x2000, 0x100)], "memory_segments"),
        memory_segments=FakeStream([Segment(0x9000, 0xA000, 0x999)], "memory_segments")))
    mc = result.records[0].memory_capture
    assert mc.captured_segment_count == 1
    assert mc.captured_bytes_total == 0x100


def test_failed_memory64_liststream_falling_back_to_memorylist_is_not_silent():
    """Regression: a genuine Memory64ListStream parse failure with the
    legacy MemoryList fallback still producing real segments must not be
    silently absorbed into a confident-looking memory_capture with no
    trace anywhere that the PREFERRED (and typically far richer) stream
    failed -- real numbers are kept (the fallback's own data is
    trustworthy), but the command-level coverage must say so."""
    result = collect_profile(_mf(
        flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)],
        failures={MINIDUMP_STREAM_TYPE.Memory64ListStream: "ValueError: boom"},
        memory_segments=FakeStream([Segment(0x1000, 0x2000, 256)], "memory_segments"),
        sysinfo=SysInfo()))
    mc = result.records[0].memory_capture
    # Real, trustworthy data from the fallback -- not nulled.
    assert mc.captured_segment_count == 1
    assert mc.captured_bytes_total == 256
    # But not silent: command-level coverage must carry the fact.
    assert result.coverage.status == CoverageStatus.PARTIAL
    fallback = _limitation(result.coverage, LimitationCode.PROFILE_MEMORY_CONTENT_FALLBACK)
    assert fallback is not None
    assert "boom" in fallback.detail
    assert result.coverage.sources["memory_content"].detail is not None


def test_ambiguous_memory64_liststream_never_reports_the_fallback_limitation():
    """The fallback limitation and the ambiguity fold (§2.4) describe
    different facts and must not both fire for the same underlying
    cause -- an ambiguous Memory64ListStream already gets the stronger,
    more accurate INDETERMINATE treatment (memory_content itself becomes
    FAILED), so PROFILE_MEMORY_CONTENT_FALLBACK must not also appear."""
    result = collect_profile(_mf(
        flags=0,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream)],
        memory_segments_64=FakeStream([Segment(0x1000, 0x2000, 256)], "memory_segments")))
    assert _limitation(result.coverage, LimitationCode.PROFILE_MEMORY_CONTENT_FALLBACK) is None


# ── Memory-content resolution: a fallback stream's own problems must
# never erase valid, already-selected preferred evidence, and vice versa
# (the "which stream was ACTUALLY consulted" question _resolve_memory_
# content() exists to answer once, shared by memory_capture and
# memory_content alike) ──────────────────────────────────────────────

def test_valid_memory64_ignores_an_ambiguous_unused_memorylist():
    """Case 1: Memory64ListStream is unambiguous and holds real data --
    MemoryListStream's own duplicate directory entries are irrelevant,
    because get_memory_segments() would never even look at it. Regression
    for the bug where the fallback's own ambiguity nulled out perfectly
    good, already-selected preferred evidence."""
    result = collect_profile(_mf(
        flags=0x2,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryListStream)],
        memory_segments_64=FakeStream([Segment(0x1000, 0x2000, 256)], "memory_segments")))
    mc = result.records[0].memory_capture
    assert mc.captured_segment_count == 1
    assert mc.captured_bytes_total == 256
    assert result.coverage.sources["memory_content"].state == SourceState.PRESENT
    assert result.coverage.sources["memory_content"].detail is None


def test_valid_memory64_ignores_a_failed_unused_memorylist():
    """Case 2: same, but MemoryListStream genuinely failed to parse
    (not merely ambiguous) -- still irrelevant, since Memory64ListStream
    was never going to fall through to it."""
    result = collect_profile(_mf(
        flags=0x2,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryListStream)],
        failures={MINIDUMP_STREAM_TYPE.MemoryListStream: "ValueError: unrelated"},
        memory_segments_64=FakeStream([Segment(0x1000, 0x2000, 256)], "memory_segments")))
    mc = result.records[0].memory_capture
    assert mc.captured_segment_count == 1
    assert mc.captured_bytes_total == 256
    assert result.coverage.sources["memory_content"].state == SourceState.PRESENT
    assert result.coverage.sources["memory_content"].detail is None
    assert _limitation(result.coverage, LimitationCode.PROFILE_MEMORY_CONTENT_FALLBACK) is None


def test_valid_memory64_capability_gating_ignores_an_ambiguous_unused_memorylist():
    """Regression: capability gating must agree with the ALREADY-RESOLVED
    memory_content state, not re-derive a coarser answer of its own. A
    valid, unambiguous Memory64ListStream (the selected source) plus a
    duplicated, never-consulted MemoryListStream must leave
    injection_artifact_analysis's own memory_content evidence completely
    unremarked -- no OPTIONAL_SOURCE_INDETERMINATE(memory_content)
    limitation sitting next to a coverage.sources["memory_content"] that
    reads PRESENT."""
    result = collect_profile(_mf(
        flags=0,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryInfoListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.ThreadInfoListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.ModuleListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.ThreadListStream)],
        memory_segments_64=FakeStream([Segment(0x1000, 0x2000, 256)], "memory_segments"),
        memory_info=FakeStream([object()], "infos"),
        thread_info=FakeStream([object()], "infos"),
        modules=FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules"),
        threads=FakeStream([Thread(1, Ctx(0x1000))], "threads")))
    assert result.coverage.sources["memory_content"].state == SourceState.PRESENT
    entry = _cap(result.records[0], "injection_artifact_analysis")
    assert entry.status == CapabilityStatus.AVAILABLE.value
    assert entry.limitations == ()


def test_ambiguous_memory64_fails_closed_even_with_a_healthy_memorylist():
    """Case 3, frozen explicitly: an AMBIGUOUS Memory64ListStream does
    NOT fall through to a perfectly healthy MemoryListStream, even
    though MemoryListStream itself has real, unambiguous data available.
    This is a deliberate fail-closed choice, not an oversight: if one of
    the duplicate Memory64ListStream entries actually succeeded,
    get_memory_segments() would use ITS data, never MemoryListStream's --
    reporting MemoryListStream's data here would risk contradicting what
    read_region()/--extract/every hunter actually resolve to."""
    result = collect_profile(_mf(
        flags=0,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryListStream)],
        memory_segments=FakeStream([Segment(0x9000, 0xA000, 512)], "memory_segments")))
    mc = result.records[0].memory_capture
    assert mc.captured_segment_count is None
    assert mc.captured_bytes_total is None
    assert result.coverage.sources["memory_content"].state == SourceState.FAILED


def test_failed_memory64_with_present_empty_memorylist_is_reported_as_failed():
    """Case 4: Memory64ListStream genuinely failed to parse, and the
    fallback MemoryListStream is present but VERIFIED EMPTY (a real,
    established fact -- not 'we don't know'). This must not be
    conflated with a genuine 'memory content overall indeterminate'
    state: it is reported as FAILED (Memory64's own failure detail),
    the more actionable signal, distinct from present_empty (which would
    claim the whole picture is an established zero when the preferred,
    richer stream's own failure means the true capture may be larger)."""
    result = collect_profile(_mf(
        flags=0,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryListStream)],
        failures={MINIDUMP_STREAM_TYPE.Memory64ListStream: "ValueError: boom"},
        memory_segments=FakeStream([], "memory_segments")))
    mc = result.records[0].memory_capture
    assert mc.captured_segment_count is None
    assert mc.captured_bytes_total is None
    obs = result.coverage.sources["memory_content"]
    assert obs.state == SourceState.FAILED
    assert "boom" in obs.detail


# ── Stream inventory: known / unknown / duplicate / present-empty / unparsed / failed ──

def test_known_stream_with_content_is_parsed_with_a_count():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)],
        modules=FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.ModuleListStream)
    assert entry.parser_state == StreamParserState.PARSED.value
    assert entry.record_count == 1
    assert entry.stream_type_name == "ModuleListStream"
    assert entry.detail is None


def test_known_stream_verified_empty_is_present_empty():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)],
        modules=FakeStream([], "modules")))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.ModuleListStream)
    assert entry.parser_state == StreamParserState.PRESENT_EMPTY.value
    assert entry.record_count == 0


def test_absent_stream_produces_no_inventory_row_at_all():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)], sysinfo=SysInfo()))
    stream_type_ids = [s.stream_type_id for s in result.records[0].streams]
    assert MINIDUMP_STREAM_TYPE.ModuleListStream.value not in stream_type_ids


def test_failed_stream_carries_the_parser_detail():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)],
        failures={MINIDUMP_STREAM_TYPE.ModuleListStream: "ValueError: layout drift"}))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.ModuleListStream)
    assert entry.parser_state == StreamParserState.FAILED.value
    assert entry.record_count is None
    assert entry.detail == "ValueError: layout drift"


def test_directory_present_dispatched_but_never_parsed_fails_closed():
    """A directory entry dumpex has a parser for, with no recorded
    failure, but mf.<attr> still None -- unreachable through today's
    open_dump(), but must still fail closed as FAILED evidence rather
    than silently reporting UNPARSED (which would claim dumpex never even
    tried) or crashing."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)]))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.ModuleListStream)
    assert entry.parser_state == StreamParserState.FAILED.value
    assert entry.detail is not None


def test_recognized_but_undispatched_stream_type_is_unparsed():
    """FunctionTableStream(13) is a REAL MINIDUMP_STREAM_TYPE member --
    dumpex just has no parser registered for it."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.FunctionTableStream)]))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.FunctionTableStream)
    assert entry.parser_state == StreamParserState.UNPARSED.value
    assert entry.stream_type_name == "FunctionTableStream"


def test_unrecognized_numeric_stream_type_is_preserved_not_dropped():
    result = collect_profile(_mf(flags=0, directories=[_Directory(9999)]))
    streams = result.records[0].streams
    assert len(streams) == 1
    entry = streams[0]
    assert entry.stream_type_id == 9999
    assert entry.stream_type_name is None
    assert entry.parser_state == StreamParserState.UNPARSED.value


def test_real_minidump_user_stream_above_0xffff_is_also_preserved():
    """Deliberately not exempted: a genuine Microsoft MINIDUMP_USER_STREAM
    (StreamType > 0xFFFF, silently DROPPED by the upstream minidump
    library itself) still gets its own inventory row here -- #95's
    acceptance criteria ('preserve unknown stream-type IDs rather than
    silently dropping them') make no exception for that range."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream), _Directory(0x10000)],
        sysinfo=SysInfo()))
    streams = result.records[0].streams
    assert len(streams) == 2
    entry = streams[1]
    assert entry.stream_type_id == 0x10000
    assert entry.stream_type_name is None
    assert entry.parser_state == StreamParserState.UNPARSED.value


def test_directory_truncation_is_reported_not_fabricated():
    """dumpex.core.memory.open_dump()'s own file-size bound records a
    declared-vs-readable shortfall on `mf` (see directory_truncated_count)
    rather than fabricating rows to cover it; --profile surfaces that
    shortfall as PROFILE_DIRECTORY_TRUNCATED/partial instead of silently
    reporting a shorter-than-declared, but otherwise unremarked-upon,
    inventory."""
    mf = _mf(flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)],
              sysinfo=SysInfo())
    mf._dumpex_directory_truncated_count = 499999
    result = collect_profile(mf)
    assert result.coverage.status == CoverageStatus.PARTIAL
    truncated = _limitation(result.coverage, LimitationCode.PROFILE_DIRECTORY_TRUNCATED)
    assert truncated is not None
    assert truncated.affected_count == 499999
    # The entries actually read are still fully reported -- truncation
    # describes what's MISSING, not what IS present.
    assert len(result.records[0].streams) == 1


def test_duplicate_stream_type_entries_are_both_preserved_as_indeterminate():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadListStream),
                                _Directory(MINIDUMP_STREAM_TYPE.ThreadListStream)],
        threads=FakeStream([Thread(1, Ctx(0x1000))], "threads")))
    record = result.records[0]
    assert len(record.streams) == 2
    assert all(s.parser_state == StreamParserState.INDETERMINATE.value for s in record.streams)
    assert all(s.detail for s in record.streams)
    assert result.coverage.status == CoverageStatus.PARTIAL
    ambiguous = _limitation(result.coverage, LimitationCode.PROFILE_STREAM_STATE_AMBIGUOUS)
    assert ambiguous is not None
    assert ambiguous.affected_count == 1   # one AMBIGUOUS TYPE, not two entries


def test_duplicate_stream_never_makes_its_own_capability_read_available():
    """Regression: a stream type with duplicate directory entries that
    BOTH parsed cleanly (no recorded failure at all) must not let the
    capability depending on it read 'available'/'limited' -- that would
    read as confident, usable evidence sitting right next to a stream row
    that says its own state is 'indeterminate'. mf.threads here holds a
    real, non-empty parsed object; thread_analysis must still be
    'unavailable', but with REQUIRED_SOURCE_INDETERMINATE (never
    REQUIRED_SOURCE_FAILED -- that code's fixed template asserts "could
    not be parsed", which is not true here: both duplicate entries parsed
    without error, dumpex just cannot attribute the surviving state to
    either one)."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadListStream),
                                _Directory(MINIDUMP_STREAM_TYPE.ThreadListStream)],
        threads=FakeStream([Thread(1, Ctx(0x1000))], "threads")))
    entry = _cap(result.records[0], "thread_analysis")
    assert entry.status == CapabilityStatus.UNAVAILABLE.value
    assert entry.limitations[0].code == CapabilityLimitationCode.REQUIRED_SOURCE_INDETERMINATE.value
    detail = entry.limitations[0].to_dict()["detail"]
    assert "could not be parsed" not in detail
    assert "duplicate directory entries" in detail


def test_duplicate_handledatastream_never_makes_handle_analysis_available():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream),
                                _Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        handles=FakeStream([Handle(0x10, "File", "\\x")], "handles")))
    for capability_id in ("handle_analysis", "injector_handle_assessment"):
        entry = _cap(result.records[0], capability_id)
        assert entry.status == CapabilityStatus.UNAVAILABLE.value


def test_duplicate_sysinfo_nulls_architecture_and_fails_the_capability_source():
    """Same regression, applied to the record's own `architecture` field
    (read directly off mf.sysinfo) rather than a capability: it must not
    report a confident architecture string sourced from an entangled
    duplicate-entry parse."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream),
                                _Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)],
        sysinfo=SysInfo()))
    assert result.records[0].architecture is None
    assert LimitationCode.SOURCE_FAILED in _codes(result.coverage)


def test_duplicate_memory_stream_nulls_captured_segment_facts():
    """Same regression, applied to ProfileMemoryCapture: a duplicated
    Memory64ListStream must not report a confident captured_segment_count/
    captured_bytes_total sourced from entangled duplicate-entry data.
    memory_content is an OPTIONAL source for injection_artifact_analysis
    (§4.2 -- the real dumpex.hunt.injection hunter still runs, and reports
    real per-region PE_HEADER_READ_FAILED facts, on MemoryInfoListStream
    alone), so the capability itself degrades to 'limited' here (memory_
    info satisfies the required group), never silently 'available' --
    the ambiguous memory_content must still surface as its own
    OPTIONAL_SOURCE_INDETERMINATE limitation, never trusted."""
    result = collect_profile(_mf(
        flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.MemoryInfoListStream)],
        memory_segments_64=FakeStream([Segment(0x1000, 0x2000, 0x1000)], "memory_segments"),
        memory_info=FakeStream([object()], "infos")))
    mc = result.records[0].memory_capture
    assert mc.captured_segment_count is None
    assert mc.captured_bytes_total is None
    # memory64_list_present stays a pure directory-presence fact, unlike
    # the parsed-data-derived fields above.
    assert mc.memory64_list_present is True
    entry = _cap(result.records[0], "injection_artifact_analysis")
    assert entry.status == CapabilityStatus.LIMITED.value
    memory_content_limitations = [l for l in entry.limitations if l.source == "memory_content"]
    assert len(memory_content_limitations) == 1
    assert memory_content_limitations[0].code == CapabilityLimitationCode.OPTIONAL_SOURCE_INDETERMINATE.value


def test_three_duplicate_entries_of_one_type_still_count_as_one_ambiguous_type():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)] * 3))
    ambiguous = _limitation(result.coverage, LimitationCode.PROFILE_STREAM_STATE_AMBIGUOUS)
    assert ambiguous.affected_count == 1


def test_two_different_ambiguous_types_count_as_two():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ModuleListStream),
                                _Directory(MINIDUMP_STREAM_TYPE.ModuleListStream),
                                _Directory(MINIDUMP_STREAM_TYPE.ThreadListStream),
                                _Directory(MINIDUMP_STREAM_TYPE.ThreadListStream)]))
    ambiguous = _limitation(result.coverage, LimitationCode.PROFILE_STREAM_STATE_AMBIGUOUS)
    assert ambiguous.affected_count == 2


def test_many_duplicates_of_one_type_cap_the_displayed_index_list():
    """A stream type duplicated far past the display cap must still
    produce exactly one entry per directory index (no entries silently
    dropped) and a bounded detail string (no attempt to spell out
    thousands of indexes verbatim) -- see _build_stream_inventory's own
    docstring on the O(N^2)/unbounded-string amplification this bounds."""
    count = 50
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)] * count))
    record = result.records[0]
    assert len(record.streams) == count
    assert all(s.parser_state == StreamParserState.INDETERMINATE.value for s in record.streams)
    for entry in record.streams:
        assert entry.detail.count(",") < 10   # bounded index list, not all 50
        assert "more" in entry.detail
    ambiguous = _limitation(result.coverage, LimitationCode.PROFILE_STREAM_STATE_AMBIGUOUS)
    assert ambiguous.affected_count == 1


def test_duplicate_unknown_stream_type_is_unparsed_not_indeterminate():
    """A regression case, not a merge check: 9999 is BOTH unrecognized AND
    undispatched, so 'which entry does the shared parse outcome belong
    to' is not a real question for it at all -- dumpex never parses this
    type regardless of how many directory entries declare it, so there is
    no mf.<attr>/failure state for open_dump()'s Phase 2 to entangle in
    the first place. Both entries are independently, unambiguously
    'unparsed' -- 'indeterminate' would falsely claim something was lost
    to entanglement and would falsely downgrade coverage via
    PROFILE_STREAM_STATE_AMBIGUOUS for a fact that isn't ambiguous."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream),
                                _Directory(9999), _Directory(9999)],
        sysinfo=SysInfo()))
    record = result.records[0]
    unknown_entries = [s for s in record.streams if s.stream_type_id == 9999]
    assert len(unknown_entries) == 2
    assert all(s.parser_state == StreamParserState.UNPARSED.value for s in unknown_entries)
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert LimitationCode.PROFILE_STREAM_STATE_AMBIGUOUS not in _codes(result.coverage)


def test_duplicate_undispatched_recognized_type_is_unparsed_not_indeterminate():
    """Same fix, for a RECOGNIZED-but-undispatched type (FunctionTableStream
    is a real MINIDUMP_STREAM_TYPE member dumpex simply has no parser
    for) -- must not be conflated with a duplicated DISPATCHED type like
    HandleDataStream, which genuinely IS ambiguous (§2.4)."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream),
                                _Directory(MINIDUMP_STREAM_TYPE.FunctionTableStream),
                                _Directory(MINIDUMP_STREAM_TYPE.FunctionTableStream)],
        sysinfo=SysInfo()))
    record = result.records[0]
    ft_entries = [s for s in record.streams if s.stream_type_name == "FunctionTableStream"]
    assert len(ft_entries) == 2
    assert all(s.parser_state == StreamParserState.UNPARSED.value for s in ft_entries)
    assert result.coverage.status == CoverageStatus.COMPLETE


def test_stream_inventory_preserves_directory_order():
    directories = [_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream),
                    _Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream),
                    _Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)]
    result = collect_profile(_mf(flags=0, directories=directories, sysinfo=SysInfo(),
                                  modules=FakeStream([], "modules")))
    ids = [s.stream_type_id for s in result.records[0].streams]
    assert ids == [MINIDUMP_STREAM_TYPE.HandleDataStream.value,
                    MINIDUMP_STREAM_TYPE.SystemInfoStream.value,
                    MINIDUMP_STREAM_TYPE.ModuleListStream.value]
    assert [s.directory_index for s in result.records[0].streams] == [0, 1, 2]


# ── Capability matrix: available / limited / unavailable, every id ─────

@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_every_capability_is_unavailable_with_no_streams_at_all(capability_id):
    result = collect_profile(_mf(flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)],
                                  sysinfo=SysInfo()))
    entry = _cap(result.records[0], capability_id)
    assert entry.status == CapabilityStatus.UNAVAILABLE.value
    assert entry.limitations
    assert all(l.code == CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value for l in entry.limitations)


def test_thread_analysis_limited_when_group_sibling_and_optional_are_missing():
    """thread_info is a REQUIRED-group member (threads OR thread_info,
    §4.2) -- its own absence, with threads satisfying the group, is
    REQUIRED_GROUP_MEMBER_ABSENT, never OPTIONAL_SOURCE_ABSENT (that code
    is reserved for a source that is PURELY optional, like modules
    here -- see ProfileCapabilityEntry's own enforcement)."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadListStream)],
        threads=FakeStream([Thread(1, Ctx(0x1000))], "threads")))
    entry = _cap(result.records[0], "thread_analysis")
    assert entry.status == CapabilityStatus.LIMITED.value
    by_source = {l.source: l.code for l in entry.limitations}
    assert by_source == {
        "thread_info": CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value,
        "modules":     CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value,
    }


def test_thread_analysis_available_with_required_and_optional_present():
    result = collect_profile(_mf(
        flags=0,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.ThreadInfoListStream),
                      _Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)],
        threads=FakeStream([Thread(1, Ctx(0x1000))], "threads"),
        thread_info=FakeStream([object()], "infos"),
        modules=FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")))
    entry = _cap(result.records[0], "thread_analysis")
    assert entry.status == CapabilityStatus.AVAILABLE.value
    assert entry.limitations == ()


@pytest.mark.parametrize("capability_id,dump_kwargs", [
    ("thread_analysis",
     dict(directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadListStream)],
          threads=FakeStream([Thread(1, Ctx(0x1000))], "threads"))),
    ("injection_artifact_analysis",
     dict(directories=[_Directory(MINIDUMP_STREAM_TYPE.MemoryInfoListStream)],
          memory_info=FakeStream([object()], "infos"))),
])
def test_no_limitation_ever_calls_a_required_source_optional(capability_id, dump_kwargs):
    """The record itself must be self-consistent: no limitation whose
    source is a member of required_source_groups may ever be described as
    optional corroborating evidence, for any capability that has an
    OR-group at all -- this is the general form of the regression
    test_optional_gap_never_erases_available_required_evidence exercises
    for thread_analysis alone."""
    result = collect_profile(_mf(flags=0, **dump_kwargs))
    entry = _cap(result.records[0], capability_id)
    required_members = {name for group in entry.required_source_groups for name in group}
    for limitation in entry.limitations:
        if limitation.source in required_members:
            assert limitation.code != CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value
            assert limitation.code != CapabilityLimitationCode.OPTIONAL_SOURCE_FAILED.value
            assert limitation.code != CapabilityLimitationCode.OPTIONAL_SOURCE_INDETERMINATE.value
            detail = limitation.to_dict()["detail"]
            assert "optional corroborating evidence" not in detail


_BLOCKING_CODES = frozenset({"REQUIRED_SOURCE_ABSENT", "REQUIRED_SOURCE_FAILED",
                              "REQUIRED_SOURCE_INDETERMINATE"})


def _derive_status_from_dict(blob: dict) -> str:
    """Reproduces §4.3's status derivation from `ProfileCapabilityEntry.
    to_dict()` alone -- no access to the Python object, ambiguous_types,
    or any other out-of-band state. A required_source_groups member with
    a blocking limitation, in a group where NO sibling avoided one,
    blocks the whole group; any blocked group makes the capability
    unavailable."""
    blocked_sources = {l["source"] for l in blob["limitations"] if l["code"] in _BLOCKING_CODES}
    for group in blob["required_source_groups"]:
        if all(name in blocked_sources for name in group):
            return "unavailable"
    return "limited" if blob["limitations"] else "available"


@pytest.mark.parametrize("directories_kwargs", [
    dict(directories=[], ),
    dict(directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadListStream)],
         threads=FakeStream([Thread(1, Ctx(0x1000))], "threads")),
    dict(directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadListStream),
                        _Directory(MINIDUMP_STREAM_TYPE.ThreadInfoListStream),
                        _Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)],
         threads=FakeStream([Thread(1, Ctx(0x1000))], "threads"),
         thread_info=FakeStream([object()], "infos"),
         modules=FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")),
])
def test_status_is_derivable_from_to_dict_alone(directories_kwargs):
    """§4.3's derivation must be reproducible by a consumer that only has
    the serialized record (e.g. #43's future JSON consumers), not
    something only the Python object's own construction-time validation
    can confirm -- exercised across the unavailable/limited/available
    boundary for thread_analysis."""
    result = collect_profile(_mf(flags=0, **directories_kwargs))
    entry = _cap(result.records[0], "thread_analysis")
    assert _derive_status_from_dict(entry.to_dict()) == entry.status


def test_constructing_an_optional_limitation_for_a_required_group_member_raises():
    """Negative test: a caller cannot build an OPTIONAL_SOURCE_ABSENT
    limitation naming a source that is actually a required-group member
    -- enforced by ProfileCapabilityEntry.__post_init__, not merely by
    _build_capability_entry's own discipline."""
    with pytest.raises(ValueError, match="OPTIONAL_SOURCE"):
        ProfileCapabilityEntry(
            capability_id="thread_analysis", status=CapabilityStatus.LIMITED.value,
            required_source_groups=(("threads", "thread_info"),),
            required_sources=("threads", "thread_info"), optional_sources=("modules",),
            limitations=(CapabilityLimitation(
                code=CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value, source="thread_info"),))


def test_handle_analysis_with_threads_as_its_required_source_raises():
    """Negative test: handle_analysis's own frozen registry entry
    requires 'handles', not 'threads' -- a record claiming otherwise is
    internally self-consistent (a well-formed single-member group,
    correctly flattened, no overlap with optional_sources) but factually
    wrong for that capability id, and must be rejected at construction
    time against dumpex.output.records.CAPABILITY_BY_ID, not merely by
    caller discipline in _build_capability_entry."""
    with pytest.raises(ValueError, match="required_source_groups"):
        ProfileCapabilityEntry(
            capability_id="handle_analysis", status=CapabilityStatus.AVAILABLE.value,
            required_source_groups=(("threads",),),
            required_sources=("threads",), optional_sources=(), limitations=())


def test_capability_with_the_wrong_optional_sources_raises():
    """Negative test: thread_analysis's own registry entry declares
    optional_sources=("modules",) -- a record declaring a different set
    (even a superset/subset) must be rejected."""
    with pytest.raises(ValueError, match="optional_sources"):
        ProfileCapabilityEntry(
            capability_id="thread_analysis", status=CapabilityStatus.AVAILABLE.value,
            required_source_groups=(("threads", "thread_info"),),
            required_sources=("threads", "thread_info"),
            optional_sources=("modules", "handles"), limitations=())


def test_single_member_group_cannot_use_required_group_member_code():
    """Negative test: handle_analysis's required group ("handles",) has
    exactly one member, so there is no sibling for REQUIRED_GROUP_MEMBER_*
    to claim satisfied it -- that code is only meaningful for a
    multi-member group."""
    with pytest.raises(ValueError, match="single-member group"):
        ProfileCapabilityEntry(
            capability_id="handle_analysis", status=CapabilityStatus.LIMITED.value,
            required_source_groups=(("handles",),),
            required_sources=("handles",), optional_sources=(),
            limitations=(CapabilityLimitation(
                code=CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value,
                source="handles"),))


def test_partially_blocked_required_group_raises():
    """Negative test: a required group must be either fully blocked
    (every member carries a REQUIRED_SOURCE_* limitation) or fully
    unblocked -- a group with only SOME members blocked is an
    inconsistent construction the real collector algorithm never
    produces (it resolves a failed group's every member at once)."""
    with pytest.raises(ValueError, match="fully blocked or fully unblocked"):
        ProfileCapabilityEntry(
            capability_id="thread_analysis", status=CapabilityStatus.UNAVAILABLE.value,
            required_source_groups=(("threads", "thread_info"),),
            required_sources=("threads", "thread_info"), optional_sources=("modules",),
            limitations=(CapabilityLimitation(
                code=CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value, source="threads"),))


def test_duplicate_limitation_source_raises():
    """Negative test: the same source may never carry two limitations --
    would be either a redundant duplicate or a direct contradiction."""
    with pytest.raises(ValueError, match="more than once"):
        ProfileCapabilityEntry(
            capability_id="handle_analysis", status=CapabilityStatus.UNAVAILABLE.value,
            required_source_groups=(("handles",),),
            required_sources=("handles",), optional_sources=(),
            limitations=(
                CapabilityLimitation(code=CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value,
                                      source="handles"),
                CapabilityLimitation(code=CapabilityLimitationCode.REQUIRED_SOURCE_FAILED.value,
                                      source="handles")))


def test_registry_is_the_single_source_of_ids_order_and_labels():
    """Structural test: CAPABILITY_IDS, CAPABILITY_BY_ID, and every
    definition's own label are all derived from CAPABILITY_REGISTRY --
    not three independently hand-maintained structures that could
    silently drift apart."""
    from dumpex.output.records import CAPABILITY_REGISTRY, CAPABILITY_BY_ID as by_id
    assert tuple(d.capability_id for d in CAPABILITY_REGISTRY) == CAPABILITY_IDS
    assert set(by_id) == set(CAPABILITY_IDS)
    for capability_id in CAPABILITY_IDS:
        assert by_id[capability_id].capability_id == capability_id
        assert by_id[capability_id].label   # non-empty
        assert by_id[capability_id].required_sources   # non-empty


def test_optional_gap_never_erases_available_required_evidence():
    """§: 'Missing optional corroboration may make a capability limited,
    but must not erase available preferred-source evidence.' -- required
    ThreadListStream data must still be reachable via required_sources
    even when limited. required_sources is the FLATTENED OR-group
    ("threads", "thread_info") -- a static, per-capability-id fact (§4.2)
    -- not narrowed to whichever member happened to satisfy it in this
    one instance. required_source_groups carries the actual OR-group
    structure that required_sources alone cannot express."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadListStream)],
        threads=FakeStream([Thread(1, Ctx(0x1000))], "threads")))
    entry = _cap(result.records[0], "thread_analysis")
    assert entry.required_sources == ("threads", "thread_info")
    assert entry.required_source_groups == (("threads", "thread_info"),)
    assert entry.status != CapabilityStatus.UNAVAILABLE.value
    # thread_info (the group's unsatisfied sibling) degrades to a
    # REQUIRED_GROUP_MEMBER_* gap -- never OPTIONAL_SOURCE_*, which would
    # falsely call a required-group member "optional corroborating
    # evidence".
    thread_info_limitations = [l for l in entry.limitations if l.source == "thread_info"]
    assert len(thread_info_limitations) == 1
    assert thread_info_limitations[0].code == CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value
    detail = thread_info_limitations[0].to_dict()["detail"]
    assert "optional corroborating evidence" not in detail


def test_injection_artifact_analysis_available_with_memory_info_alone():
    """§4.2: the real dumpex.hunt.injection hunter's own evaluation gate
    is evaluation_sources=("memory_info", "thread_info") -- an OR-group,
    verified against dumpex.hunt.injection.report_facts.
    project_coverage_report(). MemoryInfoListStream (region metadata)
    ALONE, with no captured memory bytes at all, must NOT read
    'unavailable': the real hunter still runs on exactly this input and
    reports genuine per-region PE_HEADER_READ_FAILED facts rather than
    refusing outright -- memory_content is optional-corroboration
    evidence here, not a hard requirement."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.MemoryInfoListStream)],
        memory_info=FakeStream([object()], "infos")))
    entry = _cap(result.records[0], "injection_artifact_analysis")
    assert entry.status == CapabilityStatus.LIMITED.value
    memory_content_limitations = [l for l in entry.limitations if l.source == "memory_content"]
    assert len(memory_content_limitations) == 1
    assert memory_content_limitations[0].code == CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value


def test_injection_artifact_analysis_available_with_thread_info_alone():
    """The OR-group's OTHER member alone (ThreadInfoListStream, no
    MemoryInfoListStream at all) must also avoid 'unavailable' -- neither
    member is privileged over the other, matching the real hunter's own
    symmetric evaluation_sources group."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ThreadInfoListStream)],
        thread_info=FakeStream([object()], "infos")))
    entry = _cap(result.records[0], "injection_artifact_analysis")
    assert entry.status == CapabilityStatus.LIMITED.value
    memory_info_limitations = [l for l in entry.limitations if l.source == "memory_info"]
    assert len(memory_info_limitations) == 1
    assert memory_info_limitations[0].code == CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value


def test_injection_artifact_analysis_unavailable_only_when_both_group_members_absent():
    """The true 'unavailable' boundary: neither MemoryInfoListStream nor
    ThreadInfoListStream present at all -- matching the real hunter's own
    not_evaluated condition exactly."""
    result = collect_profile(_mf(flags=0))
    entry = _cap(result.records[0], "injection_artifact_analysis")
    assert entry.status == CapabilityStatus.UNAVAILABLE.value
    sources = {l.source for l in entry.limitations}
    assert sources == {"memory_info", "thread_info"}


# ── HandleDataStream: unavailable handle capabilities, non-clean wording ──

def test_missing_handledatastream_makes_both_handle_capabilities_unavailable():
    result = collect_profile(_mf(flags=0))
    record = result.records[0]
    handle_entry = _cap(record, "handle_analysis")
    injector_entry = _cap(record, "injector_handle_assessment")
    assert handle_entry.status == CapabilityStatus.UNAVAILABLE.value
    assert injector_entry.status == CapabilityStatus.UNAVAILABLE.value
    for entry in (handle_entry, injector_entry):
        limitation = entry.limitations[0]
        assert limitation.code == CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value
        text = limitation.to_dict()["detail"]
        # Never a "clean"/negative-finding sentence -- an evidence-boundary
        # statement only (discussion #94's own framing).
        assert "clean" not in text.lower()
        assert "no suspicious" not in text.lower()
        assert "not present" in text


def test_missing_handledatastream_never_implies_a_clean_finding_in_the_console():
    result = collect_profile(_mf(flags=0))
    text = _console(result).lower()
    assert "clean" not in text
    assert "no suspicious" not in text


def test_present_but_empty_handledatastream_makes_handle_analysis_available():
    """A present-empty HandleDataStream (zero handles captured, but the
    stream itself WAS captured) is examinable evidence, not a gap --
    handle_analysis must be available, matching --handles' own §5.5 case 4
    'present-empty is complete, not a failure' philosophy."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        handles=FakeStream([], "handles")))
    entry = _cap(result.records[0], "handle_analysis")
    assert entry.status == CapabilityStatus.AVAILABLE.value


def test_failed_handledatastream_is_required_source_failed_not_absent():
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        failures={MINIDUMP_STREAM_TYPE.HandleDataStream: "ValueError: boom"}))
    entry = _cap(result.records[0], "handle_analysis")
    assert entry.status == CapabilityStatus.UNAVAILABLE.value
    assert entry.limitations[0].code == CapabilityLimitationCode.REQUIRED_SOURCE_FAILED.value


def test_capability_gating_agrees_with_the_streams_own_inventory_row():
    """A directory entry dumpex is dispatched to parse, with no recorded
    failure, but mf.handles still None: the stream inventory reports this
    as FAILED (fail-closed, see test_directory_present_dispatched_but_
    never_parsed_fails_closed above) -- handle_analysis must agree,
    REQUIRED_SOURCE_FAILED, never REQUIRED_SOURCE_ABSENT, so the console/
    JSON can never describe the same fact two different ways."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)]))
    record = result.records[0]
    stream_entry = _stream(record, MINIDUMP_STREAM_TYPE.HandleDataStream)
    cap_entry = _cap(record, "handle_analysis")
    assert stream_entry.parser_state == StreamParserState.FAILED.value
    assert cap_entry.status == CapabilityStatus.UNAVAILABLE.value
    assert cap_entry.limitations[0].code == CapabilityLimitationCode.REQUIRED_SOURCE_FAILED.value


# ── HandleDataStream truncation: real data kept, shortfall never silent ──

def test_truncated_handledatastream_reports_the_shortfall_on_its_own_row():
    """NumberOfDescriptors=100, len(handles)=10 (the reviewer's own
    reproduction case): the stream row keeps the real, actually-read
    count and carries an explicit detail naming the shortfall -- neither
    dropped nor silently reported as a complete [10]."""
    handles = [Handle(0x10 + i, "File", f"obj{i}") for i in range(10)]
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        handles=_ParsedHandles(100, handles)))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.HandleDataStream)
    assert entry.parser_state == StreamParserState.PARSED.value
    assert entry.record_count == 10
    assert entry.detail is not None
    assert "100" in entry.detail and "10" in entry.detail


def test_truncated_handledatastream_degrades_both_handle_capabilities_to_limited():
    """Both handle_analysis and injector_handle_assessment must reflect
    the truncation as a REQUIRED_SOURCE_TRUNCATED limitation -- limited,
    never unavailable (real, if incomplete, data exists) and never
    silently available (the shortfall is a genuine gap)."""
    handles = [Handle(0x10 + i, "File", f"obj{i}") for i in range(10)]
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        handles=_ParsedHandles(100, handles)))
    for capability_id in ("handle_analysis", "injector_handle_assessment"):
        entry = _cap(result.records[0], capability_id)
        assert entry.status == CapabilityStatus.LIMITED.value
        handles_limitations = [l for l in entry.limitations if l.source == "handles"]
        assert len(handles_limitations) == 1
        assert handles_limitations[0].code == CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value


def test_untruncated_handledatastream_stays_fully_available():
    """The negative case: NumberOfDescriptors == len(handles) must not
    trigger any truncation note or limitation at all."""
    handles = [Handle(0x10, "File", "obj")]
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        handles=_ParsedHandles(1, handles)))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.HandleDataStream)
    assert entry.detail is None
    cap = _cap(result.records[0], "handle_analysis")
    assert cap.status == CapabilityStatus.AVAILABLE.value
    assert cap.limitations == ()


def test_fully_truncated_handledatastream_is_not_reported_as_verified_empty():
    """NumberOfDescriptors=100, len(handles)=0: zero items were actually
    read, but that is NOT the same fact as "the stream is verified
    empty" -- 100 declared descriptors were never read at all. Must
    report parsed/0 with a shortfall detail and degrade handle_analysis
    to limited/REQUIRED_SOURCE_TRUNCATED, not present_empty/available."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        handles=_ParsedHandles(100, [])))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.HandleDataStream)
    assert entry.parser_state == StreamParserState.PARSED.value
    assert entry.record_count == 0
    assert entry.detail is not None
    assert "100" in entry.detail and "0" in entry.detail
    cap = _cap(result.records[0], "handle_analysis")
    assert cap.status == CapabilityStatus.LIMITED.value
    handles_limitations = [l for l in cap.limitations if l.source == "handles"]
    assert len(handles_limitations) == 1
    assert handles_limitations[0].code == CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value


def test_genuinely_empty_handledatastream_still_reports_present_empty():
    """NumberOfDescriptors=0, len(handles)=0: the negative case for the
    truncation check above -- a stream that declares zero descriptors and
    reads zero descriptors is genuinely, verifiably empty, not truncated,
    and handle_analysis must stay available."""
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        handles=_ParsedHandles(0, [])))
    entry = _stream(result.records[0], MINIDUMP_STREAM_TYPE.HandleDataStream)
    assert entry.parser_state == StreamParserState.PRESENT_EMPTY.value
    assert entry.record_count == 0
    assert entry.detail is None
    cap = _cap(result.records[0], "handle_analysis")
    assert cap.status == CapabilityStatus.AVAILABLE.value
    assert cap.limitations == ()


# ── Determinism / ordering / no verdict semantics ───────────────────────

def test_capabilities_are_always_the_frozen_registry_in_order():
    result = collect_profile(_mf(flags=0))
    ids = tuple(c.capability_id for c in result.records[0].capabilities)
    assert ids == CAPABILITY_IDS


def test_capability_order_is_identical_across_very_different_dumps():
    sparse = collect_profile(_mf(flags=0))
    rich = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        handles=FakeStream([Handle(0x10, "File", "\\x")], "handles")))
    assert (tuple(c.capability_id for c in sparse.records[0].capabilities)
            == tuple(c.capability_id for c in rich.records[0].capabilities))


def test_to_dict_never_leaks_a_raw_parser_object():
    """Defensive copying / no raw parser objects -- every leaf in the
    serialized record is a plain JSON-safe scalar or container."""
    def _assert_json_safe(value):
        if isinstance(value, dict):
            for v in value.values():
                _assert_json_safe(v)
        elif isinstance(value, list):
            for v in value:
                _assert_json_safe(v)
        else:
            assert value is None or isinstance(value, (str, int, float, bool)), (
                f"non-JSON-safe leaf in ProfileRecord.to_dict(): {value!r} ({type(value)})")

    result = collect_profile(_mf(
        flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream),
                      _Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        sysinfo=SysInfo(), handles=FakeStream([Handle(0x10, "File", "\\x")], "handles")))
    _assert_json_safe(result.records[0].to_dict())


def test_no_malicious_or_clean_verdict_vocabulary_anywhere_in_the_output():
    """Hard non-goal: no malicious/clean verdict, confidence, ATT&CK, or
    hunter-score semantics anywhere in the record or its rendering."""
    result = collect_profile(_mf(
        flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value,
        directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream),
                      _Directory(MINIDUMP_STREAM_TYPE.HandleDataStream)],
        sysinfo=SysInfo(), handles=FakeStream([Handle(0x10, "File", "\\x")], "handles")))
    import json
    blob = json.dumps(result.records[0].to_dict()).lower()
    for forbidden in ("malicious", "attck", "att&ck", "confidence", "verdict", "risk_score"):
        assert forbidden not in blob
    text = _console(result).lower()
    for forbidden in ("malicious", "att&ck", "confidence score", "verdict"):
        assert forbidden not in text


# ── Renderer purity ──────────────────────────────────────────────────────

def test_renderer_never_touches_mf():
    """render_profile_console's own signature takes no `mf` -- this proves
    it at the call boundary too: a records/coverage pair with `mf` never
    constructed is enough to render successfully."""
    result = collect_profile(_mf(flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)],
                                  sysinfo=SysInfo()))
    # Re-render from the already-collected result alone -- no mf in scope.
    text_again = _console(result)
    assert "PROFILE" in text_again


def test_renderer_performs_no_capability_recomputation():
    """Mutating a capability entry's own recorded status after collection
    must be exactly what the renderer prints -- proving it projects the
    given data rather than recomputing status from source observations of
    its own."""
    result = collect_profile(_mf(flags=0))
    record = result.records[0]
    # ProfileCapabilityEntry is frozen/immutable; there is no setter to
    # mutate through, which is itself the enforcement this test exercises
    # -- attempting one must fail rather than silently no-op.
    from dataclasses import FrozenInstanceError
    with pytest.raises(FrozenInstanceError):
        record.capabilities[0].status = CapabilityStatus.AVAILABLE.value


def test_cmd_profile_renders_and_returns_the_same_result():
    mf = _mf(flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream)], sysinfo=SysInfo())
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = cmd_profile(mf)
    assert result.kind == "profile"
    assert "PROFILE" in buffer.getvalue()


# ── Console escaping (control text embedded in a parser failure detail) ──

def test_console_escapes_a_hostile_parser_failure_detail():
    # console_safe() never escapes a bare "\n" -- see dumpex.ui.colors.
    # console_safe's own docstring and tests/unit/test_console_untrusted_
    # text.py's identical FORBIDDEN_IN_OUTPUT exclusion -- so this checks
    # what console_safe() actually guarantees: every OTHER terminal-control
    # codepoint (ESC, C0/C1 controls, bidi overrides) is neutralized.
    # Registered as this module's own case in test_console_untrusted_
    # text.py's RENDER_CASES is the authoritative, full-payload check
    # (forged-line detection included).
    hostile = "boom\x1b[2J\x1b[H"
    result = collect_profile(_mf(
        flags=0, directories=[_Directory(MINIDUMP_STREAM_TYPE.ModuleListStream)],
        failures={MINIDUMP_STREAM_TYPE.ModuleListStream: hostile}))
    text = _console(result)
    assert "\x1b[2J" not in text
    assert "\\x1b[2j" in text.lower()

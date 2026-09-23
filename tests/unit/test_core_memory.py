"""Unit tests for dumpex.core.memory's cross-platform path helpers."""
import io
import struct
import types

import pytest

from dumpex.core.memory import (
    module_name_only, verdict_for, _verdict, _search_string_in_memory, StringSearchStats,
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_LIKELY_MALICIOUS, VERDICT_HIGH_CONFIDENCE_MALICIOUS,
    va_range_captured_bytes, clamped_reader, read_region_clamped, read_region_spanning,
    has_stream_directory, handle_stream_evidence,
    HandleStreamContractError, declared_descriptor_count, truncated_descriptor_count,
    ip_context_conflict_for, enriched_thread_contexts,
    dump_flags_state, dump_flags_tags, dump_flags_value, recorded_start_address,
    parse_thread_info_stream, ThreadInfoStreamFramingError, RawThreadInfo,
    declared_thread_info_count, truncated_thread_info_count,
    MAX_THREAD_INFO_RAW_BYTES,
    DUMP_FLAGS_RESOLVED, DUMP_FLAGS_UNRESOLVED, DUMP_FLAGS_ABSENT,
    START_ADDRESS_RECORDED, START_ADDRESS_INVALID, START_ADDRESS_UNVERIFIED,
    START_ADDRESS_ABSENT,
)
from minidump.constants import MINIDUMP_STREAM_TYPE

import dumpex.core.memory as core_memory_mod
from tests.fixtures.fakes import (
    FakeMF, FakeStream, Handle, Region, Segment, mem_reader,
    mf_with_handle_stream, parsed_handle_stream, ThreadInfo, Thread, Ctx,
    parsed_thread_info_stream, build_thread_info_stream, ThreadInfoStreamDirectory,
    THREAD_INFO_ENTRY_SIZE,
)


# ── ip_context_conflict_for: tri-state join of CONTEXT against DumpFlags ──

def test_ip_context_conflict_for_is_false_when_ip_is_none_regardless_of_record():
    # Nothing captured, nothing to dispute -- true whether or not
    # ThreadInfoListStream covers this TID.
    assert ip_context_conflict_for(None, ThreadInfo(1, 0x2000)) is False
    assert ip_context_conflict_for(None, RawThreadInfo(1)) is False
    assert ip_context_conflict_for(
        None, ThreadInfo(1, 0x2000, dump_flags="MINIDUMP_THREAD_INFO_INVALID_CONTEXT")) is False


def test_ip_context_conflict_for_is_none_when_no_thread_info_record_exists():
    # ip was captured, but there is no ThreadInfoListStream record for
    # this TID to join it against -- undeterminable, not a confirmed
    # False the way a genuinely clean DumpFlags is.
    assert ip_context_conflict_for(0x1000, None) is None
    assert ip_context_conflict_for(0x1000, RawThreadInfo(1)) is None
    assert ip_context_conflict_for(0, RawThreadInfo(1)) is None


def test_ip_context_conflict_for_is_true_only_for_a_real_record_flagging_invalid_context():
    ti = ThreadInfo(1, 0x2000, dump_flags="MINIDUMP_THREAD_INFO_INVALID_CONTEXT")
    assert ip_context_conflict_for(0x1000, ti) is True
    assert ip_context_conflict_for(0, ti) is True


def test_ip_context_conflict_for_is_true_for_a_combined_value_including_invalid_context():
    # INVALID_CONTEXT | EXITED_THREAD. The dispute is the same fact
    # whether the producer set that bit alone or alongside others.
    combined = ThreadInfo(1, 0x2000, dump_flags=0x14)
    assert combined.DumpFlags is None          # unrepresentable upstream
    assert ip_context_conflict_for(0x1000, combined) is True


def test_ip_context_conflict_for_is_false_for_a_real_clean_record():
    assert ip_context_conflict_for(0x1000, ThreadInfo(1, 0x2000)) is False


def test_ip_context_conflict_for_is_none_when_the_records_flags_could_not_be_read():
    # A record whose DumpFlags value could not be recovered disputes
    # nothing AND clears nothing: reporting False here would publish an
    # unreadable value as a confirmed absence of conflict.
    unreadable = ThreadInfo(1, 0x2000, raw_dump_flags=None)
    assert dump_flags_value(unreadable) is None
    assert ip_context_conflict_for(0x1000, unreadable) is None
    assert ip_context_conflict_for(None, unreadable) is False


# -- DumpFlags: raw value, state, and tags --------------------------------

def test_dump_flags_tags_reports_every_bit_of_a_combined_value():
    assert dump_flags_tags(ThreadInfo(1, 0x2000, dump_flags=0x14)) == ["EXITED", "NO_CTX"]
    assert dump_flags_tags(ThreadInfo(1, 0x2000, dump_flags=0x10)) == ["NO_CTX"]
    assert dump_flags_tags(ThreadInfo(1, 0x2000)) == []


def test_dump_flags_value_falls_back_to_a_library_style_enum_attribute():
    # A record carrying only the library's own single-member DumpFlags
    # enum -- no raw value -- still has an exactly-known value: that
    # member's own `.value` IS what was on disk wherever the lookup
    # succeeded at all.
    ti = ThreadInfo(1, 0x2000, dump_flags="MINIDUMP_THREAD_INFO_INVALID_CONTEXT",
                    raw_dump_flags=None)
    assert ti.RawDumpFlags is None and ti.DumpFlags is not None
    assert dump_flags_value(ti) == 0x10
    assert dump_flags_state(ti) == DUMP_FLAGS_RESOLVED


def test_dump_flags_state_separates_a_flagless_thread_from_an_unreadable_one():
    # An empty tag list means two different things, and only this field
    # tells them apart.
    assert dump_flags_state(ThreadInfo(1, 0x2000)) == DUMP_FLAGS_RESOLVED
    unreadable = ThreadInfo(1, 0x2000, raw_dump_flags=None)
    assert dump_flags_tags(unreadable) == []
    assert dump_flags_state(unreadable) == DUMP_FLAGS_UNRESOLVED
    assert dump_flags_state(RawThreadInfo(1)) == DUMP_FLAGS_ABSENT
    assert dump_flags_state(None) == DUMP_FLAGS_ABSENT


# -- recorded_start_address: what a StartAddress is actually worth --------

def test_recorded_start_address_returns_a_clean_records_own_address():
    assert recorded_start_address(ThreadInfo(1, 0x2000)) == (0x2000, START_ADDRESS_RECORDED)


def test_recorded_start_address_drops_an_address_its_own_record_disowns():
    # ERROR_THREAD: "no thread information exists beyond the thread
    # identifier". The zeroed StartAddress field is missing evidence, so
    # it is reported as unknown rather than as address 0x0.
    for flag in ("MINIDUMP_THREAD_INFO_ERROR_THREAD", "MINIDUMP_THREAD_INFO_INVALID_INFO"):
        assert recorded_start_address(ThreadInfo(1, 0, dump_flags=flag)) == (
            None, START_ADDRESS_INVALID)
    # Non-zero bytes in that field do not rescue it either.
    assert recorded_start_address(
        ThreadInfo(1, 0x2000, dump_flags="MINIDUMP_THREAD_INFO_ERROR_THREAD")) == (
            None, START_ADDRESS_INVALID)


def test_recorded_start_address_keeps_flags_that_say_nothing_about_the_start_address():
    # EXITED/DUMPER/NO_CTX/NO_TEB describe the thread or its context, not
    # the validity of this record's own fields.
    for flag in ("MINIDUMP_THREAD_INFO_EXITED_THREAD", "MINIDUMP_THREAD_INFO_WRITING_THREAD",
                 "MINIDUMP_THREAD_INFO_INVALID_CONTEXT", "MINIDUMP_THREAD_INFO_INVALID_TEB"):
        assert recorded_start_address(ThreadInfo(1, 0x2000, dump_flags=flag)) == (
            0x2000, START_ADDRESS_RECORDED)


def test_recorded_start_address_is_invalid_for_a_combined_value_carrying_error_thread():
    assert recorded_start_address(ThreadInfo(1, 0x2000, dump_flags=0x5)) == (
        None, START_ADDRESS_INVALID)


def test_recorded_start_address_keeps_but_does_not_vouch_for_an_unreadable_record():
    assert recorded_start_address(ThreadInfo(1, 0x2000, raw_dump_flags=None)) == (
        0x2000, START_ADDRESS_UNVERIFIED)


def test_recorded_start_address_is_absent_without_a_record_and_never_zero():
    assert recorded_start_address(RawThreadInfo(1)) == (None, START_ADDRESS_ABSENT)
    assert recorded_start_address(None) == (None, START_ADDRESS_ABSENT)


# -- parse_thread_info_stream: one validated layout, bounded ------------

def test_parse_thread_info_stream_recovers_a_combined_value_the_library_drops():
    # The installed library parses DumpFlags through a single-member Enum
    # lookup: 0x14 is unrepresentable and comes back None, exactly like
    # 0x0. Only the raw value tells the two apart.
    parsed = parsed_thread_info_stream([
        {"tid": 1, "dump_flags": 0x14, "start_address": 0x2000},
        {"tid": 2, "dump_flags": 0x00, "start_address": 0x3000},
    ])
    combined, clean = parsed.infos
    assert combined.DumpFlags is None and clean.DumpFlags is None
    assert combined.RawDumpFlags == 0x14 and clean.RawDumpFlags == 0x00
    assert dump_flags_tags(combined) == ["EXITED", "NO_CTX"]
    assert dump_flags_tags(clean) == []
    assert ip_context_conflict_for(0x1000, combined) is True
    assert ip_context_conflict_for(0x1000, clean) is False


def test_parse_thread_info_stream_keeps_a_single_member_value_the_library_does_parse():
    parsed = parsed_thread_info_stream([{"tid": 1, "dump_flags": 0x10, "start_address": 0x2000}])
    (info,) = parsed.infos
    assert info.DumpFlags.value == 0x10
    assert info.RawDumpFlags == 0x10


def test_parse_thread_info_stream_reports_an_error_thread_start_as_unknown():
    parsed = parsed_thread_info_stream([{"tid": 1, "dump_flags": 0x1, "start_address": 0}])
    (info,) = parsed.infos
    assert recorded_start_address(info) == (None, START_ADDRESS_INVALID)


def test_parse_thread_info_stream_reads_every_field_from_the_declared_stride():
    # A producer declaring a LONGER record than the 64-byte layout carries
    # trailing fields dumpex does not read; every field it DOES read must
    # still come from this entry, not from the previous one's padding.
    # The padding here is crafted to hold the NEXT entry's own ThreadId,
    # which a walk that confirms correspondence by ThreadId alone would
    # accept while reading every later field from the wrong bytes.
    parsed = parsed_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x10, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x10, "start_address": 0x500100}],
        size_of_entry=72, entry_padding=struct.pack("<II", 2, 0))
    first, second = parsed.infos
    assert (first.ThreadId, first.StartAddress) == (1, 0x400100)
    assert (second.ThreadId, second.StartAddress) == (2, 0x500100)
    assert recorded_start_address(second) == (0x500100, START_ADDRESS_RECORDED)


def test_parse_thread_info_stream_leaves_a_field_the_record_never_carried_unset():
    # An 8-byte declared record holds ThreadId and DumpFlags and nothing
    # else. Reading StartAddress from bytes that are not part of this
    # record -- or from the empty read the library's fixed-layout parse
    # turns into 0 -- would publish an address the producer never wrote.
    parsed = parsed_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x10, "start_address": 0x500100}], size_of_entry=8)
    (info,) = parsed.infos
    assert info.ThreadId == 1
    assert info.RawDumpFlags == 0x10        # readable flags
    assert info.StartAddress is None        # ... say nothing about the address field
    assert info.KernelTime is None
    assert recorded_start_address(info) == (None, START_ADDRESS_ABSENT)
    assert dump_flags_state(info) == DUMP_FLAGS_RESOLVED


def test_readable_flags_never_promote_a_start_address_the_record_never_held():
    # The two facts are independent: a record can have perfectly readable
    # DumpFlags and still stop short of its own StartAddress field.
    for size_of_entry in (8, 16, 32, 48):
        parsed = parsed_thread_info_stream(
            [{"tid": 1, "dump_flags": 0x10, "start_address": 0x500100}],
            size_of_entry=size_of_entry)
        (info,) = parsed.infos
        assert recorded_start_address(info) == (None, START_ADDRESS_ABSENT), size_of_entry


def test_a_record_the_stream_cuts_short_keeps_the_fields_it_did_carry():
    # A standard 64-byte record the stream's own DataSize cuts off after
    # ThreadId and DumpFlags is not a record with a zero StartAddress,
    # and it is not a thread that does not exist either: its TID and its
    # captured flags are real evidence, and dropping them would read
    # downstream as a thread the dump never had.
    body, _data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x10, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x10, "start_address": 0x500100}])
    parsed = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=12 + THREAD_INFO_ENTRY_SIZE + 8),
        io.BytesIO(body))
    assert [i.ThreadId for i in parsed.infos] == [1, 2]
    tail = parsed.infos[1]
    assert dump_flags_tags(tail) == ["NO_CTX"]
    assert ip_context_conflict_for(0x1000, tail) is True
    assert recorded_start_address(tail) == (None, START_ADDRESS_ABSENT)
    assert truncated_thread_info_count(parsed) == 0


def test_a_record_the_file_ends_partway_through_keeps_the_fields_it_did_carry():
    # Same rule against the independent bound: the stream declares the
    # entry, the file simply stops inside it.
    body, data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x10, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x10, "start_address": 0x500100}],
        body_bytes=12 + THREAD_INFO_ENTRY_SIZE + 8)
    parsed = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=data_size), io.BytesIO(body))
    assert [i.ThreadId for i in parsed.infos] == [1, 2]
    assert recorded_start_address(parsed.infos[1]) == (None, START_ADDRESS_ABSENT)
    assert truncated_thread_info_count(parsed) == 0


def test_a_record_reduced_to_its_thread_id_is_still_a_record():
    # A whole ThreadId survives and nothing else does. That ThreadId is
    # what attributes a record to a thread at all, so the record stays --
    # dropping it is what makes that thread look absent from this stream
    # -- with its DumpFlags reported as unreadable rather than as 0.
    body, data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x10, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x10, "start_address": 0x500100}],
        body_bytes=12 + THREAD_INFO_ENTRY_SIZE + 4)
    parsed = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=data_size), io.BytesIO(body))
    assert [i.ThreadId for i in parsed.infos] == [1, 2]
    tail = parsed.infos[1]
    assert tail.RawDumpFlags is None
    assert dump_flags_state(tail) == DUMP_FLAGS_UNRESOLVED
    assert ip_context_conflict_for(0x1000, tail) is None
    assert recorded_start_address(tail) == (None, START_ADDRESS_ABSENT)
    assert truncated_thread_info_count(parsed) == 0


def test_a_record_without_even_a_whole_thread_id_is_not_offered_but_is_counted():
    # Fewer than a whole ThreadId remain: there is nothing to attribute
    # to a thread at all. The record is not invented, and the shortfall
    # stays recoverable so a consumer knows this stream cannot settle
    # which TIDs exist.
    body, data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x10, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x10, "start_address": 0x500100}],
        body_bytes=12 + THREAD_INFO_ENTRY_SIZE + 3)
    parsed = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=data_size), io.BytesIO(body))
    assert [i.ThreadId for i in parsed.infos] == [1]
    assert parsed.header.NumberOfEntries == 2
    assert truncated_thread_info_count(parsed) == 2 - 1


def test_truncated_thread_info_count_claims_nothing_it_cannot_establish():
    # No stream, a fixture with no header, and a stream that delivered
    # everything it declared all report 0 -- a count nothing establishes
    # must never read as a gap.
    assert truncated_thread_info_count(None) == 0
    assert truncated_thread_info_count(FakeStream([ThreadInfo(1, 0x2000)], "infos")) == 0
    parsed = parsed_thread_info_stream([{"tid": 1, "dump_flags": 0x10, "start_address": 0x2000}])
    assert truncated_thread_info_count(parsed) == 0
    assert declared_thread_info_count(parsed) == 1


def test_truncated_thread_info_count_reads_a_contradictory_header_as_no_gap():
    # A stream that delivered MORE than it declared is a contradiction in
    # the dump's own numbers, not a negative shortfall.
    body, data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x10, "start_address": 0x2000},
         {"tid": 2, "dump_flags": 0x10, "start_address": 0x3000}], number_of_entries=1)
    parsed = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=data_size), io.BytesIO(body))
    assert truncated_thread_info_count(parsed) == 0


def test_parse_thread_info_stream_never_reads_past_the_stream_it_describes():
    # The directory declares a 16-byte stream while the file holds a full
    # 64-byte entry after it. Walking the entry array at its own stride
    # would read bytes belonging to whatever follows this stream and
    # publish them as this stream's own record.
    body, _data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x14, "start_address": 0x2000}])
    assert len(body) > 16                      # the out-of-stream bytes really are there
    parsed = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=16), io.BytesIO(body))
    # The 4 bytes the stream DOES declare are this record's ThreadId, and
    # they are read. Everything after them lies outside the stream, so
    # every later field stays unknown rather than taking its value from
    # whatever follows.
    (info,) = parsed.infos
    assert info.ThreadId == 1
    assert info.RawDumpFlags is None
    assert info.StartAddress is None


def test_parse_thread_info_stream_never_sizes_a_read_from_a_dump_controlled_stride():
    # SizeOfEntry is a dump-controlled UINT32: 0xffffffff asks for a
    # ~4 GiB read. The framing is rejected outright, before any entry
    # read is attempted.
    class _RecordingHandle:
        def __init__(self, data):
            self._buf = io.BytesIO(data)
            self.reads = []

        def seek(self, *args):
            return self._buf.seek(*args)

        def read(self, size=-1):
            self.reads.append(size)
            return self._buf.read(size)

    handle = _RecordingHandle(struct.pack("<III", 12, 0xFFFFFFFF, 1) + bytes(64))
    with pytest.raises(ThreadInfoStreamFramingError):
        parse_thread_info_stream(ThreadInfoStreamDirectory(rva=0, data_size=0xFFFFFFFF), handle)
    assert all(size <= MAX_THREAD_INFO_RAW_BYTES for size in handle.reads)


def test_parse_thread_info_stream_caps_a_declared_count_it_cannot_support():
    # NumberOfEntries beyond what the stream's own extent supports is not
    # an error -- it is capped, and the shortfall stays recoverable.
    body, data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x10, "start_address": 0x2000}], number_of_entries=4096)
    parsed = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=data_size), io.BytesIO(body))
    assert [i.ThreadId for i in parsed.infos] == [1]
    assert parsed.header.NumberOfEntries == 4096


@pytest.mark.parametrize("size_of_header,data_size", [(8, None), (4096, 64)])
def test_parse_thread_info_stream_rejects_an_out_of_bounds_size_of_header(size_of_header,
                                                                          data_size):
    body, declared = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x14, "start_address": 0x2000}],
        size_of_header=size_of_header, declared_data_size=data_size)
    with pytest.raises(ThreadInfoStreamFramingError):
        parse_thread_info_stream(
            ThreadInfoStreamDirectory(rva=0, data_size=declared), io.BytesIO(body))


@pytest.mark.parametrize("size_of_entry", [0, 2, 8192])
def test_parse_thread_info_stream_rejects_an_unsupported_entry_size(size_of_entry):
    body = struct.pack("<III", 12, size_of_entry, 1) + b"\x00" * 128
    with pytest.raises(ThreadInfoStreamFramingError):
        parse_thread_info_stream(
            ThreadInfoStreamDirectory(rva=0, data_size=len(body)), io.BytesIO(body))


def test_parse_thread_info_stream_rejects_a_stream_too_small_for_its_own_header():
    with pytest.raises(ThreadInfoStreamFramingError):
        parse_thread_info_stream(ThreadInfoStreamDirectory(rva=0, data_size=4),
                                  io.BytesIO(b"\x00" * 64))
    with pytest.raises(ThreadInfoStreamFramingError):
        parse_thread_info_stream(ThreadInfoStreamDirectory(rva=0, data_size=64),
                                  io.BytesIO(b"\x00" * 4))


def test_parse_thread_info_stream_rejects_a_non_integer_declared_stream_size():
    with pytest.raises(ThreadInfoStreamFramingError):
        parse_thread_info_stream(ThreadInfoStreamDirectory(rva=0, data_size=None),
                                  io.BytesIO(b"\x00" * 128))


# -- enriched_thread_contexts: the single join --threads/--report/every
#    hunter reading a thread's current RIP/EIP now shares ----------------

def test_enriched_thread_contexts_confirmed_clean():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x2000)], "infos")
    out = enriched_thread_contexts(mf)
    assert out == [{"ThreadId": 1, "ip": 0x1000, "ip_reg": "RIP", "is_wow64": False,
                    "start_address": 0x2000, "start_address_state": START_ADDRESS_RECORDED,
                    "ip_context_conflict": False}]


def test_enriched_thread_contexts_confirmed_conflict():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")
    mf.thread_info = FakeStream(
        [ThreadInfo(1, 0x2000, dump_flags="MINIDUMP_THREAD_INFO_INVALID_CONTEXT")], "infos")
    out = enriched_thread_contexts(mf)
    assert out[0]["ip_context_conflict"] is True


def test_enriched_thread_contexts_drops_a_start_address_its_record_disowns():
    # The current IP is an independent capture from the base stream and
    # survives untouched; only the start address its own record disowns
    # goes away.
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")
    mf.thread_info = FakeStream(
        [ThreadInfo(1, 0, dump_flags="MINIDUMP_THREAD_INFO_ERROR_THREAD")], "infos")
    (out,) = enriched_thread_contexts(mf)
    assert out["start_address"] is None
    assert out["start_address_state"] == START_ADDRESS_INVALID
    assert out["ip"] == 0x1000


def test_enriched_thread_contexts_undeterminable_when_no_thread_info_record():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")   # no thread_info at all
    out = enriched_thread_contexts(mf)
    assert out[0]["start_address"] is None
    assert out[0]["ip_context_conflict"] is None


def test_module_name_only_extracts_windows_backslash_path_basename():
    # Module paths recorded in a minidump are always Windows paths (e.g.
    # "C:\\Windows\\System32\\foo.dll") regardless of the host OS this
    # tool runs on. os.path.basename only splits on "/" on a POSIX host,
    # silently returning the whole backslash-separated string unchanged
    # there -- module_name_only() must use ntpath.basename instead so
    # this extracts correctly on every host, not just Windows.
    assert module_name_only(r"C:\Windows\System32\ntdll.dll") == "ntdll.dll"


def test_module_name_only_lowercases():
    assert module_name_only(r"C:\Windows\System32\NTDLL.DLL") == "ntdll.dll"


def test_module_name_only_same_basename_different_directory_matches():
    # The exact scenario dumpex.commands.comparison.collect_module_diff
    # (and diff.py's own diff_modules) relies on: the "same" module
    # relocated to a different directory between two dumps must still
    # produce the SAME match key -- and therefore report as "rebased,"
    # not a spurious removed+added pair -- regardless of host OS.
    a = module_name_only(r"C:\Program Files\App\a.dll")
    b = module_name_only(r"C:\Windows\System32\a.dll")
    assert a == b == "a.dll"


def test_module_name_only_empty_for_none_or_empty_path():
    assert module_name_only(None) == ""
    assert module_name_only("") == ""


def test_module_name_only_forward_slash_path_still_works():
    # Not the primary case (minidump module paths are Windows paths), but
    # ntpath.basename also handles "/" -- confirms nothing regressed for
    # a path that happens to use forward slashes.
    assert module_name_only("C:/Windows/System32/ntdll.dll") == "ntdll.dll"


# ── verdict_for() (Phase E, PR3) ──────────────────────────────────────────
# _verdict()'s own colored console text is derived from verdict_for(), not
# hand-maintained separately -- these tests pin the four tier boundaries
# verdict_for() itself decides, independent of any console rendering.

def test_verdict_for_zero_dims_is_clean():
    assert verdict_for({}) == VERDICT_CLEAN


def test_verdict_for_one_dim_is_suspicious():
    assert verdict_for({"rwx_private": "x"}) == VERDICT_SUSPICIOUS


def test_verdict_for_two_dims_is_likely_malicious():
    assert verdict_for({"rwx_private": "x", "injected_pe": "y"}) == VERDICT_LIKELY_MALICIOUS


def test_verdict_for_three_dims_is_high_confidence_malicious():
    assert verdict_for(
        {"rwx_private": "x", "injected_pe": "y", "ioc_strings": "z"}
    ) == VERDICT_HIGH_CONFIDENCE_MALICIOUS


def test_verdict_for_four_dims_is_still_high_confidence_malicious():
    # INDICATOR_DIMS has exactly four possible keys -- the tier stays
    # HIGH_CONFIDENCE_MALICIOUS (not a fifth tier) once all four fire.
    assert verdict_for({
        "unbacked_thread": "a", "rwx_private": "x", "injected_pe": "y", "ioc_strings": "z",
    }) == VERDICT_HIGH_CONFIDENCE_MALICIOUS


def test_verdict_console_text_tier_matches_verdict_for():
    # _verdict()'s own colored text and verdict_for()'s machine tier must
    # never disagree about which of the four tiers a given dims dict is in
    # -- both derive from the same len(dims) rule, verdict_for() is not a
    # second, independently-maintained copy of _verdict()'s own thresholds.
    for dims, expected_substr in (
        ({}, "CLEAN"),
        ({"a": "1"}, "SUSPICIOUS"),
        ({"a": "1", "b": "2"}, "LIKELY MALICIOUS"),
        ({"a": "1", "b": "2", "c": "3"}, "HIGH CONFIDENCE MALICIOUS"),
    ):
        assert expected_substr in _verdict(dims)


# ── _search_string_in_memory() telemetry (Phase E, PR3; RevFix2-P1a) ──────
# Returns (hits, StringSearchStats(skipped, clamped, truncated)) instead of
# a bare list -- closes both the pre-existing silent-skip gap (a region
# read failure during --report-string's scan was completely invisible) and
# a false-negative gap (a needle past MAX_REGION_READ's own clamp, or past
# a short real read within that clamp, was silently treated as "not
# found" with no trace either).

def _mf_with_regions(regions, read_map):
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    return mf


def test_search_string_in_memory_returns_hits_and_zero_skipped_when_all_readable():
    # Region content padded to the full region size -- a short fixture
    # payload would otherwise register as `truncated`, conflating this
    # test's own single purpose (the skip counter) with truncation.
    data = b"header NEEDLE1234 trailer".ljust(0x1000, b"\x00")
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        {0x1000: data})
    import dumpex.core.memory as core_memory
    core_memory.read_region = mem_reader({0x1000: data})
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert len(hits) == 1
    assert stats == StringSearchStats(skipped=0, clamped=0, truncated=0)


def test_search_string_in_memory_counts_skipped_unreadable_regions():
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
         Region(0x2000, 0x2000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        {})
    import dumpex.core.memory as core_memory

    def _reader(mf_, addr, size):
        if addr == 0x1000:
            raise RuntimeError("simulated read failure")
        return b"header NEEDLE1234 trailer".ljust(0x1000, b"\x00")
    core_memory.read_region = _reader
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert stats.skipped == 1
    assert stats.clamped == 0
    assert stats.truncated == 0
    assert len(hits) == 1
    assert hits[0][0].BaseAddress == 0x2000


def test_search_string_in_memory_counts_clamped_regions_bigger_than_cap(monkeypatch):
    import dumpex.core.memory as core_memory
    monkeypatch.setattr(core_memory, "MAX_REGION_READ", 16)
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")], {})
    monkeypatch.setattr(core_memory, "read_region", lambda mf_, addr, size: b"\x00" * size)
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert stats.clamped == 1
    assert stats.truncated == 0
    assert stats.skipped == 0


def test_search_string_in_memory_counts_truncated_short_reads():
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")], {})
    import dumpex.core.memory as core_memory
    core_memory.read_region = lambda mf_, addr, size: b"only nine"   # far short of 4096
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert stats.truncated == 1
    assert stats.clamped == 0
    assert stats.skipped == 0


def test_search_string_in_memory_needle_past_truncation_is_a_miss_but_counted():
    # The exact false-negative the review flagged: the needle sits past
    # where the (clamped-and-then-short) read actually reached, so it's
    # never found -- but stats.truncated must say so, rather than the scan
    # silently claiming to have covered the whole region.
    mf = _mf_with_regions(
        [Region(0x1000, 0x1000, 4096, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")], {})
    import dumpex.core.memory as core_memory
    payload = (b"x" * 100) + b"NEEDLE1234"
    core_memory.read_region = lambda mf_, addr, size: payload[:16]   # cuts off before the needle
    hits, stats = _search_string_in_memory(mf, "NEEDLE1234")
    assert hits == []
    assert stats.truncated == 1


# ── va_range_captured_bytes() (issue #28 P1 follow-up) ────────────────────
# The structural "how much of this VA range does the dump's own segment
# table actually back" fact ScanTarget.captured_size/capture_state are
# built from -- independent of any hunt's own live-read outcome.

def _mf_with_segments(segments):
    mf = FakeMF()
    mf.memory_segments_64 = FakeStream(segments, "memory_segments")
    return mf


def test_va_range_captured_bytes_zero_when_va_not_covered_at_all():
    mf = _mf_with_segments([Segment(0x2000, 0x2000, 0x1000)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0


def test_va_range_captured_bytes_full_when_one_segment_covers_the_whole_range():
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x2000)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x1000


def test_va_range_captured_bytes_partial_when_segment_covers_only_a_prefix():
    # The exact short-read shape: the requested range starts inside a
    # segment but the segment ends before the range does -- only the
    # PREFIX up to the segment's own end is actually captured.
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x800)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x800


def test_va_range_captured_bytes_stops_at_a_gap_between_segments():
    # A LATER segment covering the range's tail, with a gap in between,
    # must not count -- the missing middle still can't be extracted as one
    # contiguous read, so only the contiguous run starting at `va` counts.
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x400),
                             Segment(0x1800, 0x1800, 0x400)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x400


def test_va_range_captured_bytes_spans_contiguous_segments():
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x800),
                             Segment(0x1800, 0x1800, 0x800)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x1000


def test_va_range_captured_bytes_zero_for_no_segment_table_at_all():
    assert va_range_captured_bytes(FakeMF(), 0x1000, 0x1000) == 0


def test_va_range_captured_bytes_zero_for_zero_or_negative_size():
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x2000)])
    assert va_range_captured_bytes(mf, 0x1000, 0) == 0
    assert va_range_captured_bytes(mf, 0x1000, -1) == 0


def test_va_range_captured_bytes_reads_an_unsorted_table_in_address_order():
    """The segment table is indexed by ascending VA before it is walked,
    so a table stored out of order resolves the same contiguous run as an
    ordered one."""
    ordered = _mf_with_segments([Segment(0x1000, 0x1000, 0x800),
                                  Segment(0x1800, 0x1800, 0x800)])
    shuffled = _mf_with_segments([Segment(0x1800, 0x1800, 0x800),
                                   Segment(0x1000, 0x1000, 0x800)])
    assert (va_range_captured_bytes(shuffled, 0x1000, 0x1000)
            == va_range_captured_bytes(ordered, 0x1000, 0x1000) == 0x1000)


def test_va_range_captured_bytes_covers_a_range_an_earlier_segment_overlaps():
    """An overlapping table (an earlier entry extending past a later
    entry's start) still resolves against the entry that actually covers
    the range, not whichever one the index landed on first."""
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x4000),
                             Segment(0x2000, 0x9000, 0x400)])
    assert va_range_captured_bytes(mf, 0x2000, 0x1000) == 0x1000


def test_va_range_captured_bytes_sees_past_short_segments_nested_in_a_long_one():
    """Short entries nested inside a longer one sit between it and the
    query address in start order, and every one of them ends before that
    address. The covering entry still has to be found -- reporting 0 here
    would claim the dump captured none of a range it holds in full."""
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x5000),    # [0x1000, 0x6000)
                             Segment(0x2000, 0x9000, 0x100),     # [0x2000, 0x2100)
                             Segment(0x3000, 0x9100, 0x100)])    # [0x3000, 0x3100)
    assert va_range_captured_bytes(mf, 0x4000, 0x800) == 0x800


def test_va_range_captured_bytes_matches_a_plain_address_ordered_walk():
    """Randomized differential check over overlapping, nested, and
    gapped tables: the index is only an entry point into the same
    contiguous-run walk, never a different answer from it."""
    import random

    def plain_walk(segments, va, size):
        end, cursor = va + size, va
        for seg in sorted(segments, key=lambda s: s.start_virtual_address):
            if seg.end_virtual_address <= cursor:
                continue
            if seg.start_virtual_address > cursor:
                break
            cursor = min(seg.end_virtual_address, end)
            if cursor >= end:
                break
        return cursor - va

    rng = random.Random(7)
    for _ in range(200):
        segments = [Segment(start, start, rng.randrange(0x100, 0x4000, 0x100))
                    for start in (rng.randrange(0x1000, 0x9000, 0x100)
                                  for _ in range(rng.randint(1, 12)))]
        rng.shuffle(segments)
        mf = _mf_with_segments(segments)
        for _ in range(25):
            va = rng.randrange(0x1000, 0x9000, 0x100)
            size = rng.randrange(0x100, 0x3000, 0x100)
            assert va_range_captured_bytes(mf, va, size) == plain_walk(segments, va, size), (
                f"va={va:#x} size={size:#x} over "
                f"{[(s.start_virtual_address, s.end_virtual_address) for s in segments]}")


def test_va_range_captured_bytes_rebuilds_its_index_when_the_table_is_replaced():
    """The per-dump index is keyed on the segment list it was built from,
    so swapping the stream out (which tests do) cannot serve an answer
    from the previous table."""
    mf = _mf_with_segments([Segment(0x1000, 0x1000, 0x1000)])
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x1000

    mf.memory_segments_64 = FakeStream([Segment(0x1000, 0x1000, 0x400)],
                                        "memory_segments")
    assert va_range_captured_bytes(mf, 0x1000, 0x1000) == 0x400


# ── clamped_reader() / read_region_clamped() (issue #40) ─────────────────
# A read(addr, size) primitive that never asks for more than the CURRENT
# segment's own remaining bytes -- see clamped_reader()'s own docstring
# for why this differs from va_range_captured_bytes() (which accumulates
# across CONTIGUOUS segments, a boundary the underlying buffered reader
# itself does not honor).

class _FakeSegment:
    def __init__(self, start, data):
        self.start_address = start
        self.data = data
        self.end_address = start + len(data)

    def remaining_len(self, position):
        if not (self.start_address <= position < self.end_address):
            return None
        return self.end_address - position


class _FakeBufferedReader:
    def __init__(self, segments: dict):
        self._segments = [_FakeSegment(start, data) for start, data in segments.items()]
        self.current_segment = None
        self.current_position = None

    def move(self, address):
        for seg in self._segments:
            if seg.start_address <= address < seg.end_address:
                self.current_segment = seg
                self.current_position = address
                return
        raise Exception("not in process memory space")

    def read(self, size):
        end = self.current_position + size
        if end > self.current_segment.end_address:
            raise Exception("read over segment boundary")
        off = self.current_position - self.current_segment.start_address
        data = self.current_segment.data[off:off + size]
        self.current_position = end
        return data


class _FakeReader:
    def __init__(self, buffered):
        self._buffered = buffered

    def get_buffered_reader(self):
        return self._buffered


def _mf_with_memory(memory: dict):
    mf = FakeMF()
    mf._reader = _FakeReader(_FakeBufferedReader(memory))
    mf.get_reader = lambda: mf._reader
    return mf


def test_clamped_reader_returns_exactly_what_is_captured():
    mf = _mf_with_memory({0x1000: b"KERNEL32.dll\x00"})
    read = clamped_reader(mf)
    assert read(0x1000, 512) == b"KERNEL32.dll\x00"   # clamped to the 13 real bytes present


def test_clamped_reader_returns_empty_bytes_when_nothing_captured():
    mf = _mf_with_memory({0x1000: b"MZ"})
    read = clamped_reader(mf)
    assert read(0x9000, 512) == b""


def test_clamped_reader_stays_within_current_segment_when_a_neighbour_follows():
    # The layout that broke a prior version of this primitive: reading
    # from the FIRST segment must never spill into the immediately
    # adjacent second one just because the two are contiguous.
    mf = _mf_with_memory({0x1000: b"AB", 0x1002: b"CD"})
    read = clamped_reader(mf)
    assert read(0x1000, 512) == b"AB"


def test_clamped_reader_construction_failure_never_raises():
    """clamped_reader(mf) itself must not propagate an exception even
    when building the bound reader fails -- the whole point of this
    primitive is "hand back bytes, never an exception", and that
    guarantee has to cover construction, not just each individual read."""
    mf = FakeMF()
    mf.get_reader = lambda: (_ for _ in ()).throw(Exception("reader unavailable"))

    read = clamped_reader(mf)   # must not raise
    assert read(0x1000, 512) == b""
    assert read(0x9999, 4) == b""


def test_clamped_reader_reuses_one_buffered_reader_across_calls():
    mf = _mf_with_memory({0x1000: b"AB", 0x2000: b"CD"})
    get_reader_calls = []
    real_get_reader = mf.get_reader
    mf.get_reader = lambda: (get_reader_calls.append(1), real_get_reader())[1]

    read = clamped_reader(mf)
    read(0x1000, 2)
    read(0x2000, 2)
    read(0x1000, 2)
    assert len(get_reader_calls) == 1


def test_read_region_clamped_one_shot_matches_clamped_reader():
    mf = _mf_with_memory({0x1000: b"KERNEL32.dll\x00"})
    assert read_region_clamped(mf, 0x1000, 512) == b"KERNEL32.dll\x00"
    assert read_region_clamped(mf, 0x9000, 512) == b""


# ── read_region_spanning() (issue #40) ────────────────────────────────────
# Walks across CONTIGUOUS segments -- the boundary va_range_captured_
# bytes() computes -- unlike read_region()/clamped_reader(), which only
# ever read through whichever ONE segment reader.move() first landed on.

def test_read_region_spanning_reads_within_a_single_segment_like_read_region():
    mf = _mf_with_memory({0x1000: b"KERNEL32.dll\x00"})
    assert read_region_spanning(mf, 0x1000, 13) == b"KERNEL32.dll\x00"


def test_read_region_spanning_recovers_a_read_split_across_two_contiguous_segments():
    # The exact layout that broke a naive read_region(mf, addr,
    # va_range_captured_bytes(mf, addr, size)) combination: two segments,
    # back to back with no gap, each holding half of what is logically
    # one contiguous structure.
    mf = _mf_with_memory({0x1000: b"ABCD", 0x1004: b"EFGH"})
    assert read_region_spanning(mf, 0x1000, 8) == b"ABCDEFGH"


def test_read_region_spanning_recovers_a_read_split_across_three_segments():
    mf = _mf_with_memory({0x1000: b"AB", 0x1002: b"CD", 0x1004: b"EF"})
    assert read_region_spanning(mf, 0x1000, 6) == b"ABCDEF"


def test_read_region_spanning_stops_at_a_genuine_gap_between_segments():
    # 0x1002..0x1010 is NOT captured -- the second segment is not
    # contiguous with the first, so the read must stop at the true end of
    # what was actually captured, not silently skip the gap.
    mf = _mf_with_memory({0x1000: b"AB", 0x1010: b"CD"})
    assert read_region_spanning(mf, 0x1000, 8) == b"AB"


def test_read_region_spanning_returns_empty_bytes_when_nothing_captured():
    mf = _mf_with_memory({0x1000: b"AB"})
    assert read_region_spanning(mf, 0x9000, 8) == b""


def test_read_region_spanning_zero_for_zero_or_negative_size():
    mf = _mf_with_memory({0x1000: b"AB"})
    assert read_region_spanning(mf, 0x1000, 0) == b""
    assert read_region_spanning(mf, 0x1000, -1) == b""


def test_read_region_spanning_never_raises_when_get_reader_fails():
    mf = FakeMF()
    mf.get_reader = lambda: (_ for _ in ()).throw(Exception("reader unavailable"))
    assert read_region_spanning(mf, 0x1000, 8) == b""


# ── has_stream_directory (issue #42 §5.5 case 1 vs case 2) ───────────────
# mf.<stream> is None both for "never captured" and for "captured, but its
# parse raised" -- the directory table is the only place those two are
# still distinguishable once open_dump() has run.

class _Dir:
    def __init__(self, stream_type):
        self.StreamType = stream_type


def test_has_stream_directory_true_when_the_dump_declares_the_stream():
    mf = FakeMF()
    mf.directories = [_Dir(MINIDUMP_STREAM_TYPE.ThreadListStream),
                       _Dir(MINIDUMP_STREAM_TYPE.HandleDataStream)]
    assert has_stream_directory(mf, MINIDUMP_STREAM_TYPE.HandleDataStream) is True


def test_has_stream_directory_false_when_another_stream_is_declared():
    mf = FakeMF()
    mf.directories = [_Dir(MINIDUMP_STREAM_TYPE.ThreadListStream)]
    assert has_stream_directory(mf, MINIDUMP_STREAM_TYPE.HandleDataStream) is False


def test_has_stream_directory_is_independent_of_whether_the_parse_succeeded():
    # The whole point: a declared stream stays declared after its parser
    # raised and left mf.handles at None.
    mf = FakeMF()
    mf.directories = [_Dir(MINIDUMP_STREAM_TYPE.HandleDataStream)]
    mf.handles = None
    mf._dumpex_stream_failures = {MINIDUMP_STREAM_TYPE.HandleDataStream: "boom"}
    assert has_stream_directory(mf, MINIDUMP_STREAM_TYPE.HandleDataStream) is True


def test_has_stream_directory_tolerates_a_dump_object_without_directories():
    # A test/fixture-built mf that never went through open_dump() has no
    # directories list at all -- treated as declaring nothing, never an
    # AttributeError, matching stream_failure()'s own tolerance.
    assert has_stream_directory(FakeMF(), MINIDUMP_STREAM_TYPE.HandleDataStream) is False


# ── The one reader of header.NumberOfDescriptors ─────────────────────────
# `--handles`, `--profile` and `--hunt pipe` all describe the same
# truncated stream from these two functions, so one dump cannot be
# reported three different ways in one case file.

def _stream(handles, declared=None):
    return FakeStream(handles, "handles", declared=declared)


@pytest.mark.parametrize("parsed, expected", [
    (None, 0),                                              # no stream at all
    (_stream([Handle(0x1, "File", "x")], declared=False), 0),   # no usable declared count
    (_stream([], declared=0), 0),                            # declared none, delivered none
    (_stream([Handle(0x1, "File", "x")], declared=1), 0),    # delivered what it declared
    (_stream([Handle(0x1, "File", "x")], declared=9), 8),
    (_stream([], declared=3), 3),                            # array cut off entirely
    # More delivered than declared is a contradiction in the dump's own
    # numbers, not a negative shortfall: no descriptor is missing.
    (_stream([Handle(0x10 * (i + 1), "File", "x") for i in range(4)], declared=2), 0),
])
def test_truncated_descriptor_count_never_invents_a_gap(parsed, expected):
    assert truncated_descriptor_count(parsed) == expected


def test_truncated_descriptor_count_over_a_really_truncated_file():
    """The real parser, over a stream whose framing claims room for five
    descriptors while the file only ever held two -- the shape where
    reading the shortfall off the header and recomputing it from the
    framing disagree (3 versus 0)."""
    parsed = parsed_handle_stream([{"handle": 0x10 * (i + 1)} for i in range(2)],
                                   number_of_descriptors=5,
                                   declared_data_size=16 + 5 * 32)
    assert (parsed.header.NumberOfDescriptors, len(parsed.handles)) == (5, 2)
    assert truncated_descriptor_count(parsed) == 3


@pytest.mark.parametrize("declared", [True, "4", 4.0, None, -1])
def test_a_declared_count_that_is_not_a_count_states_nothing(declared):
    """A declared count that is not usable as one says nothing about how
    many descriptors the stream holds, and a fabricated number would be
    worse than none -- `bool` included, since it is an int subclass and a
    stray boolean there is a parse bug, not 0 or 1. Mirrors how
    parse_handle_stream itself treats those values when it bounds its own
    read."""
    parsed = _stream([Handle(0x1, "File", "x")], declared=declared)
    assert declared_descriptor_count(parsed) is None
    assert truncated_descriptor_count(parsed) == 0


@pytest.mark.parametrize("parsed", [
    types.SimpleNamespace(handles=[]),                                   # no .header
    types.SimpleNamespace(header=types.SimpleNamespace(), handles=[]),    # header, no count
])
def test_a_stream_shape_the_parser_no_longer_produces_fails_loudly(parsed):
    """A renamed attribute or a changed return shape must not degrade into
    "0 declared, so nothing was truncated": that answer is
    indistinguishable from a complete stream, which is the silent clean
    result the truncation limitation exists to prevent."""
    with pytest.raises(HandleStreamContractError):
        truncated_descriptor_count(parsed)


def test_a_stream_missing_only_its_handles_list_also_fails_loudly():
    parsed = types.SimpleNamespace(header=types.SimpleNamespace(NumberOfDescriptors=3))
    with pytest.raises(HandleStreamContractError):
        truncated_descriptor_count(parsed)


# ── The one discriminator of the handle stream's three states ────────────

def test_handle_stream_evidence_tells_never_captured_from_unparseable():
    absent = mf_with_handle_stream()
    parsed = mf_with_handle_stream(parsed=parsed_handle_stream([{"handle": 0x10}]))
    failed = mf_with_handle_stream(failure="SizeOfHeader 4 is out of bounds")

    assert handle_stream_evidence(absent) == ("absent", None, None)
    assert handle_stream_evidence(parsed)[0] == "parsed"
    assert handle_stream_evidence(failed) == (
        "failed", None, "SizeOfHeader 4 is out of bounds")


def test_a_declared_stream_that_never_arrived_is_failed_not_absent():
    """A directory entry with neither a parsed stream nor a recorded
    failure means the stream was captured but never reached the loader.
    Unreachable through today's open_dump(), and it fails closed toward
    the honest answer: the dump HAS handle data, so telling an analyst to
    re-collect with it would be wrong."""
    mf = mf_with_handle_stream(has_directory=True)
    state, parsed, detail = handle_stream_evidence(mf)
    assert (state, parsed) == ("failed", None)
    assert "no parsed stream is available" in detail

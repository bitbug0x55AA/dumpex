"""
Unit tests for dumpex.core.memory.open_dump() -- corrupted/malformed dump
handling.

A missing file already exited cleanly with a "File not found" message.
A file that EXISTS but isn't a valid minidump (corrupted, truncated,
or just not a .dmp at all) previously propagated whatever internal
exception the minidump library happened to raise as a raw, unhandled
traceback all the way up through cli.main() -- an analyst feeding
dumpex bad evidence deserves the same clean refusal as the missing-file
case, not an implementation-detail stack trace.
"""
import struct
import time

import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE

import dumpex.core.memory as dumpex_memory
from dumpex.core.memory import open_dump


def _build_minidump(stream_types: "list[int]", flags: int = 0,
                     declared_count: "int | None" = None) -> bytes:
    """The minimum real MINIDUMP_HEADER (32 bytes: sig+ver+implver+
    numstreams+streamdirrva+checksum+union+flags -- see dumpex.core.
    memory._correct_header_union's own docstring for the exact layout)
    plus a flat directory table (12 bytes/entry: StreamType(4) + Location
    (DataSize(4)+Rva(4))) and one zero-length data blob per stream --
    just enough bytes for open_dump()'s own Phase 1 walk to run over a
    caller-chosen list of raw StreamType values, some of which may not be
    real MINIDUMP_STREAM_TYPE members at all.

    `declared_count` (default: `len(stream_types)`, i.e. the header's own
    NumberOfStreams matches what the file actually holds) lets a caller
    declare MORE entries than the file's directory table actually backs
    -- the exact "attacker-controlled NumberOfStreams vs. the file's real
    size" mismatch dumpex.core.memory.open_dump()'s own file-size bound
    (§2.5 of docs/developer/recon_profile_contract.md) exists to guard against."""
    n = len(stream_types)
    header_size = 32
    dir_rva = header_size
    dir_size = n * 12
    data_rva = dir_rva + dir_size

    header = (b"MDMP" + struct.pack("<HH", 1, 1)
              + struct.pack("<I", declared_count if declared_count is not None else n)
              + struct.pack("<I", dir_rva) + struct.pack("<I", 0) + struct.pack("<I", 0)
              + struct.pack("<Q", flags))
    directory = b"".join(struct.pack("<III", stype, 0, data_rva) for stype in stream_types)
    return header + directory


def test_missing_file_exits_1_with_clean_message(capsys):
    with pytest.raises(SystemExit) as exc:
        open_dump("/definitely_does_not_exist_dumpex_test.dmp")
    assert exc.value.code == 1
    assert "File not found" in capsys.readouterr().out


def test_corrupted_file_exits_cleanly_instead_of_raw_traceback(tmp_path, capsys):
    bogus = tmp_path / "garbage.dmp"
    bogus.write_bytes(b"NOT A REAL MINIDUMP FILE" * 100)

    with pytest.raises(SystemExit) as exc:
        open_dump(str(bogus))

    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Could not parse" in out
    assert str(bogus) in out


def test_empty_file_exits_cleanly(tmp_path, capsys):
    empty = tmp_path / "empty.dmp"
    empty.write_bytes(b"")

    with pytest.raises(SystemExit) as exc:
        open_dump(str(empty))

    assert exc.value.code == 1
    assert "Could not parse" in capsys.readouterr().out


# ── Unrecognized directory StreamType values (issue #95) ────────────────
# The installed minidump library's own MINIDUMP_DIRECTORY.parse() special-
# cases exactly one unrecognized-StreamType shape: a value > LastReserved
# Stream (0xFFFF), a real Microsoft MINIDUMP_USER_STREAM, is silently
# DROPPED (not even its Location is read), matching Microsoft's own
# documented "tools that don't understand it should ignore it" guidance.
# Any OTHER raw value that is not one of MINIDUMP_STREAM_TYPE's ~30 named
# members -- a gap value like 9999, reachable from a fuzzed/vendor-
# specific/corrupted dump -- used to raise ValueError() INSIDE that
# library call, uncaught, aborting open_dump()'s entire Phase 1
# try/except with exit(1): a dump that may otherwise be perfectly
# analyzable, refused outright, for every dumpex command, not just
# --profile. dumpex.core.memory._parse_directory_entry() closes that gap
# -- and, since issue #95's own acceptance criteria make no exception for
# the >0xFFFF range either ("preserve unknown stream-type IDs rather than
# silently dropping them"), does NOT reproduce the upstream drop: a real
# MINIDUMP_USER_STREAM is preserved as its own row too, same as any other
# unrecognized type. These tests are the regression guard for both.

def test_unrecognized_stream_type_no_longer_crashes_the_whole_dump_open(tmp_path):
    data = _build_minidump([MINIDUMP_STREAM_TYPE.SystemInfoStream.value, 9999,
                             MINIDUMP_STREAM_TYPE.HandleDataStream.value])
    dump = tmp_path / "unknown_stream.dmp"
    dump.write_bytes(data)

    mf = open_dump(str(dump))

    stream_type_values = [
        d.StreamType.value if isinstance(d.StreamType, MINIDUMP_STREAM_TYPE) else d.StreamType
        for d in mf.directories]
    assert stream_type_values == [MINIDUMP_STREAM_TYPE.SystemInfoStream.value, 9999,
                                    MINIDUMP_STREAM_TYPE.HandleDataStream.value]
    # The unrecognized entry's own StreamType is the raw int itself, never
    # coerced into (or silently dropped as) a MINIDUMP_STREAM_TYPE member.
    unknown_entry = mf.directories[1]
    assert unknown_entry.StreamType == 9999
    assert not isinstance(unknown_entry.StreamType, MINIDUMP_STREAM_TYPE)


def test_unrecognized_stream_types_location_is_still_parsed(tmp_path):
    """The fallback must still consume/parse the entry's own Location
    (Rva/DataSize) rather than leaving the directory walk's file position
    wrong for whatever comes next -- open_dump() reseeks per-entry, so a
    wrong position here would only ever surface as a wrong Location on
    THIS entry, which this test checks directly."""
    data = _build_minidump([9999])
    dump = tmp_path / "unknown_only.dmp"
    dump.write_bytes(data)

    mf = open_dump(str(dump))

    assert len(mf.directories) == 1
    assert mf.directories[0].Location is not None
    assert mf.directories[0].Location.DataSize == 0


def test_real_user_stream_above_0xffff_is_preserved_not_dropped(tmp_path):
    """Deliberately DIFFERENT from the upstream library's own
    MINIDUMP_DIRECTORY.parse(), which silently drops a real Microsoft
    MINIDUMP_USER_STREAM (> LastReservedStream) without even reading its
    Location. Issue #95's own acceptance criteria make no exception for
    that range ("Every directory entry is represented, including unknown
    and duplicate stream types" / "preserve unknown stream-type IDs
    rather than silently dropping them"), so dumpex.core.memory.
    _parse_directory_entry() preserves it as its own inventory row
    instead, same as any other unrecognized StreamType."""
    data = _build_minidump([MINIDUMP_STREAM_TYPE.SystemInfoStream.value, 0x10000])
    dump = tmp_path / "user_stream.dmp"
    dump.write_bytes(data)

    mf = open_dump(str(dump))

    assert len(mf.directories) == 2
    assert mf.directories[0].StreamType == MINIDUMP_STREAM_TYPE.SystemInfoStream
    assert mf.directories[1].StreamType == 0x10000
    assert not isinstance(mf.directories[1].StreamType, MINIDUMP_STREAM_TYPE)


def test_duplicate_stream_type_entries_do_not_crash_open_dump(tmp_path):
    data = _build_minidump([MINIDUMP_STREAM_TYPE.ModuleListStream.value,
                             MINIDUMP_STREAM_TYPE.ModuleListStream.value])
    dump = tmp_path / "duplicate_stream.dmp"
    dump.write_bytes(data)

    mf = open_dump(str(dump))

    assert len(mf.directories) == 2
    assert all(d.StreamType == MINIDUMP_STREAM_TYPE.ModuleListStream for d in mf.directories)


# ── open_dump()'s own file-size bound (§2.5) -- real files, not a
# hand-set FakeMF attribute, driving through open_dump() end to end. This
# is the highest-risk new code in the whole change (it prevents a tiny
# crafted file from fabricating hundreds of thousands of directory
# entries and burning real CPU/memory), so it gets its own dedicated
# regression tests rather than relying solely on --profile's own
# collector-level test that sets `mf._dumpex_directory_truncated_count`
# directly on a FakeMF.

def test_header_only_file_with_huge_declared_count_completes_instantly(tmp_path):
    data = _build_minidump([], declared_count=10_000_000)
    dump = tmp_path / "huge_declared_count.dmp"
    dump.write_bytes(data)

    start = time.monotonic()
    mf = open_dump(str(dump))
    elapsed = time.monotonic() - start

    assert len(mf.directories) == 0
    assert dumpex_memory.directory_truncated_count(mf) == 10_000_000
    assert elapsed < 1.0   # a 32-byte file must never cost real wall-clock time


def test_partial_directory_table_reads_exactly_what_the_file_holds(tmp_path):
    """The realistic truncated-transfer scenario: the file genuinely
    holds 3 directory entries' worth of bytes but its own header claims
    10 -- the 3 that ARE there must be fully, correctly inventoried, and
    the shortfall (7) reported, never silently dropped or fabricated."""
    data = _build_minidump(
        [MINIDUMP_STREAM_TYPE.SystemInfoStream.value, MINIDUMP_STREAM_TYPE.ModuleListStream.value,
         MINIDUMP_STREAM_TYPE.HandleDataStream.value], declared_count=10)
    dump = tmp_path / "partial_directory.dmp"
    dump.write_bytes(data)

    mf = open_dump(str(dump))

    assert len(mf.directories) == 3
    assert [d.StreamType for d in mf.directories] == [
        MINIDUMP_STREAM_TYPE.SystemInfoStream, MINIDUMP_STREAM_TYPE.ModuleListStream,
        MINIDUMP_STREAM_TYPE.HandleDataStream]
    assert dumpex_memory.directory_truncated_count(mf) == 7
    assert mf.header.NumberOfStreams == len(mf.directories) + dumpex_memory.directory_truncated_count(mf)


def test_stream_directory_rva_past_eof_reads_zero_entries(tmp_path):
    """StreamDirectoryRva itself pointing past the end of the file (a
    corrupt/adversarial header, distinct from NumberOfStreams simply
    being too large for an otherwise-normal layout) must not underflow
    the file-size bound into a negative-turned-huge unsigned count or
    raise -- zero readable entries, the full declared count reported as
    the shortfall."""
    data = _build_minidump([MINIDUMP_STREAM_TYPE.SystemInfoStream.value])
    # Overwrite StreamDirectoryRva (header bytes 12-15: sig(4) + Version(2)
    # + ImplementationVersion(2) + NumberOfStreams(4) = offset 12) to
    # point past EOF.
    data = bytearray(data)
    struct.pack_into("<I", data, 12, len(data) + 1000)
    dump = tmp_path / "rva_past_eof.dmp"
    dump.write_bytes(bytes(data))

    mf = open_dump(str(dump))

    assert len(mf.directories) == 0
    assert dumpex_memory.directory_truncated_count(mf) == mf.header.NumberOfStreams == 1


def test_declared_plus_truncated_always_equals_number_of_streams(tmp_path):
    """The reconciliation invariant every other test in this section
    relies on, asserted directly and generically: however many entries
    open_dump() actually inventories, that count plus the reported
    shortfall must reproduce the header's own declared NumberOfStreams
    exactly -- nothing is ever double-counted or silently lost between
    the two."""
    for declared, actual in [(0, 0), (1, 1), (5, 2), (100, 0)]:
        stream_types = [MINIDUMP_STREAM_TYPE.SystemInfoStream.value] * actual
        data = _build_minidump(stream_types, declared_count=declared)
        dump = tmp_path / f"reconcile_{declared}_{actual}.dmp"
        dump.write_bytes(data)

        mf = open_dump(str(dump))

        assert len(mf.directories) + dumpex_memory.directory_truncated_count(mf) == declared

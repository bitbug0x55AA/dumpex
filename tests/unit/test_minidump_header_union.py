"""Unit tests for dumpex.core.memory._correct_header_union() -- the
MINIDUMP_HEADER fields open_dump() has to re-read off the file itself.

The real MINIDUMP_HEADER declares Reserved/TimeDateStamp as a UNION (one
UINT32 at offset 0x14) followed by a ULONG64 Flags. The installed minidump
library reads that as three separate UINT32s, which still totals the same
32 bytes -- so the parse succeeds, the signature check passes, and nothing
raises -- while shifting every field from 0x14 on by one slot:
`header.TimeDateStamp` ends up holding Flags's low 32 bits. Uncorrected,
--sysinfo's `dump_time_utc` (§4.2.2) rendered a dump's TYPE FLAGS as epoch
seconds: a constant 1970 date, identical across every dump from the same
producer, presented as the moment the dump was written.

These tests drive the REAL byte-level parse (open_dump() on a real file),
not a fake header object: a test double with `TimeDateStamp` assigned
directly -- which is what the existing --sysinfo unit tests use, and
rightly so for what they assert -- cannot see a field-offset bug at all,
which is exactly why this one went unnoticed.
"""
import struct

import pytest

from minidump.header import MinidumpHeader

from dumpex.commands.sysinfo import collect_sysinfo
from dumpex.core.memory import open_dump


# A plausible real dump timestamp (2025-11-05 01:14:37 UTC) and a
# plausible real MINIDUMP_TYPE mask, deliberately chosen so that
# misreading the mask AS the timestamp produces the exact symptom this
# fix-up exists for: 0x00241826 seconds after the epoch is 1970-01-28.
REAL_TIME_DATE_STAMP = 0x690AA4FD
REAL_FLAGS           = 0x0000000000241826


def _minidump_bytes(time_date_stamp=REAL_TIME_DATE_STAMP, flags=REAL_FLAGS,
                    number_of_streams=0):
    """A 32-byte MINIDUMP_HEADER laid out the way dbghelp.h actually
    defines it -- the union at 0x14, a ULONG64 Flags at 0x18 -- with no
    streams, since every field under test lives in the header itself."""
    return (b"MDMP"
            + struct.pack("<H", 42899)                # Version
            + struct.pack("<H", 0)                    # ImplementationVersion
            + struct.pack("<I", number_of_streams)
            + struct.pack("<I", 32)                   # StreamDirectoryRva
            + struct.pack("<I", 0)                    # CheckSum
            + struct.pack("<I", time_date_stamp)      # 0x14: the union
            + struct.pack("<Q", flags))               # 0x18: ULONG64 Flags


def _write(tmp_path, data, name="header.dmp"):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_time_date_stamp_is_the_dumps_own_timestamp_not_its_type_flags(tmp_path):
    mf = open_dump(_write(tmp_path, _minidump_bytes()))
    assert mf.header.TimeDateStamp == REAL_TIME_DATE_STAMP


def test_reserved_holds_the_same_value_because_it_is_the_same_union(tmp_path):
    # Not "TimeDateStamp copied into Reserved": the two names describe one
    # UINT32. A reader who reaches for either must get the same bytes.
    mf = open_dump(_write(tmp_path, _minidump_bytes()))
    assert mf.header.Reserved == mf.header.TimeDateStamp == REAL_TIME_DATE_STAMP


def test_flags_is_the_full_64_bit_field_not_its_high_dword(tmp_path):
    # Uncorrected, this was the dword at 0x1C -- 0 for every currently
    # defined MINIDUMP_TYPE bit, so "no flags at all" for every real dump.
    mf = open_dump(_write(tmp_path, _minidump_bytes()))
    assert int(mf.header.Flags) == REAL_FLAGS


def test_flags_with_bits_no_enum_member_covers_is_kept_as_its_raw_value(tmp_path):
    # A mask carrying bits outside MINIDUMP_TYPE (a newer dbghelp, or a
    # non-Microsoft producer) must not cost the analyst the header: the
    # raw value survives, decoded or not.
    unknown = 0x8000_0000_0000_0001
    mf = open_dump(_write(tmp_path, _minidump_bytes(flags=unknown)))
    assert int(mf.header.Flags) == unknown


def test_sysinfo_dump_time_reports_the_real_dump_time(tmp_path):
    # The end the whole fix-up exists for (§4.2.2), through the real
    # command path rather than the header alone.
    mf = open_dump(_write(tmp_path, _minidump_bytes()))
    assert collect_sysinfo(mf).records[0].dump_time_utc == "2025-11-05 01:14:37 UTC"


def test_an_unset_time_date_stamp_still_reports_no_dump_time(tmp_path):
    # 0 means "the producer never filled the field in" and must stay
    # unavailable evidence -- the fix-up must not turn it into 1970-01-01.
    mf = open_dump(_write(tmp_path, _minidump_bytes(time_date_stamp=0)))
    assert mf.header.TimeDateStamp == 0
    assert collect_sysinfo(mf).records[0].dump_time_utc is None


@pytest.mark.parametrize("kept_bytes", [20, 23])
def test_a_header_truncated_before_the_union_reports_no_dump_time(
        tmp_path, kept_bytes):
    # A file truncated INSIDE the header still parses upstream
    # (int.from_bytes(b'') is 0), so "the header parsed" is no proof that
    # the union's four bytes were there to re-read. A short read must
    # neither raise nor leave the shifted upstream value in place -- the
    # timestamp is simply unavailable.
    path = _write(tmp_path, _minidump_bytes()[:kept_bytes], name="short.dmp")
    mf = open_dump(path)   # must not raise / SystemExit
    assert mf.header.TimeDateStamp == 0
    assert mf.header.Flags is None
    assert collect_sysinfo(mf).records[0].dump_time_utc is None


@pytest.mark.parametrize("kept_bytes", [24, 31])
def test_a_header_truncated_inside_flags_still_reports_the_dump_time(
        tmp_path, kept_bytes):
    # The two fields are independent: the union's own bytes are all here,
    # so the timestamp is real evidence and must be reported. Only Flags
    # -- whose eight bytes are not all present -- goes unset.
    path = _write(tmp_path, _minidump_bytes()[:kept_bytes], name="no-flags.dmp")
    mf = open_dump(path)

    assert mf.header.TimeDateStamp == REAL_TIME_DATE_STAMP
    assert mf.header.Flags is None
    assert collect_sysinfo(mf).records[0].dump_time_utc == "2025-11-05 01:14:37 UTC"


def test_the_installed_library_still_misreads_the_union(tmp_path):
    # Freezes the upstream behavior _correct_header_union() compensates
    # for (minidump is pinned to one release -- see
    # tests/unit/test_minidump_version_pin.py). The fix-up re-reads the
    # bytes itself and stays correct either way, so this failing is not a
    # defect: it means a newer library parses the union correctly and the
    # fix-up has become redundant rather than load-bearing.
    with open(_write(tmp_path, _minidump_bytes()), "rb") as fh:
        header = MinidumpHeader.parse(fh)
    assert header.TimeDateStamp == REAL_FLAGS & 0xFFFFFFFF
    assert header.Reserved == REAL_TIME_DATE_STAMP

"""Hunter-level tests for dumpex.hunt.cs_beacon (Cobalt Strike beacon config)."""
import struct

import pytest

from tests.fixtures.fakes import (Region, Segment, FakeReader, FakeStream, FakeMF,
                                   cs_beacon_config_bytes)

import dumpex.hunt.cs_beacon as cs_beacon
import dumpex.hunt.cs_beacon.parser as parser
import dumpex.hunt.cs_beacon.der as cs_der
import dumpex.hunt.cs_beacon.report_console as report_console


def _mk_segment_data(config_bytes: bytes, pad_before: int = 0x100, pad_after: int = 0x100) -> bytes:
    return b'\x00' * pad_before + config_bytes + b'\x00' * pad_after


def _tlv(fid, ftype, raw):
    return struct.pack('>HHH', fid, ftype, len(raw)) + raw


# ── no memory segments at all -> NOT_EVALUATED, never a bare CLEAN ────────

def test_no_memory_segments_not_evaluated():
    class MF(FakeMF):
        memory_segments_64 = None
        memory_segments      = None

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_EVALUATED"
    assert f["verdict_level"] == "not_evaluated"


# ── segments present, nothing found -> NOT_DETECTED_IN_SCANNED_SCOPE ──────

def test_clean_scan_no_hits():
    seg_va, seg_fo = 0x10000, 0x1000
    data = b'\x00' * 0x2000
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["verdict_level"] == "clean"
    assert f["coverage_status"] == "complete"


# ── missing MemoryInfoListStream must not pretend full verification even ──
# on an otherwise-clean (no hits) result -- region/context corroboration
# could not be checked, so this must be INCONCLUSIVE, not "clean".

def test_missing_mem_info_makes_coverage_partial_even_when_clean():
    seg_va, seg_fo = 0x10000, 0x1000
    data = b'\x00' * 0x2000
    seg = Segment(seg_va, seg_fo, len(data))

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = None   # stream ABSENT
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["verdict_level"] == "inconclusive"
    assert f["coverage_status"] == "partial"
    assert any("MemoryInfoListStream" in r for r in f["coverage_reasons"])


# ── a single structurally-valid config, no context corroboration -> 1 ─────

def test_structural_config_uncorroborated_scores_1():
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    # Ordinary, non-executable, non-private region -> no corroboration signal.
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        threads               = None
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 1
    assert f["max_score"] == 2
    assert f["status"] == "DETECTED"
    assert f["verdict_level"] == "likely"
    assert f["config_count"] == 1
    assert len(f["configs"]) == 1
    assert f["configs"][0]["context_corroborated"] is False
    assert f["configs"][0]["cs_version_note"]   # estimated, not confirmed
    dets = [x for x in f["findings"] if x["tag"] == "detection"]
    assert len(dets) == 1
    assert dets[0]["confidence"] == "medium"
    # ThreadListStream is absent here (FakeMF default) and the hit isn't
    # corroborated by region protection either -- RIP/EIP corroboration
    # could not be ruled out, so this is a real coverage gap for the top
    # tier, not just "checked, found nothing more".
    assert f["coverage"]["thread_list_stream"] is False
    assert f["coverage_status"] == "partial"
    assert any("ThreadListStream" in r for r in f["coverage_reasons"])
    assert any("live-execution corroboration" in lim for lim in dets[0]["limitations"])


# ── a structurally-valid config whose fid=0 terminator sits at the exact ──
# end of the segment, with no trailing padding, must still be detected —
# not silently lost to the "terminator needs 6 bytes available" bug.

def test_structural_config_with_terminator_at_segment_end_is_detected():
    seg_va, seg_fo = 0x21000, 0x2100
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config, pad_before=0x100, pad_after=0)   # nothing after the terminator
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert f["config_count"] == 1


# ── same uncorroborated scenario, but with a ThreadListStream that only ───
# partially parsed (some threads have CONTEXT, some don't) -- the explicit
# threads_total/contexts_parsed/contexts_missing counts must reflect the
# partial gap, not just a blanket "stream missing".

def test_partial_thread_contexts_with_uncorroborated_hit_is_coverage_partial():
    seg_va, seg_fo = 0x25000, 0x2500
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        threads               = FakeStream([object(), object()], "threads")   # 2 threads total
        _reader                = FakeReader({seg_va: data})
    cs_beacon.get_thread_contexts = lambda mf: []   # 0 parsed -- 2/2 missing

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 1
    assert f["coverage_status"] == "partial"
    assert f["coverage"]["threads_total"]    == 2
    assert f["coverage"]["contexts_missing"] == 2
    assert any("2/2 thread" in r for r in f["coverage_reasons"])


# ── same config, but enclosing region is executable+private -> 2 ──────────

def test_executable_private_region_corroborates_scores_2():
    seg_va, seg_fo = 0x30000, 0x3000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 2
    assert f["verdict_level"] == "high"
    assert f["configs"][0]["context_corroborated"] is True
    dets = [x for x in f["findings"] if x["tag"] == "detection"]
    assert dets[0]["confidence"] == "high"
    # ThreadListStream is ALSO absent here (FakeMF default), but region
    # protection alone already reached the top tier -- RIP/EIP coverage
    # was never actually needed for this result, so it must not be
    # penalized as a coverage gap.
    assert f["coverage"]["thread_list_stream"] is False
    assert f["coverage_status"] == "complete"
    assert not any("ThreadListStream" in r for r in f["coverage_reasons"])


# ── a thread's current RIP executing in the same allocation also ──────────
# corroborates (not just region protection) -----------------------------

def test_rip_in_same_allocation_corroborates_scores_2():
    seg_va, seg_fo = 0x40000, 0x4000
    config = cs_beacon_config_bytes(0x69)
    pad_before = 0x100
    data = _mk_segment_data(config, pad_before=pad_before)
    seg = Segment(seg_va, seg_fo, len(data))
    # Region is ordinary (RW) -- corroboration must come from the RIP hit,
    # not region protection.
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        threads               = FakeStream([object()], "threads")   # presence only
        _reader                = FakeReader({seg_va: data})

    cs_beacon.get_thread_contexts = lambda mf: [
        {"ThreadId": 7, "ip": seg_va + 10, "ip_reg": "RIP", "is_wow64": False}
    ]
    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)

    assert f["score"] == 2
    assert f["configs"][0]["context_corroborated"] is True


# ── multiple DISTINCT hits, none corroborated -> score stays 1, never ─────
# auto-escalates from the count alone (config_count is a fact, not a
# confidence multiplier).

def test_multiple_uncorroborated_hits_stay_at_score_1():
    seg1_va, seg1_fo = 0x50000, 0x5000
    seg2_va, seg2_fo = 0x60000, 0x6000
    config1 = cs_beacon_config_bytes(0x69)
    config2 = cs_beacon_config_bytes(0x2e)
    data1 = _mk_segment_data(config1)
    data2 = _mk_segment_data(config2)
    seg1 = Segment(seg1_va, seg1_fo, len(data1))
    seg2 = Segment(seg2_va, seg2_fo, len(data2))
    regions = [
        Region(seg1_va, seg1_va, len(data1), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(seg2_va, seg2_va, len(data2), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg1, seg2], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg1_va: data1, seg2_va: data2})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["config_count"] == 2
    assert len(f["configs"]) == 2
    assert f["score"] == 1, "two distinct uncorroborated hits must not escalate to 2"
    assert f["verdict_level"] == "likely"


def test_console_pairs_each_config_block_with_its_own_finding(capsys):
    """Console output association test: "Beacon config #1"'s own printed
    block (VA/file offset/region/... plus its cs_beacon.structural_config
    Finding narrative) must contain config #1's VA and NOT config #2's --
    guards against the zip()-based pairing in presentation.py silently
    matching a config to the wrong Finding (or the right count but wrong
    order) when aggregate.py's hit_records/findings_list ordering ever
    drifts apart."""
    seg1_va, seg1_fo = 0x50000, 0x5000
    seg2_va, seg2_fo = 0x60000, 0x6000
    config1 = cs_beacon_config_bytes(0x69)
    config2 = cs_beacon_config_bytes(0x2e)
    data1 = _mk_segment_data(config1)
    data2 = _mk_segment_data(config2)
    seg1 = Segment(seg1_va, seg1_fo, len(data1))
    seg2 = Segment(seg2_va, seg2_fo, len(data2))
    regions = [
        Region(seg1_va, seg1_va, len(data1), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(seg2_va, seg2_va, len(data2), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg1, seg2], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg1_va: data1, seg2_va: data2})

    cs_beacon._hunt_cs_beacon(MF(), verbose=True)
    out = capsys.readouterr().out

    assert "COBALT STRIKE — 2 beacon config(s)" in out
    block1 = out.split("Beacon config #1", 1)[1].split("Beacon config #2", 1)[0]
    block2 = out.split("Beacon config #2", 1)[1]

    # Every fact/header line in a config's own block is built relative to
    # its segment's own VA (the hit is at some offset inside it) -- assert
    # on that segment VA, present in both hex-padding styles the render
    # path uses (zero-padded for the header table, un-padded in facts).
    assert f"0x{seg1_va:016x}" in block1 or f"0x{seg1_va:x}" in block1
    assert f"0x{seg2_va:016x}" not in block1 and f"0x{seg2_va:x}" not in block1
    assert f"0x{seg2_va:016x}" in block2 or f"0x{seg2_va:x}" in block2
    assert f"0x{seg1_va:016x}" not in block2 and f"0x{seg1_va:x}" not in block2


# ── --verbose Full Config Field Table: no hex-ID column, no value/raw ─────
# duplication for binary fields (console field-table patch, no schema impact)

def test_full_field_table_has_no_hex_id_column_and_has_type_column(capsys):
    seg_va, seg_fo = 0x90000, 0x9000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    cs_beacon._hunt_cs_beacon(MF(), verbose=True)
    out = capsys.readouterr().out

    table = out.split("Full Config Field Table", 1)[1]
    assert "Field" in table and "Type" in table and "Value" in table
    assert "0x0001" not in table and "0x0007" not in table
    assert "uint16" in table   # BeaconType's type, spelled out
    assert "bytes" in table    # PublicKey's type, spelled out
    # PublicKey (binary/non-printable) must show exactly one hex rendering,
    # not a decoded-text repr AND a separate bracketed raw preview.
    pubkey_line = next(l for l in table.splitlines() if "PublicKey" in l)
    assert pubkey_line.count("30") >= 1   # some hex is present
    assert "[" not in pubkey_line and "]" not in pubkey_line, (
        "no separate bracketed raw-hex preview alongside value")


def test_full_field_table_printable_field_preserves_repeated_whitespace(capsys):
    # Same whitespace-preservation guarantee as the Process Injection test
    # of the same name -- a printable type-3 field's value must render
    # VERBATIM in the field table too, not re-wrapped/re-joined in a way
    # that would collapse repeated spaces already present in the bytes.
    seg_va, seg_fo = 0x91000, 0x9100
    printable = b"alpha  beta   gamma"   # 2 and 3 consecutive spaces
    config = _config_with_extra_field(0x002e, 3, printable)   # ProcInject_Transform_x86
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    cs_beacon._hunt_cs_beacon(MF(), verbose=True)
    out = capsys.readouterr().out

    table = out.split("Full Config Field Table", 1)[1].split("Process Injection", 1)[0]
    field_line = next(l for l in table.splitlines() if "ProcInject_Transform_x86" in l)
    assert repr(printable.decode("ascii")) in field_line


def _config_with_extra_field(fid: int, ftype: int, value: bytes, xor_key: int = 0x69) -> bytes:
    """Splice one extra TLV field into an otherwise-valid (BeaconType +
    validated PublicKey + terminator) config -- a synthetic blob missing
    PublicKey never passes `_cs_sanity_check()`, so it would never reach
    `fields` as a scored hit at all."""
    base = cs_beacon_config_bytes(xor_key)
    decoded = bytes(b ^ xor_key for b in base)
    terminator = struct.pack('>H', 0)
    assert decoded.endswith(terminator)
    body = decoded[:-len(terminator)]
    extra = struct.pack('>HHH', fid, ftype, len(value)) + value
    plaintext = body + extra + terminator
    return bytes(b ^ xor_key for b in plaintext)


# ── Process Injection inline section shares _field_display_value() with ──
# the Full Config Field Table (same console patch) -- these pin its actual
# rendering, not just "it didn't crash", for the two ProcInject_Transform_x86/
# x64-style type-3 fields that section prints.

def test_process_injection_printable_transform_shows_repr_text(capsys):
    seg_va, seg_fo = 0xd0000, 0xd000
    printable = b"C:\\Windows\\System32\\svchost.exe"
    config = _config_with_extra_field(0x002e, 3, printable)   # ProcInject_Transform_x86
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    # Process Injection transforms are a --verbose-only expansion (issue #9
    # console scope) -- this section no longer renders in normal mode.
    cs_beacon._hunt_cs_beacon(MF(), verbose=True)
    out = capsys.readouterr().out

    section = out.split("Process Injection", 1)[1].split("Malleable C2", 1)[0]
    transform_line = next(l for l in section.splitlines() if "ProcInject_Transform_x86" in l)
    text_repr = repr(printable.decode("ascii"))
    assert text_repr in transform_line
    # repr() is the ONLY rendering -- not repr() alongside a separate,
    # un-repr'd copy of the same text (which would look like the quoted
    # text appearing, then the same content again unquoted).
    assert transform_line.count(text_repr) == 1
    assert transform_line.replace(text_repr, "", 1).count("svchost.exe") == 0


def test_process_injection_printable_transform_preserves_repeated_whitespace(capsys):
    # A printable type-3 field's value must render VERBATIM -- the
    # binary-hex wrapping this issue (#46) adds must never be reached for
    # text, and no other rewrap should collapse whitespace that was
    # actually present in the field's own bytes (`wrap_text()`'s
    # `text.split()`/`" ".join()` would silently turn "a  b" into "a b").
    seg_va, seg_fo = 0xd1000, 0xd100
    printable = b"alpha  beta   gamma"   # 2 and 3 consecutive spaces
    config = _config_with_extra_field(0x002e, 3, printable)   # ProcInject_Transform_x86
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    cs_beacon._hunt_cs_beacon(MF(), verbose=True)
    out = capsys.readouterr().out

    section = out.split("Process Injection", 1)[1].split("Malleable C2", 1)[0]
    transform_line = next(l for l in section.splitlines() if "ProcInject_Transform_x86" in l)
    assert repr(printable.decode("ascii")) in transform_line


def test_process_injection_binary_transform_shows_full_raw_hex_once_with_trailing_nul(capsys):
    seg_va, seg_fo = 0xe0000, 0xe000
    # Non-printable payload with trailing NUL padding -- the old
    # `(value or '').strip('\x00') or raw.hex()[:60]` logic would have
    # stripped the NUL bytes out of whatever little it showed; the new
    # shared renderer must show them (as part of the full raw hex).
    binary = bytes([0x01, 0x02, 0x03, 0xff, 0xfe]) + b"\x00\x00\x00"
    config = _config_with_extra_field(0x002f, 3, binary)   # ProcInject_Transform_x64
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    # Process Injection transforms are a --verbose-only expansion (issue #9
    # console scope) -- this section no longer renders in normal mode.
    cs_beacon._hunt_cs_beacon(MF(), verbose=True)
    out = capsys.readouterr().out

    section = out.split("Process Injection", 1)[1].split("Malleable C2", 1)[0]
    transform_line = next(l for l in section.splitlines() if "ProcInject_Transform_x64" in l)
    full_hex = binary.hex()   # includes the trailing NUL bytes, unstripped
    assert full_hex in transform_line
    assert transform_line.count(full_hex) == 1   # shown exactly once, no duplicate raw preview


def test_process_injection_long_binary_transform_wraps_without_truncating(capsys):
    # issue #46: this field used to be hard-truncated at 64 hex chars with
    # a trailing "..." -- even under --verbose, whose own hint text
    # promises "the complete field table". Use the same 40-byte
    # (80-hex-char) payload the old truncating behavior was pinned on, and
    # assert the COMPLETE value now survives -- wrapped across lines
    # (never split mid-byte), never shortened, no "..." marker anywhere.
    seg_va, seg_fo = 0xf0000, 0xf000
    binary = bytes(range(1, 41))   # 40 bytes, includes non-printable control
                                    # chars (0x01-0x08 etc.) -- guaranteed binary
    assert len(binary.hex()) == 80 > 64
    config = _config_with_extra_field(0x002f, 3, binary)   # ProcInject_Transform_x64
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    # Process Injection transforms are a --verbose-only expansion (issue #9
    # console scope) -- this section no longer renders in normal mode.
    cs_beacon._hunt_cs_beacon(MF(), verbose=True)
    out = capsys.readouterr().out

    section = out.split("Process Injection", 1)[1].split("Malleable C2", 1)[0]
    full_hex = binary.hex()
    # Continuation lines carry a hanging indent, not the original spacing,
    # so reconstruct by dropping all whitespace/newlines rather than
    # matching one literal line -- a wrapped value's hex digits are still
    # exactly adjacent once the line breaks/indent are stripped back out.
    squashed = "".join(section.split())
    assert full_hex in squashed
    assert "..." not in section


def test_full_field_table_long_binary_field_wraps_without_truncating(capsys):
    # Same issue #46 regression as the Process Injection test above, but
    # for the OTHER call site the bug report names -- _field_table_lines().
    seg_va, seg_fo = 0xa0000, 0xa000
    binary = bytes(range(1, 41))   # 40 bytes -> 80 hex chars, over the old 64-char cutoff
    config = _config_with_extra_field(0x002f, 3, binary)   # ProcInject_Transform_x64
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    cs_beacon._hunt_cs_beacon(MF(), verbose=True)
    out = capsys.readouterr().out

    table = out.split("Full Config Field Table", 1)[1].split("Process Injection", 1)[0]
    full_hex = binary.hex()
    squashed = "".join(table.split())
    assert full_hex in squashed
    assert "..." not in table


def test_wrap_hex_value_never_drops_content_regardless_of_width():
    # issue #46's own regression demand: "Confirm terminal width changes
    # wrapping only, never evidence content." Exercise the wrapper
    # directly across the full clamped width range (dumpex.hunt._console's
    # MIN_WIDTH/MAX_WIDTH) plus a pathological near-zero width, for a
    # value much longer than any of them.
    hexs = (bytes(range(0, 200)) * 2).hex()   # 800 hex chars, well past every width below
    prefix = "        ProcInject_Transform_x64  "
    hang = len(prefix)
    for width in (1, 2, 40, 80, 100, 120, 500):
        lines = report_console._wrap_hex_value(hexs, prefix, width)
        assert lines[0].startswith(prefix)
        assert all(line.startswith(" " * hang) for line in lines[1:])
        chunks = [lines[0][hang:]] + [line[hang:] for line in lines[1:]]
        assert "".join(chunks) == hexs   # every hex digit present, in order, nothing dropped
        for chunk in chunks:
            assert len(chunk) % 2 == 0   # never split a byte across a line break


# ── a segment read failure must be counted as a coverage gap, not ─────────
# silently dropped: a "clean" result achieved only because a segment could
# never actually be read must not read as a genuine NOT_DETECTED_IN_SCANNED_SCOPE.

def test_read_failed_segment_makes_result_inconclusive():
    good_va, good_fo = 0x70000, 0x7000
    bad_va, bad_fo   = 0x80000, 0x8000
    data = b'\x00' * 0x1000
    good_seg = Segment(good_va, good_fo, len(data))
    bad_seg  = Segment(bad_va, bad_fo, 0x1000)
    regions = [Region(good_va, good_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class FlakyReader:
        def read(self, addr, size):
            if addr == bad_va:
                raise OSError("simulated unreadable segment")
            return data

    class MF(FakeMF):
        memory_segments_64 = FakeStream([good_seg, bad_seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FlakyReader()

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert any("failed to read" in r for r in f["coverage_reasons"])


# ── a segment that returns FEWER bytes than its own declared size (a ──────
# short read, no exception raised) must not be silently treated as a
# complete scan -- the unread tail could hide a real config.

def test_short_read_segment_makes_result_inconclusive():
    seg_va, seg_fo = 0x90000, 0x9000
    declared_size = 0x2000
    actual_bytes  = b'\x00' * 0x1000   # only half of what the segment claims
    seg = Segment(seg_va, seg_fo, declared_size)
    regions = [Region(seg_va, seg_va, declared_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: actual_bytes})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert any("short read" in r for r in f["coverage_reasons"])


# A short read that still contains a real config hit in the part that WAS
# read must not lose the detection -- the gap only affects coverage, not
# whether a genuine hit found in the returned bytes gets reported.

def test_short_read_segment_with_hit_in_readable_portion_still_detects():
    seg_va, seg_fo = 0xa0000, 0xa000
    declared_size = 0x4000
    config = cs_beacon_config_bytes(0x69)
    actual_bytes = _mk_segment_data(config)   # much shorter than declared_size
    seg = Segment(seg_va, seg_fo, declared_size)
    regions = [Region(seg_va, seg_va, declared_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: actual_bytes})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "partial"
    assert any("short read" in r for r in f["coverage_reasons"])


# ── _cs_decode_and_parse_tlv: structural TLV validation ────────────────────
# a config missing a legitimate fid=0 terminator, or containing a truncated
# field, a duplicate field id, or an illegal field type must NOT be reported
# as `complete` -- only a properly-terminated, well-formed blob may pass the
# downstream sanity check as a "found" config.

def test_decode_and_parse_tlv_no_terminator_is_incomplete():
    # Two well-formed fields but no trailing fid=0 record.
    plaintext = _tlv(0x0001, 1, struct.pack('>H', 0)) + _tlv(0x0007, 3, bytes([0x30, 0x81]))
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = parser._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "terminator" in parsed["reason"]


def test_decode_and_parse_tlv_truncated_field_payload_is_incomplete():
    # First field matches the plaintext signature exactly; second field
    # declares a 100-byte payload but the buffer ends right after its header.
    plaintext = _tlv(0x0001, 1, struct.pack('>H', 0)) + struct.pack('>HHH', 0x0007, 3, 100)
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = parser._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "0007" in parsed["reason"] and "length" in parsed["reason"]


def test_decode_and_parse_tlv_duplicate_field_id_is_incomplete():
    field = _tlv(0x0001, 1, struct.pack('>H', 0))
    plaintext = field + field   # same field id twice
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = parser._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "duplicate" in parsed["reason"]


def test_decode_and_parse_tlv_illegal_field_type_is_incomplete():
    plaintext = _tlv(0x0001, 1, struct.pack('>H', 0)) + struct.pack('>HHH', 0x0002, 9, 0)
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = parser._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "illegal field type" in parsed["reason"]


# ── a type-1/type-2 field whose declared length doesn't match its own ─────
# type (a type-1 "uint16" field claiming a length other than 2, or a
# type-2 "uint32" field claiming a length other than 4) must be rejected
# as incomplete, not silently accepted with `value=None` -- that used to
# crash the whole scan the first time it reached models.ConfigField's own
# type validation (int|str only), turning one malformed marker match
# anywhere in a dump into a hard failure of the entire hunter.

def test_decode_and_parse_tlv_wrong_length_uint16_field_is_incomplete():
    plaintext = (_tlv(0x0001, 1, struct.pack('>H', 0))
                 + struct.pack('>HHH', 0x0002, 1, 3) + b'\x00\x00\x00')   # type 1, length 3 (not 2)
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = parser._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "invalid length" in parsed["reason"]


def test_decode_and_parse_tlv_wrong_length_uint32_field_is_incomplete():
    plaintext = (_tlv(0x0001, 1, struct.pack('>H', 0))
                 + struct.pack('>HHH', 0x0004, 2, 2) + b'\x00\x00')   # type 2, length 2 (not 4)
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = parser._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "invalid length" in parsed["reason"]


def test_malformed_field_length_candidate_does_not_crash_the_whole_scan():
    """Hunter-level regression: a candidate whose BeaconType/PublicKey are
    otherwise genuinely valid (would pass `_cs_sanity_check` and become a
    real hit) but carries one type-1 field with the wrong declared length
    must not be counted as a hit -- and, critically, must not raise at all
    (the whole `--hunt cs-beacon` scan must complete and report the rest
    of the dump normally, not crash on one malformed candidate). Spliced
    into the SAME base config `test_sanity_check_accepts_well_formed_
    public_key` proves passes sanity checking, so this exercises the path
    that used to reach `models.ConfigField`'s own construction (and crash
    there) rather than being rejected earlier by an unrelated DER/
    BeaconType failure."""
    seg_va, seg_fo = 0x120000, 0x12000
    xor_key = 0x69
    base = cs_beacon_config_bytes(xor_key)
    decoded = bytes(b ^ xor_key for b in base)
    terminator = struct.pack('>H', 0)
    assert decoded.endswith(terminator)
    body = decoded[:-len(terminator)]
    # type 1 (uint16) field declaring length 3 -- not the required 2.
    malformed_field = struct.pack('>HHH', 0x0002, 1, 3) + b'\x00\x00\x00'
    plaintext = body + malformed_field + terminator
    config = bytes(b ^ xor_key for b in plaintext)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)   # must not raise
    assert f["configs"] == []
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"


# ── _cs_decode_type3_value: the shared printable/binary decode helper ─────
# (schema v2.7 / console field-table patch) -- the ONE place
# _cs_decode_and_parse_tlv() (building `value`) and presentation.py
# (deciding how to render a field under --verbose) both get this decision
# from, so they can never disagree.

def test_decode_type3_value_printable_ascii_is_text():
    value, is_text = parser._cs_decode_type3_value(b"example.com")
    assert is_text is True
    assert value == "example.com"


def test_decode_type3_value_multiline_printable_is_text():
    # tab/CR/LF count as printable here -- a Malleable C2 header block or
    # SpawnTo path can legitimately contain them.
    raw = b"line one\nline two\r\ttabbed"
    value, is_text = parser._cs_decode_type3_value(raw)
    assert is_text is True
    assert value == raw.decode("utf-8")


def test_decode_type3_value_binary_is_not_text():
    raw = bytes([0x30, 0x14, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86])   # DER-ish, non-printable
    value, is_text = parser._cs_decode_type3_value(raw)
    assert is_text is False
    assert value == raw.hex()


def test_decode_type3_value_binary_with_trailing_nul_strips_nul_from_value_only():
    raw = bytes([0x30, 0x14, 0x30, 0x0d]) + b"\x00\x00\x00"
    value, is_text = parser._cs_decode_type3_value(raw)
    assert is_text is False
    # `value` is hex of the NUL-STRIPPED bytes -- shorter than raw.hex().
    assert value == raw.rstrip(b"\x00").hex()
    assert value != raw.hex()
    assert len(value) < len(raw.hex())


def test_decode_type3_value_undecodable_utf8_is_not_text():
    raw = bytes([0xff, 0xfe, 0x00, 0x01])   # invalid UTF-8
    value, is_text = parser._cs_decode_type3_value(raw)
    assert is_text is False
    assert value == raw.rstrip(b"\x00").hex()


def test_decode_type3_value_matches_what_the_tlv_parser_actually_stores():
    # The parser's own `value` (built via this same helper) must be
    # byte-for-byte what _cs_decode_type3_value() alone would produce --
    # proves _cs_decode_and_parse_tlv() didn't drift onto a second,
    # separately-maintained copy of this decision.
    raw_printable = b"HTTP/1.1"
    raw_binary = bytes([0x30, 0x81, 0x9f, 0x30, 0x0d])
    for raw in (raw_printable, raw_binary):
        # plaintext must start with CS_BEACON_SIGNATURE (the 6-byte header
        # of a field_id=1/type=1/length=2 record) or the parser rejects
        # the whole buffer before ever reaching field 0x0007.
        plaintext = _tlv(0x0001, 1, struct.pack('>H', 0)) + _tlv(0x0007, 3, raw)
        encoded = bytes(b ^ 0x69 for b in plaintext)
        parsed = parser._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
        expected_value, _ = parser._cs_decode_type3_value(raw)
        assert parsed["fields"][0x0007]["value"] == expected_value


def test_decode_and_parse_tlv_terminator_at_exact_buffer_end_is_complete():
    # The fid=0 terminator is only 2 bytes -- it must be recognized even
    # when those are the LAST 2 bytes of the available buffer, with no
    # trailing padding to satisfy a full 6-byte header read. A prior bug
    # required 6 bytes to be available before even checking fid==0,
    # incorrectly reporting a legitimately-terminated config as
    # truncated whenever it wasn't followed by at least 4 extra bytes.
    plaintext = (_tlv(0x0001, 1, struct.pack('>H', 0))
                 + _tlv(0x0007, 3, bytes([0x30, 0x81]))
                 + struct.pack('>H', 0))   # 2-byte terminator, nothing after it
    encoded = bytes(b ^ 0x69 for b in plaintext)   # no trailing padding after the terminator
    parsed = parser._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is True
    assert parsed["reason"] is None
    assert parsed["consumed"] == len(plaintext)


# ── _cs_validate_public_key_der: the PublicKey field must be a minimally ──
# consistent X.509 SubjectPublicKeyInfo DER structure carrying the
# rsaEncryption OID, not just three fixed hex nibbles ("308") followed by
# arbitrary bytes -- a fake ASN.1 prefix with no real DER structure behind
# it must be rejected.

def _valid_public_key_der() -> bytes:
    rsa_encryption_oid = bytes.fromhex('06092a864886f70d010101')
    der_null            = bytes.fromhex('0500')
    algorithm_id        = bytes([0x30, len(rsa_encryption_oid) + len(der_null)]) \
                           + rsa_encryption_oid + der_null
    bit_string           = bytes([0x03, 0x03, 0x00, 0x30, 0x00])   # unused-bits=0 + DER SEQUENCE (RSAPublicKey)
    content               = algorithm_id + bit_string
    return bytes([0x30, len(content)]) + content


def test_validate_public_key_der_accepts_well_formed_structure():
    valid, reason = cs_der._cs_validate_public_key_der(_valid_public_key_der())
    assert valid is True
    assert reason == ""


def test_validate_public_key_der_rejects_oid_outside_zero_length_inner_sequence():
    # The AlgorithmIdentifier SEQUENCE declares 0 bytes of content, but a
    # real OID sits immediately after it in the buffer anyway -- outside
    # what the structure actually claims to contain. The OID comparison
    # must be bounded by AlgorithmIdentifier's own declared length, not
    # just checked against overall buffer availability.
    oid = bytes.fromhex('06092a864886f70d010101')
    algorithm_id_header = bytes([0x30, 0x00])   # SEQUENCE, declared length 0
    outer_content = algorithm_id_header + oid + bytes(20)
    der = bytes([0x30, len(outer_content)]) + outer_content
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert reason


def test_validate_public_key_der_rejects_algorithm_id_extending_past_outer_sequence():
    # The outer SubjectPublicKeyInfo SEQUENCE declares a length far
    # shorter than the AlgorithmIdentifier that follows actually needs,
    # even though the buffer has plenty of real bytes past that
    # artificially-short declared end. AlgorithmIdentifier must be
    # bounded by the OUTER SEQUENCE's own declared end, not merely by
    # len(raw).
    oid = bytes.fromhex('06092a864886f70d010101')
    der_null = bytes.fromhex('0500')
    algorithm_id = bytes([0x30, len(oid) + len(der_null)]) + oid + der_null   # 15 bytes
    der = bytes([0x30, 5]) + algorithm_id + bytes(10)   # outer claims only 5 content bytes
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert reason


def test_validate_public_key_der_rejects_bit_string_tag_with_no_length():
    # The BIT STRING tag (0x03) sits immediately after AlgorithmIdentifier,
    # exactly like a real SubjectPublicKeyInfo -- but nothing else follows
    # it: no length byte, no unused-bits byte, no key material at all. A
    # prior version only checked for the tag byte's presence and accepted
    # this as a complete structure.
    oid = bytes.fromhex('06092a864886f70d010101')
    der_null = bytes.fromhex('0500')
    algorithm_id = bytes([0x30, len(oid) + len(der_null)]) + oid + der_null
    content = algorithm_id + b'\x03'   # bare tag, no length byte at all
    der = bytes([0x30, len(content)]) + content
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert reason


def test_validate_public_key_der_rejects_bit_string_not_filling_outer_sequence():
    # The BIT STRING's declared length leaves trailing bytes inside the
    # outer SEQUENCE unaccounted for by any actual field -- the outer
    # SEQUENCE claims more content than AlgorithmIdentifier + BIT STRING
    # together actually declare.
    oid = bytes.fromhex('06092a864886f70d010101')
    der_null = bytes.fromhex('0500')
    algorithm_id = bytes([0x30, len(oid) + len(der_null)]) + oid + der_null
    bit_string = bytes([0x03, 0x02, 0x00, 0x30])   # unused-bits=0 + SEQUENCE tag, otherwise well-formed
    content = algorithm_id + bit_string
    der = bytes([0x30, len(content) + 10]) + content + bytes(10)   # outer overclaims by 10
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert reason


def test_validate_public_key_der_rejects_bit_string_extending_past_outer_sequence():
    # The BIT STRING's own declared length reaches past the outer
    # SEQUENCE's declared end -- its content claims to include bytes the
    # outer structure never said were part of it.
    oid = bytes.fromhex('06092a864886f70d010101')
    der_null = bytes.fromhex('0500')
    algorithm_id = bytes([0x30, len(oid) + len(der_null)]) + oid + der_null
    bit_string_header = bytes([0x03, 0x7f])   # BIT STRING claims 127 bytes of content
    content = algorithm_id + bit_string_header + b'\xff' * 5   # buffer only has 5 more real bytes
    der = bytes([0x30, len(content)]) + content
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert reason


def test_validate_public_key_der_rejects_empty_bit_string():
    # "03 01 00" -- a BIT STRING containing only the mandatory unused-bits
    # byte and nothing else. Structurally a complete, self-consistent BIT
    # STRING (length matches what follows, fits inside the outer SEQUENCE),
    # but there is no actual key material behind it at all.
    oid = bytes.fromhex('06092a864886f70d010101')
    der_null = bytes.fromhex('0500')
    algorithm_id = bytes([0x30, len(oid) + len(der_null)]) + oid + der_null
    bit_string = bytes([0x03, 0x01, 0x00])   # empty BIT STRING: just the unused-bits byte
    content = algorithm_id + bit_string
    der = bytes([0x30, len(content)]) + content
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert "key material" in reason


def test_validate_public_key_der_rejects_bit_string_nonzero_unused_bits():
    # The unused-bits byte is non-zero -- a real RSA SubjectPublicKeyInfo's
    # key material is always byte-aligned (unused-bits == 0). A non-zero
    # value here means this isn't a genuine byte-aligned RSAPublicKey.
    oid = bytes.fromhex('06092a864886f70d010101')
    der_null = bytes.fromhex('0500')
    algorithm_id = bytes([0x30, len(oid) + len(der_null)]) + oid + der_null
    bit_string = bytes([0x03, 0x03, 0x04, 0x30, 0x00])   # unused-bits=4, not byte-aligned
    content = algorithm_id + bit_string
    der = bytes([0x30, len(content)]) + content
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert "unused-bits" in reason


def test_validate_public_key_der_rejects_bit_string_content_not_sequence():
    # The BIT STRING has real content behind the unused-bits byte, but it
    # isn't a DER SEQUENCE -- not the RSAPublicKey structure it claims to
    # carry, just arbitrary bytes shaped enough to pass a length check.
    oid = bytes.fromhex('06092a864886f70d010101')
    der_null = bytes.fromhex('0500')
    algorithm_id = bytes([0x30, len(oid) + len(der_null)]) + oid + der_null
    bit_string = bytes([0x03, 0x03, 0x00, 0xff, 0xff])   # content doesn't start with 0x30
    content = algorithm_id + bit_string
    der = bytes([0x30, len(content)]) + content
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert "SEQUENCE" in reason


def test_validate_public_key_der_rejects_fake_asn1_prefix():
    # Exactly what the OLD "hex startswith '308'" check accepted: a
    # SEQUENCE tag + long-form length byte followed by arbitrary zero
    # bytes, with no real AlgorithmIdentifier/OID behind it at all.
    fake = bytes([0x30, 0x81]) + b'\x00' * 20
    valid, reason = cs_der._cs_validate_public_key_der(fake)
    assert valid is False
    assert reason


def test_validate_public_key_der_rejects_too_short_buffer():
    valid, reason = cs_der._cs_validate_public_key_der(b'\x30\x05\x00\x00\x00')
    assert valid is False
    assert "too short" in reason


def test_validate_public_key_der_rejects_non_sequence_tag():
    valid, reason = cs_der._cs_validate_public_key_der(b'\x04' + b'\x00' * 20)
    assert valid is False
    assert "SEQUENCE tag" in reason


def test_validate_public_key_der_rejects_length_exceeding_buffer():
    # Declares a SEQUENCE of 100 bytes but the buffer only has 18 more.
    der = bytes([0x30, 0x64]) + b'\x00' * 18
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert "exceeds" in reason


def test_validate_public_key_der_rejects_wrong_oid():
    # Well-formed DER shape, but the AlgorithmIdentifier OID is NOT
    # rsaEncryption (e.g. ecPublicKey, 1.2.840.10045.2.1) -- structurally
    # valid ASN.1, still not what a CS beacon actually embeds.
    ec_public_key_oid = bytes.fromhex('06072a8648ce3d0201')
    der_null            = bytes.fromhex('0500')
    algorithm_id        = bytes([0x30, len(ec_public_key_oid) + len(der_null)]) \
                           + ec_public_key_oid + der_null
    bit_string           = bytes([0x03, 0x03, 0x00, 0x30, 0x00])   # unused-bits=0 + DER SEQUENCE (RSAPublicKey)
    content               = algorithm_id + bit_string
    der = bytes([0x30, len(content)]) + content
    valid, reason = cs_der._cs_validate_public_key_der(der)
    assert valid is False
    assert "rsaEncryption" in reason


def test_sanity_check_rejects_fake_public_key_prefix():
    fields = {
        0x0001: {'value': 0},   # HTTP -- recognized BeaconType
        0x0007: {'raw': bytes([0x30, 0x81]) + b'\x00' * 20},   # fake prefix only
    }
    assert parser._cs_sanity_check(fields) is False


def test_sanity_check_accepts_well_formed_public_key():
    fields = {
        0x0001: {'value': 0},
        0x0007: {'raw': _valid_public_key_der()},
    }
    assert parser._cs_sanity_check(fields) is True


# ── hunter-level: a candidate with the OLD-style fake "308..." PublicKey ──
# prefix (no real DER structure behind it) must not be counted as a found
# config, even though its BeaconType and terminator are otherwise legitimate.

def test_fake_public_key_prefix_candidate_is_not_counted_as_hit():
    seg_va, seg_fo = 0x110000, 0x11000
    fake_pubkey = bytes([0x30, 0x81]) + b'\x00' * 20
    plaintext = (_tlv(0x0001, 1, struct.pack('>H', 0))
                 + _tlv(0x0007, 3, fake_pubkey)
                 + struct.pack('>H', 0))   # terminator
    config = bytes(b ^ 0x69 for b in plaintext)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["configs"] == []
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"


# ── hunter-level: a marker match whose TLV never legitimately terminates ──
# must not be counted as a found config, even though the plaintext
# signature itself matched.

def test_missing_terminator_marker_is_not_counted_as_hit():
    seg_va, seg_fo = 0xb0000, 0xb000
    plaintext = _tlv(0x0001, 1, struct.pack('>H', 0)) + _tlv(0x0007, 3,
                     bytes([0x30, 0x81]) + b'\x00' * 20)   # no terminator
    config = bytes(b ^ 0x69 for b in plaintext)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["configs"] == []
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"


# ── hunter-level: a segment stuffed with mass duplicate marker bytes must ──
# hit the global candidate budget and stop scanning safely rather than
# examining every occurrence, and the result must be reported as
# coverage-partial (not silently "clean").

def test_mass_duplicate_markers_triggers_budget_and_stops_safely(monkeypatch):
    monkeypatch.setattr(cs_beacon, "CS_MAX_CANDIDATES", 5)
    seg_va, seg_fo = 0xc0000, 0xc000
    data = cs_beacon.CS_SIG_XOR69 * 50   # far more than the 5-candidate budget
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("budget" in r for r in f["coverage_reasons"])


# ── hunter-level: the scan deadline must be enforced even when every ──────
# segment is marker-free — a candidate-loop-only deadline check never runs
# at all for a segment with zero candidates, so a long run of large,
# marker-free segments could scan unbounded past CS_SCAN_DEADLINE_SECONDS.
# Reproduced with a simulated clock: the deadline is established on the
# very first time.monotonic() call, then every later call reports time
# already far past it — this must stop the scan and mark coverage partial,
# not silently finish "complete" having called monotonic() only once.

def test_scan_deadline_enforced_across_marker_free_segments(monkeypatch):
    n_segs = 5
    seg_size = 0x1000
    segs = []
    read_map = {}
    for i in range(n_segs):
        va = 0x70000000 + i * 0x100000
        segs.append(Segment(va, va, seg_size))
        read_map[va] = b'\x00' * seg_size   # no beacon markers anywhere

    regions = [Region(va, va, seg_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for va in (s.start_virtual_address for s in segs)]

    class MF(FakeMF):
        memory_segments_64 = FakeStream(segs, "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader(read_map)

    calls = {"n": 0}

    def fake_monotonic():
        calls["n"] += 1
        # First call establishes scan_deadline; every call after that
        # (including the very next one) reports time already twice the
        # whole deadline budget forward.
        return calls["n"] * (cs_beacon.CS_SCAN_DEADLINE_SECONDS * 2)

    monkeypatch.setattr(cs_beacon.time, "monotonic", fake_monotonic)

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)

    assert calls["n"] > 1, (
        "deadline must be re-checked per segment, not established once and "
        "never consulted again for marker-free segments"
    )
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("deadline" in r.lower() for r in f["coverage_reasons"])


# ── hunter-level: a total-scanned-bytes cap independently bounds work ─────
# across many marker-free segments even when each individual segment is
# well under CS_MAX_SEG_SCAN and the wall-clock deadline hasn't elapsed —
# defense in depth alongside the per-segment deadline check above.

def test_total_scanned_bytes_budget_stops_marker_free_segments(monkeypatch):
    monkeypatch.setattr(cs_beacon, "CS_MAX_TOTAL_SCANNED_BYTES", 0x2000)   # 8 KB
    n_segs = 5
    seg_size = 0x1000   # 4 KB each -- second segment already exceeds the cap
    segs = []
    read_map = {}
    for i in range(n_segs):
        va = 0x71000000 + i * 0x100000
        segs.append(Segment(va, va, seg_size))
        read_map[va] = b'\x00' * seg_size

    regions = [Region(va, va, seg_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for va in (s.start_virtual_address for s in segs)]

    class MF(FakeMF):
        memory_segments_64 = FakeStream(segs, "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader(read_map)

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)

    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("scanned-bytes budget" in r for r in f["coverage_reasons"])


# ── hunter-level: the scanned-bytes budget must be caught even when the ───
# segment that pushes the total over the cap is the LAST (here, the only)
# segment in the dump -- a check performed only against the ALREADY-
# accumulated total, re-evaluated solely at the top of the NEXT segment's
# loop iteration, would never fire when there is no next iteration, and
# the scan would silently report "complete" despite having read well past
# CS_MAX_TOTAL_SCANNED_BYTES.

def test_total_scanned_bytes_budget_stops_on_final_segment(monkeypatch):
    monkeypatch.setattr(cs_beacon, "CS_MAX_TOTAL_SCANNED_BYTES", 0x2000)   # 8 KB cap
    seg_size = 0x3000   # 12 KB in a single segment -- already over the cap alone
    va = 0x72000000
    seg = Segment(va, va, seg_size)
    regions = [Region(va, va, seg_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({va: b'\x00' * seg_size})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)

    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("scanned-bytes budget" in r for r in f["coverage_reasons"])


# ── hunter-level: the decoded-bytes budget must be caught even when the ───
# candidate that pushes the total over the cap is the LAST candidate
# examined -- decoding it is what crosses the budget, so the overrun can
# only be noticed by checking again right after that decode, not by
# waiting for a next candidate that never comes. The config is still a
# real hit (still DETECTED), but coverage must reflect that the scan
# stopped short of its budget, not silently claim "complete".

def test_decoded_bytes_budget_marks_partial_on_final_candidate(monkeypatch):
    monkeypatch.setattr(cs_beacon, "CS_MAX_DECODED_BYTES", 1)   # far below one config
    seg_va, seg_fo = 0x23000, 0x2300
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)

    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "partial"
    assert any("scan resource budget exhausted" in r for r in f["coverage_reasons"])

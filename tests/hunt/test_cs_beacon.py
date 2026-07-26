"""Hunter-level tests for dumpex.hunt.cs_beacon (Cobalt Strike beacon config)."""
import struct

from tests.fixtures.fakes import (Region, Segment, FakeReader, FakeStream, FakeMF,
                                   cs_beacon_config_bytes)

import dumpex.hunt.cs_beacon as cs_beacon
from dumpex.ui.structured import StructuredOutput


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


# ── the ACTUAL hunter output (not a mock) round-trips through structured.py ─
# with the identical verdict_level it reports itself -- console and JSON/CSV
# must never disagree on the same result.

def test_real_hunter_output_verdict_level_matches_structured_output():
    seg_va, seg_fo = 0x90000, 0x9000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    result = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    assert result["verdict_level"] == "high"

    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    row = out._section_to_tables("hunt", {"cs-beacon": result})["summary"][0]
    assert row["verdict_level"] == result["verdict_level"]
    assert row["verdict"] == result["verdict_level"].upper()


# ── _cs_decode_and_parse_tlv: structural TLV validation ────────────────────
# a config missing a legitimate fid=0 terminator, or containing a truncated
# field, a duplicate field id, or an illegal field type must NOT be reported
# as `complete` -- only a properly-terminated, well-formed blob may pass the
# downstream sanity check as a "found" config.

def test_decode_and_parse_tlv_no_terminator_is_incomplete():
    # Two well-formed fields but no trailing fid=0 record.
    plaintext = _tlv(0x0001, 1, struct.pack('>H', 0)) + _tlv(0x0007, 3, bytes([0x30, 0x81]))
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = cs_beacon._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "terminator" in parsed["reason"]


def test_decode_and_parse_tlv_truncated_field_payload_is_incomplete():
    # First field matches the plaintext signature exactly; second field
    # declares a 100-byte payload but the buffer ends right after its header.
    plaintext = _tlv(0x0001, 1, struct.pack('>H', 0)) + struct.pack('>HHH', 0x0007, 3, 100)
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = cs_beacon._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "0007" in parsed["reason"] and "length" in parsed["reason"]


def test_decode_and_parse_tlv_duplicate_field_id_is_incomplete():
    field = _tlv(0x0001, 1, struct.pack('>H', 0))
    plaintext = field + field   # same field id twice
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = cs_beacon._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "duplicate" in parsed["reason"]


def test_decode_and_parse_tlv_illegal_field_type_is_incomplete():
    plaintext = _tlv(0x0001, 1, struct.pack('>H', 0)) + struct.pack('>HHH', 0x0002, 9, 0)
    encoded = bytes(b ^ 0x69 for b in plaintext)
    parsed = cs_beacon._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
    assert parsed["complete"] is False
    assert "illegal field type" in parsed["reason"]


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
    parsed = cs_beacon._cs_decode_and_parse_tlv(encoded, 0, 0x69, 8192)
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
    bit_string           = bytes([0x03, 0x03, 0x00]) + b'\xff\xff'
    content               = algorithm_id + bit_string
    return bytes([0x30, len(content)]) + content


def test_validate_public_key_der_accepts_well_formed_structure():
    valid, reason = cs_beacon._cs_validate_public_key_der(_valid_public_key_der())
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
    valid, reason = cs_beacon._cs_validate_public_key_der(der)
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
    valid, reason = cs_beacon._cs_validate_public_key_der(der)
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
    valid, reason = cs_beacon._cs_validate_public_key_der(der)
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
    bit_string = bytes([0x03, 0x01, 0x00])   # BIT STRING, only the mandatory unused-bits byte
    content = algorithm_id + bit_string
    der = bytes([0x30, len(content) + 10]) + content + bytes(10)   # outer overclaims by 10
    valid, reason = cs_beacon._cs_validate_public_key_der(der)
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
    valid, reason = cs_beacon._cs_validate_public_key_der(der)
    assert valid is False
    assert reason


def test_validate_public_key_der_rejects_fake_asn1_prefix():
    # Exactly what the OLD "hex startswith '308'" check accepted: a
    # SEQUENCE tag + long-form length byte followed by arbitrary zero
    # bytes, with no real AlgorithmIdentifier/OID behind it at all.
    fake = bytes([0x30, 0x81]) + b'\x00' * 20
    valid, reason = cs_beacon._cs_validate_public_key_der(fake)
    assert valid is False
    assert reason


def test_validate_public_key_der_rejects_too_short_buffer():
    valid, reason = cs_beacon._cs_validate_public_key_der(b'\x30\x05\x00\x00\x00')
    assert valid is False
    assert "too short" in reason


def test_validate_public_key_der_rejects_non_sequence_tag():
    valid, reason = cs_beacon._cs_validate_public_key_der(b'\x04' + b'\x00' * 20)
    assert valid is False
    assert "SEQUENCE tag" in reason


def test_validate_public_key_der_rejects_length_exceeding_buffer():
    # Declares a SEQUENCE of 100 bytes but the buffer only has 18 more.
    der = bytes([0x30, 0x64]) + b'\x00' * 18
    valid, reason = cs_beacon._cs_validate_public_key_der(der)
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
    bit_string           = bytes([0x03, 0x03, 0x00]) + b'\xff\xff'
    content               = algorithm_id + bit_string
    der = bytes([0x30, len(content)]) + content
    valid, reason = cs_beacon._cs_validate_public_key_der(der)
    assert valid is False
    assert "rsaEncryption" in reason


def test_sanity_check_rejects_fake_public_key_prefix():
    fields = {
        0x0001: {'value': 0},   # HTTP -- recognized BeaconType
        0x0007: {'raw': bytes([0x30, 0x81]) + b'\x00' * 20},   # fake prefix only
    }
    assert cs_beacon._cs_sanity_check(fields) is False


def test_sanity_check_accepts_well_formed_public_key():
    fields = {
        0x0001: {'value': 0},
        0x0007: {'raw': _valid_public_key_der()},
    }
    assert cs_beacon._cs_sanity_check(fields) is True


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

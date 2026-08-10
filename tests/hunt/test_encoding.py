"""Hunter-level tests for dumpex.hunt.encoding (obfuscation/entropy/Base64/GZIP)."""
import base64
import random

from tests.fixtures.fakes import (Region, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)

import dumpex.hunt.encoding as encoding


# ── arbitrary data starting with call/pop -> never scored ─────────────────

def test_call_pop_prefix_never_scores():
    random.seed(2)
    region_base = 0x400000
    shellcode_prefix = b'\xe8\x00\x00\x00\x00\x58'
    payload = shellcode_prefix + bytes(random.getrandbits(8) for _ in range(200))
    b64_payload = base64.b64encode(payload)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_payload.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    tags = {finding["check"]: (finding["tag"], finding["confidence"]) for finding in f["findings"]}
    assert f["score"] == 0
    assert tags.get("obfuscation.shellcode_bootstrap_lead") == ("lead", "low")
    assert "obfuscation.structural_payload" not in tags


# ── same shellcode-bootstrap prefix, but the containing region is ─────────
# ALSO executable+private (MEM_PRIVATE + PAGE_EXECUTE_READWRITE) -- the
# combination is a stronger lead than the bare pattern match above, so
# confidence is raised to medium, but it still must never score.

def test_call_pop_prefix_in_rwx_private_region_raises_lead_confidence():
    random.seed(2)
    region_base = 0x410000
    shellcode_prefix = b'\xe8\x00\x00\x00\x00\x58'
    payload = shellcode_prefix + bytes(random.getrandbits(8) for _ in range(200))
    b64_payload = base64.b64encode(payload)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_payload.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    tags = {finding["check"]: (finding["tag"], finding["confidence"]) for finding in f["findings"]}
    assert f["score"] == 0
    assert tags.get("obfuscation.shellcode_bootstrap_lead") == ("lead", "medium")
    assert "obfuscation.structural_payload" not in tags


# ── Bonus: a validated PE payload (even Base64-wrapped) still scores ──────

def test_validated_pe_still_scores():
    region_base = 0x300000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_pe.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 1
    assert f["confidence"] == "high"


# ── a short read in ANY of the three region-scanning layers (sleep-mask, ──
# entropy, decode) must not be silently treated as a complete scan — the
# unread tail could hide a real payload. Each test below isolates ONE
# layer via its own filter differences (region size vs. the other layers'
# thresholds, or MEM_IMAGE vs MEM_PRIVATE) so a regression in only one
# layer's short-read counting would be caught precisely.

def test_sleep_mask_layer_short_read_makes_result_inconclusive():
    region_base = 0x500000
    declared_size = 0x2000   # passes sleep-mask's own size floor (1300 bytes)
    actual_bytes  = b'\x00' * 0x400   # far short of declared_size
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: actual_bytes})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r for r in f["coverage_reasons"])


def test_entropy_layer_short_read_makes_result_inconclusive():
    region_base = 0x600000
    # Between DECODE_SCAN_MAX (2 MB) and ENTROPY_SCAN_MAX (10 MB), and not
    # PAGE_READWRITE -- decode is size-skipped and sleep-mask is protect-
    # filtered before either ever attempts a read, isolating this short
    # read to the entropy layer alone.
    declared_size = 3 * 1024 * 1024
    actual_bytes  = b'\x00' * 0x400
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_READONLY", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: actual_bytes})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r for r in f["coverage_reasons"])


def test_decode_layer_short_read_makes_result_inconclusive():
    region_base = 0x700000
    # MEM_IMAGE -- both sleep-mask and entropy require MEM_PRIVATE and
    # skip this before ever reading, isolating this short read to the
    # decode layer alone (decode accepts MEM_PRIVATE or MEM_IMAGE).
    declared_size = 0x2000
    actual_bytes  = b'\x00' * 0x400
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")   # no modules -> not classified as a system DLL
    encoding.read_region = mem_reader({region_base: actual_bytes})

    f = encoding._hunt_encoding(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r for r in f["coverage_reasons"])


# ── --verbose must still surface fields Finding.facts never carried ───────
# (file offset for every layer, raw Base64 length) -- these used to come
# from presentation.py's own hand-written verbose expansion; centralizing
# rendering on Finding.print() dropped them because Finding.facts (built
# for --json) never had them in the first place. Regression test for
# that loss being silently reintroduced.

def test_verbose_shows_file_offset_and_b64_length_not_shown_normally(capsys, monkeypatch):
    # va_to_file_offset() returns None whenever the fake dump has no memory
    # segment table (true of every other fixture in this file) -- asserting
    # only the *label* "File_offset" is present would pass even if the
    # value printed is always the vacuous "(not captured)" placeholder.
    # Monkeypatched here to a real, non-None value so the assertion below
    # actually exercises the printed offset text, not just its label.
    # Patched on dumpex.hunt._location (the ONE shared resolver import
    # point resolve_location() calls into) rather than on aggregate --
    # aggregate.py no longer imports va_to_file_offset at all; resolution
    # now happens in each scan layer, before aggregate.py ever sees it.
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset", lambda mf, va: 0x1234)

    region_base = 0x300000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_pe.ljust(0x1000, b"\x00")})

    encoding._hunt_encoding(MF(), verbose=False)
    normal_out = capsys.readouterr().out
    assert "B64_length" not in normal_out
    assert "File_offset" not in normal_out
    assert "0x1234" not in normal_out

    encoding._hunt_encoding(MF(), verbose=True)
    verbose_out = capsys.readouterr().out
    assert f"B64_length={len(b64_pe)}chars" in verbose_out
    assert "File_offset=0x1234" in verbose_out


def test_verbose_file_offset_zero_is_not_mistaken_for_not_captured(capsys, monkeypatch):
    # va_to_file_offset() can legitimately return 0 (a region mapped at the
    # very start of the dump file) -- the printed-offset logic must branch
    # on `fo is not None`, not on `fo` being truthy, or a real offset of 0
    # would misprint as "(not captured)".
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset", lambda mf, va: 0)

    region_base = 0x300000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_pe.ljust(0x1000, b"\x00")})

    encoding._hunt_encoding(MF(), verbose=True)
    out = capsys.readouterr().out
    assert "File_offset=0x0" in out
    assert "(not captured)" not in out


def test_verbose_xor_detail_includes_decoding_evidence(capsys, monkeypatch):
    """The verbose evidence obfuscation.xor_observation's Finding.
    verbose_facts carries must preserve evidence not in the compact status
    line: dump offset, key, decoded type, and IOC text -- built (once, in
    aggregate.py's _xor_verbose_fact()) from the exact same Hit the
    compact line and Finding.facts already read, through the real
    end-to-end scan/aggregate/render path (not a direct call into a
    presentation-layer helper -- there is no such per-hunter helper left
    to call; see dumpex/hunt/encoding/report_console.py's own module
    docstring for why)."""
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset", lambda mf, va: 0x456)

    key = 0x5A
    plaintext = b"beacon http://185.220.101.5/submit.php callback data padding here for length"
    encoded = bytes(b ^ key for b in plaintext)
    region_base = 0x301000
    regions = [Region(region_base, region_base, len(encoded), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: encoded})

    encoding._hunt_encoding(MF(), verbose=True)
    out = capsys.readouterr().out

    assert "XOR single-byte obfuscation" in out
    assert f"VA=0x{region_base:016x}" in out
    assert "File_offset=0x456" in out
    assert "XOR_key=0x5a" in out
    assert "Decoded_type=IOC_TEXT" in out
    assert "IOC_strings=http://185.220.101.5/submit.php" in out


def test_verbose_lists_every_structural_pe_hit_beyond_the_facts_cap(capsys):
    # obfuscation.structural_payload's Finding.facts (built for --json)
    # cap the hit list at 20 with a "... and N more" sentinel entry --
    # --verbose is supposed to mean "the complete list". Finding.
    # verbose_facts (not Finding.facts) is the --verbose detail source for
    # this check, built uncapped -- see aggregate.py's own comment where
    # obfuscation.structural_payload's Finding is constructed.
    # Each region's PE content must be BYTE-DISTINCT (a different
    # `timestamp`) -- the decode budget dedupes by decoded-content hash
    # (dumpex/hunt/encoding/decoding.py's seen_content()) independently of
    # region address, so 21 byte-identical payloads at 21 different
    # addresses would still collapse to a single retained hit.
    n = 21
    region_base = 0x600000
    regions = [Region(region_base + i * 0x1000, region_base + i * 0x1000, 0x1000,
                       "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for i in range(n)]
    read_map = {}
    for i in range(n):
        pe_bytes = build_pe_header(
            [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
              "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
            timestamp=0x12345678 + i, size_of_image=0x2000, trailing_padding=0x300)
        read_map[region_base + i * 0x1000] = base64.b64encode(pe_bytes).ljust(0x1000, b"\x00")

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader(read_map)

    encoding._hunt_encoding(MF(), verbose=False)
    normal_out = capsys.readouterr().out
    last_va = region_base + (n - 1) * 0x1000
    assert f"0x{last_va:016x}" not in normal_out

    encoding._hunt_encoding(MF(), verbose=True)
    verbose_out = capsys.readouterr().out
    assert "... and" not in verbose_out, \
        "verbose_facts must fully replace the capped Finding.facts sentinel, not coexist with it"
    for i in range(n):
        va = region_base + i * 0x1000
        assert f"0x{va:016x}" in verbose_out, f"PE hit {i} (VA 0x{va:x}) missing from --verbose output"


def test_verbose_lists_every_shellcode_hit_beyond_the_facts_cap(capsys):
    # Same regression, for obfuscation.shellcode_bootstrap_lead. Each
    # region's decoded content must be byte-distinct -- see the sibling PE
    # test above for why (the decode budget dedupes by content hash,
    # independent of region address).
    n = 21
    region_base = 0x610000
    shellcode_prefix = b'\xe8\x00\x00\x00\x00\x58'
    regions = [Region(region_base + i * 0x1000, region_base + i * 0x1000, 0x1000,
                       "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for i in range(n)]
    read_map = {}
    for i in range(n):
        random.seed(2 + i)
        payload = shellcode_prefix + bytes(random.getrandbits(8) for _ in range(200))
        read_map[region_base + i * 0x1000] = base64.b64encode(payload).ljust(0x1000, b'\x00')

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader(read_map)

    encoding._hunt_encoding(MF(), verbose=False)
    normal_out = capsys.readouterr().out
    last_va = region_base + (n - 1) * 0x1000
    assert f"0x{last_va:016x}" not in normal_out

    encoding._hunt_encoding(MF(), verbose=True)
    verbose_out = capsys.readouterr().out
    assert "... and" not in verbose_out, \
        "verbose_facts must fully replace the capped Finding.facts sentinel, not coexist with it"
    for i in range(n):
        va = region_base + i * 0x1000
        assert f"0x{va:016x}" in verbose_out, f"shellcode hit {i} (VA 0x{va:x}) missing from --verbose output"

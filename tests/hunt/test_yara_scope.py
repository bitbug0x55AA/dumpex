"""Tests for the generalized YARA rule memory-scope mechanism
(dumpex_scope="private_or_unbacked" rule meta -- see
dumpex/hunt/yara_hunt/config.py's SCOPE_PRIVATE_OR_UNBACKED and
dumpex/hunt/yara_hunt/context.py's classify_scoped_hit).

A rule carrying this meta is only trusted as a confirmed hit when it
resolves to memory NOT backed by a known module: MEM_PRIVATE, or an
unbacked mapping that also carries execute permission. A module-backed/
MEM_IMAGE hit is suppressed outright (never reaches triggered_rules or
matches); a MEM_MAPPED/read-only hit (or one with no context source
available at all) is kept visible in matches but downgraded to
context_unverified rather than scored.

Needs the real yara-python package -- an optional ("full") dependency --
so this whole module is skipped (not failed) when it isn't present.
"""
import os
import tempfile

import pytest

pytest.importorskip("yara")

from tests.fixtures.fakes import Region, Module, Segment, FakeReader, FakeStream, FakeMF

import dumpex.hunt.yara_hunt.context as context
import dumpex.hunt.yara_hunt as yara_hunt


def _write_rule(d, name, body):
    with open(os.path.join(d, name), "w") as fh:
        fh.write(body)


# ── classify_scoped_hit: all classification outcomes ──────────────────────

def test_classify_scoped_image_via_module_is_suppressed():
    addr = 0x1000
    modules = [Module(0x1000, 0x2000, r"C:\Windows\System32\ntdll.dll")]
    suppressed, unverified, ctx_value = context.classify_scoped_hit(
        addr, modules, [], modules_available=True, mem_info_available=False)
    assert suppressed is True
    assert unverified is False
    assert ctx_value == "image"


def test_classify_scoped_mem_private_is_allowed():
    addr = 0x3000
    regions = [Region(0x3000, 0x3000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    suppressed, unverified, ctx_value = context.classify_scoped_hit(
        addr, [], regions, modules_available=False, mem_info_available=True)
    assert suppressed is False
    assert unverified is False
    assert ctx_value == "private"


def test_classify_scoped_unregistered_is_allowed():
    addr = 0x4000
    modules = [Module(0x9000, 0x1000, r"C:\Windows\System32\ntdll.dll")]
    suppressed, unverified, ctx_value = context.classify_scoped_hit(
        addr, modules, [], modules_available=True, mem_info_available=False)
    assert suppressed is False
    assert unverified is False
    assert ctx_value == "unregistered"


def test_classify_scoped_mem_mapped_readonly_is_unverified():
    addr = 0x5000
    regions = [Region(0x5000, 0x5000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")]
    suppressed, unverified, ctx_value = context.classify_scoped_hit(
        addr, [], regions, modules_available=False, mem_info_available=True)
    assert suppressed is False
    assert unverified is True
    assert ctx_value == "other"


def test_classify_scoped_mem_mapped_executable_is_allowed():
    # Unbacked AND executable -- just as worth flagging as MEM_PRIVATE,
    # even though the region type is MEM_MAPPED rather than MEM_PRIVATE.
    addr = 0x5500
    regions = [Region(0x5500, 0x5500, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_MAPPED")]
    suppressed, unverified, ctx_value = context.classify_scoped_hit(
        addr, [], regions, modules_available=False, mem_info_available=True)
    assert suppressed is False
    assert unverified is False
    assert ctx_value == "other"


def test_classify_scoped_unknown_when_no_context_source_available():
    addr = 0x6000
    suppressed, unverified, ctx_value = context.classify_scoped_hit(
        addr, [], [], modules_available=False, mem_info_available=False)
    assert suppressed is False
    assert unverified is True
    assert ctx_value == "unknown"


# ── end-to-end: a scoped rule dispatched purely by meta, not by name ─────

_SCOPED_RULE = ('rule ScopedMarker {\n'
                 '    meta:\n'
                 '        dumpex_scope = "private_or_unbacked"\n'
                 '    strings:\n'
                 '        $a = "SCOPED_MARKER_XYZ"\n'
                 '    condition:\n'
                 '        $a\n'
                 '}\n')

_UNSCOPED_RULE = ('rule HighSpecificityMarker {\n'
                   '    strings:\n'
                   '        $a = "HIGH_SPECIFICITY_MARKER"\n'
                   '    condition:\n'
                   '        $a\n'
                   '}\n')


def test_scoped_rule_hit_in_known_module_is_suppressed():
    seg_va, seg_fo = 0x70000, 0x7000
    data = b'\x00' * 0x100 + b'SCOPED_MARKER_XYZ' + b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "scoped.yar", _SCOPED_RULE)
        seg = Segment(seg_va, seg_fo, len(data))
        module = Module(seg_va, len(data), r"C:\Windows\System32\legit.dll")

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            modules              = FakeStream([module], "modules")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["matches"] == []
    assert "ScopedMarker" not in f.get("rules_hit", [])


def test_scoped_rule_hit_in_readonly_mem_mapped_is_context_unverified():
    seg_va, seg_fo = 0x80000, 0x8000
    data = b'\x00' * 0x100 + b'SCOPED_MARKER_XYZ' + b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "scoped.yar", _SCOPED_RULE)
        seg = Segment(seg_va, seg_fo, len(data))
        regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")]

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            memory_info          = FakeStream(regions, "infos")
            modules               = None
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert len(f["matches"]) == 1
    assert f["matches"][0]["context_unverified"] is True
    assert "ScopedMarker" not in f.get("rules_hit", [])


def test_scoped_rule_hit_in_executable_mem_private_triggers_and_scores():
    seg_va, seg_fo = 0x90000, 0x9000
    data = b'\x00' * 0x100 + b'SCOPED_MARKER_XYZ' + b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "scoped.yar", _SCOPED_RULE)
        seg = Segment(seg_va, seg_fo, len(data))
        regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            memory_info          = FakeStream(regions, "infos")
            modules               = None
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert "ScopedMarker" in f["rules_hit"]
    assert f["matches"][0]["context_unverified"] is False
    assert f["matches"][0]["memory_context"] == "private"


def test_unscoped_high_specificity_rule_still_triggers_in_known_module():
    # A rule with NO dumpex_scope meta is unaffected by the mechanism --
    # module-backed hits still trigger normally, exactly as before. This
    # matters because high-specificity rules (Mimikatz/PSExec-style
    # strings) must still fire even inside a legitimately-loaded but
    # malicious module -- see rule-file guidance in
    # dumpex/hunt/yara_hunt/config.py.
    seg_va, seg_fo = 0xA0000, 0xA000
    data = b'\x00' * 0x100 + b'HIGH_SPECIFICITY_MARKER' + b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "unscoped.yar", _UNSCOPED_RULE)
        seg = Segment(seg_va, seg_fo, len(data))
        module = Module(seg_va, len(data), r"C:\Windows\System32\legit.dll")

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            modules              = FakeStream([module], "modules")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert "HighSpecificityMarker" in f["rules_hit"]


def test_only_unverified_scoped_hits_is_inconclusive_score_zero():
    seg_va, seg_fo = 0xB0000, 0xB000
    data = b'\x00' * 0x100 + b'SCOPED_MARKER_XYZ' + b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "scoped.yar", _SCOPED_RULE)
        seg = Segment(seg_va, seg_fo, len(data))
        # No modules, no memory_info -- neither context source available.
        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert f["verdict_level"] == "inconclusive"
    assert f["matches"][0]["context_unverified"] is True


def test_mixed_confirmed_and_unverified_hits_scores_only_confirmed():
    # Two rules in one scan: one matches inside executable MEM_PRIVATE
    # (confirmed), the other inside PAGE_READONLY MEM_MAPPED (unverified).
    # Overall result must be DETECTED, and score must count only the
    # confirmed rule -- the unverified one must not inflate it.
    confirmed_va, confirmed_fo = 0xC0000, 0xC000
    unverified_va, unverified_fo = 0xC1000, 0xC100
    confirmed_data = b'\x00' * 0x100 + b'CONFIRMED_MARKER_ABC' + b'\x00' * 0x100
    unverified_data = b'\x00' * 0x100 + b'UNVERIFIED_MARKER_DEF' + b'\x00' * 0x100

    rule_body = ('rule ConfirmedScoped {\n'
                 '    meta:\n'
                 '        dumpex_scope = "private_or_unbacked"\n'
                 '    strings:\n'
                 '        $a = "CONFIRMED_MARKER_ABC"\n'
                 '    condition:\n'
                 '        $a\n'
                 '}\n'
                 'rule UnverifiedScoped {\n'
                 '    meta:\n'
                 '        dumpex_scope = "private_or_unbacked"\n'
                 '    strings:\n'
                 '        $a = "UNVERIFIED_MARKER_DEF"\n'
                 '    condition:\n'
                 '        $a\n'
                 '}\n')

    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "mixed.yar", rule_body)
        confirmed_seg = Segment(confirmed_va, confirmed_fo, len(confirmed_data))
        unverified_seg = Segment(unverified_va, unverified_fo, len(unverified_data))
        regions = [
            Region(confirmed_va, confirmed_va, len(confirmed_data), "MEM_COMMIT",
                   "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
            Region(unverified_va, unverified_va, len(unverified_data), "MEM_COMMIT",
                   "PAGE_READONLY", "MEM_MAPPED"),
        ]

        class MF(FakeMF):
            memory_segments_64 = FakeStream([confirmed_seg, unverified_seg], "memory_segments")
            memory_info          = FakeStream(regions, "infos")
            modules               = None
            _reader                = FakeReader({confirmed_va: confirmed_data,
                                                   unverified_va: unverified_data})
        f = yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)

    assert f["status"] == "DETECTED"
    assert f["score"] == 1
    assert f["rules_hit"] == ["ConfirmedScoped"]
    assert len(f["matches"]) == 2   # both hits kept visible in matches
    unverified_hits = [m for m in f["matches"] if m["rule"] == "UnverifiedScoped"]
    assert unverified_hits and unverified_hits[0]["context_unverified"] is True


# ── regression: real packaged rules must not fire on ordinary module ─────
# content -- the exact clean-Notepad false positives this change fixes
# (WMI/VirtualAlloc-sequence/Shellcode-bootstrap strings/bytes that occur
# incidentally or routinely inside legitimately loaded system DLLs).

def _packaged_rules_dir():
    from dumpex.hunt.yara_hunt import rules
    d = rules.packaged_yara_rules_dir()
    assert d is not None, "packaged YARA rules directory must be resolvable for this test"
    return d


def test_wmic_string_in_known_module_does_not_detect():
    seg_va, seg_fo = 0xD0000, 0xD000
    data = b'\x00' * 0x100 + b'wmic.exe' + b'\x00' * 0x100
    seg = Segment(seg_va, seg_fo, len(data))
    module = Module(seg_va, len(data), r"C:\Windows\System32\ordinary.dll")

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        modules              = FakeStream([module], "modules")
        _reader                = FakeReader({seg_va: data})
    f = yara_hunt._hunt_yara(MF(), rules_dir=_packaged_rules_dir(), verbose=False)

    assert "WMI_Lateral_Movement" not in f.get("rules_hit", [])
    assert f["status"] != "DETECTED"


def test_virtualalloc_sequence_strings_in_known_module_does_not_detect():
    seg_va, seg_fo = 0xE0000, 0xE000
    data = (b'\x00' * 0x100 + b'VirtualAllocEx' + b'\x00' * 0x40
            + b'WriteProcessMemory' + b'\x00' * 0x100)
    seg = Segment(seg_va, seg_fo, len(data))
    module = Module(seg_va, len(data), r"C:\Windows\System32\kernel32.dll")

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        modules              = FakeStream([module], "modules")
        _reader                = FakeReader({seg_va: data})
    f = yara_hunt._hunt_yara(MF(), rules_dir=_packaged_rules_dir(), verbose=False)

    assert "Suspicious_VirtualAlloc_Sequence" not in f.get("rules_hit", [])
    assert f["status"] != "DETECTED"


def test_shellcode_bootstrap_bytes_in_known_module_does_not_detect():
    seg_va, seg_fo = 0xF0000, 0xF000
    data = b'\x00' * 0x100 + bytes.fromhex("e800000000") + b'\x59' + b'\x00' * 0x100
    seg = Segment(seg_va, seg_fo, len(data))
    module = Module(seg_va, len(data), r"C:\Windows\System32\ntdll.dll")

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        modules              = FakeStream([module], "modules")
        _reader                = FakeReader({seg_va: data})
    f = yara_hunt._hunt_yara(MF(), rules_dir=_packaged_rules_dir(), verbose=False)

    assert "Shellcode_Bootstrap_x64" not in f.get("rules_hit", [])
    assert f["status"] != "DETECTED"


def test_lsass_dump_keywords_in_known_module_does_not_detect():
    seg_va, seg_fo = 0x100000, 0x10000
    data = b'\x00' * 0x100 + b'lsass.exe' + b'\x00' * 0x40 + b'comsvcs.dll' + b'\x00' * 0x100
    seg = Segment(seg_va, seg_fo, len(data))
    module = Module(seg_va, len(data), r"C:\Windows\System32\KERNELBASE.dll")

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        modules              = FakeStream([module], "modules")
        _reader                = FakeReader({seg_va: data})
    f = yara_hunt._hunt_yara(MF(), rules_dir=_packaged_rules_dir(), verbose=False)

    assert "LSASS_Dump_Keywords" not in f.get("rules_hit", [])
    assert f["status"] != "DETECTED"

"""Semantics of the `--report` PE, instruction, and IAT correlation
collectors.

A synthetic main image is mapped at ``PE_IMAGE_BASE`` with one imported
symbol and a ``call [rip+X]`` at its entry point through the IAT slot,
plus a second module the live thunk target resolves into. The four Phase
2 collectors are exercised against it directly; the isolated disassembler
seam and the VA-resolution join have their own tests in
``tests/unit/test_disasm.py`` and ``tests/unit/test_va_location.py``.
"""
import struct
import sys

import pytest

from dumpex.commands.report import collect_report
import dumpex.commands.report as report_mod
from dumpex.commands.report_enrichment import (
    PeProfileCache, RegionEvidence, collect_anchor_pe_context,
    collect_iat_correlation, collect_instruction_context, collect_pe_context,
)
from dumpex.core.disasm import MAX_DECODE_BYTES, disasm_available
from dumpex.output.records import (
    ENRICHMENT_COMPLETE, ENRICHMENT_MISSING, ENRICHMENT_PARTIAL,
)
from tests.fixtures.fakes import (
    Ctx, EnvBufferedReader, EnvReader, FakeMF, FakeStream, Module, Peb, Region,
    Segment, Thread, ThreadInfo, mem_reader,
)

ANCHOR_TID = 0x11
PE_IMAGE_BASE = 0x140000000
PE_KERNEL_BASE = PE_IMAGE_BASE + 0x1000000
PE_ENTRY_VA = PE_IMAGE_BASE + 0x1000
PE_IAT_SLOT_VA = PE_IMAGE_BASE + 0x2000
PE_THUNK_TARGET_VA = PE_KERNEL_BASE + 0x1000

_needs_capstone = pytest.mark.skipif(not disasm_available(),
                                     reason="capstone not installed")


def _pe_header_bytes() -> bytes:
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x5A6B7C8D, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<Q", opt, 24, PE_IMAGE_BASE)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<I", opt, 56, 0x4000)
    struct.pack_into("<I", opt, 60, 0x200)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<H", opt, 70, 0x40)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112 + 1 * 8, 0x2040, 0x28)
    struct.pack_into("<II", opt, 112 + 12 * 8, 0x2000, 0x40)
    sections = bytearray()
    for name, rva, raw in ((b".text", 0x1000, 0x200), (b".rdata", 0x2000, 0x1200)):
        record = bytearray(40)
        record[0:8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIII", record, 8, 0x1000, rva, 0x1000, raw)
        struct.pack_into("<I", record, 36,
                         0x60000020 if name == b".text" else 0x40000040)
        sections += record
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sections)


def _pe_image_memory() -> bytes:
    buf = bytearray(0x3000)
    buf[0:0x1D8] = _pe_header_bytes()
    # .text: call qword [rip + 0xffa]  (slot at RVA 0x2000), then ret.
    buf[0x1000:0x1006] = b"\xff\x15\xfa\x0f\x00\x00"
    buf[0x1006] = 0xC3
    struct.pack_into("<Q", buf, 0x2000, PE_THUNK_TARGET_VA)
    # IMPORT descriptor at RVA 0x2040 (20 bytes), then a zeroed terminator
    # descriptor at 0x2054. The INT and names sit past both so nothing
    # overlaps the terminator.
    struct.pack_into("<IIIII", buf, 0x2040, 0x2100, 0, 0, 0x2120, 0x2000)
    struct.pack_into("<QQ", buf, 0x2100, 0x2130, 0)
    buf[0x2120:0x2128] = b"K32.dll\x00"
    buf[0x2130:0x2132] = b"\x00\x00"
    buf[0x2132:0x2132 + 15] = b"GetProcAddress\x00"
    return bytes(buf)


def _pe_mf():
    mf = FakeMF()
    mf.peb = Peb(PE_IMAGE_BASE, "app.exe")
    mf.modules = FakeStream([Module(PE_IMAGE_BASE, 0x4000, "app.exe"),
                             Module(PE_KERNEL_BASE, 0x4000, "kernel32.dll")], "modules")
    mf.thread_info = FakeStream([ThreadInfo(ANCHOR_TID, PE_ENTRY_VA)], "infos")
    mf.threads = FakeStream([Thread(ANCHOR_TID, Ctx(PE_ENTRY_VA))], "threads")
    mf.memory_info = FakeStream([
        Region(PE_IMAGE_BASE, PE_IMAGE_BASE, 0x1000, "MEM_COMMIT", "PAGE_READONLY",
               "MEM_IMAGE"),
        Region(PE_IMAGE_BASE + 0x1000, PE_IMAGE_BASE, 0x1000, "MEM_COMMIT",
               "PAGE_EXECUTE_READ", "MEM_IMAGE"),
        Region(PE_IMAGE_BASE + 0x2000, PE_IMAGE_BASE, 0x2000, "MEM_COMMIT",
               "PAGE_READONLY", "MEM_IMAGE"),
        Region(PE_KERNEL_BASE, PE_KERNEL_BASE, 0x4000, "MEM_COMMIT",
               "PAGE_EXECUTE_READ", "MEM_IMAGE"),
    ], "infos")
    mf.memory_segments_64 = FakeStream(
        [Segment(PE_IMAGE_BASE, 0, 0x3000), Segment(PE_KERNEL_BASE, 0x3000, 0x4000)],
        "memory_segments")
    mf._reader = EnvReader(EnvBufferedReader({
        PE_IMAGE_BASE: _pe_image_memory(),
        PE_KERNEL_BASE: bytes(0x4000)}))
    mf._dumpex_stream_failures = {}
    return mf


def _cache(mf):
    return PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE))


def _instruction(cache, mf, candidates, *, iat_raw=None, base=PE_IMAGE_BASE,
                 thread_ip_reg=None, wow64_hint=None):
    record, slots = collect_instruction_context(
        cache, mf=mf, anchor_candidates=candidates,
        region_evidence=RegionEvidence.from_dump(mf), iat_raw=iat_raw,
        instruction_module_base=base,
        instruction_module_profile=cache.profile_at_base(base) if base is not None else None,
        thread_ip_reg=thread_ip_reg, wow64_hint=wow64_hint)
    return record, slots


def test_pe_context_publishes_identity_and_no_conflicts_for_a_benign_image():
    context = collect_pe_context(_cache(_pe_mf()))
    assert context.section.status in (ENRICHMENT_COMPLETE, ENRICHMENT_PARTIAL)
    assert context.image_base == "0x0000000140000000"
    assert context.machine == 0x8664
    assert context.pe32_plus is True
    assert context.module_match == "resolved"
    assert context.conflict_count == 0
    assert context.observations == ()


def test_pe_context_is_missing_when_no_image_base_resolves():
    context = collect_pe_context(PeProfileCache.from_dump(_pe_mf(), None))
    assert context.section.status == ENRICHMENT_MISSING
    assert context.section.limitations


def test_anchor_pe_context_places_the_entry_point_in_executable_code():
    mf = _pe_mf()
    context = collect_anchor_pe_context(
        _cache(mf), anchor_address=PE_ENTRY_VA,
        region_evidence=RegionEvidence.from_dump(mf))
    assert context.classification == "code"
    assert context.registration == "registered"
    assert context.module_owner == "app.exe"
    assert context.section_name == ".text"
    assert context.declared_executable is True
    assert context.live_protection == "PAGE_EXECUTE_READ"
    assert context.protection_matches_declared is True


def test_anchor_pe_context_classifies_a_private_region_anchor():
    mf = FakeMF()
    mf.modules = FakeStream([Module(PE_IMAGE_BASE, 0x4000, "app.exe")], "modules")
    mf.memory_info = FakeStream([Region(0x9000000, 0x9000000, 0x1000, "MEM_COMMIT",
                                        "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")], "infos")
    mf._dumpex_stream_failures = {}
    context = collect_anchor_pe_context(
        _cache(mf), anchor_address=0x9000800,
        region_evidence=RegionEvidence.from_dump(mf))
    assert context.classification == "private"
    assert context.registration == "unregistered"


def test_anchor_pe_context_is_missing_when_nothing_places_the_anchor():
    mf = FakeMF()
    mf.modules = FakeStream([], "modules")
    mf.memory_info = FakeStream([], "infos")
    mf._dumpex_stream_failures = {}
    context = collect_anchor_pe_context(
        PeProfileCache.from_dump(mf, None), anchor_address=0xdead0000,
        region_evidence=RegionEvidence.from_dump(mf))
    assert context.classification == "unresolved"
    assert context.section.status == ENRICHMENT_MISSING


@_needs_capstone
def test_instruction_context_decodes_the_window_and_resolves_the_iat_call():
    mf = _pe_mf()
    cache = _cache(mf)
    context, slots = _instruction(
        cache, mf, [("card_anchor", PE_ENTRY_VA)], iat_raw=cache.iat_at_base(PE_IMAGE_BASE))
    assert context.decoder_state == "decoded"
    assert context.architecture == "x64"
    assert context.instructions[0].is_anchor and context.instructions[0].is_call
    assert slots == (PE_IAT_SLOT_VA,)
    slot_targets = [t for t in context.branch_targets if t.kind == "iat_slot"]
    (target,) = slot_targets
    assert target.target_address == "0x0000000140002000"
    assert target.resolved_target_address == f"0x{PE_THUNK_TARGET_VA:016x}"
    assert target.module_owner == "kernel32.dll"
    assert target.iat_symbol == "GetProcAddress"


def test_instruction_context_is_partial_without_a_disassembler(monkeypatch):
    monkeypatch.setitem(sys.modules, "capstone", None)
    mf = _pe_mf()
    context, _slots = _instruction(_cache(mf), mf, [("card_anchor", PE_ENTRY_VA)])
    assert context.decoder_state == "unavailable"
    assert context.section.status == ENRICHMENT_PARTIAL
    assert context.instructions == ()


@_needs_capstone
def test_instruction_context_is_unsupported_for_a_non_x86_machine():
    mf = _pe_mf()
    # Rewrite the COFF Machine field to ARM64 (0xaa64) in the mapped image.
    memory = bytearray(_pe_image_memory())
    memory[0x84:0x86] = (0xAA64).to_bytes(2, "little")
    mf._reader = EnvReader(EnvBufferedReader({
        PE_IMAGE_BASE: bytes(memory), PE_KERNEL_BASE: bytes(0x4000)}))
    context, _slots = _instruction(_cache(mf), mf, [("card_anchor", PE_ENTRY_VA)])
    assert context.decoder_state == "unsupported_arch"
    assert context.architecture is None
    assert context.section.status == ENRICHMENT_PARTIAL
    assert context.instructions == ()


def test_instruction_context_is_missing_without_captured_bytes():
    mf = _pe_mf()
    mf._reader = EnvReader(EnvBufferedReader({PE_IMAGE_BASE: bytes(0x400)}))
    context, _slots = _instruction(_cache(mf), mf, [("card_anchor", PE_ENTRY_VA)])
    assert context.section.status == ENRICHMENT_MISSING
    assert context.decoder_state == "not_run"


_PRIVATE_CODE_VA = 0x5000000


def _private_code_mf(code: bytes):
    """A dump with executable code in a MEM_PRIVATE region owned by no
    module -- the injected-code case."""
    mf = FakeMF()
    mf.modules = FakeStream([Module(PE_IMAGE_BASE, 0x4000, "app.exe")], "modules")
    mf.thread_info = FakeStream([ThreadInfo(ANCHOR_TID, _PRIVATE_CODE_VA)], "infos")
    mf.threads = FakeStream([Thread(ANCHOR_TID, Ctx(_PRIVATE_CODE_VA))], "threads")
    mf.memory_info = FakeStream([
        Region(_PRIVATE_CODE_VA, _PRIVATE_CODE_VA, 0x1000, "MEM_COMMIT",
               "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")], "infos")
    mf.memory_segments_64 = FakeStream(
        [Segment(_PRIVATE_CODE_VA, 0, len(code))], "memory_segments")
    mf._reader = EnvReader(EnvBufferedReader({_PRIVATE_CODE_VA: code}))
    mf._dumpex_stream_failures = {}
    return mf


@_needs_capstone
def test_instruction_context_decodes_an_anchor_in_unbacked_private_code():
    # call rel32 -> +0x100, then ret. The anchor is in no PE image, so the
    # architecture must come from the thread context flavour.
    code = b"\xe8\xfb\x00\x00\x00\xc3"
    mf = _private_code_mf(code)
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")
    assert record.decoder_state == "decoded"
    assert record.architecture == "x64"
    assert record.instructions[0].is_call
    (target,) = [t for t in record.branch_targets if t.kind == "direct"]
    assert target.target_address == f"0x{_PRIVATE_CODE_VA + 0x100:016x}"


@_needs_capstone
def test_instruction_context_arch_undetermined_is_not_reported_as_unsupported():
    mf = _private_code_mf(b"\xc3\xc3\xc3")
    mf.threads = None       # no thread context
    mf.thread_info = None
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, None), mf, [("card_anchor", _PRIVATE_CODE_VA)],
        base=None, thread_ip_reg=None)
    assert record.decoder_state == "arch_undetermined"
    assert record.architecture is None
    assert record.section.status == ENRICHMENT_PARTIAL
    assert any("architecture could not be determined" in note
               for note in record.section.limitations)


@_needs_capstone
def test_instruction_context_partial_when_the_region_exceeds_the_byte_window(monkeypatch):
    import dumpex.commands.report_enrichment as re_mod
    monkeypatch.setattr(re_mod, "MAX_DECODE_BYTES", 8)
    mf = _private_code_mf(b"\xc3" * 40)   # 40 bytes of `ret`, window cap is 8
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")
    assert record.decoder_state == "decoded"
    assert record.section.status == ENRICHMENT_PARTIAL
    assert record.section.total is None
    assert any("instructions past the cap were not evaluated" in note
               for note in record.section.limitations)


@_needs_capstone
def test_instruction_context_short_undecoded_tail_is_partial_and_uncertain():
    # A ret, then bytes that do not decode with too few left to tell a
    # cut-short instruction from an invalid opcode.
    mf = _private_code_mf(b"\xc3\xe8\xfb")
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")
    assert record.decoder_state == "undecoded_tail"
    assert record.section.status == ENRICHMENT_PARTIAL
    assert any("invalid opcode, or an instruction the capture cut short" in note
               for note in record.section.limitations)


@_needs_capstone
def test_iat_correlation_retains_the_instruction_correlated_slot():
    mf = _pe_mf()
    cache = _cache(mf)
    correlation = collect_iat_correlation(
        cache, anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=cache.iat_at_base(PE_IMAGE_BASE),
        region_evidence=RegionEvidence.from_dump(mf),
        instruction_slot_vas={PE_IAT_SLOT_VA})
    assert correlation.section.status == ENRICHMENT_COMPLETE
    assert correlation.module_owner == "app.exe"
    (entry,) = correlation.entries
    assert entry.symbol == "GetProcAddress"
    assert entry.selection_reason == "instruction_correlated"
    assert entry.iat_slot_va == "0x0000000140002000"


def test_iat_correlation_drops_a_benign_slot_no_branch_points_at():
    mf = _pe_mf()
    cache = _cache(mf)
    correlation = collect_iat_correlation(
        cache, anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=cache.iat_at_base(PE_IMAGE_BASE),
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=())
    assert correlation.section.status == ENRICHMENT_COMPLETE
    assert correlation.entries == ()


def test_iat_correlation_is_none_without_an_owning_module():
    mf = _pe_mf()
    assert collect_iat_correlation(
        _cache(mf), anchor_module=None, anchor_module_base=None, iat_raw=None,
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=()) is None


def test_pe_profile_cache_builds_each_module_profile_once():
    cache = _cache(_pe_mf())
    assert cache.profile_at_base(PE_IMAGE_BASE) is cache.profile_at_base(PE_IMAGE_BASE)


def test_report_run_carries_pe_context_and_card_sections(monkeypatch):
    mf = _pe_mf()
    monkeypatch.setattr(
        report_mod, "read_region",
        mem_reader({PE_ENTRY_VA: b"\xff\x15\xfa\x0f\x00\x00\xc3"}))
    result = collect_report(mf, report_addr=hex(PE_ENTRY_VA))

    assert result.summary["pe_context"]["image_base"] == "0x0000000140000000"
    card = result.records[0]
    assert card.anchor_pe_context.classification == "code"
    assert card.iat_correlation is not None
    assert card.verdict == "CLEAN"

    # The populated sections validate against the current schema in a real
    # envelope, not just at the record boundary.
    import json

    import jsonschema

    from dumpex.output.collector import V2Output
    from dumpex.schemas import CURRENT_SCHEMA, schema_path

    output = V2Output(dump_path="x.dmp")
    output.set_command_result(result)
    doc = json.loads(output.to_json())
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as handle:
        validator = jsonschema.Draft202012Validator(json.load(handle))
    assert list(validator.iter_errors(doc)) == []
    assert doc["result"]["summary"]["pe_context"]["conflict_count"] == 0


@pytest.mark.parametrize("verbose", [False, True])
def test_report_console_renders_the_new_sections(monkeypatch, capsys, verbose):
    mf = _pe_mf()
    monkeypatch.setattr(
        report_mod, "read_region",
        mem_reader({PE_ENTRY_VA: b"\xff\x15\xfa\x0f\x00\x00\xc3"}))
    result = collect_report(mf, report_addr=hex(PE_ENTRY_VA))
    report_mod.render_report_console(
        result.records, result.coverage, result.diagnostics, result.artifacts,
        result.summary, mf, min_len=6, verbose=verbose)
    out = capsys.readouterr().out
    assert "MAIN IMAGE PE CONTEXT" in out
    assert "ANCHOR PLACEMENT" in out
    assert "INSTRUCTION CONTEXT" in out
    assert "IAT CORRELATION" in out
    if disasm_available():
        assert "GetProcAddress" in out


# ── review follow-ups ────────────────────────────────────────────────

import types  # noqa: E402

from dumpex.commands.report_enrichment import MAX_MODULE_PROFILES  # noqa: E402
from dumpex.commands.report_enrichment import _instruction_arch  # noqa: E402


def _iat_raw(**overrides):
    base = dict(
        import_directory_present=True, table_present=True, dll_count=1, entry_count=0,
        entries=(), directory_table_incomplete=False, directory_read_failed=False,
        directory_short_read=False, descriptor_read_failed_count=0,
        descriptor_short_read_count=0, thunk_read_failed_count=0,
        thunk_short_read_count=0, name_read_failed_count=0, unterminated_table=False,
        cycle_detected=False, bounds_exceeded=False, truncation=None)
    base.update(overrides)
    return types.SimpleNamespace(**base)


def test_iat_correlation_undetermined_import_directory_is_partial_not_a_negative():
    mf = _pe_mf()
    correlation = collect_iat_correlation(
        _cache(mf), anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=_iat_raw(import_directory_present=None, directory_table_incomplete=True),
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=())
    assert correlation.section.status == ENRICHMENT_PARTIAL
    assert correlation.section.total is None   # eligible population undetermined
    assert correlation.import_directory_present is None
    assert all("declares no import directory" not in note
               for note in correlation.section.limitations)


def test_iat_correlation_positively_absent_import_directory_is_a_completed_negative():
    mf = _pe_mf()
    correlation = collect_iat_correlation(
        _cache(mf), anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=_iat_raw(import_directory_present=False),
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=())
    assert correlation.section.status == ENRICHMENT_COMPLETE
    assert any("declares no import directory" in note
              for note in correlation.section.limitations)


def _arch(machine=None, *, thread_ip_reg=None, sysinfo_arch=None, main_machine=None,
          wow64_hint=None):
    module_profile = (types.SimpleNamespace(machine=machine, machine_name=None)
                      if machine is not None else None)
    main_profile = (types.SimpleNamespace(machine=main_machine, machine_name=None)
                    if main_machine is not None else None)
    sysinfo = None
    if sysinfo_arch is not None:
        sysinfo = types.SimpleNamespace(
            ProcessorArchitecture=types.SimpleNamespace(name=sysinfo_arch))
    mf = types.SimpleNamespace(sysinfo=sysinfo)
    return _instruction_arch(module_profile=module_profile, thread_ip_reg=thread_ip_reg,
                             mf=mf, main_profile=main_profile, wow64_hint=wow64_hint)


@pytest.mark.parametrize("machine, expected, non_x86", [
    (0x014C, "x86", False),   # I386
    (0x8664, "x64", False),   # AMD64
    (0xAA64, None, True),     # ARM64 -- a determined "cannot decode"
    (0x01C4, None, True),     # ARMNT
    (0x0200, None, True),     # IA64
    (0x0EBC, None, True),     # EBC
])
def test_instruction_arch_from_a_concrete_machine(machine, expected, non_x86):
    assert _arch(machine) == (expected, non_x86)


def test_instruction_arch_a_concrete_owning_module_machine_wins_over_a_wow64_hint():
    # The wow64cpu transition stubs are genuine x64 code in a WOW64
    # process: the module's own Machine is the authority.
    assert _arch(0x8664, wow64_hint=True) == ("x64", False)


def test_instruction_arch_wow64_hint_settles_an_anchor_with_no_owning_module():
    assert _arch(machine=None, wow64_hint=True) == ("x86", False)


def test_instruction_arch_prefers_the_main_image_over_host_system_info():
    # WOW64 shape: the main image is I386, SystemInfo reports the AMD64
    # host. The process runs x86.
    assert _arch(machine=None, main_machine=0x014C, sysinfo_arch="AMD64") == ("x86", False)


def test_instruction_arch_falls_back_to_the_thread_context_then_system_info():
    assert _arch(machine=None, thread_ip_reg="RIP") == ("x64", False)
    assert _arch(machine=None, thread_ip_reg="EIP") == ("x86", False)
    assert _arch(machine=None, sysinfo_arch="AMD64") == ("x64", False)


def test_instruction_arch_is_undetermined_with_no_signal_at_all():
    assert _arch(machine=None) == (None, False)


def test_profile_cache_reports_why_a_profile_is_absent():
    cache = _cache(_pe_mf())
    for offset in range(MAX_MODULE_PROFILES):
        cache.profile_at_base(0x50000000 + offset * 0x10000)
    # The per-invocation profile budget is now spent; the next base gets
    # no profile, with a reason that distinguishes it from a read failure.
    assert cache.profile_at_base(0x90000000) is None
    assert cache.profile_absent_reason(0x90000000) == "cap_reached"
    assert cache.profile_absent_reason(PE_IMAGE_BASE) is None


def test_anchor_pe_context_names_the_profile_budget_when_the_cap_is_hit():
    mf = _pe_mf()
    mf.modules = FakeStream(
        [Module(0x10000000 + i * 0x100000, 0x4000, f"m{i}.dll")
         for i in range(MAX_MODULE_PROFILES + 1)], "modules")
    mf.memory_info = FakeStream(
        [Region(0x10000000 + i * 0x100000, 0x10000000 + i * 0x100000, 0x4000,
                "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")
         for i in range(MAX_MODULE_PROFILES + 1)], "infos")
    cache = PeProfileCache.from_dump(mf, None)
    for i in range(MAX_MODULE_PROFILES):
        cache.profile_at_base(0x10000000 + i * 0x100000)
    last_base = 0x10000000 + MAX_MODULE_PROFILES * 0x100000
    context = collect_anchor_pe_context(
        cache, anchor_address=last_base + 0x10, region_evidence=RegionEvidence.from_dump(mf))
    assert context.classification == "module"
    assert context.section.status == ENRICHMENT_PARTIAL
    assert any("PE profile this run built" in note
               for note in context.section.limitations)


@_needs_capstone
def test_instruction_slot_vas_survive_the_branch_target_cap():
    # A .text blob of many `call qword [rip + disp_i]`, each through a
    # distinct IAT slot, so more slots are instruction-correlated than the
    # public branch_targets list retains.
    call_count = 20
    memory = bytearray(_pe_image_memory())
    offset = 0x1000
    slots = []
    for i in range(call_count):
        slot_rva = 0x2000 + i * 8
        disp = slot_rva - (offset + 6)
        memory[offset:offset + 6] = b"\xff\x15" + disp.to_bytes(4, "little", signed=True)
        slots.append(PE_IMAGE_BASE + slot_rva)
        offset += 6
    memory[offset] = 0xC3
    # Widen the IAT directory to cover every slot.
    struct.pack_into("<II", memory, 0x98 + 112 + 12 * 8, 0x2000, call_count * 8)
    mf = _pe_mf()
    mf._reader = EnvReader(EnvBufferedReader({
        PE_IMAGE_BASE: bytes(memory), PE_KERNEL_BASE: bytes(0x4000)}))
    cache = _cache(mf)
    record, all_slots = _instruction(cache, mf, [("card_anchor", PE_ENTRY_VA)])
    assert record.branch_targets_total == call_count
    assert len(record.branch_targets) < call_count      # public list is capped
    assert len(all_slots) == call_count                 # internal set is not
    assert set(all_slots) == set(slots)


def test_report_does_not_use_an_uncorrelated_process_exception_as_the_window_anchor(
        monkeypatch):
    from tests.fixtures.fakes import (
        ExceptionListStream, ExceptionRecordDetail, ExceptionStreamEntry)

    mf = _pe_mf()
    # An exception on a DIFFERENT thread, at an address in kernel32 -- a
    # process-wide crash record, not this card's.
    mf.exception = ExceptionListStream([ExceptionStreamEntry(
        0x999, ExceptionRecordDetail(0xC0000005, code_name="EXCEPTION_ACCESS_VIOLATION",
                                     address=PE_KERNEL_BASE + 0x2000))])
    monkeypatch.setattr(
        report_mod, "read_region",
        mem_reader({PE_ENTRY_VA: b"\xff\x15\xfa\x0f\x00\x00\xc3"}))
    result = collect_report(mf, report_addr=hex(PE_ENTRY_VA))
    card = result.records[0]
    if card.instruction_context is not None:
        assert card.instruction_context.anchor_source != "exception_rip"
    # The IAT correlation stays with the card anchor's own module.
    assert card.iat_correlation.module_owner == "app.exe"


@_needs_capstone
def test_instruction_context_partial_on_a_mid_stream_invalid_opcode():
    # A ret, then a long run of 0x06 (invalid in 64-bit mode).
    mf = _private_code_mf(b"\xc3" + b"\x06" * 20)
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")
    assert record.decoder_state == "decode_error"
    assert record.section.status == ENRICHMENT_PARTIAL
    assert any("invalid opcode" in note for note in record.section.limitations)


@_needs_capstone
def test_a_stop_far_from_the_byte_cap_locates_itself_and_never_claims_the_cap():
    """A stop inside the window is a property of the bytes at that
    address. It names the address and how far decoding reached, it does
    not borrow the byte cap's explanation, and it makes no claim about
    the bytes after it -- they were never offered to the decoder."""
    # Seven multi-byte NOPs fill 70 bytes, then 0x06 (invalid in 64-bit
    # mode) runs well past the window: the stop is 442 bytes short of the
    # cap, and both caps are far from reached.
    nop11 = b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"
    mf = _private_code_mf(nop11 * 6 + b"\x0f\x1f\x40\x00" + b"\x06" * 600)
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")

    assert record.decoder_state == "decode_error"
    assert record.bytes_read == MAX_DECODE_BYTES
    assert record.bytes_decoded == 70
    assert record.decode_stop_address == f"0x{_PRIVATE_CODE_VA + 70:016x}"

    (stop_note,) = [note for note in record.section.limitations
                    if "linear decoding stopped" in note]
    assert f"0x{_PRIVATE_CODE_VA + 70:x}" in stop_note
    assert f"70 of {MAX_DECODE_BYTES} byte(s) in" in stop_note
    assert f"not the {MAX_DECODE_BYTES}-byte cap" in stop_note
    assert "cut short" not in stop_note
    # The cap is a real, separate limit on this window and keeps its own
    # sentence; it is never the reason decoding stopped where it did.
    assert any("the region holds more than the" in note
               for note in record.section.limitations)


@_needs_capstone
def test_a_stop_at_the_byte_cap_is_labelled_as_the_boundary_it_is():
    """The opposite case: decoding ran the whole window and the region
    continues. That is the cap, and it says so without borrowing the
    invalid-opcode wording."""
    nop11 = b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"
    # 46 eleven-byte NOPs reach offset 506; a seven-byte call then crosses
    # the 512-byte cap and the lookahead completes it.
    code = nop11 * 46 + b"\xff\x14\x25\x11\x22\x33\x44" + b"\x90" * 10
    mf = _private_code_mf(code)
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")

    assert record.decoder_state == "decoded"
    assert record.bytes_decoded == 506
    (cap_note,) = [note for note in record.section.limitations
                   if "linear decoding ran the whole" in note]
    assert f"{MAX_DECODE_BYTES}-byte window" in cap_note
    assert "beginning an instruction that crosses it" in cap_note
    assert all("invalid opcode" not in note for note in record.section.limitations)


# Each fixture is a complete x64 byte sequence in unbacked private code.
# They differ only in the one relationship the lead ladder tests for, so
# a demotion in any of them is attributable to that difference alone.
#
#   call +0 / pop rax          -- leaves this code's own address in rax
#   add rax, 0x10
#   xor byte ptr [rax], 0x41   -- transforms bytes at that address
#   inc rax / sub rcx, 1
#   jne back to the xor        -- closes the loop around the write
#   call rax                   -- leaves through a register
_SELF_DECODING_STUB = bytes.fromhex(
    "e800000000" "58" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "ffd0" "c3")
_STUB_CALL_OFFSET = 0x00
_STUB_POP_OFFSET = 0x05
_STUB_XOR_OFFSET = 0x0a
_STUB_JNE_OFFSET = 0x14
_STUB_CALL_RAX_OFFSET = 0x16

# The same loop over a register that no call/pop ever wrote: an ordinary
# in-place buffer transform, which is what most of these loops are.
_PLAIN_TRANSFORM_LOOP = bytes.fromhex("803341" "48ffc3" "48ffc9" "75f5" "c3")

# The stub's shape, but the loop writes through rbx while the call/pop
# filled rax: the get-PC value reaches nothing the write addresses.
_STUB_WRITING_AN_UNRELATED_REGISTER = bytes.fromhex(
    "e800000000" "58" "4883c010" "803341" "48ffc3" "4883e901" "75f4" "ffd0" "c3")

# The stub's shape with a `ret` between the pop and the loop: no single
# linear run covers both, so the two are not shown to belong together.
_STUB_WITH_A_RETURN_BEFORE_THE_LOOP = bytes.fromhex(
    "e800000000" "58" "4883c010" "c3" "803041" "48ffc0" "4883e901" "75f4" "c3")

# The stub's shape with `xor rax, rax` after the pop: the register the
# write addresses no longer carries the code's own address.
_STUB_WITH_THE_POPPED_REGISTER_ZEROED = bytes.fromhex(
    "e800000000" "58" "4831c0" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "c3")

# The backward branch lands on a `ret`, so the loop leaves immediately and
# the write below it is bytes in the branch's address span that no run of
# this loop reaches.
_LOOP_BRANCHING_TO_A_RETURN = bytes.fromhex(
    "e800000000" "58" "4883c010" "c3" "803041" "48ffc9" "75f7" "c3")

# A `ret` between the write and the branch that would close the loop: the
# run ends before the loop is ever closed.
_WRITE_CUT_OFF_FROM_ITS_CLOSING_BRANCH = bytes.fromhex(
    "803041" "c3" "48ffc9" "75f7" "c3")

# The backward branch targets an address one byte into the `xor`, which
# is not an instruction boundary this decode produced.
_LOOP_BRANCHING_INTO_THE_MIDDLE_OF_AN_INSTRUCTION = bytes.fromhex(
    "803041" "c3" "48ffc9" "75f8" "c3")

# An unconditional backward `jmp` closes the loop, so nothing follows it
# on any run -- the `call rax` after it is not "after the loop".
_LOOP_CLOSED_BY_AN_UNCONDITIONAL_JUMP = bytes.fromhex("803041" "ebfb" "ffd0" "c3")


def _lead_for(code, *, ip_reg="RIP"):
    """The instruction record for `code` in unbacked private memory.
    `ip_reg` fixes the decode width: RIP is x64, EIP is x86."""
    mf = _private_code_mf(code)
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg=ip_reg)
    return record


@_needs_capstone
def test_a_write_loop_alone_supports_only_the_transform_loop_name():
    """An in-place write inside a loop is all an ordinary buffer decode
    looks like too, so that is the whole claim: the name says nothing
    about the bytes being written."""
    record = _lead_for(_PLAIN_TRANSFORM_LOOP)
    (lead,) = record.leads
    assert lead.name == "memory_transform_loop"
    assert set(lead.signals) == {"memory_write_back", "backward_branch_loop"}
    assert "not shown to be code" in lead.detail


@_needs_capstone
def test_a_get_pc_value_reaching_the_write_upgrades_to_a_self_decoding_stub():
    """The written operand's base register carries what the call/pop read
    as this code's own address, and one uninterrupted linear run covers
    the pop and the loop. Only then is the stronger name used."""
    record = _lead_for(_SELF_DECODING_STUB)
    (lead,) = record.leads
    assert lead.name == "self_decoding_stub"
    assert set(lead.signals) == {
        "memory_write_back", "backward_branch_loop", "get_pc_register_flows_to_write",
        "linear_fall_through_from_get_pc", "register_transfer_after_loop"}
    assert lead.evidence_addresses == tuple(
        f"0x{_PRIVATE_CODE_VA + offset:016x}" for offset in
        (_STUB_CALL_OFFSET, _STUB_POP_OFFSET, _STUB_XOR_OFFSET, _STUB_JNE_OFFSET,
         _STUB_CALL_RAX_OFFSET))
    assert set(lead.evidence_addresses) <= {insn.address for insn in record.instructions}
    assert "this code's own address" in lead.detail


@_needs_capstone
def test_a_write_through_a_register_the_get_pc_never_filled_is_not_a_stub():
    """A call/pop elsewhere in the same 512-byte window is not evidence
    about this loop: the write addresses a register the get-PC value
    never reached."""
    (lead,) = _lead_for(_STUB_WRITING_AN_UNRELATED_REGISTER).leads
    assert lead.name == "memory_transform_loop"
    assert "get_pc_register_flows_to_write" not in lead.signals
    # The register-indirect transfer after the loop still holds, and on
    # its own it still does not upgrade the name.
    assert "register_transfer_after_loop" in lead.signals


@_needs_capstone
def test_a_return_between_the_get_pc_and_the_loop_is_not_a_stub():
    """No single linear run covers the pop and the loop, so the two
    fragments are not shown to belong to each other -- exactly what the
    listing's own "not an executed path" caveat means."""
    (lead,) = _lead_for(_STUB_WITH_A_RETURN_BEFORE_THE_LOOP).leads
    assert lead.name == "memory_transform_loop"
    assert "linear_fall_through_from_get_pc" not in lead.signals


@_needs_capstone
def test_a_popped_register_zeroed_before_the_write_is_not_a_stub():
    """`xor rax, rax` discards the code's own address; a later
    `add rax, 0x10` rebuilds an address from nothing the get-PC left."""
    (lead,) = _lead_for(_STUB_WITH_THE_POPPED_REGISTER_ZEROED).leads
    assert lead.name == "memory_transform_loop"
    assert "get_pc_register_flows_to_write" not in lead.signals


# `rax`, `eax`, `ax`, `al` and `ah` are one register. Each of these is
# the stub, with one narrowing write inserted between the pop and the
# address arithmetic: the code's own address does not survive it, so the
# write's address no longer derives from the call/pop.
_STUB_WITH_EAX_ZEROED = bytes.fromhex(
    "e800000000" "58" "31c0" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "c3")
_STUB_WITH_EAX_MOVED_ZERO = bytes.fromhex(
    "e800000000" "58" "b800000000" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "c3")
_STUB_WITH_AL_MOVED_ZERO = bytes.fromhex(
    "e800000000" "58" "b000" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "c3")
# The same, in the r8/r8d/r8w/r8b family rather than the legacy one.
_R8_STUB_WITH_R8D_ZEROED = bytes.fromhex(
    "e800000000" "4158" "4531c0" "4983c010" "41803041" "49ffc0" "4883e901" "75f3" "c3")
_R8_STUB = bytes.fromhex(
    "e800000000" "4158" "4983c010" "41803041" "49ffc0" "4883e901" "75f3" "c3")
# 32-bit code, where `eax` IS the full width and a write to it preserves
# the address the call/pop produced.
_X86_STUB = bytes.fromhex("e800000000" "58" "83c010" "803041" "40" "49" "75f9" "c3")


@_needs_capstone
@pytest.mark.parametrize("code, inserted", [
    (_STUB_WITH_EAX_ZEROED, "xor eax, eax"),
    (_STUB_WITH_EAX_MOVED_ZERO, "mov eax, 0"),
    (_STUB_WITH_AL_MOVED_ZERO, "mov al, 0"),
    (_R8_STUB_WITH_R8D_ZEROED, "xor r8d, r8d"),
])
def test_a_narrowing_write_ends_the_get_pc_value_it_overwrites(code, inserted):
    """A write to any name of a register is a write to that register. In
    64-bit mode a 32-bit write zeroes the upper half outright, and an
    8-bit one leaves the rest stale; in neither case is the address the
    call/pop produced still there to be written through."""
    (lead,) = _lead_for(code).leads
    assert lead.name == "memory_transform_loop", inserted
    assert "get_pc_register_flows_to_write" not in lead.signals


# Reading a carrying register does not make the result derive from it.
# Each of these reads the register the call/pop filled and leaves
# something that no longer depends on the code's own address.
_STUB_WITH_RAX_ANDED_TO_ZERO = bytes.fromhex(
    "e800000000" "58" "4883e000" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "c3")
_STUB_WITH_RAX_ORED_TO_ONES = bytes.fromhex(
    "e800000000" "58" "4883c8ff" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "c3")
# `xchg` writes two destinations that are not interchangeable: the code
# address ends up in rbx, and rax -- which the loop writes through --
# takes the zero that was in rbx.
_STUB_WITH_THE_ADDRESS_EXCHANGED_AWAY = bytes.fromhex(
    "e800000000" "58" "48c7c300000000" "4887d8" "4883c010" "803041" "48ffc0"
    "4883e901" "75f4" "c3")
# `mul` overwrites rax without naming it as an operand at all.
_STUB_WITH_RAX_CLOBBERED_IMPLICITLY = bytes.fromhex(
    "e800000000" "58" "48f7e3" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "c3")
# A load brings back what the memory held, not the address used to reach
# it, so rbx is not the code's own address.
_STUB_LOADING_THROUGH_THE_ADDRESS = bytes.fromhex(
    "e800000000" "58" "488b18" "803341" "48ffc3" "4883e901" "75f4" "c3")

# The two copy forms that DO carry the address onward, so the demotions
# above are attributable to their own instruction and not to blanket
# suppression.
_STUB_COPIED_THROUGH_MOV = bytes.fromhex(
    "e800000000" "58" "4889c3" "4883c310" "803341" "48ffc3" "4883e901" "75f4" "c3")
_STUB_COMPUTED_THROUGH_LEA = bytes.fromhex(
    "e800000000" "58" "488d5808" "803341" "48ffc3" "4883e901" "75f4" "c3")


@_needs_capstone
@pytest.mark.parametrize("code, inserted", [
    (_STUB_WITH_RAX_ANDED_TO_ZERO, "and rax, 0"),
    (_STUB_WITH_RAX_ORED_TO_ONES, "or rax, -1"),
    (_STUB_WITH_THE_ADDRESS_EXCHANGED_AWAY, "xchg rax, rbx"),
    (_STUB_WITH_RAX_CLOBBERED_IMPLICITLY, "mul rbx"),
    (_STUB_LOADING_THROUGH_THE_ADDRESS, "mov rbx, qword ptr [rax]"),
])
def test_reading_a_carrying_register_is_not_deriving_from_it(code, inserted):
    """Only the forms whose data flow this module models carry a value
    onward. A reduction to a constant, an exchange that writes two
    destinations, an implicit clobber, and a load all read the register
    the call/pop filled and leave something else behind."""
    (lead,) = _lead_for(code).leads
    assert lead.name == "memory_transform_loop", inserted
    assert "get_pc_register_flows_to_write" not in lead.signals


@_needs_capstone
@pytest.mark.parametrize("code, form", [
    (_STUB_COPIED_THROUGH_MOV, "mov rbx, rax"),
    (_STUB_COMPUTED_THROUGH_LEA, "lea rbx, [rax + 8]"),
])
def test_a_modelled_copy_carries_the_address_to_another_register(code, form):
    """The control for the demotions above: a register-to-register copy
    and an address computation do carry the value, so the loop writing
    through the destination is still the stronger lead."""
    (lead,) = _lead_for(code).leads
    assert lead.name == "self_decoding_stub", form
    assert "get_pc_register_flows_to_write" in lead.signals


@_needs_capstone
def test_the_extended_register_family_still_carries_a_full_width_value():
    """The control for the r8 case above: with no narrowing write, the
    same family carries the address to the write as the legacy registers
    do."""
    (lead,) = _lead_for(_R8_STUB).leads
    assert lead.name == "self_decoding_stub"
    assert "get_pc_register_flows_to_write" in lead.signals


@_needs_capstone
def test_full_width_is_the_architecture_s_own_width():
    """`eax` is a narrowing write on x64 and the whole register on x86.
    The same shape decoded 32-bit therefore does carry its value."""
    record = _lead_for(_X86_STUB, ip_reg="EIP")
    assert record.architecture == "x86"
    (lead,) = record.leads
    assert lead.name == "self_decoding_stub"


# 32-bit code whose backward branch lands on a far `ljmp`: every run of
# the loop leaves through it, so the write below is never reached. The
# far jump is a different capstone instruction id from the near one, and
# its mnemonic is not "jmp".
_X86_LOOP_BRANCHING_TO_A_FAR_JUMP = bytes.fromhex(
    "ea785634120800" "803041" "49" "75f3")
# The same loop with the far jump replaced by seven one-byte NOPs, so
# only that instruction differs.
_X86_LOOP_WITH_A_REACHABLE_WRITE = bytes.fromhex("90" * 7 + "803041" "49" "75f3")
# `retf` inside the loop body: a return this module must recognise
# whatever its width.
_LOOP_WITH_A_FAR_RETURN_IN_THE_BODY = bytes.fromhex("803041" "cb" "48ffc9" "75f7" "c3")


# 32-bit code whose backward branch lands on an instruction that never
# reaches its successor: `ud2` faults on every pass, and `rsm` either
# resumes the context System Management Mode interrupted or faults. In
# both the write below is unreachable.
_X86_LOOP_BRANCHING_TO_AN_UNDEFINED_OPCODE = bytes.fromhex(
    "0f0b" "803041" "49" "75f8")
_X86_LOOP_BRANCHING_TO_A_MODE_RESUME = bytes.fromhex(
    "0faa" "803041" "49" "75f8")
# `sysenter` records no return address, and is not one half of a pair
# with `sysexit`: where control resumes is an OS convention, not
# something these bytes state.
_X86_LOOP_BRANCHING_TO_A_FAST_SYSTEM_CALL = bytes.fromhex(
    "0f34" "803041" "49" "75f8")
# The same loop with those two bytes replaced by two one-byte NOPs, so
# only that instruction differs.
_X86_LOOP_WITH_THE_UNDEFINED_OPCODE_REPLACED = bytes.fromhex(
    "9090" "803041" "49" "75f8")


@_needs_capstone
def test_an_undefined_opcode_at_the_loop_entry_makes_the_write_unreachable():
    """`ud2` raises #UD on every pass. There is no path from the loop
    entry to the write, so no lead -- a handler that resumed below it is
    not something this window shows."""
    record = _lead_for(_X86_LOOP_BRANCHING_TO_AN_UNDEFINED_OPCODE, ip_reg="EIP")
    assert any(insn.text.startswith("ud2") for insn in record.instructions)
    assert any(insn.text.startswith("xor") for insn in record.instructions)
    assert record.leads == ()


@_needs_capstone
def test_a_mode_resume_at_the_loop_entry_makes_the_write_unreachable():
    """`rsm` returns to the state SMM interrupted, and raises #UD
    anywhere else. Neither outcome continues at the instruction below
    it, so the loop reaches no write."""
    record = _lead_for(_X86_LOOP_BRANCHING_TO_A_MODE_RESUME, ip_reg="EIP")
    assert any(insn.text.startswith("rsm") for insn in record.instructions)
    assert any(insn.text.startswith("xor") for insn in record.instructions)
    assert record.leads == ()


@_needs_capstone
def test_a_fast_system_call_entry_at_the_loop_entry_makes_the_write_unreachable():
    """`sysenter` saves no user instruction pointer, so nothing in these
    bytes says control comes back below it. The loop reaches no write."""
    record = _lead_for(_X86_LOOP_BRANCHING_TO_A_FAST_SYSTEM_CALL, ip_reg="EIP")
    assert any(insn.text.startswith("sysenter") for insn in record.instructions)
    assert any(insn.text.startswith("xor") for insn in record.instructions)
    assert record.leads == ()


@_needs_capstone
def test_the_same_loop_without_the_undefined_opcode_still_reports_its_write():
    """The control for the three cases above: with those two bytes
    replaced by NOPs and nothing else changed, the loop reaches its
    write."""
    (lead,) = _lead_for(_X86_LOOP_WITH_THE_UNDEFINED_OPCODE_REPLACED,
                        ip_reg="EIP").leads
    assert lead.name == "memory_transform_loop"


@_needs_capstone
def test_a_far_jump_ends_the_run_exactly_as_a_near_one_does():
    """`ljmp` is unconditional. Every run of this loop leaves through it
    before reaching the write, so the write is not something the loop
    transforms -- and the decode layer decides that from the instruction
    id, not from the mnemonic text."""
    record = _lead_for(_X86_LOOP_BRANCHING_TO_A_FAR_JUMP, ip_reg="EIP")
    assert record.architecture == "x86"
    assert any(insn.text.startswith("ljmp") for insn in record.instructions)
    assert any(insn.text.startswith("xor") for insn in record.instructions)
    assert record.leads == ()


@_needs_capstone
def test_the_same_loop_without_the_far_jump_still_reports_its_write():
    """The control for the case above: with the far jump replaced by
    NOPs and nothing else changed, the loop reaches its write."""
    record = _lead_for(_X86_LOOP_WITH_A_REACHABLE_WRITE, ip_reg="EIP")
    (lead,) = record.leads
    assert lead.name == "memory_transform_loop"


@_needs_capstone
def test_a_far_return_ends_the_run_like_a_near_one():
    record = _lead_for(_LOOP_WITH_A_FAR_RETURN_IN_THE_BODY)
    assert any(insn.text.startswith("retf") for insn in record.instructions)
    assert record.leads == ()


@_needs_capstone
def test_a_loop_that_branches_to_a_return_runs_no_write():
    """The write lies between the branch target and the branch, and no
    run of the loop reaches it: the target is a `ret`. An address inside
    the span is not reachability, so there is no lead at all -- not even
    the base one."""
    record = _lead_for(_LOOP_BRANCHING_TO_A_RETURN)
    assert any(insn.text.startswith("xor") for insn in record.instructions)
    assert record.leads == ()


@_needs_capstone
def test_a_write_cut_off_from_its_closing_branch_runs_no_loop():
    """The other end of the same rule: a `ret` after the write ends the
    run before the branch that would close the loop is reached."""
    record = _lead_for(_WRITE_CUT_OFF_FROM_ITS_CLOSING_BRANCH)
    assert any(insn.text.startswith("xor") for insn in record.instructions)
    assert record.leads == ()


@_needs_capstone
def test_a_branch_into_the_middle_of_an_instruction_is_not_a_loop_entry():
    """The branch target has to be an instruction boundary this decode
    produced. An address inside a decoded instruction is not a loop entry
    this run can reason about."""
    record = _lead_for(_LOOP_BRANCHING_INTO_THE_MIDDLE_OF_AN_INSTRUCTION)
    assert record.leads == ()


@_needs_capstone
def test_nothing_follows_an_unconditional_backward_jump():
    """A conditional branch falls through to what comes after the loop; an
    unconditional one never does. The register-indirect `call` sitting
    after it is not reachable from the loop, so the signal is absent --
    the loop itself is still reported."""
    (lead,) = _lead_for(_LOOP_CLOSED_BY_AN_UNCONDITIONAL_JUMP).leads
    assert lead.name == "memory_transform_loop"
    assert "register_transfer_after_loop" not in lead.signals


@_needs_capstone
def test_a_window_with_no_write_loop_reports_no_lead():
    record = _lead_for(b"\x48\x83\xc0\x10\x48\xff\xc0\xc3")   # add, inc, ret
    assert record.leads == ()


@_needs_capstone
def test_a_memory_write_outside_the_loop_span_reports_no_lead():
    """The write has to be inside the span the backward branch closes. A
    loop and a store that merely share a window are not a loop that runs
    the store."""
    #   sub rcx, 1 / jne back to itself / xor byte ptr [rax], 0x41 / ret
    record = _lead_for(bytes.fromhex("4883e901" "75fa" "803041" "c3"))
    assert any(insn.text.startswith("xor") for insn in record.instructions)
    assert record.leads == ()


@_needs_capstone
def test_a_branch_into_unbacked_private_memory_still_resolves_its_region():
    """A direct target no module owns is still placed by the captured
    region table, which is what the console labels it with -- no extra
    field on the published record is needed to say so."""
    record = _lead_for(_SELF_DECODING_STUB)
    direct = [t for t in record.branch_targets if t.kind == "direct"]
    assert direct
    assert all(t.module_owner is None for t in direct)
    assert all(t.region_type == "MEM_PRIVATE" for t in direct)
    assert all(t.registration == "unregistered" for t in direct)


def test_va_location_resolution_is_memoised_across_calls(monkeypatch):
    import dumpex.commands.report_enrichment as re_mod
    from dumpex.commands.report_enrichment import _resolve_target

    calls = []
    real = re_mod.resolve_va_location

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(re_mod, "resolve_va_location", counting)
    cache = _cache(_pe_mf())
    region_evidence = RegionEvidence.from_dump(_pe_mf())
    _resolve_target(cache, PE_THUNK_TARGET_VA, region_evidence)
    _resolve_target(cache, PE_THUNK_TARGET_VA, region_evidence)
    _resolve_target(cache, PE_THUNK_TARGET_VA, region_evidence)
    assert len(calls) == 1


def test_parse_iat_runs_once_per_module_per_invocation(monkeypatch):
    import dumpex.commands.report_enrichment as re_mod

    bases = []
    real = re_mod.parse_iat

    def counting(read, image_base, pe):
        bases.append(image_base)
        return real(read, image_base, pe)

    monkeypatch.setattr(re_mod, "parse_iat", counting)
    cache = _cache(_pe_mf())
    cache.iat_at_base(PE_IMAGE_BASE)
    cache.iat_at_base(PE_IMAGE_BASE)
    cache.iat_at_base(PE_IMAGE_BASE)
    assert bases == [PE_IMAGE_BASE]


@_needs_capstone
def test_a_bad_opcode_near_the_byte_cap_is_a_decode_error_not_a_tail():
    # 46 eleven-byte NOPs fill the window to offset 506, then an invalid
    # 0x06 leaves 6 bytes -- fewer than one instruction. The window is cut
    # by the 512-byte cap, but the region has more bytes and the tail
    # still would not decode: a possible anti-disassembly artefact, not a
    # cut-short instruction.
    nop11 = b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"
    code = nop11 * 46 + b"\x06" + b"\x90" * 20
    mf = _private_code_mf(code)
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")
    assert record.decoder_state == "decode_error"
    assert record.section.status == ENRICHMENT_PARTIAL


@_needs_capstone
def test_wow64_process_private_code_is_decoded_x86(monkeypatch):
    # SystemInfo reports the AMD64 host; the main image is I386; the anchor
    # is in unbacked private code and there is no anchor thread.
    mf = _pe_mf()
    memory = bytearray(_pe_image_memory())
    memory[0x84:0x86] = (0x014C).to_bytes(2, "little")   # main image Machine -> I386
    mf._reader = EnvReader(EnvBufferedReader({
        PE_IMAGE_BASE: bytes(memory),
        PE_KERNEL_BASE: bytes(0x4000),
        _PRIVATE_CODE_VA: b"\xe8\xfb\x00\x00\x00\xc3"}))
    mf.memory_info = FakeStream(list(mf.memory_info.infos) + [
        Region(_PRIVATE_CODE_VA, _PRIVATE_CODE_VA, 0x1000, "MEM_COMMIT",
               "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")], "infos")
    mf.memory_segments_64 = FakeStream(list(mf.memory_segments_64.memory_segments) + [
        Segment(_PRIVATE_CODE_VA, 0x7000, 8)], "memory_segments")
    mf.sysinfo = types.SimpleNamespace(
        ProcessorArchitecture=types.SimpleNamespace(name="AMD64"))
    mf.threads = None
    monkeypatch.setattr(report_mod, "read_region", mem_reader({_PRIVATE_CODE_VA: b"\x00"}))
    result = collect_report(mf, report_addr=hex(_PRIVATE_CODE_VA))
    ic = result.records[0].instruction_context
    assert ic is not None
    assert ic.architecture == "x86"
    assert ic.decoder_state == "decoded"


def test_explicit_report_addr_leads_the_instruction_anchor_priority(monkeypatch):
    mf = _pe_mf()
    # The anchor thread's live RIP is elsewhere; the explicit --report-addr
    # is what the analyst pointed at and must lead.
    mf.threads = FakeStream([Thread(ANCHOR_TID, Ctx(PE_KERNEL_BASE + 0x200))], "threads")
    monkeypatch.setattr(
        report_mod, "read_region",
        mem_reader({PE_ENTRY_VA: b"\xff\x15\xfa\x0f\x00\x00\xc3"}))
    result = collect_report(mf, report_tid=hex(ANCHOR_TID), report_addr=hex(PE_ENTRY_VA))
    card = result.records[0]
    assert card.instruction_context is not None
    assert card.instruction_context.anchor_source == "card_anchor"
    assert card.instruction_context.anchor_address == f"0x{PE_ENTRY_VA:016x}"


@_needs_capstone
def test_indirect_memory_branch_is_uncertain_when_the_iat_bounds_are_unreadable():
    mf = _pe_mf()
    kern = bytearray(0x4000)
    kern[0x1000:0x1006] = b"\xff\x15\x10\x00\x00\x00"   # call qword [rip + 0x10]
    kern[0x1006] = 0xC3
    mf._reader = EnvReader(EnvBufferedReader({
        PE_IMAGE_BASE: _pe_image_memory(), PE_KERNEL_BASE: bytes(kern)}))
    record, slots = _instruction(
        _cache(mf), mf, [("card_anchor", PE_KERNEL_BASE + 0x1000)],
        base=PE_KERNEL_BASE, iat_raw=None)
    assert record.decoder_state == "decoded"
    assert record.section.status == ENRICHMENT_PARTIAL
    assert any("not confirmed to be outside the IAT" in note
               for note in record.section.limitations)
    (target,) = [t for t in record.branch_targets if t.kind == "indirect_memory"]
    assert target.target_address == f"0x{PE_KERNEL_BASE + 0x1006 + 0x10:016x}"
    assert target.iat_classification_uncertain is True
    assert slots == ()


@_needs_capstone
def test_a_legit_instruction_crossing_the_byte_cap_is_a_byte_cap_not_an_error():
    nop11 = b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"
    # 46 eleven-byte NOPs to offset 506, then a seven-byte call the window
    # cuts; the lookahead completes it.
    code = nop11 * 46 + b"\xff\x14\x25\x11\x22\x33\x44" + b"\x90" * 10
    mf = _private_code_mf(code)
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")
    assert record.decoder_state == "decoded"
    assert record.section.status == ENRICHMENT_PARTIAL
    assert record.section.total is None
    assert all("invalid opcode" not in note for note in record.section.limitations)


@_needs_capstone
def test_a_short_capture_with_no_decode_reports_an_unknown_total():
    mf = _private_code_mf(b"\xc3\xc3\xc3")
    mf.threads = None
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, None), mf, [("card_anchor", _PRIVATE_CODE_VA)],
        base=None, thread_ip_reg=None)
    assert record.decoder_state == "arch_undetermined"
    assert record.section.status == ENRICHMENT_PARTIAL
    assert record.section.total is None       # 3 bytes may hold 1-3 instructions
    assert record.section.included == 0


@_needs_capstone
def test_iat_correlation_incomplete_walk_reports_an_unknown_total():
    mf = _pe_mf()
    cache = _cache(mf)
    correlation = collect_iat_correlation(
        cache, anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=_iat_raw(import_directory_present=True, entries=(), dll_count=1,
                         entry_count=0, unterminated_table=True),
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=())
    assert correlation.section.status == ENRICHMENT_PARTIAL
    assert correlation.section.total is None


@_needs_capstone
def test_a_short_tail_with_partial_lookahead_is_undecoded_tail_not_decode_error():
    # An eleven-byte NOP begins at offset 506; the capture ends at 513, so
    # only 7 of its bytes are available -- not enough to prove it invalid.
    nop11 = b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"
    code = nop11 * 46 + nop11[:7]
    mf = _private_code_mf(code)
    record, _slots = _instruction(
        PeProfileCache.from_dump(mf, hex(PE_IMAGE_BASE)), mf,
        [("thread_rip", _PRIVATE_CODE_VA)], base=None, thread_ip_reg="RIP")
    assert record.decoder_state == "undecoded_tail"
    assert record.section.status == ENRICHMENT_PARTIAL


@_needs_capstone
def test_iat_correlation_incomplete_walk_still_reports_retention_truncation():
    mf = _pe_mf()
    cache = _cache(mf)
    slots = [PE_IMAGE_BASE + 0x2000 + i * 8 for i in range(20)]
    entries = tuple(
        types.SimpleNamespace(
            import_by="name", dll="K32.dll", symbol=f"F{i}", ordinal=None,
            iat_slot_va=slot, resolved_target_va=0xdead0000, slot_in_bounds=False)
        for i, slot in enumerate(slots))
    correlation = collect_iat_correlation(
        cache, anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=_iat_raw(import_directory_present=True, entries=entries, dll_count=1,
                         entry_count=len(entries), unterminated_table=True),
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=())
    assert correlation.section.status == ENRICHMENT_PARTIAL
    assert correlation.section.total is None           # walk was incomplete
    assert correlation.section.truncated is True       # >16 known-eligible, cap dropped some
    assert correlation.section.included == 16


def test_iat_correlation_no_import_directory_has_no_missed_slot_limitation():
    mf = _pe_mf()
    correlation = collect_iat_correlation(
        _cache(mf), anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=_iat_raw(import_directory_present=False, directory_table_incomplete=True),
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=())
    assert correlation.section.status == ENRICHMENT_COMPLETE
    assert any("declares no import directory" in note
              for note in correlation.section.limitations)
    assert all("could not be evaluated" not in note
               for note in correlation.section.limitations)


def test_iat_correlation_name_read_failure_keeps_an_exact_total():
    mf = _pe_mf()
    entry = types.SimpleNamespace(
        import_by="ordinal", dll="K32.dll", symbol=None, ordinal=7,
        iat_slot_va=PE_IMAGE_BASE + 0x2000, resolved_target_va=0xdead0000,
        slot_in_bounds=False)
    correlation = collect_iat_correlation(
        _cache(mf), anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=_iat_raw(import_directory_present=True, entries=(entry,), dll_count=1,
                         entry_count=1, name_read_failed_count=1),
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=())
    assert correlation.section.status == ENRICHMENT_PARTIAL
    assert correlation.section.total == 1        # population fully enumerated
    assert correlation.section.included == 1
    assert any("import symbol name" in note for note in correlation.section.limitations)
    assert all("could not be evaluated" not in note
               for note in correlation.section.limitations)


def test_iat_correlation_unknown_directory_bounds_make_the_total_undeterminable():
    mf = _pe_mf()
    # The slot's in-bounds check could not run because the IAT directory
    # bounds are unreadable -- it might belong in the eligible set.
    entry = types.SimpleNamespace(
        import_by="name", dll="K32.dll", symbol="Sleep", ordinal=None,
        iat_slot_va=PE_IMAGE_BASE + 0x2000, resolved_target_va=None,
        slot_in_bounds=None)
    correlation = collect_iat_correlation(
        _cache(mf), anchor_module=mf.modules.modules[0], anchor_module_base=PE_IMAGE_BASE,
        iat_raw=_iat_raw(import_directory_present=True, table_present=None,
                         directory_table_incomplete=True, entries=(entry,),
                         dll_count=1, entry_count=1),
        region_evidence=RegionEvidence.from_dump(mf), instruction_slot_vas=())
    assert correlation.section.status == ENRICHMENT_PARTIAL
    assert correlation.section.total is None
    assert correlation.iat_directory_present is None
    assert any("IAT directory bounds are undetermined" in note
               for note in correlation.section.limitations)


# ── decoder guidance: accurate for how this process was packaged ──────

import builtins  # noqa: E402

from dumpex.core import runtime  # noqa: E402
from dumpex.core.disasm import DisasmBackend, DisasmBackendStatus  # noqa: E402
from dumpex.commands.report_enrichment import (  # noqa: E402
    _decoder_unavailable_limitation,
)
from dumpex.output.records import ENRICHMENT_TEXT_CAP  # noqa: E402


def _unloadable_capstone(monkeypatch, exc=None):
    """Make ``import capstone`` fail the way a packaged build with a
    missing or incompatible native library fails."""
    exc = exc or ImportError("ERROR: fail to load the dynamic library.")
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "capstone" or name.startswith("capstone."):
            raise exc
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def _limitation(context) -> str:
    (limitation,) = [text for text in context.section.limitations
                     if "disassembler" in text]
    return limitation


def test_a_python_install_without_the_decoder_is_told_it_is_incomplete(monkeypatch):
    # The decoder is a base dependency, so a Python install that lacks it
    # is broken rather than merely missing an unrequested feature.
    monkeypatch.setattr(runtime.sys, "frozen", False, raising=False)
    monkeypatch.setitem(sys.modules, "capstone", None)
    mf = _pe_mf()
    context, _slots = _instruction(_cache(mf), mf, [("card_anchor", PE_ENTRY_VA)])
    limitation = _limitation(context)
    assert context.decoder_state == "unavailable"
    assert "this installation is incomplete" in limitation
    assert "dumpex[disasm]" not in limitation


def test_a_frozen_runtime_is_never_told_to_pip_install(monkeypatch):
    monkeypatch.setattr(runtime.sys, "frozen", True, raising=False)
    monkeypatch.setitem(sys.modules, "capstone", None)
    mf = _pe_mf()
    context, _slots = _instruction(_cache(mf), mf, [("card_anchor", PE_ENTRY_VA)])
    limitation = _limitation(context)
    assert context.decoder_state == "unavailable"
    assert "pip" not in limitation
    assert "distribution defect" in limitation


def test_a_packaged_backend_that_did_not_load_is_a_distribution_defect(monkeypatch):
    monkeypatch.setattr(runtime.sys, "frozen", True, raising=False)
    _unloadable_capstone(monkeypatch)
    mf = _pe_mf()
    context, _slots = _instruction(_cache(mf), mf, [("card_anchor", PE_ENTRY_VA)])
    limitation = _limitation(context)
    assert context.decoder_state == "unavailable"
    assert "did not load (ImportError)" in limitation
    assert "pip" not in limitation


def test_an_installed_backend_that_did_not_load_is_not_called_uninstalled(monkeypatch):
    monkeypatch.setattr(runtime.sys, "frozen", False, raising=False)
    _unloadable_capstone(monkeypatch)
    mf = _pe_mf()
    context, _slots = _instruction(_cache(mf), mf, [("card_anchor", PE_ENTRY_VA)])
    limitation = _limitation(context)
    assert "this installation is incomplete" not in limitation
    assert "did not load (ImportError)" in limitation


def test_the_limitation_carries_no_path_and_no_traceback(monkeypatch):
    _unloadable_capstone(monkeypatch, OSError(
        r"cannot load D:\build-agent\lib\capstone.dll"))
    mf = _pe_mf()
    context, _slots = _instruction(_cache(mf), mf, [("card_anchor", PE_ENTRY_VA)])
    limitation = _limitation(context)
    assert "D:\\" not in limitation
    assert "Traceback" not in limitation
    assert len(limitation) <= ENRICHMENT_TEXT_CAP


def test_every_decoder_limitation_stays_within_the_enrichment_text_cap(monkeypatch):
    for frozen in (False, True):
        monkeypatch.setattr(runtime.sys, "frozen", frozen, raising=False)
        for backend in (
                DisasmBackend(status=DisasmBackendStatus.MODULE_ABSENT),
                DisasmBackend(status=DisasmBackendStatus.LOAD_FAILURE,
                              exception_type="ImportError"),
                None):
            assert len(_decoder_unavailable_limitation(backend)) <= ENRICHMENT_TEXT_CAP


def test_an_unclassified_backend_keeps_the_absent_dependency_wording(monkeypatch):
    # A decode result that carries no backend record names no exception
    # type; the safe reading is the dependency being absent.
    monkeypatch.setattr(runtime.sys, "frozen", False, raising=False)
    assert "this installation is incomplete" in _decoder_unavailable_limitation(None)

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
from dumpex.core.disasm import disasm_available
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
    assert any("more than the" in note for note in record.section.limitations)


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
    assert "ANCHOR IN THE PE IMAGE" in out
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

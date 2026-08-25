"""
Integration tests for dumpex.hunt.cmd_hunt() -- the --hunt CLI dispatcher
that wraps each individual hunter's findings and sanitizes them for JSON
serialization (int-keyed field dicts -> str keys, bytes -> hex).

The CS Beacon sanitization step used to hand-reconstruct each config dict
field-by-field, which silently dropped any field _hunt_cs_beacon added
that this dispatcher didn't already know about (context_corroborated,
cs_version_note) -- these tests pin that every field a hunter reports
survives the dispatcher unchanged.

`test_report_fields_survive_the_dispatcher()` below generalizes this to
all seven `HUNTERS`, and to both `cmd_hunt()` and `collect_hunt()` (issue
#72's own cutover, per `docs/hunt_analyzer_registry_contract.md` §12's
note that #72 "should extend this file to a HUNTERS-parametrized
field-survives-the-dispatcher check ... covering both cmd_hunt() and
collect_hunt()" -- registry-driven dispatch removes the per-hunter
hand-rolled reconstruction the original CS-Beacon-only test exists to
guard against, which is exactly what makes a general version of it cheap
to add).
"""
import base64

import pytest

from tests.fixtures.fakes import (
    Region, Module, ThreadInfo, Ctx, Thread, Handle, Segment, FakeReader, FakeStream,
    FakeMF, Peb, build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    mem_reader, matching_module_and_ref, cs_beacon_config_bytes,
)

import dumpex.hunt as hunt
import dumpex.hunt.injection as injection
import dumpex.hunt.hollowing as hollowing
import dumpex.hunt.stomping as stomping
import dumpex.hunt.pipe as pipemod
import dumpex.hunt.encoding as encoding
from dumpex.hunt._registry import REGISTRY
from dumpex.output.records import HUNTERS


def _mk_segment_data(config_bytes: bytes, pad_before: int = 0x100, pad_after: int = 0x100) -> bytes:
    return b'\x00' * pad_before + config_bytes + b'\x00' * pad_after


def test_cs_beacon_config_fields_survive_dispatcher():
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    # executable + private -> context-corroborated, so context_corroborated
    # is not just present but actually True, and cs_version_note is set.
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    results = hunt.cmd_hunt(MF(), "cs-beacon", verbose=False)
    cfg = results["cs-beacon"]["configs"][0]
    assert cfg["context_corroborated"] is True
    assert "cs_version_note" in cfg and cfg["cs_version_note"]
    assert cfg["cs_version"]
    assert cfg["xor_key"] == 0x69
    # fields dict must still be JSON-safe (str keys, no raw bytes objects)
    assert all(isinstance(k, str) for k in cfg["fields"].keys())
    assert isinstance(cfg["fields"]["1"]["raw"], str)


# ── HUNTERS-parametrized generalization (issue #72) ──────────────────────
#
# Each scenario builder below returns `(mf_factory, cli_kwargs)`:
# `mf_factory` is a zero-argument callable that returns a FRESH `MF`
# instance with the same synthetic data every call (never a shared, once-
# built instance -- a `Report` built from one already-consumed `mf` cannot
# safely be built a second time, since several hunters' own FakeMF-backed
# streams are one-shot), and `cli_kwargs` is the subset of
# `{"ref_dir": ..., "yara_dir": ...}` (cmd_hunt()'s/collect_hunt()'s own
# EXTERNAL option names) this scenario needs. Every scenario is a non-
# trivial DETECTED case (adapted from tests/fixtures/hunt_cases.py's own
# scenarios of the same shape), not `empty_mf()`'s NOT_EVALUATED path --
# a report with real, populated fields is what actually exercises "does a
# reconstruction step at the dispatcher layer drop or transform a field",
# the concrete regression this whole file exists to catch.

def _injection_scenario(monkeypatch, tmp_path):
    alloc_base = 0x7ff700000000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000, "rawptr": 0x400,
          "rawsize": 0x1000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, alloc_base + 0x2000)]
    thread_list = [Thread(0x1, Ctx(alloc_base + 0x2000))]
    monkeypatch.setattr(injection, "read_region", mem_reader({alloc_base + 0x2000: pe_bytes}))

    def mf_factory():
        class MF(FakeMF):
            memory_info = FakeStream(regions, "infos")
            modules      = FakeStream(mods, "modules")
            thread_info   = FakeStream(thread_infos, "infos")
            threads        = FakeStream(thread_list, "threads")
        return MF()
    return mf_factory, {}


def _hollowing_scenario(monkeypatch, tmp_path):
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    monkeypatch.setattr(hollowing, "read_region", mem_reader({image_base: b"MZ" + b"\x90" * 62}))

    def mf_factory():
        class MF(FakeMF):
            peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
            modules = FakeStream([module], "modules")
            memory_info = FakeStream(regions, "infos")
        return MF()
    return mf_factory, {}


def _stomping_scenario(monkeypatch, tmp_path):
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    tampered_text = bytes(b ^ 0xFF for b in mem_text)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]
    monkeypatch.setattr(stomping, "read_region", mem_reader(
        {module_base: header, module_base + section["vaddr"]: tampered_text}))
    (tmp_path / "legit.dll").write_bytes(ref_file)

    def mf_factory():
        class MF(FakeMF):
            memory_info = FakeStream(regions, "infos")
            modules      = FakeStream(mods, "modules")
        return MF()
    return mf_factory, {"ref_dir": str(tmp_path)}


def _pipe_scenario(monkeypatch, tmp_path):
    region_base = 0x1230000
    pipe_name = b"\\\\.\\pipe\\msagent_1337"
    pipe_off = 0x100
    data = (b"A" * pipe_off + pipe_name + b"\x00"
            + b"http://198.51.100.7:8080/submit.php" + b"B" * 0x200)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_PRIVATE")]
    handle_list = [Handle(0x88, "File", r"\Device\NamedPipe\msagent_1337")]
    thread_infos = [ThreadInfo(0x999, region_base + 0x10)]
    pipe_va = region_base + pipe_off
    monkeypatch.setattr(pipemod, "read_region", mem_reader({region_base: data}))
    monkeypatch.setattr(pipemod, "get_thread_contexts", lambda mf: [
        {"ThreadId": 0x999, "ip": pipe_va + 5, "ip_reg": "RIP", "is_wow64": False}])

    def mf_factory():
        class MF(FakeMF):
            memory_info = FakeStream(regions, "infos")
            modules      = FakeStream([], "modules")
            thread_info   = FakeStream(thread_infos, "infos")
            handles        = FakeStream(handle_list, "handles")
        return MF()
    return mf_factory, {}


def _cs_beacon_scenario(monkeypatch, tmp_path):
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    def mf_factory():
        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            memory_info          = FakeStream(regions, "infos")
            _reader                = FakeReader({seg_va: data})
        return MF()
    return mf_factory, {}


def _yara_scenario(monkeypatch, tmp_path):
    seg_va, seg_fo = 0x50000, 0x5000
    data = b"A" * 0x100 + b"FINDME_MARKER" + b"B" * 0x100
    (tmp_path / "hit.yar").write_text(
        'rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
    seg = Segment(seg_va, seg_fo, len(data))

    def mf_factory():
        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        return MF()
    return mf_factory, {"yara_dir": str(tmp_path)}


def _obfuscation_scenario(monkeypatch, tmp_path):
    region_base = 0x300000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    monkeypatch.setattr(encoding, "read_region", mem_reader({region_base: b64_pe.ljust(0x1000, b"\x00")}))

    def mf_factory():
        class MF(FakeMF):
            memory_info = FakeStream(regions, "infos")
            modules      = FakeStream([], "modules")
        return MF()
    return mf_factory, {}


_SCENARIO_BUILDERS = {
    "injection": _injection_scenario,
    "hollowing": _hollowing_scenario,
    "stomping": _stomping_scenario,
    "pipe": _pipe_scenario,
    "cs-beacon": _cs_beacon_scenario,
    "yara": _yara_scenario,
    "obfuscation": _obfuscation_scenario,
}
assert set(_SCENARIO_BUILDERS) == set(HUNTERS)


@pytest.mark.parametrize("identity", HUNTERS)
def test_report_fields_survive_the_dispatcher(monkeypatch, tmp_path, capsys, identity):
    """Since issue #72's cutover, `cmd_hunt()`/`collect_hunt()` never
    touch a Report's fields themselves -- both call `spec.renderer(report,
    verbose)`/`spec.record_projector(report)` directly, via
    `dumpex.hunt._execute_full_scope()` -- so this proves "every field
    survives the dispatcher" by equivalence: a Report built directly
    through `AnalyzerRegistry`'s own `builder`/`renderer`/
    `record_projector` for this identity must produce EXACTLY what
    `cmd_hunt()`/`collect_hunt()` themselves return for a fresh,
    identically-built Report of the same scenario -- proving neither
    function reconstructs, drops, or transforms a single field along the
    way, the same property `test_cs_beacon_config_fields_survive_
    dispatcher()` above pins by hand for one hunter and one hard-coded
    field set."""
    if identity == "yara":
        pytest.importorskip("yara")

    mf_factory, cli_kwargs = _SCENARIO_BUILDERS[identity](monkeypatch, tmp_path)
    spec = REGISTRY.get(identity)
    options = {"ref_dir": cli_kwargs.get("ref_dir"), "rules_dir": cli_kwargs.get("yara_dir")}
    builder_kwargs = {name: options[name] for name in spec.option_names}

    reference_report = spec.builder(mf_factory(), **builder_kwargs)
    expected_rendered = spec.renderer(reference_report, False)
    expected_record = spec.record_projector(reference_report).to_dict()

    actual_results = hunt.cmd_hunt(mf_factory(), identity, verbose=False, **cli_kwargs)
    assert actual_results[identity] == expected_rendered

    collected = hunt.collect_hunt(mf_factory(), identity, **cli_kwargs)
    assert collected.records[0].to_dict() == expected_record

    capsys.readouterr()   # drain cmd_hunt()'s console output

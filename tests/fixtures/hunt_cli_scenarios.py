"""
Single source of truth for every `--hunt` CLI golden scenario's FakeMF
construction -- shared by tests/integration/test_hunt_cli_compat_freeze.py
(which runs each scenario normal AND --verbose, parametrized) and
scripts/update_hunt_cli_goldens.py (which regenerates the golden fixtures
those tests diff against). Before this module existed, the two had their
own independent copies of every fixture's construction code, which is
exactly the kind of drift a golden-fixture suite exists to prevent
elsewhere but was quietly exposed to itself.

Each `HuntCliScenario.build(monkeypatch, tmp_path)` returns a
`BuiltScenario` bundling the FakeMF plus whatever CLI args/rules-dir
placeholder that scenario needs -- never a bare MF, so a scenario that
needs `--ref-dir`/`--yara-dir` doesn't need a special case at the call
site.

`expected_exit_code` (default 0) is asserted for EVERY scenario, not just
ones with `extra_checks` -- exit code isn't captured in any golden fixture
(JSON/console text say nothing about the process's own exit code), so
without this a CLI regression that silently changed e.g. hollowing's exit
code from 0 to 3 would pass both `--check` and the parametrized pytest
with zero diff anywhere.

`extra_checks(exit_code, doc, body)` is an optional hook for further
scenario-specific semantic assertions (DETECTED vs. INCONCLUSIVE,
coverage.status, a Finding appearing exactly once in `body`, the
normalized -- rules-dir-substituted -- console text) that either
`expected_exit_code` doesn't cover or that a pure byte-diff against a
golden fixture wouldn't itself explain if it failed -- see each scenario's
own comment for why its assertion is there. Called unconditionally by
BOTH scripts/update_hunt_cli_goldens.py and the parametrized test, for
both the normal and --verbose run of a scenario, so a regression can never
be "fixed" by regenerating goldens without `extra_checks` itself failing
first and blocking the write.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from dumpex.output.envelope import SCHEMA_VERSION


@dataclass
class BuiltScenario:
    mf: object
    extra_argv: list = field(default_factory=list)
    rules_dir: Optional[Path] = None   # set only when --yara-dir was passed


@dataclass
class HuntCliScenario:
    name: str                                   # golden fixture prefix (usually == ttp)
    ttp: str                                     # --hunt <ttp> value
    build: Callable[[object, Path], BuiltScenario]
    needs_yara: bool = False
    expected_exit_code: int = 0
    extra_checks: Optional[Callable[[int, dict, str], None]] = None


def _build_injection(monkeypatch, tmp_path) -> BuiltScenario:
    from tests.fixtures.fakes import (FakeMF, FakeStream, Region, Module, ThreadInfo, Ctx, Thread,
        build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)
    import dumpex.hunt.injection as injection
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
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream(mods, "modules")
    mf.thread_info = FakeStream(thread_infos, "infos")
    mf.threads = FakeStream(thread_list, "threads")
    monkeypatch.setattr(injection, "read_region", mem_reader({alloc_base + 0x2000: pe_bytes}))
    return BuiltScenario(mf=mf)


def _check_injection(exit_code, doc, body):
    # expected_exit_code=3 (below) already covers the EXIT_PARTIAL check --
    # one of this scenario's two memory-info regions is a short read while
    # checking for hidden PE headers, so status is DETECTED (score 3/3) but
    # coverage.status is "partial", independent dimensions. This hook only
    # adds the semantics a byte-diff wouldn't itself explain if it failed.
    assert doc["meta"]["schema_version"] == SCHEMA_VERSION
    assert doc["meta"]["execution"]["command"] == "hunt_injection"
    assert doc["meta"]["execution"]["started_at"] == "2024-01-01T00:00:00Z"
    assert doc["result"]["kind"] == "hunt"
    assert doc["result"]["data"]["records"][0]["status"] == "DETECTED"
    assert doc["result"]["coverage"]["status"] == "partial"
    assert [r["hunter"] for r in doc["result"]["data"]["records"]] == ["injection"]


def _build_hollowing(monkeypatch, tmp_path) -> BuiltScenario:
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Module, Peb, mem_reader
    import dumpex.hunt.hollowing as hollowing
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    mf = FakeMF()
    mf.peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
    mf.modules = FakeStream([module], "modules")
    mf.memory_info = FakeStream(regions, "infos")
    monkeypatch.setattr(hollowing, "read_region", mem_reader({image_base: b"MZ" + b"\x90" * 62}))
    return BuiltScenario(mf=mf)


def _check_hollowing(exit_code, doc, body):
    # Regression guard for the duplicate rendering the verdict-first
    # console (issue #10) removed: the pre-migration renderer printed a
    # terse `_print_check` status block for each of the four checks AND
    # THEN every Finding in construction order, so each check reached the
    # transcript twice, in two different vocabularies. Counted on the
    # check's human TITLE, which is what the new console prints in BOTH
    # modes (the raw check id only appears under --verbose, so counting
    # that alone would read 0 in normal mode and prove nothing). Checked
    # here rather than only via a golden byte-diff so a
    # `scripts/update_hunt_cli_goldens.py` run made WHILE the duplication
    # is back fails before it can write a fixture baking it in.
    for title in ("Correlated structural hollowing indicators",
                  "MEM_PRIVATE memory at the image base",
                  "RWX protection at the image base"):
        assert body.count(title) == 1, title
    # The raw image-base facts belong to the bounded --verbose evidence
    # section only; normal-mode triage output must not carry them.
    if "IMAGE BASE\n" in body:
        assert "PEB ImagePath:" in body
    else:
        assert "PEB ImagePath" not in body


def _build_stomping(monkeypatch, tmp_path) -> BuiltScenario:
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Module, mem_reader, matching_module_and_ref
    import dumpex.hunt.stomping as stomping
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    tampered_text = bytes(b ^ 0xFF for b in mem_text)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream(mods, "modules")
    monkeypatch.setattr(stomping, "read_region", mem_reader(
        {module_base: header, module_base + section["vaddr"]: tampered_text}))
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    (ref_dir / "legit.dll").write_bytes(ref_file)
    return BuiltScenario(mf=mf, extra_argv=["--ref-dir", str(ref_dir)])


def _build_stomping_ioc_hit(monkeypatch, tmp_path) -> BuiltScenario:
    """A genuine content-change detection AND an IOC-string lead in the
    same dump -- regression fixture for the stomping.ioc_string_lead
    duplicate-print bug (presentation.py used to hand-render its own
    summary line for this Finding AND ALSO print every Finding in
    report.findings_list unconditionally). `mimikatz` is XOR-encoded into
    the fixture's clean text BEFORE the stomping-simulation XOR is
    applied, so it decodes back to a readable IOC string once "tampered"
    -- matching how the hunter actually reads it out of (simulated)
    memory."""
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Module, mem_reader, matching_module_and_ref
    import dumpex.hunt.stomping as stomping
    module_base = 0x7ff600000000
    raw_mimikatz_xored = bytes(b ^ 0xFF for b in b"mimikatz")
    filler = bytearray((i * 7) % 251 for i in range(0x2000))
    filler[0x40:0x40 + 8] = raw_mimikatz_xored
    header, mem_text, ref_file, section = matching_module_and_ref(module_base, text_bytes=bytes(filler))
    tampered_text = bytes(b ^ 0xFF for b in mem_text)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream(mods, "modules")
    monkeypatch.setattr(stomping, "read_region", mem_reader(
        {module_base: header, module_base + section["vaddr"]: tampered_text}))
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    (ref_dir / "legit.dll").write_bytes(ref_file)
    return BuiltScenario(mf=mf, extra_argv=["--ref-dir", str(ref_dir)])


def _check_stomping_ioc_hit(exit_code, doc, body):
    findings = doc["result"]["data"]["records"][0]["findings"]
    ioc_findings = [f for f in findings if f["check"] == "stomping.ioc_string_lead"]
    assert len(ioc_findings) == 1
    # Regression guard for the duplicate-print bug this scenario exists
    # for: presentation.py used to hand-render its own summary line for
    # this Finding (under the human label "IOC strings in module code
    # regions (lead)") AND ALSO print every Finding in
    # report.findings_list unconditionally. Checked here (not just via a
    # golden byte-diff) so a `scripts/update_hunt_cli_goldens.py` run made
    # WHILE the bug is back fails before it can write a fixture that
    # "fixes" the diff by baking the duplicate in as the new expected
    # output.
    #
    # Counted on the check's human TITLE, which is what the verdict-first
    # console (issue #8) prints in BOTH modes -- the raw check id only
    # appears under --verbose, so counting that alone would read 0 in
    # normal mode and prove nothing (it also never caught the original
    # bug, whose duplicate block used the human label rather than the id).
    assert body.count("IOC strings in module code regions") == 1
    assert body.count("stomping.ioc_string_lead") <= 1
    assert "IOC strings in module code regions (lead)" not in body


def _build_pipe(monkeypatch, tmp_path) -> BuiltScenario:
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Handle, ThreadInfo, mem_reader
    import dumpex.hunt.pipe as pipemod
    region_base = 0x1230000
    pipe_name = b"\\\\.\\pipe\\msagent_1337"
    pipe_off = 0x100
    data = (b"A" * pipe_off + pipe_name + b"\x00"
            + b"http://198.51.100.7:8080/submit.php" + b"B" * 0x200)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_PRIVATE")]
    handle_list = [Handle(0x88, "File", r"\Device\NamedPipe\msagent_1337")]
    thread_infos = [ThreadInfo(0x999, region_base + 0x10)]
    pipe_va = region_base + pipe_off
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream([], "modules")
    mf.thread_info = FakeStream(thread_infos, "infos")
    mf.handles = FakeStream(handle_list, "handles")
    monkeypatch.setattr(pipemod, "read_region", mem_reader({region_base: data}))
    monkeypatch.setattr(pipemod, "get_thread_contexts", lambda mf: [
        {"ThreadId": 0x999, "ip": pipe_va + 5, "ip_reg": "RIP", "is_wow64": False}])
    return BuiltScenario(mf=mf)


def _check_pipe(exit_code, doc, body):
    # expected_exit_code=3 (below) already covers the EXIT_PARTIAL check --
    # this FakeMF's memory-string scan hits a short read (see the golden
    # fixture's own coverage.reasons), so status is DETECTED (full
    # corroboration, score 3/3) but coverage.status is "partial".
    assert doc["result"]["data"]["records"][0]["status"] == "DETECTED"
    assert doc["result"]["coverage"]["status"] == "partial"


def _build_cs_beacon(monkeypatch, tmp_path) -> BuiltScenario:
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment, FakeReader, cs_beacon_config_bytes
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = b"\x00" * 0x100 + config + b"\x00" * 0x100
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    mf = FakeMF()
    mf.memory_segments_64 = FakeStream([seg], "memory_segments")
    mf.memory_info = FakeStream(regions, "infos")
    mf._reader = FakeReader({seg_va: data})
    return BuiltScenario(mf=mf)


def _build_cs_beacon_multi(monkeypatch, tmp_path) -> BuiltScenario:
    """Two DISTINCT, uncorroborated beacon configs in one dump -- exercises
    dumpex/hunt/cs_beacon/report_console.py's per-hit identity pairing
    (config #1's own printed BEACON CONFIGS block must show config #1's VA,
    not config #2's -- see tests/hunt/test_cs_beacon_domain.py's own
    corroborated-sorts-first test for the same pairing guarantee)."""
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment, FakeReader, cs_beacon_config_bytes
    seg1_va, seg1_fo = 0x50000, 0x5000
    seg2_va, seg2_fo = 0x60000, 0x6000
    config1 = cs_beacon_config_bytes(0x69)
    config2 = cs_beacon_config_bytes(0x2e)
    data1 = b"\x00" * 0x100 + config1 + b"\x00" * 0x100
    data2 = b"\x00" * 0x100 + config2 + b"\x00" * 0x100
    seg1 = Segment(seg1_va, seg1_fo, len(data1))
    seg2 = Segment(seg2_va, seg2_fo, len(data2))
    regions = [
        Region(seg1_va, seg1_va, len(data1), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(seg2_va, seg2_va, len(data2), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mf = FakeMF()
    mf.memory_segments_64 = FakeStream([seg1, seg2], "memory_segments")
    mf.memory_info = FakeStream(regions, "infos")
    mf._reader = FakeReader({seg1_va: data1, seg2_va: data2})
    return BuiltScenario(mf=mf)


def _check_cs_beacon_multi(exit_code, doc, body):
    # expected_exit_code=3 (below) already covers the EXIT_PARTIAL check --
    # no ThreadListStream -> RIP/EIP corroboration coverage gap for both
    # uncorroborated hits -> coverage.status "partial", same reasoning as
    # injection's own check.
    record = doc["result"]["data"]["records"][0]
    assert len([f for f in record["findings"] if f["check"] == "cs_beacon.structural_config"]) == 2


def _build_yara(monkeypatch, tmp_path) -> BuiltScenario:
    from tests.fixtures.fakes import FakeMF, FakeStream, Segment, FakeReader
    seg_va, seg_fo = 0x50000, 0x5000
    data = b"A" * 0x100 + b"FINDME_MARKER" + b"B" * 0x100
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "hit.yar").write_text('rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
    seg = Segment(seg_va, seg_fo, len(data))
    mf = FakeMF()
    mf.memory_segments_64 = FakeStream([seg], "memory_segments")
    mf._reader = FakeReader({seg_va: data})
    return BuiltScenario(mf=mf, extra_argv=["--yara-dir", str(rules_dir)], rules_dir=rules_dir)


def _build_obfuscation(monkeypatch, tmp_path) -> BuiltScenario:
    import base64
    from tests.fixtures.fakes import (FakeMF, FakeStream, Region, build_pe_header,
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)
    import dumpex.hunt.encoding as encoding
    region_base = 0x300000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream([], "modules")
    monkeypatch.setattr(encoding, "read_region", mem_reader({region_base: b64_pe.ljust(0x1000, b"\x00")}))
    return BuiltScenario(mf=mf)


# Ordered so a full-suite regen (scripts/update_hunt_cli_goldens.py) and a
# `pytest -k` run of the parametrized test list scenarios in a stable,
# reviewable order -- not dict/import order, which is an implementation
# detail neither consumer should depend on.
# ── targeted (`--hunt-addr`) scenarios ───────────────────────────────────
# A targeted invocation is a second public shape of the same `--hunt` surface,
# and it freezes the same way: one analyzer, one record, one console card. Its
# `--hunt-addr`/`--size` arguments ride in `extra_argv`, so the shared runner
# still builds `--hunt <ttp> ...` exactly once and no scenario needs a special
# case at the call site.

_TARGETED_BASE = 0x10000000
_TARGETED_SIZE = 0x2000
_TARGETED_FILE_OFFSET = 0x3000


def _targeted_mf(protection="PAGE_EXECUTE_READ", mtype="MEM_IMAGE"):
    """One committed region, captured in full by one segment -- the shape a
    targeted rescan is eligible for, with no boundary caveat of its own."""
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(_TARGETED_BASE, _TARGETED_BASE, _TARGETED_SIZE, "MEM_COMMIT", protection, mtype)],
        "infos")
    mf.memory_segments_64 = FakeStream(
        [Segment(_TARGETED_BASE, _TARGETED_FILE_OFFSET, _TARGETED_SIZE)], "memory_segments")
    mf.modules = FakeStream([], "modules")
    return mf


def _targeted_argv():
    return ["--hunt-addr", hex(_TARGETED_BASE), "--size", hex(_TARGETED_SIZE)]


def _targeted_reader(payload):
    def _read(mf, addr, size):
        offset = addr - _TARGETED_BASE
        return payload[offset:offset + size]
    return _read


def _build_pipe_targeted(monkeypatch, tmp_path) -> BuiltScenario:
    """One captured range rescanned for pipe names and C2 context. The bytes
    carry a private pipe name, so both of pipe's closures have something real
    to report about the range the analyst named."""
    import dumpex.hunt.pipe.targeted as pipe_targeted
    name = b"\\\\.\\pipe\\msagent_1337\x00"
    payload = (b"\x00" * 0x100 + name).ljust(_TARGETED_SIZE, b"\x00")
    monkeypatch.setattr(pipe_targeted, "read_region_spanning", _targeted_reader(payload))
    return BuiltScenario(mf=_targeted_mf(), extra_argv=_targeted_argv())


def _check_pipe_targeted(exit_code, doc, body):
    """The document reports the requested range back under `scan_scope`, which
    is what a new result is reconciled against -- and pipe closes its two
    scopes independently even though its grant is unscoped."""
    scan_scope = doc["result"]["summary"]["scan_scope"]
    assert scan_scope["kind"] == "targeted"
    assert scan_scope["hunter"] == "pipe"
    assert scan_scope["base_address"] == f"0x{_TARGETED_BASE:016x}"
    assert scan_scope["size"] == _TARGETED_SIZE
    assert scan_scope["scopes"] == ["c2_context", "pipe_name"]


def _build_obfuscation_targeted(monkeypatch, tmp_path) -> BuiltScenario:
    """The same range rescanned for obfuscation, whose one invocation always
    attempts all three granted layers."""
    import dumpex.hunt.encoding.targeted as encoding_targeted
    payload = (bytes(range(256)) * (_TARGETED_SIZE // 256))[:_TARGETED_SIZE]
    monkeypatch.setattr(encoding_targeted, "read_region_spanning", _targeted_reader(payload))
    return BuiltScenario(mf=_targeted_mf(protection="PAGE_READWRITE", mtype="MEM_PRIVATE"),
                          extra_argv=_targeted_argv())


def _check_obfuscation_targeted(exit_code, doc, body):
    details = doc["result"]["data"]["records"][0]["details"]
    assert [item["scope"] for item in details["targeted_scope"]] == [
        "sleep_mask", "entropy", "decode"]
    assert doc["result"]["summary"]["scan_scope"]["scopes"] == [
        "decode", "entropy", "sleep_mask"]


def _build_pipe_oversized(monkeypatch, tmp_path) -> BuiltScenario:
    """One fully captured region past the pipe scan's own size cap.

    Every other scenario's skipped regions are ones this dump holds no
    bytes for, so their coverage costs exactly zero capturable memory and
    the coverage line stays a bare status word. This one is the opposite
    case and the one an analyst actually has to act on: real captured
    memory, genuinely unscanned, which is what puts a byte figure on the
    line. The region is declared in the segment table but its bytes are
    never read -- the scan skips it on size before any read is issued, so
    nothing here depends on materializing 16 MB.
    """
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment
    region_base = 0x4000000
    size = 16 * 1024 * 1024
    regions = [Region(region_base, region_base, size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.memory_segments_64 = FakeStream([Segment(region_base, 0x1000, size)],
                                        "memory_segments")
    mf.modules = FakeStream([], "modules")
    return BuiltScenario(mf=mf)


def _check_pipe_oversized(exit_code, doc, body):
    """The point of this fixture: a coverage line that quantifies the gap,
    and a structured aggregate that agrees with it."""
    record = doc["result"]["data"]["records"][0]
    missed = record["coverage"]["missed_bytes"]
    assert missed == {"state": "exact", "bytes": 16 * 1024 * 1024, "complete": True,
                       "quantified_gaps": 1, "unquantified_gaps": 0, "distinct_ranges": 1}
    assert "16 MB unscanned across 1 range(s)" in body
    # The quantification is a field beside the reasons, never a new
    # sentence inside them.
    assert not any("unscanned" in reason for reason in record["coverage"]["reasons"])


SCENARIOS = {
    "injection": HuntCliScenario("injection", "injection", _build_injection,
                                  expected_exit_code=3, extra_checks=_check_injection),
    "hollowing": HuntCliScenario("hollowing", "hollowing", _build_hollowing,
                                  extra_checks=_check_hollowing),
    "stomping": HuntCliScenario("stomping", "stomping", _build_stomping),
    "stomping_ioc_hit": HuntCliScenario("stomping_ioc_hit", "stomping", _build_stomping_ioc_hit,
                                         extra_checks=_check_stomping_ioc_hit),
    "pipe": HuntCliScenario("pipe", "pipe", _build_pipe,
                             expected_exit_code=3, extra_checks=_check_pipe),
    "pipe_oversized": HuntCliScenario("pipe_oversized", "pipe", _build_pipe_oversized,
                                       expected_exit_code=3,
                                       extra_checks=_check_pipe_oversized),
    "cs-beacon": HuntCliScenario("cs-beacon", "cs-beacon", _build_cs_beacon),
    "cs-beacon_multi": HuntCliScenario("cs-beacon_multi", "cs-beacon", _build_cs_beacon_multi,
                                        expected_exit_code=3, extra_checks=_check_cs_beacon_multi),
    "yara": HuntCliScenario("yara", "yara", _build_yara, needs_yara=True),
    "obfuscation": HuntCliScenario("obfuscation", "obfuscation", _build_obfuscation),
    "pipe_targeted": HuntCliScenario("pipe_targeted", "pipe", _build_pipe_targeted,
                                      extra_checks=_check_pipe_targeted),
    "obfuscation_targeted": HuntCliScenario("obfuscation_targeted", "obfuscation",
                                             _build_obfuscation_targeted,
                                             extra_checks=_check_obfuscation_targeted),
}

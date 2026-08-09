"""Unit tests for dumpex.hunt._deep_triage.run_deep_triage() -- the opt-in
`--triage-skipped` budgeted deep-content triage engine (issue #19 Phase 2).
Builds a real `InvestigationAction` queue via
`dumpex.hunt._investigation.build_investigation_queue()` (same style as
tests/hunt/test_investigation.py) over a synthetic `FakeMF`/`Region`/
`FakeStream` dump (same style as tests/unit/test_report_cmd.py), then runs
the real engine against it -- no monkeypatching of `run_deep_triage()`
internals, only of `read_region` (dual-patched into both
`dumpex.commands.report` and `dumpex.core.memory`, exactly like
`_search_string_in_memory`'s own module-global `read_region` requires --
see test_report_cmd.py's own module docstring)."""
import pytest

import dumpex.commands.report as report_mod
import dumpex.core.memory as core_memory_mod
import dumpex.hunt._deep_triage as deep_triage_mod
from tests.fixtures.fakes import FakeMF, FakeStream, Region

from dumpex.hunt._investigation import (
    build_investigation_queue, InvestigationActionType, MAX_FINDINGS_PER_TARGET,
)
from dumpex.hunt._deep_triage import run_deep_triage
from dumpex.output.coverage import ScanTarget, ScanTargetKind, CoverageLimitation, LimitationCode, \
    CoverageReport, CoverageStatus
from dumpex.output.records import HunterRecord, PipeDetails, ObfuscationDetails, YaraDetails


def _target(base=0x2000, size=20 * 1024 * 1024, size_limit=8 * 1024 * 1024,
            file_offset=999, type_="MEM_PRIVATE", protection="PAGE_READWRITE"):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base, size=size,
                       size_limit=size_limit, file_offset=file_offset, allocation_base=base,
                       state="MEM_COMMIT", type=type_, protection=protection)


def _segment_target(base=0x2000, size=20 * 1024 * 1024, size_limit=8 * 1024 * 1024,
                     file_offset=999):
    # ScanTargetKind.MEMORY_SEGMENT carries NO MemoryInfo facts at all --
    # see ScanTarget.__post_init__'s own enforcement of that.
    return ScanTarget(kind=ScanTargetKind.MEMORY_SEGMENT, base_address=base, size=size,
                       size_limit=size_limit, file_offset=file_offset)


def _limitation(source, targets, scope=None):
    return CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                               source=source, scope=scope, affected_count=len(targets),
                               targets=tuple(targets))


def _pipe_record(limitations=()):
    details = PipeDetails(handle_pipes=[], private_pipes=[], c2_context=[],
                           framework_pipes=[], unbacked_in_rgn=[])
    return HunterRecord(hunter="pipe", status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0, max_score=3,
        verdict_level="clean", confidence="none", lead_count=0, review_priority="none",
        coverage=CoverageReport(status=CoverageStatus.PARTIAL, limitations=list(limitations)),
        findings=[], details=details)


def _yara_record(limitations=()):
    # segment_scan (cs-beacon/YARA) is the one SCAN_REGION_OVERSIZED_SKIPPED
    # source contract that allows memory_segment targets -- see
    # dumpex.output.coverage._SCAN_REGION_OVERSIZED_SKIPPED_SOURCE_CONTRACTS.
    details = YaraDetails(matches=[], rules_hit=[])
    return HunterRecord(hunter="yara", status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0,
        max_score=None, verdict_level="clean", confidence=None, lead_count=None,
        review_priority=None,
        coverage=CoverageReport(status=CoverageStatus.PARTIAL, limitations=list(limitations)),
        findings=[], details=details)


def _obfuscation_record(limitations=()):
    details = ObfuscationDetails(sleep_mask=[], entropy=[], base64=[], xor=[],
                                  compressed=[], hidden_pe=[], hidden_shellcode=[])
    return HunterRecord(hunter="obfuscation", status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0,
        max_score=2, verdict_level="clean", confidence="none", lead_count=0,
        review_priority="none",
        coverage=CoverageReport(status=CoverageStatus.PARTIAL, limitations=list(limitations)),
        findings=[], details=details)


def _mk_mf(monkeypatch, *, regions, read_map=None, reader=None):
    mf = FakeMF()
    mf.filename = "test.dmp"
    mf.modules = FakeStream([], "modules")
    mf.thread_info = FakeStream([], "infos")
    mf.memory_info = FakeStream(regions, "infos")
    calls = []
    if reader is not None:
        def _reader(mf_, addr, size):
            calls.append((addr, size))
            return reader(mf_, addr, size)
        monkeypatch.setattr(report_mod, "read_region", _reader)
        monkeypatch.setattr(core_memory_mod, "read_region", _reader)
    elif read_map is not None:
        def _reader(mf_, addr, size):
            calls.append((addr, size))
            for base, data in read_map.items():
                if base <= addr < base + len(data):
                    off = addr - base
                    return data[off:off + size]
            return b'\x00' * size
        monkeypatch.setattr(report_mod, "read_region", _reader)
        monkeypatch.setattr(core_memory_mod, "read_region", _reader)
    return mf, calls


# ── not-captured targets never trigger a read ───────────────────────────────

def test_not_captured_target_skips_the_read_entirely(monkeypatch):
    t = _target(base=0x3000, file_offset=None)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0x3000, 0x3000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, calls = _mk_mf(monkeypatch, regions=regions, read_map={0x3000: b"x" * 4096})
    actions = build_investigation_queue([rec], regions)
    assert actions[0].evidence_availability == "not_captured"

    new_actions, diagnostics = run_deep_triage(mf, actions)

    assert new_actions[0].triage.mode == "deep"
    assert new_actions[0].triage.status == "not_captured"
    assert new_actions[0].triage.bytes_examined == 0
    assert new_actions[0].triage.content_reason_codes == ()
    assert calls == []   # no read was ever attempted
    assert any(d.code == "DEEP_TRIAGE_SUMMARY" for d in diagnostics)


# ── a small, fully-captured target reads to completion ──────────────────────

def test_small_target_reads_to_completion(monkeypatch):
    t = _target(base=0x4000, size=4096 + 8 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0x4000, 0x4000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, calls = _mk_mf(monkeypatch, regions=regions, read_map={0x4000: b"\x00" * t.size})
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=t.size + 1,
                                          run_budget=t.size + 1, max_targets=5)

    triage = new_actions[0].triage
    assert triage.status == "completed"
    assert triage.bytes_examined == t.size
    assert triage.region_fully_examined is True
    assert triage.content_reason_codes == ()
    assert len(calls) == 1


# ── per-target limit clamps a bigger target (no shortfall from the dump) ────

def test_target_larger_than_per_target_limit_is_clamped(monkeypatch):
    t = _target(base=0x5000, size=20 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0x5000, 0x5000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0x5000: b"\x00" * t.size})
    actions = build_investigation_queue([rec], regions)

    per_target_limit = 1024 * 1024
    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=per_target_limit,
                                          run_budget=64 * 1024 * 1024, max_targets=5)

    triage = new_actions[0].triage
    assert triage.status == "clamped"
    assert triage.bytes_examined == per_target_limit
    assert triage.region_fully_examined is False
    action_types = {a.type for a in new_actions[0].recommended_actions}
    assert InvestigationActionType.CHUNKED_ANALYSIS.value in action_types


# ── a genuine short read is "partial", even though read_cap < target.size ───
# (issue #19 Phase 2 review, item 2: checking "did we ask for less than the
# whole target" before "did the dump actually have what we asked for" would
# misclassify this as a policy clamp and hide the real evidence gap -- since
# a skipped target's own size always exceeds the cap that skipped it,
# read_cap < target.size is true for nearly every real deep-triage read.)

def test_short_read_is_partial_even_when_also_clamped_by_budget(monkeypatch):
    t = _target(base=0x6000, size=20 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0x6000, 0x6000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    # Only 10 real bytes are backed at this VA; per_target_limit (4 MiB,
    # smaller than target.size) ALSO clamps the request -- both are true
    # at once, and partial must win.
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0x6000: b"A" * 10})
    actions = build_investigation_queue([rec], regions)

    per_target_limit = 4 * 1024 * 1024
    assert per_target_limit < t.size
    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=per_target_limit,
                                          run_budget=64 * 1024 * 1024, max_targets=5)

    triage = new_actions[0].triage
    assert triage.status == "partial"
    assert triage.bytes_examined == 10
    assert triage.region_fully_examined is False


# ── genuine read failure -> unreadable, without needing region resolution ───

def test_read_exception_is_unreadable(monkeypatch):
    t = _target(base=0x7000)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0x7000, 0x7000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    def _raising_reader(mf_, addr, size):
        raise OSError("simulated read failure")

    mf, calls = _mk_mf(monkeypatch, regions=regions, reader=_raising_reader)
    actions = build_investigation_queue([rec], regions)

    new_actions, diagnostics = run_deep_triage(mf, actions)

    triage = new_actions[0].triage
    assert triage.status == "unreadable"
    assert triage.bytes_examined == 0
    assert len(calls) == 1   # the read WAS attempted -- only the read itself failed
    assert any(d.code == "DEEP_TRIAGE_READ_FAILED" for d in diagnostics)


# ── memory_segment targets (no MemoryInfo entry) are read correctly ─────────
# (issue #19 Phase 2 review, item 1)

def test_memory_segment_target_with_no_memoryinfo_entry_reads_correctly(monkeypatch):
    t = _segment_target(base=0x8000, size=1024 + 8 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _yara_record([_limitation("segment_scan", [t])])
    # Deliberately NO MemoryInfo region at all covering 0x8000 -- a
    # yara/cs-beacon segment target legitimately has none.
    regions = []
    data = b"payload marker: http://evil.example/c2" + b"\x00" * 512
    mf, calls = _mk_mf(monkeypatch, regions=regions, read_map={0x8000: data})
    actions = build_investigation_queue([rec], regions)
    assert actions[0].target.kind.value == "memory_segment"
    assert actions[0].evidence_availability == "captured"   # file_offset is set

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=len(data),
                                          run_budget=len(data), max_targets=5)

    triage = new_actions[0].triage
    # Previously this misreported as "unreadable" (no _get_region_at() hit)
    # despite the bytes being genuinely captured and readable.
    assert triage.status != "unreadable"
    assert triage.bytes_examined == len(data)
    assert "IOC_PATTERN_STRING_MATCH" in triage.content_reason_codes
    assert len(calls) == 1
    assert calls[0][0] == 0x8000   # read from the TARGET's own base_address


def test_target_inside_a_larger_memoryinfo_region_reads_from_its_own_base(monkeypatch):
    """A skipped target can be a sub-range of a MUCH larger MemoryInfo
    region (a specific hunter's own oversized-skip cap applied to a
    sub-scope, not necessarily the whole region). Reading from the
    region's own BaseAddress instead of the target's would scan the
    wrong bytes -- prove it doesn't by putting different, distinguishing
    content at each address."""
    region_base = 0x9000
    target_base = 0x9000 + 4096   # well inside the region, not at its start
    t = _target(base=target_base, size=1024 + 8 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    # The MemoryInfo region is much larger than, and starts before, the target.
    regions = [Region(region_base, region_base, 16 * 1024 * 1024, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    read_map = {
        # Deliberately short (well under the 4096-byte gap to target_base)
        # so its own address range can never accidentally cover
        # target_base too -- a real overlap would let this test pass for
        # the wrong reason.
        region_base: b"WRONG LOCATION http://should-not-be-seen.example" + b"\x00" * 100,
        target_base: b"http://correct-location.example" + b"\x00" * 512,
    }
    mf, calls = _mk_mf(monkeypatch, regions=regions, read_map=read_map)
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=600,
                                          run_budget=600, max_targets=5)

    assert calls[0][0] == target_base
    assert "IOC_PATTERN_STRING_MATCH" in new_actions[0].triage.content_reason_codes


# ── whole-run budget exhaustion defers later (lower-priority) targets ───────

def test_run_budget_exhaustion_defers_remaining_targets_deterministically(monkeypatch):
    hi = _target(base=0x8100, size=2 * 1024 * 1024 + 8 * 1024 * 1024, protection="PAGE_EXECUTE_READWRITE")
    lo = _target(base=0x9100, size=2 * 1024 * 1024 + 8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [hi, lo])])
    regions = [
        Region(hi.base_address, hi.base_address, hi.size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(lo.base_address, lo.base_address, lo.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    read_map = {hi.base_address: b"\x00" * hi.size, lo.base_address: b"\x00" * lo.size}
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map=read_map)
    actions = build_investigation_queue([rec], regions)
    # hi is PRIVATE + RWX -> has_exec_signal -> higher priority than lo,
    # so build_investigation_queue() already sorted hi before lo.
    assert actions[0].target.base_address == hi.base_address
    assert actions[1].target.base_address == lo.base_address

    per_target_limit = 1024 * 1024
    new_actions, diagnostics = run_deep_triage(
        mf, actions, per_target_limit=per_target_limit, run_budget=per_target_limit,
        max_targets=5)

    assert new_actions[0].triage.status == "clamped"   # consumed the whole budget
    assert new_actions[1].triage.status == "budget_deferred"
    assert new_actions[1].triage.bytes_examined == 0
    assert any(d.code == "DEEP_TRIAGE_BUDGET_EXHAUSTED" for d in diagnostics)

    # Re-running with the SAME budgets against the SAME queue defers the
    # SAME target -- deterministic, not incidental ordering.
    again, _diag2 = run_deep_triage(mf, actions, per_target_limit=per_target_limit,
                                     run_budget=per_target_limit, max_targets=5)
    assert again[1].triage.status == "budget_deferred"


# ── max_targets cutoff defers even when byte budget is not exhausted ────────

def test_max_targets_cutoff_defers_regardless_of_remaining_bytes(monkeypatch):
    t1 = _target(base=0xa000, protection="PAGE_EXECUTE_READWRITE")
    t2 = _target(base=0xb000, protection="PAGE_EXECUTE_READWRITE")
    rec = _pipe_record([_limitation("pipe_name_scan", [t1, t2])])
    regions = [
        Region(t1.base_address, t1.base_address, t1.size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(t2.base_address, t2.base_address, t2.size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
    ]
    read_map = {t1.base_address: b"\x00" * 100, t2.base_address: b"\x00" * 100}
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map=read_map)
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=1024 * 1024,
                                          run_budget=64 * 1024 * 1024, max_targets=1)

    assert new_actions[0].triage.status != "budget_deferred"
    assert new_actions[1].triage.status == "budget_deferred"


# ── content_reason_codes are derived from the deep read itself ──────────────

def test_ioc_and_network_pattern_string_match_detected(monkeypatch):
    t = _target(base=0xc000, size=1024 + 8 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0xc000, 0xc000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    # \x00 between the two runs so _extract_strings_from_data() (a greedy
    # printable-character regex) extracts them as two SEPARATE strings,
    # not one merged run (space is itself printable, so a plain space
    # would not split them).
    data = b"junk header\x00" + b"http://evil.example/beacon" + b"\x00" * 512
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0xc000: data})
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=len(data),
                                          run_budget=len(data), max_targets=5)

    codes = new_actions[0].triage.content_reason_codes
    assert "IOC_PATTERN_STRING_MATCH" in codes
    assert "NETWORK_PATTERN_STRING_MATCH" in codes

    # issue #19 Phase 2 review, item 4: content_reason_codes alone is a
    # summary -- the actual evidence lives in triage.findings.
    findings = new_actions[0].triage.findings
    assert len(findings) == 1
    assert findings[0].type == "ioc_string"
    assert findings[0].value == "http://evil.example/beacon"
    assert findings[0].is_network_pattern is True
    assert findings[0].module_context is None
    assert new_actions[0].triage.finding_count == 1
    assert new_actions[0].triage.findings_truncated is False


def test_injected_pe_header_detected_in_unregistered_memory(monkeypatch):
    t = _target(base=0xd000, size=1024 + 8 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0xd000, 0xd000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    data = b"MZ" + b"\x90" * 62 + b"\x00" * 512
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0xd000: data})
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=len(data),
                                          run_budget=len(data), max_targets=5)

    # mf.modules is set (empty list) -> modules_available=True, no match ->
    # unregistered -> both codes: the raw MZ-header fact and the stronger,
    # confirmed-unregistered injected-PE fact.
    assert new_actions[0].triage.content_reason_codes == \
        ("MZ_HEADER_DETECTED", "INJECTED_PE_HEADER")
    findings = new_actions[0].triage.findings
    assert len(findings) == 1
    assert findings[0].type == "mz_header"
    assert findings[0].address == "0x000000000000d000"
    assert findings[0].module_context == "unregistered"
    assert new_actions[0].triage.finding_count == 1
    assert new_actions[0].triage.findings_truncated is False


def test_mz_header_without_module_classification_is_not_dropped(monkeypatch):
    """issue #19 Phase 2 review, item 3: when ModuleListStream itself is
    absent (module_context == 'unavailable'), has_injected_pe cannot be
    confirmed (stays None/falsy) -- but the raw MZ_HEADER_DETECTED fact
    must still surface; it must never be silently dropped just because
    module classification wasn't possible."""
    t = _target(base=0xd800, size=1024 + 8 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0xd800, 0xd800, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    data = b"MZ" + b"\x90" * 62 + b"\x00" * 512
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0xd800: data})
    mf.modules = None   # ModuleListStream absent entirely -> modules_available=False
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=len(data),
                                          run_budget=len(data), max_targets=5)

    codes = new_actions[0].triage.content_reason_codes
    assert "MZ_HEADER_DETECTED" in codes
    assert "INJECTED_PE_HEADER" not in codes   # could not be confirmed
    findings = new_actions[0].triage.findings
    assert len(findings) == 1
    assert findings[0].type == "mz_header"
    assert findings[0].module_context == "unavailable"
    assert new_actions[0].triage.finding_count == 1
    assert new_actions[0].triage.findings_truncated is False


def test_findings_are_capped_at_max_per_target(monkeypatch):
    # Build far more than MAX_FINDINGS_PER_TARGET distinct IOC hits by
    # repeating a short IOC-pattern string many times, each separated by
    # a non-printable \x00 byte so _extract_strings_from_data()'s greedy
    # printable-character regex extracts every occurrence as its own
    # separate string instead of merging them into one long run.
    chunk = b"cmd.exe\x00"
    data = chunk * (MAX_FINDINGS_PER_TARGET + 10) + b"\x00" * 512
    t = _target(base=0xe800, size=len(data) + 8 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0xe800, 0xe800, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0xe800: data})
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=len(data),
                                          run_budget=len(data), max_targets=5)

    triage = new_actions[0].triage
    assert len(triage.findings) == MAX_FINDINGS_PER_TARGET
    assert triage.finding_count == MAX_FINDINGS_PER_TARGET + 10
    assert triage.findings_truncated is True


# ── representative-first selection (issue #19 Phase 2 review round 2, item 2) ──
# Filling `findings` in bare offset order until the cap, THEN trying to add
# an MZ finding, meant a target with >=20 plain IOC hits silently crowded
# out both the MZ finding and any network-pattern IOC finding -- even
# though content_reason_codes would still list MZ_HEADER_DETECTED/
# NETWORK_PATTERN_STRING_MATCH with no structured evidence behind them.

def test_findings_selection_guarantees_a_representative_per_reason_code(monkeypatch):
    plain_chunk = b"cmd.exe\x00"
    network_chunk = b"http://evil.example/c2\x00"
    # MZ header at the very start, then 20 plain IOC hits, THEN one
    # network-pattern IOC hit, then 5 more plain IOC hits -- a naive
    # offset-order fill to the cap would already be full of plain hits by
    # the time the network hit (and the MZ finding, added only afterward
    # in the old code) is reached.
    data = (b"MZ" + b"\x90" * 62 + b"\x00"
            + plain_chunk * 20 + network_chunk + plain_chunk * 5 + b"\x00" * 512)
    t = _target(base=0xec00, size=len(data) + 8 * 1024 * 1024, size_limit=8 * 1024 * 1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0xec00, 0xec00, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0xec00: data})
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=len(data),
                                          run_budget=len(data), max_targets=5)

    triage = new_actions[0].triage
    codes = triage.content_reason_codes
    assert "MZ_HEADER_DETECTED" in codes
    assert "IOC_PATTERN_STRING_MATCH" in codes
    assert "NETWORK_PATTERN_STRING_MATCH" in codes

    findings = triage.findings
    assert len(findings) == MAX_FINDINGS_PER_TARGET
    assert findings[0].type == "mz_header"
    assert any(f.type == "ioc_string" and f.is_network_pattern for f in findings)
    assert any(f.type == "ioc_string" and not f.is_network_pattern for f in findings)

    # 1 MZ finding + 26 IOC hits (25 plain + 1 network) found in total,
    # only 20 fit -- truncated, and the total is reported honestly.
    assert triage.finding_count == 1 + 26
    assert triage.findings_truncated is True


# ── analysis-stage bugs must not be mislabeled as ordinary unreadable ───────
# (issue #19 Phase 2 review round 2, item 1)

def test_analysis_bug_after_a_successful_read_is_not_converted_to_unreadable(monkeypatch):
    t = _target(base=0xed00)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0xed00, 0xed00, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0xed00: b"perfectly readable bytes"})
    actions = build_investigation_queue([rec], regions)

    def _broken_extract(data, min_len):
        raise TypeError("simulated programming bug in string extraction")
    monkeypatch.setattr(report_mod, "_extract_strings_from_data", _broken_extract)

    with pytest.raises(TypeError, match="simulated programming bug"):
        run_deep_triage(mf, actions, per_target_limit=1024, run_budget=1024, max_targets=5)


def test_no_indicators_found_yields_empty_content_reason_codes(monkeypatch):
    t = _target(base=0xe000, size=4096, size_limit=1024)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0xe000, 0xe000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0xe000: b"\x00" * t.size})
    actions = build_investigation_queue([rec], regions)

    new_actions, _diag = run_deep_triage(mf, actions, per_target_limit=t.size,
                                          run_budget=t.size, max_targets=5)

    assert new_actions[0].triage.status == "completed"
    assert new_actions[0].triage.content_reason_codes == ()


# ── dedup-before-read: one physical target, two skippers, one real read ─────

def test_two_hunters_skipping_the_same_target_trigger_exactly_one_read(monkeypatch):
    t_pipe = _target(base=0xf000)
    t_obf = _target(base=0xf000, size_limit=10 * 1024 * 1024)   # same physical target
    pipe = _pipe_record([_limitation("pipe_name_scan", [t_pipe])])
    obf = _obfuscation_record([_limitation("encoding_scan", [t_obf], scope="entropy")])
    regions = [Region(0xf000, 0xf000, t_pipe.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, calls = _mk_mf(monkeypatch, regions=regions, read_map={0xf000: b"\x00" * t_pipe.size})
    actions = build_investigation_queue([pipe, obf], regions)
    assert len(actions) == 1
    assert len(actions[0].skipped_by) == 2

    run_deep_triage(mf, actions, per_target_limit=t_pipe.size + 1, run_budget=t_pipe.size + 1)

    assert len(calls) == 1


# ── collector reuse: --report's OWN low-level scan primitive is called ──────

def test_reuses_scan_content_range_with_explicit_requested_size(monkeypatch):
    t = _target(base=0x10000)
    rec = _pipe_record([_limitation("pipe_name_scan", [t])])
    regions = [Region(0x10000, 0x10000, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf, _calls = _mk_mf(monkeypatch, regions=regions, read_map={0x10000: b"\x00" * t.size})
    actions = build_investigation_queue([rec], regions)

    seen_kwargs = {}
    real_scan = report_mod._scan_content_range

    def spy(mf_, **kwargs):
        seen_kwargs.update(kwargs)
        return real_scan(mf_, **kwargs)

    monkeypatch.setattr(deep_triage_mod, "_scan_content_range", spy)

    per_target_limit = 3 * 1024 * 1024
    run_deep_triage(mf, actions, per_target_limit=per_target_limit,
                     run_budget=per_target_limit, max_targets=5)

    assert seen_kwargs["requested_size"] == per_target_limit
    assert seen_kwargs["base_address"] == t.base_address


# ── empty queue is a no-op ───────────────────────────────────────────────────

def test_empty_queue_returns_empty():
    assert run_deep_triage(FakeMF(), []) == ([], [])

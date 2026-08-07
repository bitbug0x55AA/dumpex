"""
Unit tests for dumpex.hunt.pipe.collect.collect_pipe_record() -- PR2b's
HunterRecord-producing path for the pipe hunter. Every scenario here
mirrors tests/hunt/test_pipe.py's own fixtures (same literal inputs),
confirming collect_pipe_record() and the console path (_hunt_pipe())
always agree on the same underlying Report.
"""
import json

import pytest

from tests.fixtures.fakes import Region, Handle, ThreadInfo, FakeStream, FakeMF, mem_reader

import dumpex.hunt.pipe as pipemod
import dumpex.hunt.pipe.memory_scan as memory_scan_mod
from dumpex.hunt.pipe.collect import collect_pipe_record
from dumpex.output.records import HunterRecord, PipeDetails

jsonschema = pytest.importorskip("jsonschema")
from dumpex.schemas import schema_path


@pytest.fixture(scope="module")
def hunter_record_validator():
    with schema_path("dumpex-output-v2.7.schema.json") as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/hunterRecord", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


def _assert_matches_console_dict(rec: HunterRecord, console_dict: dict):
    assert rec.score == console_dict["score"]
    assert rec.max_score == console_dict["max_score"]
    assert rec.status == console_dict["status"]
    assert rec.verdict_level == console_dict["verdict_level"]
    assert rec.confidence == console_dict["confidence"]
    assert rec.lead_count == console_dict["lead_count"]
    assert rec.review_priority == console_dict["review_priority"]
    assert rec.findings == console_dict["findings"]


def test_empty_handle_stream_is_complete_clean(hunter_record_validator):
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")   # stream PRESENT, zero handles
    pipemod.read_region = mem_reader({})

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    assert isinstance(rec, HunterRecord)
    assert rec.hunter == "pipe"
    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert rec.coverage.status.value == "complete"
    assert isinstance(rec.details, PipeDetails)
    assert rec.details.handle_pipes == []
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_missing_handle_stream_is_partial(hunter_record_validator):
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = None   # stream ABSENT
    pipemod.read_region = mem_reader({})

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    assert any(lim.source == "handle_data" for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_memory_info_absent_alone_does_not_force_partial(hunter_record_validator):
    # Regression: _pipe_coverage_report() initially listed "memory_info"
    # as its own completeness_check, which would flip coverage.status to
    # "partial" whenever memory_info was absent -- but this hunter's real
    # `complete` boolean never consults mem_info_available at all (only
    # `evaluated` does, via the combined evaluation_sources group), so a
    # memory_info-absent/handle_data-present/otherwise-clean run must
    # still report "complete", matching v1.1's own coverage_status.
    class MF(FakeMF):
        memory_info = FakeStream([], "infos")   # stream absent (no .infos items)
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")   # stream PRESENT, zero handles
    pipemod.read_region = mem_reader({})

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert console_dict["coverage_status"] == "complete"
    assert rec.coverage.status.value == "complete"
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_pipe_nearby_c2_and_rip_scores_3(hunter_record_validator):
    region_base = 0x1000000
    region_size = 0x10000
    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"
    data = bytearray(region_size)
    data[0x100:0x100 + len(pipe_name)] = pipe_name
    c2_offset = 0x100 + len(pipe_name) + 100
    data[c2_offset:c2_offset + 40] = b"http://198.51.100.7:8080/submit.php\x00\x00\x00"
    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x99, "File", r"\Device\NamedPipe\my_custom_ipc_channel")]
    pipe_va = region_base + 0x100

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: bytes(data)})
    pipemod.get_thread_contexts = lambda mf: [{"ThreadId": 1, "ip": pipe_va + 50,
                                                 "ip_reg": "RIP", "is_wow64": False}]

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.score == 3
    assert rec.status == "DETECTED"
    handle_dict = rec.details.handle_pipes[0]["handle"]
    assert handle_dict["handle"] == "0x0000000000000099"
    assert handle_dict["object_name"] == r"\Device\NamedPipe\my_custom_ipc_channel"
    assert handle_dict["granted_access"] == 0x12019f   # plain int, not hex-formatted
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_short_read_region_makes_result_inconclusive(hunter_record_validator):
    region_base = 0x2000000
    regions = [Region(region_base, region_base, 0x10000, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")

    def short_reader(mf, addr, size):
        return b"\x00" * 4   # far short of the declared 0x10000 RegionSize
    pipemod.read_region = short_reader

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"
    assert any(lim.code.value == "SCAN_REGION_SHORT_READ" for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_oversized_region_is_skipped(monkeypatch, hunter_record_validator):
    """`PIPE_SCAN_MAX` shrunk (via monkeypatch, auto-restored) below this
    region's own size, so it's skipped without ever being read --
    exercises `_pipe_coverage_report()`'s SCAN_REGION_OVERSIZED_SKIPPED
    branch (memory_scan.scan_pipe_names' own `r.RegionSize > PIPE_SCAN_MAX`
    check, note_skipped_oversize())."""
    region_base = 0x3000000
    regions = [Region(region_base, region_base, 0x10000, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")

    # PIPE_SCAN_MAX is read directly inside memory_scan.py, not re-exported
    # through dumpex.hunt.pipe -- must be patched at its own module.
    monkeypatch.setattr(memory_scan_mod, "PIPE_SCAN_MAX", 0x100)
    pipemod.read_region = mem_reader({})

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_REGION_OVERSIZED_SKIPPED")
    assert lim.source == "pipe_name_scan"
    assert lim.affected_count == 1
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_region_read_failure_is_tracked(hunter_record_validator):
    """`read_region` raising (a real read failure, not a short read)
    exercises `_pipe_coverage_report()`'s SCAN_REGION_READ_FAILED branch
    (memory_scan.scan_pipe_names' own `except Exception:
    coverage_counts.note_read_failed()`)."""
    region_base = 0x4000000
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")

    def failing_reader(mf, addr, size):
        raise OSError("simulated read failure")
    pipemod.read_region = failing_reader

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    lim = next(l for l in rec.coverage.limitations if l.code.value == "SCAN_REGION_READ_FAILED")
    assert lim.source == "pipe_name_scan"
    assert lim.affected_count == 1
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_c2_budget_deadline_exhausted_is_tracked(monkeypatch, hunter_record_validator):
    """`PIPE_C2_BUDGET_TIME_SECONDS` set negative (via monkeypatch, auto-
    restored) so `_build_pipe_report()`'s own `time.monotonic() +
    PIPE_C2_BUDGET_TIME_SECONDS` deadline is already in the past --
    `c2_budget.exhausted()` is True from the start (see
    dumpex.hunt._budget.ScanBudget.exhausted's own deadline check),
    exercising `_pipe_coverage_report()`'s c2_context-scoped
    SCAN_BUDGET_EXHAUSTED branch independently of pipe_name_budget."""
    region_base = 0x5000000
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")

    monkeypatch.setattr(pipemod, "PIPE_C2_BUDGET_TIME_SECONDS", -1.0)
    pipemod.read_region = mem_reader({})

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_BUDGET_EXHAUSTED" and l.scope == "c2_context")
    assert lim.source == "pipe_name_scan"
    assert lim.detail == "deadline"
    # pipe_name_budget itself is untouched -- confirms the two budgets are
    # tracked, and can be exhausted, independently of one another.
    assert not any(l.code.value == "SCAN_BUDGET_EXHAUSTED" and l.scope == "pipe_name"
                   for l in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_pipe_name_budget_deadline_exhausted_is_tracked(monkeypatch, hunter_record_validator):
    """Same as the c2_budget case above but for `PIPE_NAME_BUDGET_TIME_
    SECONDS` -- exercises `_pipe_coverage_report()`'s pipe_name-scoped
    SCAN_BUDGET_EXHAUSTED branch."""
    region_base = 0x6000000
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")

    monkeypatch.setattr(pipemod, "PIPE_NAME_BUDGET_TIME_SECONDS", -1.0)
    pipemod.read_region = mem_reader({})

    console_dict = pipemod._hunt_pipe(MF(), verbose=False)
    rec = collect_pipe_record(MF())

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_BUDGET_EXHAUSTED" and l.scope == "pipe_name")
    assert lim.source == "pipe_name_scan"
    assert lim.detail == "deadline"
    assert not any(l.code.value == "SCAN_BUDGET_EXHAUSTED" and l.scope == "c2_context"
                   for l in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []

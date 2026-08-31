"""Every registered targeted capability routes end to end.

The capability matrix is a roster, not a per-analyzer courtesy: a hunter that
declares a targeted capability must have an executor AND a report projector, and
running it must produce a record whose closures, scope entries, and coverage all
line up. These cases drive `dumpex.hunt.execute_targeted` for every identity the
registry reports as targetable, so adding a sixth analyzer to the matrix without
wiring its projection fails here rather than at an investigator's terminal.
"""
import pytest

from dumpex.core.va_range import VirtualRange
from dumpex.hunt import execute_targeted, targeted_hunters
from dumpex.hunt._registry import REGISTRY
from dumpex.hunt._request import HuntRequest
from dumpex.output.records import HUNTERS

from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment

_BASE = 0x10000000
_SIZE = 0x1000
_FILE_OFFSET = 0x3000


def _request(identity):
    source = REGISTRY.targeted_source(identity)
    return HuntRequest.targeted(
        identity, source, VirtualRange(base_address=_BASE, size=_SIZE),
        scopes=REGISTRY.granted_scopes(identity, source))


def _empty_dump():
    """A dump with no captured evidence at all: every analyzer's targeted
    adapter reaches its own "nothing here to evaluate" path."""
    class MF(FakeMF):
        memory_info = FakeStream([], "infos")
        memory_segments_64 = FakeStream([], "memory_segments")
        modules = FakeStream([], "modules")
    return MF()


def _covered_dump():
    class MF(FakeMF):
        memory_info = FakeStream(
            [Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")],
            "infos")
        memory_segments_64 = FakeStream([Segment(_BASE, _FILE_OFFSET, _SIZE)],
                                         "memory_segments")
        modules = FakeStream([], "modules")
    return MF()


@pytest.mark.parametrize("identity", targeted_hunters())
def test_every_targeted_identity_has_an_executor_and_a_projector(identity):
    spec = REGISTRY.get(identity)
    assert spec.targeted_adapter is not None
    assert spec.targeted_report_projector is not None


@pytest.mark.parametrize("identity", targeted_hunters())
def test_every_targeted_identity_produces_a_not_evaluated_record_over_an_empty_dump(identity):
    """No captured evidence is not a clean result: every closure reports
    not_evaluated, the record follows, and the exit-code rollup does too."""
    execution = execute_targeted(_empty_dump(), _request(identity))
    record = execution.result.records[0]
    assert record.hunter == identity
    assert record.status == "NOT_EVALUATED"
    assert record.verdict_level == "not_evaluated"
    assert record.score == 0
    assert record.coverage.status.value == "not_evaluated"
    assert execution.result.coverage.status.value == "not_evaluated"


@pytest.mark.parametrize("identity", targeted_hunters())
def test_every_targeted_record_carries_one_scope_entry_per_closure(identity):
    execution = execute_targeted(_empty_dump(), _request(identity))
    record = execution.result.records[0]
    closures = [(c.source, c.scope) for c in _observation_closures(execution)]
    entries = [(item.source, item.scope) for item in record.details.targeted_scope]
    assert entries == closures
    assert all(item.size == _SIZE for item in record.details.targeted_scope)
    assert all(item.base_address == f"0x{_BASE:016x}"
               for item in record.details.targeted_scope)


def _observation_closures(execution):
    """The closures behind a projection, recovered from the record's own scope
    entries -- `execute_targeted` deliberately does not hand the raw
    observation to a command surface."""
    return [type("C", (), {"source": item.source, "scope": item.scope})()
            for item in execution.result.records[0].details.targeted_scope]


@pytest.mark.parametrize("identity", targeted_hunters())
def test_every_targeted_summary_tags_its_own_scope(identity):
    execution = execute_targeted(_empty_dump(), _request(identity))
    scan_scope = execution.result.summary["scan_scope"]
    assert scan_scope["kind"] == "targeted"
    assert scan_scope["hunter"] == identity
    assert scan_scope["source"] == REGISTRY.targeted_source(identity)
    assert scan_scope["size"] == _SIZE
    assert execution.result.summary["investigation_actions"] == []


def test_obfuscation_projects_its_three_layers_in_fixed_order():
    execution = execute_targeted(_empty_dump(), _request("obfuscation"))
    entries = execution.result.records[0].details.targeted_scope
    assert [item.scope for item in entries] == ["sleep_mask", "entropy", "decode"]


def test_pipe_projects_both_of_its_independent_closures():
    execution = execute_targeted(_empty_dump(), _request("pipe"))
    entries = execution.result.records[0].details.targeted_scope
    assert [item.scope for item in entries] == ["pipe_name", "c2_context"]


@pytest.mark.parametrize("identity", targeted_hunters())
def test_a_targeted_run_prints_nothing_unless_asked(identity, capsys):
    """`render=False` is a silence guarantee, not "the return value is
    discarded" -- a JSON-only consumer must be able to run this."""
    execute_targeted(_covered_dump(), _request(identity))
    assert capsys.readouterr().out == ""


def test_the_registry_roster_matches_the_approved_capability_matrix():
    """The five the contract's capability matrix freezes, in HUNTERS order.
    `injection` and `hollowing` are targeted-unsupported by design."""
    assert targeted_hunters() == ("stomping", "pipe", "cs-beacon", "yara", "obfuscation")
    assert set(HUNTERS) - set(targeted_hunters()) == {"injection", "hollowing"}


# ── evidence actually reaches the projected record ──────────────────────

def test_a_pipe_rescan_projects_the_ranges_own_string_lead(monkeypatch):
    """The projector feeds the range's own evidence to pipe's real
    `aggregate.build_report`, so a lead the rescan found is a lead the record
    carries -- scored exactly as full scope scores it (a bare pipe string is an
    unscored lead, never handle evidence)."""
    import dumpex.hunt.pipe.targeted as pipe_targeted

    pipe_name = rb"\\.\pipe\msagent_1337" + b"\x00"
    data = bytearray(b"\x00" * _SIZE)
    data[0x100:0x100 + len(pipe_name)] = pipe_name
    monkeypatch.setattr(pipe_targeted, "read_region_spanning",
                        lambda mf, addr, size: bytes(data)[addr - _BASE:addr - _BASE + size])

    class MF(FakeMF):
        memory_info = FakeStream(
            [Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")],
            "infos")
        memory_segments_64 = FakeStream([Segment(_BASE, _FILE_OFFSET, _SIZE)],
                                         "memory_segments")
        modules = FakeStream([], "modules")

    execution = execute_targeted(MF(), _request("pipe"))
    record = execution.result.records[0]
    assert record.details.private_pipes, "the range's own pipe-name lead reached the record"
    # A bare pipe string never scores, so the range stays a clean-but-lead
    # result rather than becoming a detection.
    assert record.score == 0
    assert record.lead_count >= 1
    assert record.coverage.status.value == "complete"


# ── the invocation's own observation registry ───────────────────────────

def test_a_targeted_run_retains_its_observation_in_the_registry():
    """The registry's produced/reused/failed instrumentation has to be real:
    a run whose result is never retained reports nothing at all, and #66's
    duplicate-scan assertion would have nothing to assert against."""
    execution = execute_targeted(_covered_dump(), _request("stomping"))
    counts = execution.context.observations.counts()
    assert counts["produced"] == 1
    assert execution.context.observations.retained == 1


def test_the_retained_observation_is_keyed_to_this_invocations_range():
    execution = execute_targeted(_covered_dump(), _request("stomping"))
    key, outcome = execution.context.observations.events()[0]
    assert outcome.value == "produced"
    assert key.analyzer == "stomping"
    assert key.is_targeted is True
    assert key.requested_range == VirtualRange(base_address=_BASE, size=_SIZE)


# ── scan_scope agrees with the closures it describes ────────────────────

@pytest.mark.parametrize("identity", targeted_hunters())
def test_scan_scope_scopes_agree_with_the_projected_closures(identity):
    """#66 reconciles on hunter + source + scope + base_address + size, so a
    consumer reading `scan_scope` alone must not conclude a run was unscoped
    when its closures carry scopes -- pipe's grant is unscoped while its
    invocation closes `pipe_name` and `c2_context` independently."""
    execution = execute_targeted(_empty_dump(), _request(identity))
    record = execution.result.records[0]
    assert execution.result.summary["scan_scope"]["scopes"] == sorted(
        {item.scope for item in record.details.targeted_scope if item.scope is not None})


def test_pipes_scan_scope_names_both_of_its_closures():
    execution = execute_targeted(_empty_dump(), _request("pipe"))
    assert execution.result.summary["scan_scope"]["scopes"] == ["c2_context", "pipe_name"]


# ── measured capture availability survives a closure that never ran ─────

def test_a_partly_captured_range_reports_its_real_prefix_even_when_nothing_ran(monkeypatch):
    """The number an analyst sizes a re-collection or the next chunk from. A
    closure that never reached its algorithm still measured the capture, so
    reporting it as unknown would throw that measurement away."""
    import dumpex.hunt.stomping.targeted as stomping_targeted

    class MF(FakeMF):
        # A committed, NON-executable region: ineligible for the IOC scan, so
        # the closure cannot run -- while the dump still backs half the range.
        memory_info = FakeStream(
            [Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")],
            "infos")
        memory_segments_64 = FakeStream([Segment(_BASE, _FILE_OFFSET, _SIZE // 2)],
                                         "memory_segments")
        modules = FakeStream([], "modules")

    monkeypatch.setattr(stomping_targeted, "read_region_spanning",
                        lambda mf, addr, size: b"\x00" * min(size, _SIZE // 2))
    execution = execute_targeted(MF(), _request("stomping"))
    entry = execution.result.records[0].details.targeted_scope[0]
    assert entry.coverage_status == "not_applicable"
    assert entry.capture_state == "partial"
    assert entry.captured_size == _SIZE // 2


# ── evidence reaches the record for the remaining two analyzers ─────────

def test_a_cs_beacon_rescan_projects_the_ranges_own_config(monkeypatch):
    """cs-beacon's projector passes hits and corroborations POSITIONALLY into
    `aggregate.build_report`; a swap would score a wrong or empty record."""
    from tests.fixtures.fakes import FakeReader, cs_beacon_config_bytes

    config = cs_beacon_config_bytes()
    data = b"\x00" * 0x100 + config + b"\x00" * 0x100

    class MF(FakeMF):
        memory_info = FakeStream(
            [Region(_BASE, _BASE, len(data), "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                     "MEM_PRIVATE")], "infos")
        memory_segments_64 = FakeStream([Segment(_BASE, _FILE_OFFSET, len(data))],
                                         "memory_segments")
        modules = FakeStream([], "modules")
        _reader = FakeReader({_BASE: data})

    source = REGISTRY.targeted_source("cs-beacon")
    request = HuntRequest.targeted(
        "cs-beacon", source, VirtualRange(base_address=_BASE, size=len(data)),
        scopes=REGISTRY.granted_scopes("cs-beacon", source))
    record = execute_targeted(MF(), request).result.records[0]
    assert record.details.config_count == len(record.details.configs) >= 1
    assert record.status == "DETECTED"
    assert record.score >= 1


def test_an_obfuscation_rescan_projects_each_layers_own_hits(monkeypatch):
    """obfuscation's projector maps three layers' coverage across ~25 keyword
    arguments; a mis-mapped layer would silently empty or mis-attribute one."""
    import base64

    import dumpex.hunt.encoding.targeted as encoding_targeted

    from tests.fixtures.fakes import build_pe_header

    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": 0x60000020}],
        size_of_image=0x2000, trailing_padding=0x300)
    payload = base64.b64encode(pe_bytes).ljust(0x1000, b"\x00")

    class MF(FakeMF):
        memory_info = FakeStream(
            [Region(_BASE, _BASE, len(payload), "MEM_COMMIT", "PAGE_READWRITE",
                     "MEM_PRIVATE")], "infos")
        memory_segments_64 = FakeStream([Segment(_BASE, _FILE_OFFSET, len(payload))],
                                         "memory_segments")
        modules = FakeStream([], "modules")

    monkeypatch.setattr(encoding_targeted, "read_region_spanning",
                        lambda mf, addr, size: payload[addr - _BASE:addr - _BASE + size])
    source = REGISTRY.targeted_source("obfuscation")
    request = HuntRequest.targeted(
        "obfuscation", source, VirtualRange(base_address=_BASE, size=len(payload)),
        scopes=REGISTRY.granted_scopes("obfuscation", source))
    record = execute_targeted(MF(), request).result.records[0]
    # The base64 layer's own hit list, reached through the decode closure.
    assert record.details.base64, "the range's own base64 decode reached the record"
    assert record.status == "DETECTED"
    assert [item.scope for item in record.details.targeted_scope] == [
        "sleep_mask", "entropy", "decode"]

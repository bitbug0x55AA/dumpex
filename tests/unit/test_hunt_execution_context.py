"""Construction, memoized memory views, and budget freshness of HuntExecutionContext."""
import dataclasses

import pytest

from dumpex.core import va_range
from dumpex.core.va_range import VirtualRange
from dumpex.hunt._execution import HuntBudgetLedger, build_execution_context
from dumpex.hunt._observation import ObservationRegistry
from dumpex.hunt._request import HuntRequest

from tests.fixtures.fakes import FakeStream, Region, Segment


class _MF:
    memory_segments_64 = FakeStream(
        [Segment(0x10000000, 0x1000, 0x2000)], "memory_segments")
    memory_segments = None
    memory_info = FakeStream(
        [Region(0x10000000, 0x10000000, 0x4000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        "infos")


def _context(mf=None):
    return build_execution_context(mf if mf is not None else _MF(), HuntRequest.full("all"))


def test_build_execution_context_fills_fresh_defaults():
    ctx = _context()
    assert isinstance(ctx.observations, ObservationRegistry)
    assert isinstance(ctx.budgets, HuntBudgetLedger)
    assert ctx.observations.retained == 0
    assert ctx.budgets.names() == ()
    assert not hasattr(ctx, "runtime")


def test_build_execution_context_rejects_a_non_request():
    with pytest.raises(TypeError):
        build_execution_context(_MF(), "all")


def test_context_is_frozen():
    ctx = _context()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.mf = None


def test_captured_views_enumerate_the_dump_once(monkeypatch):
    calls = {"segments": 0, "regions": 0}
    real_segments = va_range.captured_segments
    real_regions = va_range.enumerate_captured_regions

    def spy_segments(mf):
        calls["segments"] += 1
        return real_segments(mf)

    def spy_regions(mf):
        calls["regions"] += 1
        return real_regions(mf)

    monkeypatch.setattr(va_range, "captured_segments", spy_segments)
    monkeypatch.setattr(va_range, "enumerate_captured_regions", spy_regions)

    ctx = _context()
    first_segments = ctx.captured_segments()
    assert ctx.captured_segments() is first_segments
    assert ctx.captured_regions() is ctx.captured_regions()
    assert ctx.captured_region_enumeration() is ctx.captured_region_enumeration()
    # captured_regions() delegates to the memoized enumeration -- one walk.
    assert calls == {"segments": 1, "regions": 1}


def test_capture_of_uses_the_memoized_segments():
    ctx = _context()
    captured = ctx.capture_of(VirtualRange(0x10000000, 0x1000))
    assert captured.state is va_range.CaptureState.COMPLETE
    assert captured.captured_bytes == 0x1000


def test_capture_of_needs_a_virtual_range():
    with pytest.raises(TypeError):
        _context().capture_of((0x1000, 0x2000))


# ── budget ledger ─────────────────────────────────────────────────────

def test_budget_ledger_registers_once_and_reads_back():
    ledger = HuntBudgetLedger()
    sentinel = object()
    assert ledger.register("pipe_name", sentinel) is sentinel
    assert ledger.get("pipe_name") is sentinel
    assert "pipe_name" in ledger


def test_budget_ledger_rejects_a_double_registration():
    ledger = HuntBudgetLedger()
    ledger.register("decode", object())
    with pytest.raises(ValueError):
        ledger.register("decode", object())


def test_budget_ledger_read_before_register_raises():
    with pytest.raises(KeyError):
        HuntBudgetLedger().get("missing")


def test_budget_ledger_is_bounded():
    ledger = HuntBudgetLedger(max_budgets=2)
    ledger.register("a", object())
    ledger.register("b", object())
    with pytest.raises(ValueError):
        ledger.register("c", object())


def test_each_context_gets_its_own_registries():
    a = _context()
    b = _context()
    assert a.observations is not b.observations
    assert a.budgets is not b.budgets


def test_context_is_an_identity_object_not_value_equal():
    a = _context()
    b = _context()
    assert a != b
    assert a == a


def test_budget_ledger_private_storage_is_not_a_constructor_parameter():
    with pytest.raises(TypeError):
        HuntBudgetLedger(_budgets={"a": 1})


def test_registry_and_ledger_cannot_be_handed_to_the_context():
    from dumpex.hunt._execution import HuntExecutionContext
    # There is no injection parameter -- the context always makes its own.
    with pytest.raises(TypeError):
        HuntExecutionContext(request=HuntRequest.full("all"), mf=_MF(),
                             observations=ObservationRegistry())
    with pytest.raises(TypeError):
        build_execution_context(_MF(), HuntRequest.full("all"),
                                observations=ObservationRegistry())


def test_a_registry_or_ledger_cannot_be_claimed_by_two_contexts():
    reg = ObservationRegistry()
    reg.claim()
    with pytest.raises(ValueError):
        reg.claim()
    ledger = HuntBudgetLedger()
    ledger.claim()
    with pytest.raises(ValueError):
        ledger.claim()


def test_a_bare_registry_used_directly_is_never_claimed():
    # Direct use (a producer test) never calls claim(), so it still works.
    reg = ObservationRegistry()
    assert reg.retained == 0


# ── observation_key factory ─────────────────────────────────────────

def test_observation_key_derives_is_targeted_and_provenance_from_the_request():
    from dumpex.core.va_range import VirtualRange as _VR
    from dumpex.hunt._request import HuntRequest as _HR
    ctx = build_execution_context(
        _MF(), _HR.targeted("yara", "segment_scan", _VR(0x10000000, 0x1000)))
    key = ctx.observation_key("yara", algorithm_version="1", rule_provenance="sha:abc")
    assert key.is_targeted is True
    assert key.rule_provenance == "sha:abc"


def test_observation_key_encodes_the_unset_option_state():
    # yara declares a rules_dir option; a run without --yara-dir still gets a
    # provenance token, distinct from a configured run.
    unset = build_execution_context(
        _MF(), HuntRequest.full("yara")).observation_key("yara", algorithm_version="1")
    configured = build_execution_context(
        _MF(), HuntRequest.full("yara", rules_dir="/rules-a")).observation_key(
            "yara", algorithm_version="1")
    assert unset.rule_provenance == "rules_dir:unset"
    assert configured.rule_provenance == "/rules-a"
    assert unset != configured
    assert unset.coverage_locus == configured.coverage_locus  # -> INCOMPATIBLE_CACHE


def test_observation_key_two_rules_dirs_are_unequal_and_share_a_locus():
    a = build_execution_context(_MF(), HuntRequest.full("yara", rules_dir="/a")).observation_key(
        "yara", algorithm_version="1")
    b = build_execution_context(_MF(), HuntRequest.full("yara", rules_dir="/b")).observation_key(
        "yara", algorithm_version="1")
    assert a != b and a.coverage_locus == b.coverage_locus


def test_observation_key_needs_no_provenance_for_an_optionless_analyzer():
    ctx = _context()
    key = ctx.observation_key("pipe", algorithm_version="1")
    assert key.config_provenance is None and key.rule_provenance is None

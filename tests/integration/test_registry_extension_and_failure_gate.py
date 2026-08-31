"""Integration tests for registry extension and fail-closed execution paths."""
import pytest

from tests.fixtures.fakes import empty_mf as _empty_mf

import dumpex.hunt as hunt_pkg
from dumpex.hunt import _registry as registry_mod
from dumpex.hunt._registry import (
    REGISTRY,
    AnalyzerRegistry,
    AnalyzerSpec,
    InvalidAnalyzerSpec,
    TargetedCapability,
    TargetedGrant,
    TargetedScanUnit,
    UnpopulatedTargetedGrant,
    UnsupportedFullScopeRequest,
)
from dumpex.output.records import HUNTERS as REAL_HUNTERS


# ═══════════════════════════════════════════════════════════════════════
# Part 1 -- the future-analyzer extension fixture (contract §10)
# ═══════════════════════════════════════════════════════════════════════

_FUTURE_IDENTITY = "memscan"   # a genuinely new identity -- never one of
                                # the seven real HUNTERS members, so none
                                # of the steps below could accidentally
                                # pass by re-validating an already-correct
                                # real registration instead of this one.


class _FutureReport:
    """Synthetic report type with an identity distinct from shipped analyzers."""


def _future_builder(mf):
    # Deliberately a CLOSED signature (no declared options) -- see this
    # module's own docstring on why an open `**kwargs` catch-all would
    # misrepresent item 6's closed-option-set rule, which this fixture
    # does not otherwise exercise.
    return _FutureReport()


def _future_renderer(report, verbose):
    return {}


def _future_projector(report):
    class _Record:
        hunter = _FUTURE_IDENTITY

        def to_dict(self):
            return {"hunter": _FUTURE_IDENTITY}
    return _Record()


def _patch_hunters_with_future_identity(monkeypatch):
    """Expose the synthetic identity only to the registry under test."""
    monkeypatch.setattr(registry_mod, "HUNTERS", REAL_HUNTERS + (_FUTURE_IDENTITY,))


def _future_kwargs(**overrides):
    kwargs = dict(
        identity=_FUTURE_IDENTITY, package="tests.fixtures.future_hunter",
        report_type=_FutureReport, builder=_future_builder,
        renderer=_future_renderer, record_projector=_future_projector,
        option_names=frozenset(), provenance_hook=None,
        full_scope_capable=True, targeted_capability=None)
    kwargs.update(overrides)
    return kwargs


# ── Step 0 (§10 item 1): identity must be a reviewed HUNTERS member ─────

def test_extension_step0_unlisted_identity_is_rejected():
    # HUNTERS is NOT patched here -- "memscan" is not a reviewed identity
    # at all yet, so construction is rejected on this gate. This case
    # alone does NOT prove the identity gate is checked before any other
    # field -- every other field in `_future_kwargs()` is otherwise valid,
    # so nothing here distinguishes "checked first" from "the only bad
    # field, checked last, still fails." `..._even_with_other_invalid_
    # fields` immediately below closes that gap.
    with pytest.raises(InvalidAnalyzerSpec, match="must be one of"):
        AnalyzerSpec(**_future_kwargs())


def test_full_scope_extension_joins_the_registry_when_roster_entries_are_complete(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    patched_types = dict(registry_mod.EXPECTED_REPORT_TYPES)
    patched_types[_FUTURE_IDENTITY] = _FutureReport
    monkeypatch.setattr(registry_mod, "EXPECTED_REPORT_TYPES", patched_types)

    spec = AnalyzerSpec(**_future_kwargs())
    registry = AnalyzerRegistry(REGISTRY._all_specs() + (spec,))

    assert tuple(s.identity for s in registry._all_specs()) == REAL_HUNTERS + (_FUTURE_IDENTITY,)
    assert registry.get(_FUTURE_IDENTITY) is spec
    assert registry.select(_FUTURE_IDENTITY) == (spec,)
    assert spec in registry.select("all")


_FUTURE_CEILING = 256 * (1 << 20)


def _patch_targeted_mappings_for_future_identity(monkeypatch):
    monkeypatch.setattr(registry_mod, "_EXPECTED_TARGETED_SCAN_UNITS", {
        **registry_mod._EXPECTED_TARGETED_SCAN_UNITS, _FUTURE_IDENTITY: TargetedScanUnit.REGION})
    monkeypatch.setattr(registry_mod, "_COVERAGE_SOURCE_NAMES_BY_IDENTITY", {
        **registry_mod._COVERAGE_SOURCE_NAMES_BY_IDENTITY, _FUTURE_IDENTITY: frozenset({"future_scan"})})
    monkeypatch.setattr(registry_mod, "_EXPECTED_TARGETED_REQUEST_CEILINGS", {
        **registry_mod._EXPECTED_TARGETED_REQUEST_CEILINGS, _FUTURE_IDENTITY: _FUTURE_CEILING})
    monkeypatch.setattr(registry_mod, "_EXPECTED_TARGETED_CONSUMED_OPTIONS", {
        **registry_mod._EXPECTED_TARGETED_CONSUMED_OPTIONS, _FUTURE_IDENTITY: frozenset()})
    monkeypatch.setattr(registry_mod, "_APPROVED_TARGETED_IDENTITIES",
                         registry_mod._APPROVED_TARGETED_IDENTITIES | {_FUTURE_IDENTITY})


def test_new_targeted_extension_with_no_grants_fails_closed(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    _patch_targeted_mappings_for_future_identity(monkeypatch)
    patched_types = dict(registry_mod.EXPECTED_REPORT_TYPES)
    patched_types[_FUTURE_IDENTITY] = _FutureReport
    monkeypatch.setattr(registry_mod, "EXPECTED_REPORT_TYPES", patched_types)

    spec = AnalyzerSpec(**_future_kwargs(
        targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset())))
    registry = AnalyzerRegistry(REGISTRY._all_specs() + (spec,))

    with pytest.raises(UnpopulatedTargetedGrant):
        registry.select_targeted(_FUTURE_IDENTITY, "future_scan")


def test_new_targeted_extension_with_a_grant_succeeds(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    _patch_targeted_mappings_for_future_identity(monkeypatch)
    patched_types = dict(registry_mod.EXPECTED_REPORT_TYPES)
    patched_types[_FUTURE_IDENTITY] = _FutureReport
    monkeypatch.setattr(registry_mod, "EXPECTED_REPORT_TYPES", patched_types)

    spec = AnalyzerSpec(**_future_kwargs(
        targeted_capability=TargetedCapability(
            TargetedScanUnit.REGION, frozenset({TargetedGrant("future_scan", frozenset())}))))
    registry = AnalyzerRegistry(REGISTRY._all_specs() + (spec,))

    result = registry.select_targeted(_FUTURE_IDENTITY, "future_scan")
    assert result is spec
    assert tuple(s.identity for s in registry._all_specs()) == REAL_HUNTERS + (_FUTURE_IDENTITY,)
    assert registry.select("all")[-1] is spec


# Unknown options must fail at construction, before any builder can run.

def test_option_name_unknown_to_the_executor_cannot_be_constructed_at_all():
    real = REGISTRY.get("obfuscation")

    def fake_builder(mf, depth=None):
        return real.report_type()

    with pytest.raises(InvalidAnalyzerSpec, match="not known to _execute_full_scope"):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=fake_builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=frozenset({"depth"}), provenance_hook=real.provenance_hook,
            full_scope_capable=real.full_scope_capable, targeted_capability=real.targeted_capability)


# Import-time and per-call checks both compare the executor option view with
# the registry vocabulary. The per-call check protects already-running processes.

def test_check_option_names_in_sync_rejects_a_drifted_pair():
    with pytest.raises(InvalidAnalyzerSpec, match="has drifted"):
        hunt_pkg._check_option_names_in_sync(
            frozenset({"ref_dir"}), frozenset({"ref_dir", "rules_dir"}))
    with pytest.raises(InvalidAnalyzerSpec, match="has drifted"):
        hunt_pkg._check_option_names_in_sync(
            frozenset({"ref_dir", "rules_dir", "depth"}), frozenset({"ref_dir", "rules_dir"}))
    # No exception for a genuinely matched pair -- including the real one,
    # read off the same single source of truth `_option_view()` now is
    # (see the finding below on why a second, independent literal must
    # never come back).
    hunt_pkg._check_option_names_in_sync(frozenset({"ref_dir", "rules_dir"}), frozenset({"ref_dir", "rules_dir"}))
    hunt_pkg._check_option_names_in_sync(
        frozenset(hunt_pkg._option_view(None, None)), registry_mod.KNOWN_OPTION_NAMES)


def test_a_registry_declaring_a_new_known_option_name_without_updating_option_view_fails_with_zero_builder_calls(monkeypatch):
    """Per-call validation catches option drift before evidence collection starts."""
    patched_known = registry_mod.KNOWN_OPTION_NAMES | {"depth"}
    monkeypatch.setattr(registry_mod, "KNOWN_OPTION_NAMES", patched_known)
    _install_must_not_run_builders(monkeypatch)

    real = REGISTRY.get("obfuscation")

    def fake_builder(mf, depth=None):
        return real.report_type()

    spec = AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=fake_builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=frozenset({"depth"}), provenance_hook=real.provenance_hook,
        full_scope_capable=real.full_scope_capable, targeted_capability=real.targeted_capability)
    specs = tuple(spec if s.identity == "obfuscation" else s for s in REGISTRY._all_specs())
    registry = AnalyzerRegistry(specs)
    monkeypatch.setattr(registry_mod, "REGISTRY", registry)

    with pytest.raises(InvalidAnalyzerSpec, match="have drifted apart"):
        hunt_pkg.collect_hunt(_empty_mf(), "all")


# ═══════════════════════════════════════════════════════════════════════
# Part 2 -- registry failures never reach a real builder
# ═══════════════════════════════════════════════════════════════════════

_BUILDER_ATTR_BY_IDENTITY = {
    "injection": "_build_injection_report",
    "hollowing": "_build_hollowing_report",
    "stomping": "_build_stomping_report",
    "pipe": "_build_pipe_report",
    "cs-beacon": "_build_cs_beacon_report",
    "yara": "_build_yara_report",
    "obfuscation": "_build_encoding_report",
}


def test_builder_attr_table_covers_exactly_hunters():
    # A missing entry here would leave that identity's real builder
    # unguarded by `_install_must_not_run_builders()` below, and every
    # test using it would keep passing -- silently weaker, not visibly
    # broken -- the exact failure mode this module's own docstring
    # criticizes an earlier version of the §10 item 5 mapping tests for.
    # Mirrors `test_analyzer_registry.py`'s own
    # `test_adapter_attr_table_covers_exactly_hunters` guard for the
    # identically-shaped `_ADAPTER_ATTR` table there.
    assert set(_BUILDER_ATTR_BY_IDENTITY) == set(REAL_HUNTERS)


def _install_must_not_run_builders(monkeypatch):
    """Fail immediately if validation reaches any real analyzer builder."""
    def _must_not_run(*args, **kwargs):
        pytest.fail("a real hunter builder ran while validating a broken registry state")
    for attr in _BUILDER_ATTR_BY_IDENTITY.values():
        monkeypatch.setattr(hunt_pkg, attr, _must_not_run)


class _BrokenRegistry:
    """A registry whose selection always fails."""
    def select(self, selected):
        raise InvalidAnalyzerSpec("simulated: registry state is invalid")


@pytest.mark.parametrize("entrypoint", ["collect", "console"])
def test_broken_registry_fails_before_any_real_builder_runs(monkeypatch, entrypoint):
    _install_must_not_run_builders(monkeypatch)
    monkeypatch.setattr(registry_mod, "REGISTRY", _BrokenRegistry())

    with pytest.raises(InvalidAnalyzerSpec):
        if entrypoint == "collect":
            hunt_pkg.collect_hunt(_empty_mf(), "all")
        else:
            hunt_pkg.cmd_hunt(_empty_mf(), "all", verbose=False)


def _registry_with_one_identity_downgraded_to_targeted_only(identity):
    """Return a valid registry with one real analyzer excluded from full scope."""
    real = REGISTRY.get(identity)
    downgraded = AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=False, targeted_capability=real.targeted_capability)
    specs = tuple(downgraded if s.identity == identity else s for s in REGISTRY._all_specs())
    return AnalyzerRegistry(specs)


def test_select_raises_the_real_exception_for_a_targeted_only_single_identity_request(monkeypatch):
    """A targeted-only request fails before any builder runs."""
    _install_must_not_run_builders(monkeypatch)
    registry = _registry_with_one_identity_downgraded_to_targeted_only("stomping")
    monkeypatch.setattr(registry_mod, "REGISTRY", registry)

    with pytest.raises(UnsupportedFullScopeRequest):
        hunt_pkg._execute_full_scope(_empty_mf(), "stomping", render=True)


def test_cmd_hunt_translates_a_targeted_only_request_into_a_clear_user_facing_message(monkeypatch, capsys):
    """The console entry point turns targeted-only selection into a user error."""
    _install_must_not_run_builders(monkeypatch)
    registry = _registry_with_one_identity_downgraded_to_targeted_only("stomping")
    monkeypatch.setattr(registry_mod, "REGISTRY", registry)

    with pytest.raises(SystemExit) as exc_info:
        hunt_pkg.cmd_hunt(_empty_mf(), "stomping", verbose=False)

    assert exc_info.value.code == 1
    printed = capsys.readouterr().out
    assert "stomping" in printed
    assert "targeted-scan-only" in printed


def _install_call_counting_builders(monkeypatch):
    """Wrap real builders to record which full-scope analyzers run."""
    calls = {identity: 0 for identity in _BUILDER_ATTR_BY_IDENTITY}

    def make_wrapper(identity, real_fn):
        def wrapper(*args, **kwargs):
            calls[identity] += 1
            return real_fn(*args, **kwargs)
        return wrapper
    for identity, attr in _BUILDER_ATTR_BY_IDENTITY.items():
        monkeypatch.setattr(hunt_pkg, attr, make_wrapper(identity, getattr(hunt_pkg, attr)))
    return calls


def test_hunt_all_succeeds_and_excludes_a_targeted_only_registration(monkeypatch):
    """Full-scope collection excludes a targeted-only registration."""
    calls = _install_call_counting_builders(monkeypatch)
    registry = _registry_with_one_identity_downgraded_to_targeted_only("stomping")
    monkeypatch.setattr(registry_mod, "REGISTRY", registry)

    result = hunt_pkg.collect_hunt(_empty_mf(), "all")

    assert calls == {
        "injection": 1, "hollowing": 1, "stomping": 0,
        "pipe": 1, "cs-beacon": 1, "yara": 1, "obfuscation": 1,
    }, f"expected exactly the six non-downgraded builders to have run, downgraded stomping never: {calls}"
    assert [r.hunter for r in result.records] == [
        "injection", "hollowing", "pipe", "cs-beacon", "yara", "obfuscation"]
    assert result.summary["hunter_count"] == 6
    assert result.summary["selected"] == "all"


def test_cmd_hunt_all_also_succeeds_and_excludes_a_targeted_only_registration(monkeypatch, capsys):
    """The console path also excludes a targeted-only registration."""
    calls = _install_call_counting_builders(monkeypatch)
    registry = _registry_with_one_identity_downgraded_to_targeted_only("stomping")
    monkeypatch.setattr(registry_mod, "REGISTRY", registry)

    results = hunt_pkg.cmd_hunt(_empty_mf(), "all", verbose=False)

    assert calls["stomping"] == 0
    assert "stomping" not in results
    capsys.readouterr()   # drain the console summary card

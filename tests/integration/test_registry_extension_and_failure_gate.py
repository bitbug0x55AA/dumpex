"""
Issue #73's own two-part compatibility/extension gate, on top of the
per-gate unit coverage `tests/unit/test_analyzer_registry.py` already has
(contract `docs/hunt_analyzer_registry_contract.md` §7/§10/§12/§13).

1. **The future-analyzer extension fixture** (§10). Every existing
   negative-construction test in `test_analyzer_registry.py` exercises one
   gate at a time against one of the seven REAL identities (e.g. "what if
   injection's report_type were wrong"). None of them tells the single
   coherent story §10 itself is written as: an eighth analyzer, genuinely
   new, walking through the checklist step by step, failing on the exact
   gate the checklist names at each step, and only succeeding once every
   required step is present. This module builds that story once, against
   a synthetic identity ("memscan") that is never one of the seven real
   `HUNTERS` members, so it cannot be confused with (or accidentally
   validated by) any real analyzer's own already-correct registration.

   **Scope, stated precisely so this fixture is never read as proving more
   than it does:** "memscan" is patched only into `_registry.py`'s own
   module-level `HUNTERS` binding, never the real
   `dumpex.output.records.HUNTERS` -- the CLI-help/schema-enum/README/
   `CLI_REFERENCE.md`/`summary_presentation` display-map/
   `region_correlation._COLLECTORS` half of §10 item 2's twelve roster
   artifacts (ten non-registry artifacts -- four schema enums, two
   console display maps, `_COLLECTORS`, and the three human-facing
   CLI-help/`CLI_REFERENCE.md`/`README.md` artifacts -- plus the two the
   registry module itself adds) is deliberately untouched here (patching
   the real `HUNTERS` for one identity that doesn't otherwise exist in
   the schema, CLI help text, etc. would either require faking all ten of
   those too, well beyond a registry-focused fixture's job, or produce a
   misleadingly "passing" fixture that never actually exercised them).
   Those ten are `test_hunter_roster_alignment.py`'s own job, already
   covered there independently of `AnalyzerRegistry`. What THIS fixture
   proves is the narrower, but still real, claim §10 item 2's own closing
   note names specifically: the registry module's own two roster
   artifacts (`EXPECTED_REPORT_TYPES`, and the registration sequence's
   `HUNTERS`-order check) are enforced, not assumed -- plus item 1
   (order), item 4 (explicit full-scope declaration), and item 5
   (targeted-capability opt-in, fail-closed at every stage).

   **Item 6 (the late-bound, monkeypatchable adapter seam) is explicitly
   NOT covered here.** `AnalyzerSpec.__post_init__` itself only checks
   `callable(builder)` -- the late-binding/closed-signature validation
   item 6 actually requires (`_resolve_and_validate_builder`/`_renderer`/
   `_projector`, and the `_late_bound()` wrapper they return) only runs
   inside `_register()`, which this fixture's synthetic `_future_builder`/
   `_future_renderer`/`_future_projector` never go through -- they are
   plain, directly-captured functions, deliberately not late-bound or
   monkeypatchable, and `_future_builder` intentionally keeps a CLOSED
   signature (`(mf)`, no declared options) so nothing about this fixture
   models the open-`**kwargs` shape item 6's own closed-option-set rule
   forbids. The steps below prove only the `AnalyzerSpec`-level
   callability gate (§7.1's "adapters must be callable" half of item 6);
   the late-binding/signature-closure/monkeypatchability half is
   `test_analyzer_registry.py`'s own job (`test_builder_late_bound_for_
   every_identity`, `test_resolve_and_validate_builder_rejects_an_open_
   kwargs_catch_all`, and neighbors), already proven there for all seven
   real identities.

2. **Registry failures fail closed before any real analyzer runs** (the
   issue's own "Registry failures occur before evidence collection and
   must not be reported as a clean analyzer result" / "malformed specs
   must not invoke analyzer code" constraints), proven at the real
   `cmd_hunt()`/`collect_hunt()` entry points rather than only at
   `AnalyzerRegistry.select()` in isolation.

   **Scope, stated precisely:** `AnalyzerRegistry.__init__` runs
   `_validate_registrations()` unconditionally (contract §6) -- there is
   no way to reach a live, callable `REGISTRY` singleton that skipped
   construction-time validation, which is exactly what
   `test_analyzer_registry.py`'s own `test_registry_construction_rejects_*`
   suite already proves for every construction-time shape (duplicate/
   missing/reordered/wrong-report-type/...): none of those states can
   ever become a live registry reachable from `cmd_hunt()`/
   `collect_hunt()` in the first place, so there is no additional
   "malformed spec reaches a real builder" pathway to exercise for them.
   The one state that CAN reach these entry points in production is a
   `REGISTRY.select()` call-time failure (§7.2) -- `select()`'s own
   dedicated exceptions are each already unit-tested in isolation; what
   is proven here is that ANY such failure, encountered through the real,
   validated `cmd_hunt()`/`collect_hunt()` call path, reaches the caller
   with zero real builder invocations, using a sentinel that fails the
   test immediately and loudly the moment a real builder is ever called,
   rather than a counter checked only after the fact.
"""
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
    """Stand-in `Report` type for the synthetic future analyzer -- its own
    distinct type, so the report_type roster check (§10 item 2, §7.1
    failure #6) has something genuinely wrong to catch before it has
    something right to accept."""


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
    """Append `_FUTURE_IDENTITY` to the reviewed order, scoped to one
    test only -- patches `_registry.py`'s own module-level `HUNTERS`
    binding (the one `AnalyzerSpec`/`AnalyzerRegistry` actually read),
    never the real `dumpex.output.records.HUNTERS` (the schema/CLI/
    summary source of truth -- see this module's own docstring on why),
    the same targeted-patch pattern `test_analyzer_registry.py` already
    uses for `_EXPECTED_TARGETED_SCAN_UNITS`/
    `_COVERAGE_SOURCE_NAMES_BY_IDENTITY`."""
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

def test_extension_step0_unlisted_identity_is_rejected_before_anything_else():
    # HUNTERS is NOT patched here -- "memscan" is not a reviewed identity
    # at all yet, so construction must fail on that gate alone, before any
    # other field (callability, capability shape, ...) is ever inspected.
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_future_kwargs())


# ── Step 1 (§10 item 6, AnalyzerSpec-level callability half only) ───────
# See this module's own docstring for why late-binding/signature-closure/
# monkeypatchability (item 6's other half) is out of scope here.

def test_extension_step1_non_callable_adapter_still_rejected_once_listed(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_future_kwargs(builder="not callable"))


# ── Step 2 (§10 item 4): full_scope_capable must be stated explicitly ───

def test_extension_step2_neither_full_scope_nor_targeted_is_rejected(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_future_kwargs(full_scope_capable=False, targeted_capability=None))


def test_extension_step3_full_scope_only_spec_finally_constructs(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    spec = AnalyzerSpec(**_future_kwargs())
    assert spec.identity == _FUTURE_IDENTITY
    assert spec.targeted_capability is None


# ── Steps 4-5 (§10 item 2, registry-internal half only) ──────────────────
# `AnalyzerSpec` alone has no opinion on `EXPECTED_REPORT_TYPES` -- that
# cross-check lives at `AnalyzerRegistry` construction, over the full
# registration set (exactly like the real "injection registered with
# hollowing's report_type" case `test_analyzer_registry.py` already
# pins) -- so a spec that constructs cleanly in isolation can still be
# rejected the moment it joins a real registry missing its roster entry.
# This proves only the registry module's OWN two roster artifacts (this
# module's docstring); the other ten §10 item 2 names are
# `test_hunter_roster_alignment.py`'s job, not this fixture's.

def test_extension_step4_registry_rejects_it_without_an_expected_report_type_entry(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    spec = AnalyzerSpec(**_future_kwargs())
    specs = REGISTRY._all_specs() + (spec,)
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerRegistry(specs)


def test_extension_step5_registry_accepts_it_once_its_own_roster_entries_exist(monkeypatch):
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


# ── Step 6 (§10 item 1, order): position must match the reviewed index ──

def test_extension_step6_registry_rejects_it_spliced_into_the_wrong_position(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    patched_types = dict(registry_mod.EXPECTED_REPORT_TYPES)
    patched_types[_FUTURE_IDENTITY] = _FutureReport
    monkeypatch.setattr(registry_mod, "EXPECTED_REPORT_TYPES", patched_types)

    spec = AnalyzerSpec(**_future_kwargs())
    real_specs = list(REGISTRY._all_specs())
    # Spliced into the middle -- its only reviewed position (per the
    # patched HUNTERS order above) is LAST, not here.
    misordered = tuple(real_specs[:3] + [spec] + real_specs[3:])
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerRegistry(misordered)


# ── Steps 7a-7c (§10 item 5): three DISTINCT roster mappings, each ──────
# gated and proven in isolation -- `_EXPECTED_TARGETED_SCAN_UNITS` and
# `_COVERAGE_SOURCE_NAMES_BY_IDENTITY` are consulted inside
# `AnalyzerSpec.__post_init__` itself (so a missing entry in EITHER fails
# spec construction directly, each with its own distinct message);
# `_APPROVED_TARGETED_IDENTITIES` is a strictly later, registry-level
# gate (`AnalyzerRegistry`'s own exact-set-equality check over the WHOLE
# registration set) that a lone `AnalyzerSpec(...)` construction never
# reaches at all. An earlier version of this fixture removed all three
# mappings at once and asserted only a bare `InvalidAnalyzerSpec`, which
# would still pass if two of the three gates were silently deleted and
# only the third kept firing -- each case below removes exactly ONE
# mapping, keeps the other two (real or patched) present, and matches the
# specific message text that ONE gate raises, so a regression that
# silently drops any single gate is caught by name, not merely "some
# exception fired."

def test_extension_step7a_rejected_without_the_scan_unit_mapping(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    monkeypatch.setattr(registry_mod, "_COVERAGE_SOURCE_NAMES_BY_IDENTITY", {
        **registry_mod._COVERAGE_SOURCE_NAMES_BY_IDENTITY, _FUTURE_IDENTITY: frozenset({"future_scan"})})
    # _EXPECTED_TARGETED_SCAN_UNITS deliberately left WITHOUT an entry.
    with pytest.raises(InvalidAnalyzerSpec, match="no expected targeted scan_unit on file"):
        AnalyzerSpec(**_future_kwargs(
            targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset())))


def test_extension_step7b_rejected_without_the_coverage_source_mapping(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    monkeypatch.setattr(registry_mod, "_EXPECTED_TARGETED_SCAN_UNITS", {
        **registry_mod._EXPECTED_TARGETED_SCAN_UNITS, _FUTURE_IDENTITY: TargetedScanUnit.REGION})
    # _COVERAGE_SOURCE_NAMES_BY_IDENTITY deliberately left WITHOUT an entry.
    with pytest.raises(InvalidAnalyzerSpec, match="no coverage-source vocabulary on file"):
        AnalyzerSpec(**_future_kwargs(
            targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset())))


def test_extension_step7c_registry_rejected_without_the_approved_identities_entry(monkeypatch):
    # Both AnalyzerSpec-level mappings ARE present here, so the spec
    # constructs cleanly by itself -- this proves the SEPARATE,
    # registry-level exact-set gate over _APPROVED_TARGETED_IDENTITIES
    # fires on its own, not as a side effect of either gate above.
    _patch_hunters_with_future_identity(monkeypatch)
    monkeypatch.setattr(registry_mod, "_EXPECTED_TARGETED_SCAN_UNITS", {
        **registry_mod._EXPECTED_TARGETED_SCAN_UNITS, _FUTURE_IDENTITY: TargetedScanUnit.REGION})
    monkeypatch.setattr(registry_mod, "_COVERAGE_SOURCE_NAMES_BY_IDENTITY", {
        **registry_mod._COVERAGE_SOURCE_NAMES_BY_IDENTITY, _FUTURE_IDENTITY: frozenset({"future_scan"})})
    patched_types = dict(registry_mod.EXPECTED_REPORT_TYPES)
    patched_types[_FUTURE_IDENTITY] = _FutureReport
    monkeypatch.setattr(registry_mod, "EXPECTED_REPORT_TYPES", patched_types)
    # _APPROVED_TARGETED_IDENTITIES deliberately left WITHOUT this identity.

    spec = AnalyzerSpec(**_future_kwargs(
        targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset())))
    with pytest.raises(InvalidAnalyzerSpec, match="must equal the approved set"):
        AnalyzerRegistry(REGISTRY._all_specs() + (spec,))


def _patch_targeted_mappings_for_future_identity(monkeypatch):
    monkeypatch.setattr(registry_mod, "_EXPECTED_TARGETED_SCAN_UNITS", {
        **registry_mod._EXPECTED_TARGETED_SCAN_UNITS, _FUTURE_IDENTITY: TargetedScanUnit.REGION})
    monkeypatch.setattr(registry_mod, "_COVERAGE_SOURCE_NAMES_BY_IDENTITY", {
        **registry_mod._COVERAGE_SOURCE_NAMES_BY_IDENTITY, _FUTURE_IDENTITY: frozenset({"future_scan"})})
    monkeypatch.setattr(registry_mod, "_APPROVED_TARGETED_IDENTITIES",
                         registry_mod._APPROVED_TARGETED_IDENTITIES | {_FUTURE_IDENTITY})


def test_extension_step8_targeted_capability_spec_constructs_once_every_mapping_exists(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    _patch_targeted_mappings_for_future_identity(monkeypatch)

    spec = AnalyzerSpec(**_future_kwargs(
        targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset())))
    assert spec.targeted_capability.grants == frozenset()


def test_extension_step9_empty_grants_still_fail_closed_through_the_real_registry(monkeypatch):
    """The exact hazard §10 item 5 calls out for a brand-new analyzer: an
    empty `grants` is this release's temporary, sanctioned state for the
    FIVE REAL targeted-capable identities (#59/#61 have not landed yet)
    -- never a free pass for a new one, which item 5 requires to ship
    with a real, populated grant at registration time, with no grace
    period. Built and validated through the REAL `AnalyzerRegistry(...)`
    constructor, alongside all seven real specs (never the test-only
    `_construct_unvalidated()` escape hatch, and never a lone-spec
    registry) -- so this also proves the eighth spec's empty grant
    survives real, full-roster construction before `select_targeted()`
    is ever reached, not merely that a hand-built single-spec registry
    object can read a field off it."""
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


def test_extension_step10_a_real_populated_grant_finally_succeeds_through_the_real_registry(monkeypatch):
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
    # The eighth spec is a full, functioning registry member now, not
    # merely one that can answer select_targeted() in isolation.
    assert tuple(s.identity for s in registry._all_specs()) == REAL_HUNTERS + (_FUTURE_IDENTITY,)
    assert registry.select("all")[-1] is spec


# ═══════════════════════════════════════════════════════════════════════
# Part 2 -- a select()-raising registry never reaches a real builder
# ═══════════════════════════════════════════════════════════════════════

_REAL_BUILDER_ATTRS = (
    "_build_injection_report", "_build_hollowing_report", "_build_stomping_report",
    "_build_pipe_report", "_build_cs_beacon_report", "_build_yara_report",
    "_build_encoding_report",
)


def _install_must_not_run_builders(monkeypatch):
    """Replace every one of the seven REAL hunters' builders, seen on
    `dumpex.hunt` -- the exact seam `_registry._late_bound()` resolves at
    call time -- with a sentinel that fails the test immediately and
    loudly the moment it is ever invoked, rather than a counter checked
    only after the real function has already run underneath it."""
    def _must_not_run(*args, **kwargs):
        pytest.fail("a real hunter builder ran while validating a broken registry state")
    for attr in _REAL_BUILDER_ATTRS:
        monkeypatch.setattr(hunt_pkg, attr, _must_not_run)


class _BrokenRegistry:
    """The one shape a corrupted/replaced `REGISTRY` singleton CAN take
    when reached through `cmd_hunt()`/`collect_hunt()` (see this module's
    own docstring on why every construction-time shape is foreclosed
    before it ever becomes live): `select()` itself raises, exactly like
    every real §7.2 call-time failure already does (unknown identity,
    unsupported capability, unpopulated grant, ...) -- each of which has
    its own dedicated unit test already. What this class exists to prove
    is that ANY such failure, however it arose, reaches the caller before
    a single real builder runs."""
    def select(self, selected):
        raise InvalidAnalyzerSpec("simulated: registry state is invalid")


@pytest.mark.parametrize("selected", list(REAL_HUNTERS) + ["all"])
def test_broken_registry_fails_cmd_hunt_before_any_real_builder_runs(monkeypatch, selected):
    _install_must_not_run_builders(monkeypatch)
    monkeypatch.setattr(registry_mod, "REGISTRY", _BrokenRegistry())

    with pytest.raises(InvalidAnalyzerSpec):
        hunt_pkg.cmd_hunt(_empty_mf(), selected, verbose=False)


@pytest.mark.parametrize("selected", list(REAL_HUNTERS) + ["all"])
def test_broken_registry_fails_collect_hunt_before_any_real_builder_runs(monkeypatch, selected):
    _install_must_not_run_builders(monkeypatch)
    monkeypatch.setattr(registry_mod, "REGISTRY", _BrokenRegistry())

    with pytest.raises(InvalidAnalyzerSpec):
        hunt_pkg.collect_hunt(_empty_mf(), selected)

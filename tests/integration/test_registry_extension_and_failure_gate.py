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
   CONSTRUCTION-TIME validation, which is exactly what
   `test_analyzer_registry.py`'s own `test_registry_construction_rejects_*`
   suite already proves for every construction-time shape (duplicate/
   missing/reordered/wrong-report-type/...): none of those states can
   ever become a live registry reachable from `cmd_hunt()`/
   `collect_hunt()` in the first place. This claim is about CONSTRUCTION-
   TIME invalidity specifically -- it says nothing about a registry that
   is fully VALID at construction time but whose selected records later
   fail a DIFFERENT downstream invariant for an unrelated reason; see
   finding 4 below for exactly that case, which this module does NOT
   claim "before any builder runs" covers. Within its stated scope, the
   one state that CAN reach these entry points in production is a
   `REGISTRY.select()` call-time failure (§7.2) -- `select()`'s own
   dedicated exceptions are each already unit-tested in isolation, and
   both a real one (`UnsupportedFullScopeRequest`, via a genuinely valid
   registry) and a simulated generic one are proven below to reach the
   caller with zero real builder invocations, using a sentinel that fails
   the test immediately and loudly the moment a real builder is ever
   called, rather than a counter checked only after the fact.

3. **A finding this issue closes, not merely tests -- in two passes, the
   first of which reopened its own regression.** `AnalyzerSpec.
   option_names` (§5 field 7) used to be validated only against the
   BUILDER's own signature (§7.1 failure #7) -- never against what
   `_execute_full_scope()` (`dumpex/hunt/__init__.py`) actually knows how
   to supply a value for. A spec declaring a real, correctly-defaulted
   builder keyword outside that set used to construct successfully and
   only fail with a bare `KeyError` partway through the selection loop,
   AFTER every earlier-selected analyzer's builder had already run (six
   real builders, confirmed by direct reproduction against the pre-fix
   code) -- a direct violation of "malformed specs must not invoke
   analyzer code." `dumpex/hunt/_registry.py`'s `KNOWN_OPTION_NAMES`
   constant and the `AnalyzerSpec.__post_init__` check against it close
   the CONSTRUCTION-time half of this at the one and only construction
   path. The FIRST fix attempt paired that with an import-time-only guard
   in `dumpex/hunt/__init__.py` that compared two independently
   hand-maintained frozensets, neither one actually derived from the real
   `options` dict `_execute_full_scope()` builds -- an edit that kept
   both constants in lockstep (exactly what §10 item 3's own extension
   guidance instructs) could still leave that real dict itself out of
   sync, reproducing the identical six-builders-then-`KeyError` failure
   this whole finding exists to close. `dumpex/hunt/__init__.py`'s
   `_option_view(ref_dir, yara_dir)` is the corrected, SINGLE source of
   truth both `_execute_full_scope()` and the import-time guard now call
   -- eliminating the second literal entirely -- paired with a genuine
   PER-CALL preflight inside `_execute_full_scope()` itself (see "A
   finding closed in two passes" below, right before Part 2), since
   import-time validation is structurally a boot-time invariant that
   cannot retroactively catch a mismatch introduced after this process
   has already imported `dumpex.hunt`. There IS an entry-point-level
   companion test for this finding now -- see that same section.

4. **A finding this issue closes, not merely documents.** Registering
   the first `full_scope_capable=False` analyzer (§7.1 failure #5's own
   permitted shape) used to crash EVERY `--hunt all` invocation with a
   bare `ValueError` -- `select("all")` (§6) always correctly filtered it
   out of `records`, exactly as §2's "corrected invariant" and §10 item 4
   both claim, but `dumpex.hunt.summary.build_hunt_summary(selected=
   "all")` used to assert the unfiltered `tuple(HUNTERS)` against
   `records` unconditionally, contradicting item 4's own "silently
   changes nothing about --hunt all's record count" text -- and not as a
   cheap fail-fast: the crash fired only AFTER `_execute_full_scope()`
   had already run every one of `select("all")`'s surviving real builders
   to completion, throwing away a full round of real evidence collection
   on every single invocation. This is now fixed: `build_hunt_summary()`
   takes an explicit `full_scope_hunters` keyword, and `dumpex.hunt.
   full_scope_hunters()` (`tuple(spec.identity for spec in REGISTRY.
   select("all"))` -- literally §2's own filtered-`HUNTERS` formula) is
   what `collect_hunt()`, `cmd_hunt()`, and `dumpex/cli.py`'s own second,
   redundant `build_hunt_summary()` call all now pass, so `select("all")`
   and `build_hunt_summary`'s own expectation can no longer disagree.
   `cmd_hunt()`'s own single-identity path is fixed the same way: it used
   to let `UnsupportedFullScopeRequest` propagate as a bare traceback out
   of `dumpex.cli.main()`; it now catches it and prints the same directed
   message + `sys.exit(1)` shape its own unknown-TTP branch already used.
   The tests below prove both fixes directly: `--hunt all` now SUCCEEDS
   for a genuinely valid `full_scope_capable=False` registration (with
   that identity's own builder never called, and every other real
   builder still running normally), and a single-identity request against
   it now produces a clear, user-visible message and exit code rather
   than an exception type. **What remains genuinely open, unchanged by
   this fix**: the disclosure-mechanism DESIGN item 4 itself requires but
   does not design -- making a targeted-only exclusion *visible*
   somewhere in `--hunt all`'s own output -- is still deferred to
   whichever of #62-#66/#53 registers the first genuine targeted-only
   analyzer; only the crash/traceback that used to make the surrounding
   claims false is fixed here.
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


def test_extension_step0b_identity_gate_fires_even_with_other_invalid_fields():
    # `builder` is ALSO invalid here (non-callable) -- if the callability
    # gate ran first, this would raise "must be callable" instead of the
    # identity message. Matching on the identity gate's own message text
    # proves it genuinely runs before the callability gate, not merely
    # that "some gate, we don't know which" rejects a spec with two
    # independent defects.
    with pytest.raises(InvalidAnalyzerSpec, match="must be one of"):
        AnalyzerSpec(**_future_kwargs(builder="not callable"))


# ── Step 1 (§10 item 6, AnalyzerSpec-level callability half only) ───────
# See this module's own docstring for why late-binding/signature-closure/
# monkeypatchability (item 6's other half) is out of scope here.

def test_extension_step1_non_callable_adapter_still_rejected_once_listed(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    with pytest.raises(InvalidAnalyzerSpec, match="must be callable"):
        AnalyzerSpec(**_future_kwargs(builder="not callable"))


# ── Step 2 (§10 item 4): full_scope_capable must be stated explicitly ───

def test_extension_step2_neither_full_scope_nor_targeted_is_rejected(monkeypatch):
    _patch_hunters_with_future_identity(monkeypatch)
    with pytest.raises(InvalidAnalyzerSpec, match="could run in neither mode"):
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
    with pytest.raises(InvalidAnalyzerSpec, match="no expected report_type on file"):
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
    with pytest.raises(InvalidAnalyzerSpec, match="to match HUNTERS order"):
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


# ── A finding closed by #73 at the CONSTRUCTION-time layer ──────────────
# `AnalyzerSpec.option_names` (§5 field 7) used to be validated only
# against the BUILDER's own signature (§7.1 failure #7) -- never against
# `_registry.KNOWN_OPTION_NAMES`, the set `_execute_full_scope()`
# (dumpex/hunt/__init__.py) actually knows how to supply a value for. A
# spec declaring a real, correctly-defaulted builder keyword outside that
# set used to construct successfully -- passing `_resolve_and_validate_
# builder()`, `AnalyzerSpec.__post_init__`, and `AnalyzerRegistry`'s own
# `_validate_registrations()` alike -- and would only fail with a bare
# `KeyError` partway through `_execute_full_scope()`'s own selection
# loop, AFTER every earlier-selected analyzer's builder had already run
# (six real builders, confirmed by direct reproduction against the
# pre-fix code). `dumpex/hunt/_registry.py`'s own `AnalyzerSpec.
# __post_init__` now checks `option_names <= KNOWN_OPTION_NAMES`
# directly (`test_analyzer_registry.py`'s own
# `test_analyzer_spec_rejects_an_option_name_unknown_to_the_executor`
# pins this at the unit level, with `match=`).
#
# **This closes only the case where `option_names` itself names something
# outside `KNOWN_OPTION_NAMES` -- it does NOT, on its own, close the case
# where `KNOWN_OPTION_NAMES` and the executor's own real option view have
# drifted apart from EACH OTHER** (both agreeing on a name
# `_execute_full_scope()`'s own dict-building code doesn't actually
# produce). An earlier version of this comment block argued the opposite
# -- that no construction path could reach a live "bad" spec at all, so
# no entry-point-level companion test was needed here -- which was true
# ONLY for the narrower case this section covers, and was DISPROVEN for
# the broader one: see "A finding closed in two passes" below (right
# before Part 2), whose own entry-point-level test,
# `test_a_registry_declaring_a_new_known_option_name_without_updating_
# option_view_fails_with_zero_builder_calls`, is exactly the companion
# case that earlier reasoning claimed could never be reached.

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


# ── A finding closed in two passes, at TWO layers ────────────────────────
# `dumpex.hunt._execute_full_scope()`'s own options view is `_option_view
# (ref_dir, yara_dir)` (`dumpex/hunt/__init__.py`) -- the ONE function
# both `_execute_full_scope()` itself and the checks below read, never a
# second, independently-declared literal. It is checked against
# `_registry.KNOWN_OPTION_NAMES` at TWO layers, not one:
#
# 1. Once, at IMPORT time, by `dumpex/hunt/__init__.py`'s own module-level
#    `_check_option_names_in_sync(frozenset(_option_view(None, None)),
#    _registry.KNOWN_OPTION_NAMES)` call -- matching every other §7.1
#    construction-time invariant's whole-CLI blast radius (a mismatch
#    here fails `import dumpex.cli`, not merely the first `--hunt`
#    invocation that happens to reach it). The three tests immediately
#    below cover this layer; none needs to reload `dumpex.hunt` to prove
#    it: the comparison itself is a real, directly-testable function
#    (never a bare module-level `if`/`raise` alone), and whether it is
#    ACTUALLY called at import time -- against the REAL `_option_view()`,
#    not a second literal -- is proven by AST inspection of the call's
#    own arguments (the same AST-inspection technique
#    `test_analyzer_registry.py`'s own `test_module_actually_calls_
#    validate_scoped_sources_at_import_time` uses for `_registry.py`'s
#    own `_validate_scoped_sources()` call, strengthened here -- see that
#    test's own docstring for why the unstrengthened version could not
#    have caught this section's own finding).
#
# 2. Once PER CALL, inside `_execute_full_scope()` itself, over every
#    selected spec's `option_names` against THAT call's own real
#    `options` dict, before the builder loop starts -- because import-
#    time validation is a boot-time invariant: correct for catching a
#    genuine source-level edit the moment `dumpex.cli` next imports
#    `dumpex.hunt`, but structurally unable to catch a mismatch
#    introduced AFTER this process has already imported it (global state
#    mutated mid-session). `test_a_registry_declaring_a_new_known_
#    option_name_without_updating_option_view_fails_with_zero_builder_
#    calls`, in Part 2 below, is this layer's own entry-point-level test
#    -- reproducing exactly the regression an earlier, import-time-only
#    version of this fix reopened (see this file's own module docstring,
#    finding 3, for the full history).

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


def test_option_names_literal_is_never_reintroduced():
    # A tripwire, not a behavioral test: `_OPTION_NAMES` (a second,
    # independently-declared literal comparing itself to `_registry.
    # KNOWN_OPTION_NAMES` instead of the REAL `_option_view()` output) is
    # exactly the shape that reopened this finding once already (see this
    # module's own docstring, finding 3). If a future edit reintroduces
    # it, this fails immediately and by name, rather than waiting for
    # someone to notice the AST test above stopped meaning what its own
    # docstring says.
    assert not hasattr(hunt_pkg, "_OPTION_NAMES"), (
        "dumpex.hunt._OPTION_NAMES has come back -- this is the exact "
        "independently-drifting-literal shape this module's own finding 3 "
        "closed; _option_view() must remain the only source of truth for "
        "the executor's real option names")


def test_check_option_names_in_sync_is_actually_called_at_import_time_against_the_real_option_view():
    """Finding, #73: an earlier version of this import-time call compared
    TWO independently hand-maintained frozensets (a local `_OPTION_NAMES`
    constant against `_registry.KNOWN_OPTION_NAMES`) -- and this exact
    AST test, in its earlier form, only checked that SOME call to
    `_check_option_names_in_sync` existed at module top level, without
    inspecting its arguments. That earlier test could not have caught the
    regression: reproduced directly, `KNOWN_OPTION_NAMES` and the old
    `_OPTION_NAMES` were both updated to add a name, `_execute_full_
    scope()`'s own real `options` dict literal was left untouched, the
    import-time guard still passed (comparing two now-matching but
    independently-drifted-from-reality constants), and `collect_hunt
    ("all")` crashed with a bare `KeyError` after six real builders had
    already run. This version closes that blind spot: it inspects the
    call's own ARGUMENTS, not merely that a call with this name exists,
    and specifically requires the first argument to be built from
    `_option_view(...)` -- the same function `_execute_full_scope()`
    itself calls to build its real `options` dict -- never a bare `Name`
    reference to a second, independently-declared constant."""
    import ast
    from pathlib import Path
    hunt_init = Path(hunt_pkg.__file__)
    tree = ast.parse(hunt_init.read_text(encoding="utf-8"), filename=str(hunt_init))
    calls = [
        node.value for node in tree.body
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "_check_option_names_in_sync"
    ]
    assert len(calls) == 1, (
        f"dumpex/hunt/__init__.py must call _check_option_names_in_sync() exactly once "
        f"at module (import) time, found {len(calls)}")
    call = calls[0]
    assert len(call.args) == 2, f"expected exactly 2 positional arguments, got {len(call.args)}"

    first, second = call.args
    assert (
        isinstance(first, ast.Call) and isinstance(first.func, ast.Name) and first.func.id == "frozenset"
        and len(first.args) == 1 and isinstance(first.args[0], ast.Call)
        and isinstance(first.args[0].func, ast.Name) and first.args[0].func.id == "_option_view"
    ), (
        "the first argument to the import-time _check_option_names_in_sync() call must be "
        "frozenset(_option_view(...)) -- the SAME function _execute_full_scope() itself calls "
        "to build its real options dict -- not a second, independently-declared constant "
        f"(a bare Name reference would silently reintroduce this module's own closed finding); "
        f"got {ast.dump(first)}")
    assert isinstance(second, ast.Attribute) and second.attr == "KNOWN_OPTION_NAMES", (
        f"the second argument must be an attribute access ending in .KNOWN_OPTION_NAMES "
        f"(i.e. _registry.KNOWN_OPTION_NAMES); got {ast.dump(second)}")


def test_a_registry_declaring_a_new_known_option_name_without_updating_option_view_fails_with_zero_builder_calls(monkeypatch):
    """The residual gap import-time validation cannot, by construction,
    close on its own: import-time validation is a boot-time invariant,
    checked once, against whatever `_registry.KNOWN_OPTION_NAMES` and
    `_option_view()` say at THAT moment -- it cannot retroactively catch
    a mismatch introduced after this process already imported
    `dumpex.hunt` (the realistic shape of that, in production, is a
    source-level edit that updates `_registry.py`'s own
    `KNOWN_OPTION_NAMES` literal without updating `dumpex/hunt/__init__.
    py`'s own `_option_view()` -- caught at the NEXT process's import,
    but not retroactively in an already-running one). This is exactly
    the P1 finding's own reproduction, replayed end to end through the
    real `cmd_hunt()`/`collect_hunt()` entry points: `_registry.
    KNOWN_OPTION_NAMES` is patched to add a name `_option_view()` itself
    is deliberately left NOT knowing about, a spec declaring that option
    name is built and registered through the real, validating
    `AnalyzerRegistry(...)` constructor (which now happily accepts it,
    since `AnalyzerSpec.__post_init__`'s own `option_names <=
    KNOWN_OPTION_NAMES` check reads the patched constant) -- and the
    NEW, PER-CALL preflight check inside `_execute_full_scope()` (not the
    import-time one, which already ran and cannot re-fire) is what
    catches it here, with zero real builder invocations, closing the gap
    the import-time check alone left open."""
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
    """Replace every one of the seven REAL hunters' builders, seen on
    `dumpex.hunt` -- the exact seam `_registry._late_bound()` resolves at
    call time -- with a sentinel that fails the test immediately and
    loudly the moment it is ever invoked, rather than a counter checked
    only after the real function has already run underneath it."""
    def _must_not_run(*args, **kwargs):
        pytest.fail("a real hunter builder ran while validating a broken registry state")
    for attr in _BUILDER_ATTR_BY_IDENTITY.values():
        monkeypatch.setattr(hunt_pkg, attr, _must_not_run)


class _BrokenRegistry:
    """A registry state that is not itself one of the real, named §7.2
    exceptions -- see `test_a_real_targeted_only_spec_fails_single_
    identity_selection_with_the_real_exception` below for a genuine,
    named call-time failure reached the same way. What THIS class proves
    is the generic shape: `select()` itself raises, unconditionally, for
    any reason -- and that ANY such failure, however it arose, reaches
    the caller before a single real builder runs."""
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


def _registry_with_one_identity_downgraded_to_targeted_only(identity):
    """A real registration with ONLY `full_scope_capable` flipped to
    `False` -- every other field (builder/renderer/projector/report_type/
    targeted_capability) untouched -- exactly the shape §7.1 failure #5
    already permits and `test_analyzer_registry.py`'s own
    `test_select_single_identity_rejects_a_full_scope_incapable_spec`
    already constructs. Built through the REAL, validating
    `AnalyzerRegistry(...)` constructor alongside the other six real
    specs, unchanged -- never `_construct_unvalidated()`, so this is a
    genuinely valid registry a caller could actually end up holding, not
    a simulated failure."""
    real = REGISTRY.get(identity)
    downgraded = AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=False, targeted_capability=real.targeted_capability)
    specs = tuple(downgraded if s.identity == identity else s for s in REGISTRY._all_specs())
    return AnalyzerRegistry(specs)


def test_select_raises_the_real_exception_for_a_targeted_only_single_identity_request(monkeypatch):
    """`_BrokenRegistry` above proves only that SOME select()-raising
    failure reaches the caller with zero builder calls, using a
    simulated exception. This proves a SPECIFIC, real §7.2 call-time
    exception (`UnsupportedFullScopeRequest`, failure #11 -- "targeted-
    only analyzer requested through the single-identity --hunt path")
    does the same, at the internal `_execute_full_scope()`/`select()`
    seam, through a genuinely valid, fully-constructed registry -- not a
    stand-in class. See `test_cmd_hunt_translates_a_targeted_only_
    request_into_a_clear_user_facing_message` below for what `cmd_hunt()`
    itself does with this exception (finding, #73: it now translates it
    into a directed message and `sys.exit(1)`, rather than letting it
    propagate as a bare traceback -- this test pins the internal
    mechanism `cmd_hunt()`'s own `except` clause now catches, not the
    user-facing behavior)."""
    _install_must_not_run_builders(monkeypatch)
    registry = _registry_with_one_identity_downgraded_to_targeted_only("stomping")
    monkeypatch.setattr(registry_mod, "REGISTRY", registry)

    with pytest.raises(UnsupportedFullScopeRequest):
        hunt_pkg._execute_full_scope(_empty_mf(), "stomping", render=True)


def test_cmd_hunt_translates_a_targeted_only_request_into_a_clear_user_facing_message(monkeypatch, capsys):
    """Finding, #73: `cmd_hunt()` used to have no `except` clause around
    its own `_execute_full_scope()` call, so `UnsupportedFullScopeRequest`
    propagated all the way to `dumpex.cli.main()`'s own `except
    BaseException: ... raise` as a bare Python traceback -- contradicting
    §10 item 4's own recommended option (a): "fail with a clear 'this
    analyzer is targeted-scan only' message" (failure #11's own job).
    `cmd_hunt()` now catches `_registry.UnsupportedFullScopeRequest`
    around that call and translates it into the same directed-message-
    then-`sys.exit(1)` shape its own unknown-TTP branch, a few lines
    earlier in the same function, already used -- proven here against
    USER-VISIBLE behavior (the printed message and the process exit
    code), not merely the exception type, so this test cannot be
    satisfied by a bare re-raise."""
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
    """Unlike `_install_must_not_run_builders()` above, these wrappers
    let the real function run underneath -- the tests below use this to
    prove exactly which six of the seven real builders run (every one
    except the downgraded, correctly-excluded identity) on a SUCCESSFUL
    `--hunt all` invocation, not that they must not run at all."""
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
    """Finding, #73: `select("all")` (§6) has always correctly filtered a
    `full_scope_capable=False` spec out of `records` -- but
    `dumpex.hunt.summary.build_hunt_summary(selected="all")` used to
    assert the UNFILTERED `tuple(HUNTERS)` against `records`
    unconditionally, so registering the first targeted-only analyzer
    crashed every `--hunt all` invocation with a bare `ValueError`,
    AFTER every one of `select("all")`'s six surviving real builders had
    already run to completion (YARA's full segment scan and
    obfuscation's per-region decode included) -- a wasted scan thrown
    away on every single invocation, not merely a missing field. This is
    now fixed: `build_hunt_summary()` takes an explicit
    `full_scope_hunters` keyword (`dumpex.hunt.full_scope_hunters()`,
    itself `tuple(spec.identity for spec in REGISTRY.select("all"))`),
    and every caller that knows the real, capability-filtered roster
    (`collect_hunt()`, `cmd_hunt()`, `dumpex/cli.py`'s own second,
    redundant `build_hunt_summary()` call) passes it. This proves
    `collect_hunt(mf, "all")` now SUCCEEDS for a genuinely valid
    `full_scope_capable=False` registration, with the downgraded
    identity's own builder never called (it is correctly excluded from
    `select("all")` before the loop even starts, same as it always was)
    and every other real builder still running normally."""
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
    """The same fix, proven through `cmd_hunt()` (the actual `--hunt`
    CLI entry point, not only the JSON-only `collect_hunt()` path) --
    console rendering included, since `cmd_hunt(..., ttp="all")` also
    calls `dumpex.hunt.summary_presentation.render_hunt_summary()`, which
    reads the same `records`/`summary` this fix corrects."""
    calls = _install_call_counting_builders(monkeypatch)
    registry = _registry_with_one_identity_downgraded_to_targeted_only("stomping")
    monkeypatch.setattr(registry_mod, "REGISTRY", registry)

    results = hunt_pkg.cmd_hunt(_empty_mf(), "all", verbose=False)

    assert calls["stomping"] == 0
    assert "stomping" not in results
    capsys.readouterr()   # drain the console summary card

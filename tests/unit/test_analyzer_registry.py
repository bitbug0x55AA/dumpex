"""
Unit tests for `dumpex.hunt._registry` (issue #71, implementing the
contract frozen in `docs/hunt_analyzer_registry_contract.md`, issue #70).

Covers: the real, shipped `REGISTRY`'s roster/order/capability shape; the
call-time failure modes `AnalyzerRegistry.get()`/`select()`/
`select_targeted()` must raise (contract §7.2); the construction-time
failure modes `AnalyzerSpec`/`AnalyzerRegistry` registration must reject
(contract §7.1), exercised against synthetic specs/registrations rather
than mutating the real module-level `REGISTRY` (which is a frozen,
already-validated singleton by the time any test runs); and the
`_all_specs()` production-boundary rule (contract §6/§12).
"""
import ast
import dataclasses
from pathlib import Path

import pytest

from tests.fixtures.fakes import empty_mf

import dumpex.hunt as hunt_pkg
from dumpex.hunt._registry import (
    REGISTRY,
    EXPECTED_REPORT_TYPES,
    AnalyzerRegistry,
    AnalyzerSpec,
    InvalidAnalyzerSpec,
    TargetedCapability,
    TargetedGrant,
    TargetedScanUnit,
    UnknownAnalyzerIdentity,
    UnpopulatedTargetedGrant,
    UnsupportedFullScopeRequest,
    UnsupportedTargetedCapability,
    UnsupportedTargetedScope,
    UnsupportedTargetedSource,
)
from dumpex.output.records import HUNTERS

_REPO_ROOT = Path(__file__).parents[2]


# ── The real, shipped registry ──────────────────────────────────────────

def test_all_specs_matches_hunters_order_and_completeness():
    assert tuple(spec.identity for spec in REGISTRY._all_specs()) == HUNTERS


def test_select_all_equals_hunters_this_release():
    # All seven current specs are full_scope_capable=True, so select("all")
    # is exactly HUNTERS today (contract §2's corrected invariant).
    assert tuple(spec.identity for spec in REGISTRY.select("all")) == HUNTERS
    assert tuple(spec.identity for spec in REGISTRY.select("all")) == tuple(
        h for h in HUNTERS if REGISTRY.get(h).full_scope_capable)


@pytest.mark.parametrize("identity", HUNTERS)
def test_get_returns_the_matching_spec(identity):
    spec = REGISTRY.get(identity)
    assert spec.identity == identity
    assert spec.report_type is EXPECTED_REPORT_TYPES[identity]


@pytest.mark.parametrize("identity", HUNTERS)
def test_select_single_identity_returns_a_one_tuple(identity):
    assert tuple(spec.identity for spec in REGISTRY.select(identity)) == (identity,)


def test_zero_grants_populated_this_release():
    # Pinned explicitly (contract §12) so the day #61 writes the first
    # real grant, this assertion starts failing loudly rather than
    # silently continuing to pass.
    assert sum(
        1 for spec in REGISTRY._all_specs()
        if spec.targeted_capability is not None and spec.targeted_capability.grants
    ) == 0


def test_approved_targeted_identities_exactly_five():
    assert {
        spec.identity for spec in REGISTRY._all_specs()
        if spec.targeted_capability is not None
    } == {"pipe", "stomping", "cs-beacon", "yara", "obfuscation"}
    for identity in ("injection", "hollowing"):
        assert REGISTRY.get(identity).targeted_capability is None


@pytest.mark.parametrize("identity", HUNTERS)
def test_builder_returns_an_instance_of_its_own_report_type(identity):
    # The defense-in-depth runtime check the contract names (§7.1 failure
    # #6): construction-time identity comparison cannot see a builder that
    # is correctly wired but constructs the wrong type at runtime.
    spec = REGISTRY.get(identity)
    report = spec.builder(empty_mf())
    assert isinstance(report, spec.report_type)


@pytest.mark.parametrize("identity", HUNTERS)
def test_renderer_and_projector_produce_the_expected_shapes(identity):
    # NOT a same-Report-instance test: passing one local `report` variable
    # to both consumers below only proves this TEST called them with the
    # same object, which is tautological -- it says nothing about whether
    # a real dispatch path threads one already-built Report into both
    # (contract §8's own "same-instance invariant"). That invariant is
    # proven against the real dispatch path in
    # tests/integration/test_full_scope_executor.py (issue #72's own
    # `_execute_full_scope()`), not here; this test's real and only claim
    # is about RETURN SHAPE.
    from dumpex.output.records import HunterRecord

    spec = REGISTRY.get(identity)
    report = spec.builder(empty_mf())
    rendered = spec.renderer(report, False)
    projected = spec.record_projector(report)
    assert isinstance(rendered, dict)
    assert isinstance(projected, HunterRecord)


# ── Immutability (contract §5, the issue's own titular property) ────────
# `@dataclass(frozen=True)` blocks attribute REASSIGNMENT (not deep
# mutation of a mutable field's own contents -- but every field here is
# itself a str/type/callable/frozenset/bool/TargetedCapability, so
# reassignment is the only mutation surface that exists). Verified
# directly against dataclasses.FrozenInstanceError, never inferred from
# hashability (unfreezing TargetedGrant/TargetedCapability would
# incidentally break frozenset({grant}) elsewhere in this suite, but that
# is collateral damage, not an immutability assertion in its own right).

def test_analyzer_spec_is_frozen():
    spec = REGISTRY.get("yara")
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.identity = "not-yara"
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.builder = lambda mf: None


def test_targeted_grant_is_frozen():
    grant = TargetedGrant("ioc_string_scan", frozenset())
    with pytest.raises(dataclasses.FrozenInstanceError):
        grant.source = "other_source"


def test_targeted_capability_is_frozen():
    capability = TargetedCapability(TargetedScanUnit.REGION, frozenset())
    with pytest.raises(dataclasses.FrozenInstanceError):
        capability.scan_unit = TargetedScanUnit.SEGMENT


def test_repeated_lookups_return_the_same_spec_instance():
    # NOT an immutability test itself (the FrozenInstanceError tests above
    # are) -- this pins the singleton-identity property that makes
    # immutability actually matter: REGISTRY is process-wide, so if a spec
    # WERE mutable, one test (or one invocation, post-#72) could silently
    # rewrite another's analyzer wiring through this exact same identity.
    assert REGISTRY.get("yara") is REGISTRY.get("yara")


# ── provenance_hook shape validation (contract §5 field 8, §7.1 #7) ─────

def test_provenance_hook_is_none_for_six_of_seven_identities():
    for identity in HUNTERS:
        if identity == "yara":
            continue
        assert REGISTRY.get(identity).provenance_hook is None


def test_yara_provenance_hook_reads_off_the_report_instance():
    spec = REGISTRY.get("yara")
    assert spec.provenance_hook is not None
    report = spec.builder(empty_mf())
    result = spec.provenance_hook(report)
    provenance = report.coverage.rules.provenance
    if provenance is None:
        assert result is None
    else:
        assert result == provenance.to_dict()
        assert isinstance(result, dict)


def test_yara_provenance_hook_returns_none_when_report_has_no_provenance():
    from dumpex.hunt.yara_hunt.domain import CoverageSnapshot, RulesDiagnostics, YaraReport
    spec = REGISTRY.get("yara")
    report = YaraReport(coverage=CoverageSnapshot(
        rules=RulesDiagnostics(yara_available=True, rules_dir="x", attempted=True,
                                compiled_ok=1, provenance=None)))
    assert spec.provenance_hook(report) is None


@pytest.mark.parametrize("bad_hook", [
    lambda: None,                 # zero-arity -- rejected
    lambda a, b: None,            # wrong arity -- rejected
    lambda *, report: None,       # keyword-only -- rejected, real call sites pass positionally
])
def test_analyzer_spec_rejects_a_malformed_provenance_hook(bad_hook):
    real = REGISTRY.get("yara")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=bad_hook,
            full_scope_capable=real.full_scope_capable,
            targeted_capability=real.targeted_capability,
        )


def test_analyzer_spec_rejects_a_non_callable_provenance_hook():
    real = REGISTRY.get("yara")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook="not callable",
            full_scope_capable=real.full_scope_capable,
            targeted_capability=real.targeted_capability,
        )


# ── inspect.signature()'s own exceptions never leak as bare stdlib ──────
#    errors (finding: a C builtin with no introspectable signature -- ────
#    range/type/itertools.repeat -- raised a bare ValueError) ───────────

@pytest.mark.parametrize("uninspectable", [range, type])
def test_provenance_hook_rejects_an_uninspectable_builtin(uninspectable):
    # `inspect.signature(range)` raises ValueError ("no signature found
    # for builtin type"), not InvalidAnalyzerSpec, unless _safe_signature
    # catches it -- callable(range) is True, so this reaches signature
    # introspection.
    real = REGISTRY.get("yara")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=uninspectable,
            full_scope_capable=real.full_scope_capable,
            targeted_capability=real.targeted_capability,
        )


def test_resolve_and_validate_builder_rejects_an_uninspectable_builtin(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_builder
    monkeypatch.setattr(hunt_pkg, "_fake_builder", range, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_builder("_fake_builder", {})


def test_resolve_and_validate_renderer_rejects_an_uninspectable_builtin(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_renderer
    monkeypatch.setattr(hunt_pkg, "_fake_renderer", range, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_renderer("_fake_renderer")


def test_resolve_and_validate_projector_rejects_an_uninspectable_builtin(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_projector
    monkeypatch.setattr(hunt_pkg, "_fake_projector", range, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_projector("_fake_projector")


# ── Late-binding / monkeypatchability (contract §8) ─────────────────────
# Contract §8: "Same seam, all three adapters" -- builder/renderer/
# record_projector are late-bound IDENTICALLY, none a plain captured
# reference. Parametrized over all seven identities x all three adapters
# (21 cases), patching the real dumpex.hunt attribute (never a fake
# stand-in) and asserting spec.<adapter>(...) observes the patch -- proof
# each one re-resolves the name at CALL time, not once at import time. An
# earlier version of this suite covered only builder, only for injection;
# contract §8 calls a registry that silently freezes any of these three at
# import time "the single most important compatibility hazard this
# contract names".

_ADAPTER_ATTR = {
    "injection":   ("_build_injection_report", "_render_injection_console", "_record_from_injection_report"),
    "hollowing":   ("_build_hollowing_report", "_render_hollowing_console", "_record_from_hollowing_report"),
    "stomping":    ("_build_stomping_report", "_render_stomping_console", "_record_from_stomping_report"),
    "pipe":        ("_build_pipe_report", "_render_pipe_console", "_record_from_pipe_report"),
    "cs-beacon":   ("_build_cs_beacon_report", "_render_cs_beacon_console", "_record_from_cs_beacon_report"),
    "yara":        ("_build_yara_report", "_render_yara_console", "_record_from_yara_report"),
    "obfuscation": ("_build_encoding_report", "_render_encoding_console", "_record_from_encoding_report"),
}


def test_adapter_attr_table_covers_exactly_hunters():
    assert set(_ADAPTER_ATTR) == set(HUNTERS)


@pytest.mark.parametrize("identity", HUNTERS)
def test_builder_late_bound_for_every_identity(identity, monkeypatch):
    builder_attr, _renderer_attr, _projector_attr = _ADAPTER_ATTR[identity]
    spec = REGISTRY.get(identity)
    sentinel = object()
    monkeypatch.setattr(hunt_pkg, builder_attr, lambda mf: sentinel)
    assert spec.builder(empty_mf()) is sentinel


@pytest.mark.parametrize("identity", HUNTERS)
def test_renderer_late_bound_for_every_identity(identity, monkeypatch):
    _builder_attr, renderer_attr, _projector_attr = _ADAPTER_ATTR[identity]
    spec = REGISTRY.get(identity)
    sentinel = {"patched": True}
    monkeypatch.setattr(hunt_pkg, renderer_attr, lambda report, verbose=False: sentinel)
    assert spec.renderer(object(), False) is sentinel


@pytest.mark.parametrize("identity", HUNTERS)
def test_record_projector_late_bound_for_every_identity(identity, monkeypatch):
    _builder_attr, _renderer_attr, projector_attr = _ADAPTER_ATTR[identity]
    spec = REGISTRY.get(identity)
    sentinel = object()
    monkeypatch.setattr(hunt_pkg, projector_attr, lambda report: sentinel)
    assert spec.record_projector(object()) is sentinel


# ── Failure #8 (retained mutable state): no registered adapter is a ─────
#    closure/partial capturing anything but a plain attr-name string ────
# Field typing alone (callable/type/frozenset[str]/bool/
# TargetedCapability|None) makes a MinidumpFile itself unstorable in any
# AnalyzerSpec field -- but a closure or functools.partial that has
# already CAPTURED an `mf` object still passes callable() unchallenged
# (contract's own "so-far theoretical" gap, documented on AnalyzerSpec's
# own docstring). This is the positive-state counterpart to that
# docstring's claim: every one of the SEVEN real, shipped registrations
# is proven here to be exactly what _late_bound() produces -- a `_call`
# closure whose only captured cell is the dispatcher attribute NAME
# (a str), never a captured object -- so the "so-far theoretical" claim
# stays true of the actual shipped state, not merely asserted.

@pytest.mark.parametrize("identity", HUNTERS)
def test_registered_adapters_are_late_bound_closures_capturing_only_a_name(identity):
    spec = REGISTRY.get(identity)
    for adapter in (spec.builder, spec.renderer, spec.record_projector):
        assert adapter.__name__ == "_call", (
            f"{identity}: adapter is not a _late_bound() closure -- got "
            f"{adapter!r}, which could be a partial/closure capturing a "
            f"live object instead of a dispatcher attribute name")
        assert adapter.__closure__ is not None
        for cell in adapter.__closure__:
            assert isinstance(cell.cell_contents, str), (
                f"{identity}: adapter closure captured a non-str "
                f"{type(cell.cell_contents).__name__} -- only the "
                f"dispatcher attribute name string should ever be captured")
    # provenance_hook is the fourth callable field and, unlike the three
    # above, is NOT late-bound by name (it's a plain function/lambda
    # passed directly -- `_yara_provenance_hook`'s own docstring says so).
    # It is the field a `functools.partial(fn, mf)` would most plausibly
    # be written as, so it gets the same "captures nothing" check, just
    # without the "_call"/late-bound-seam assumption the other three make:
    # a plain top-level function referencing only module-level names has
    # no closure at all.
    assert spec.provenance_hook is None or spec.provenance_hook.__closure__ is None, (
        f"{identity}: provenance_hook is a closure -- possible mf/live-"
        f"object capture, the shape a functools.partial(fn, mf) would take")


# ── get()/select()/select_targeted() call-time failures (contract §7.2) ─

def test_get_unknown_identity_raises():
    with pytest.raises(UnknownAnalyzerIdentity):
        REGISTRY.get("not-a-hunter")


def test_unknown_identity_reports_the_registrys_actual_contents_not_hunters():
    # A partial/synthetic registry's own diagnostic must not lie about
    # what it actually holds -- reporting the global HUNTERS tuple instead
    # of self._by_identity would make a "missing registration" bug
    # self-contradicting: "unknown analyzer identity 'yara' -- must be one
    # of [... 'yara' ...]".
    partial = AnalyzerRegistry._construct_unvalidated((REGISTRY.get("injection"),))
    with pytest.raises(UnknownAnalyzerIdentity) as excinfo:
        partial.get("yara")
    assert excinfo.value.valid == {"injection"}
    with pytest.raises(UnknownAnalyzerIdentity) as excinfo:
        partial.select("yara")
    assert excinfo.value.valid == {"injection", "all"}


def test_get_all_is_rejected():
    with pytest.raises(UnknownAnalyzerIdentity):
        REGISTRY.get("all")


def test_select_unknown_identity_raises():
    with pytest.raises(UnknownAnalyzerIdentity):
        REGISTRY.select("not-a-hunter")


def test_select_targeted_all_is_rejected_as_unknown_identity():
    # "all" is failure #9 here, never a registered identity to begin with
    # -- distinct from failure #10 (real identity, no capability).
    with pytest.raises(UnknownAnalyzerIdentity):
        REGISTRY.select_targeted("all", "segment_scan")


@pytest.mark.parametrize("identity", ("injection", "hollowing"))
def test_select_targeted_unsupported_capability(identity):
    with pytest.raises(UnsupportedTargetedCapability):
        REGISTRY.select_targeted(identity, "anything")


_TARGETED_CASES = (
    ("pipe", "pipe_name_scan", None),
    ("stomping", "ioc_string_scan", None),
    ("yara", "segment_scan", None),
    ("cs-beacon", "segment_scan", None),
    ("obfuscation", "encoding_scan", "sleep_mask"),
)


@pytest.mark.parametrize("identity,source,scope", _TARGETED_CASES)
def test_select_targeted_unpopulated_grant_this_release(identity, source, scope):
    # This release's real, shipped registry has zero populated grants for
    # every targeted-capable identity -- this is the actual shipped state,
    # not a hypothetical.
    with pytest.raises(UnpopulatedTargetedGrant):
        REGISTRY.select_targeted(identity, source, scope)


def _spec_with_grant(identity, scan_unit, grant):
    real = REGISTRY.get(identity)
    return AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=real.full_scope_capable,
        targeted_capability=TargetedCapability(scan_unit, frozenset({grant})),
    )


def test_select_targeted_unpopulated_grant_positive_case():
    # A synthetic spec with a real, matching grant succeeds -- proves the
    # gate reads the field rather than always failing.
    spec = _spec_with_grant(
        "stomping", TargetedScanUnit.REGION, TargetedGrant("ioc_string_scan", frozenset()))
    registry = AnalyzerRegistry._construct_unvalidated((spec,))
    result = registry.select_targeted("stomping", "ioc_string_scan", None)
    assert result is spec


def test_select_targeted_unsupported_source_real_but_ungranted():
    # "reference_files" genuinely exists in stomping's own public sources
    # (report_facts.py) but is deliberately not the granted one.
    spec = _spec_with_grant(
        "stomping", TargetedScanUnit.REGION, TargetedGrant("ioc_string_scan", frozenset()))
    from dumpex.hunt.stomping.report_facts import COVERAGE_SOURCE_NAMES
    assert "reference_files" in COVERAGE_SOURCE_NAMES
    registry = AnalyzerRegistry._construct_unvalidated((spec,))
    with pytest.raises(UnsupportedTargetedSource):
        registry.select_targeted("stomping", "reference_files")


def test_select_targeted_unsupported_scope_a_scopeless_grant_rejects_a_scope():
    spec = _spec_with_grant(
        "pipe", TargetedScanUnit.REGION, TargetedGrant("pipe_name_scan", frozenset()))
    registry = AnalyzerRegistry._construct_unvalidated((spec,))
    with pytest.raises(UnsupportedTargetedScope):
        registry.select_targeted("pipe", "pipe_name_scan", scope="arbitrary-invalid-scope")


def test_select_targeted_unsupported_scope_a_scoped_grant_rejects_none():
    spec = _spec_with_grant(
        "obfuscation", TargetedScanUnit.REGION_LAYER,
        TargetedGrant("encoding_scan", frozenset({"sleep_mask", "entropy", "decode"})))
    registry = AnalyzerRegistry._construct_unvalidated((spec,))
    with pytest.raises(UnsupportedTargetedScope):
        registry.select_targeted("obfuscation", "encoding_scan", scope=None)


def test_select_targeted_unsupported_scope_an_unnamed_scope():
    spec = _spec_with_grant(
        "obfuscation", TargetedScanUnit.REGION_LAYER,
        TargetedGrant("encoding_scan", frozenset({"sleep_mask", "entropy", "decode"})))
    registry = AnalyzerRegistry._construct_unvalidated((spec,))
    with pytest.raises(UnsupportedTargetedScope):
        registry.select_targeted("obfuscation", "encoding_scan", scope="unpack")


def test_select_targeted_scoped_grant_named_scope_succeeds():
    spec = _spec_with_grant(
        "obfuscation", TargetedScanUnit.REGION_LAYER,
        TargetedGrant("encoding_scan", frozenset({"sleep_mask", "entropy", "decode"})))
    registry = AnalyzerRegistry._construct_unvalidated((spec,))
    result = registry.select_targeted("obfuscation", "encoding_scan", scope="sleep_mask")
    assert result is spec


def test_all_seven_are_full_scope_capable_today():
    # This release's seven are all full_scope_capable=True, so failure #11
    # is unreachable today -- proven here rather than left as an inference.
    for identity in HUNTERS:
        assert REGISTRY.get(identity).full_scope_capable is True


def test_select_single_identity_rejects_a_full_scope_incapable_spec():
    real = REGISTRY.get("stomping")
    spec = AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=False,
        targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset()),
    )
    registry = AnalyzerRegistry._construct_unvalidated((spec,))
    with pytest.raises(UnsupportedFullScopeRequest):
        registry.select("stomping")
    # "all" simply excludes it -- no exception.
    assert registry.select("all") == ()


# ── AnalyzerSpec construction-time failures (contract §7.1) ─────────────

def _valid_kwargs(**overrides):
    real = REGISTRY.get("injection")
    kwargs = dict(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=real.full_scope_capable,
        targeted_capability=real.targeted_capability,
    )
    kwargs.update(overrides)
    return kwargs


def test_analyzer_spec_rejects_identity_outside_hunters():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(identity="not-a-hunter"))


def test_analyzer_spec_rejects_all_as_identity():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(identity="all"))


def test_analyzer_spec_rejects_non_callable_builder():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(builder="not callable"))


def test_analyzer_spec_rejects_non_callable_renderer():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(renderer=None))


def test_analyzer_spec_rejects_non_callable_record_projector():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(record_projector=123))


def test_analyzer_spec_rejects_non_type_report_type():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(report_type="not a type"))


def test_analyzer_spec_rejects_non_frozenset_option_names():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(option_names=["ref_dir"]))


def test_analyzer_spec_rejects_an_option_name_unknown_to_the_executor():
    # Finding (closed by #73): §7.1 failure #7's own option_names check
    # only validates against the BUILDER's own signature, in both
    # directions -- never against what `_execute_full_scope()`
    # (dumpex/hunt/__init__.py) actually knows how to supply a value for
    # (`_registry.KNOWN_OPTION_NAMES`). A spec declaring a real, correctly
    # -defaulted builder keyword outside that set used to construct
    # successfully and only fail with a bare KeyError partway through
    # _execute_full_scope()'s own selection loop -- after every
    # earlier-selected analyzer's builder had already run. `"ref_dir"` is
    # a real, valid `KNOWN_OPTION_NAMES` member (used by the shape test
    # immediately above) -- `"depth"` is not, and is otherwise a
    # perfectly well-formed option name (a non-empty str), so this proves
    # the new gate is checking membership in `KNOWN_OPTION_NAMES`, not
    # merely re-triggering the frozenset-shape check above.
    with pytest.raises(InvalidAnalyzerSpec, match="not known to _execute_full_scope"):
        AnalyzerSpec(**_valid_kwargs(option_names=frozenset({"depth"})))


def test_analyzer_spec_rejects_non_bool_full_scope_capable():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(full_scope_capable="yes"))


def test_analyzer_spec_rejects_neither_full_scope_nor_targeted():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(full_scope_capable=False, targeted_capability=None))


def test_analyzer_spec_allows_targeted_only_analyzer():
    # Built off "stomping" (one of the five identities with a real entry in
    # _EXPECTED_TARGETED_SCAN_UNITS/_COVERAGE_SOURCE_NAMES_BY_IDENTITY),
    # not "injection" (_valid_kwargs()'s own default) -- since Findings #2/
    # #3's fix, ANY identity outside those two mappings now fails
    # construction the moment targeted_capability is non-None, regardless
    # of full_scope_capable, so this positive case needs a real
    # targeted-capable identity to reach the check it's actually testing.
    real = REGISTRY.get("stomping")
    spec = AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=False,
        targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset()))
    assert spec.full_scope_capable is False


def test_analyzer_spec_rejects_wrong_typed_targeted_capability():
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(**_valid_kwargs(targeted_capability="not a capability"))


def test_targeted_grant_rejects_empty_source():
    with pytest.raises(InvalidAnalyzerSpec):
        TargetedGrant(source="", scopes=frozenset())


def test_targeted_grant_rejects_non_frozenset_scopes():
    with pytest.raises(InvalidAnalyzerSpec):
        TargetedGrant(source="ioc_string_scan", scopes=["sleep_mask"])


def test_targeted_capability_rejects_non_scan_unit():
    with pytest.raises(InvalidAnalyzerSpec):
        TargetedCapability(scan_unit="region", grants=frozenset())


def test_targeted_capability_rejects_non_frozenset_grants():
    with pytest.raises(InvalidAnalyzerSpec):
        TargetedCapability(scan_unit=TargetedScanUnit.REGION, grants=[TargetedGrant("x", frozenset())])


def test_analyzer_spec_rejects_out_of_vocabulary_source_for_stomping():
    real = REGISTRY.get("stomping")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=real.provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.REGION, frozenset({TargetedGrant("not-a-real-source", frozenset())})))


def test_analyzer_spec_rejects_nonempty_scopes_on_a_non_obfuscation_analyzer():
    real = REGISTRY.get("stomping")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=real.provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.REGION,
                frozenset({TargetedGrant("ioc_string_scan", frozenset({"bogus_scope"}))})))


def test_analyzer_spec_rejects_out_of_vocabulary_scope_on_obfuscation():
    real = REGISTRY.get("obfuscation")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=real.provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.REGION_LAYER,
                frozenset({TargetedGrant("encoding_scan", frozenset({"unpack"}))})))


def test_analyzer_spec_allows_a_real_scoped_obfuscation_grant():
    real = REGISTRY.get("obfuscation")
    spec = AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=True,
        targeted_capability=TargetedCapability(
            TargetedScanUnit.REGION_LAYER,
            frozenset({TargetedGrant("encoding_scan", frozenset({"sleep_mask"}))})))
    assert spec.targeted_capability.grants


def test_analyzer_spec_allows_the_full_scoped_grant_set():
    real = REGISTRY.get("obfuscation")
    from dumpex.hunt.encoding.domain import OVERSIZE_SCAN_LAYERS
    spec = AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=True,
        targeted_capability=TargetedCapability(
            TargetedScanUnit.REGION_LAYER,
            frozenset({TargetedGrant("encoding_scan", frozenset(OVERSIZE_SCAN_LAYERS))})))
    assert spec.targeted_capability.grants


def test_scoped_source_rejects_empty_grant_scopes():
    # Finding: `set(grant.scopes) <= allowed_scopes` is vacuously TRUE for
    # an empty `grant.scopes` against ANY non-empty `allowed_scopes` -- so
    # a scoped-source grant with `scopes=frozenset()` used to pass
    # construction, and select_targeted(identity, source, scope=None)
    # would then succeed against a source the contract requires an
    # explicit layer choice for. "encoding_scan" is a KNOWN-scoped source
    # (per _SCOPED_TARGETED_SOURCES) -- an empty grant on it means "no
    # layer was chosen", never "this source has no layers".
    real = REGISTRY.get("obfuscation")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=real.provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.REGION_LAYER,
                frozenset({TargetedGrant("encoding_scan", frozenset())})))


def test_scoped_source_empty_grant_scopes_cannot_reach_select_targeted():
    # End-to-end proof of the same fix: since AnalyzerSpec can no longer
    # even be CONSTRUCTED with an empty-scopes grant on a known-scoped
    # source, select_targeted(..., scope=None) can never see one either --
    # closing the bypass at its source rather than only at the call site.
    with pytest.raises(InvalidAnalyzerSpec):
        _spec_with_grant(
            "obfuscation", TargetedScanUnit.REGION_LAYER,
            TargetedGrant("encoding_scan", frozenset()))


# ── AnalyzerRegistry construction-time failures over the full set ───────
# Every case below calls `AnalyzerRegistry(specs)` DIRECTLY -- the real
# constructor, not a separately-invoked `_validate_registrations()` helper
# -- per the finding that an earlier version of this suite validated
# through a bypassable side door
# (`_validate_registrations(specs); AnalyzerRegistry(specs)`) that no
# production or test code was actually forced to go through:
# `AnalyzerRegistry((duplicate, duplicate))` constructed directly used to
# succeed silently. `AnalyzerRegistry.__init__` now runs
# `_validate_registrations()` itself (dumpex/hunt/_registry.py), so these
# tests now exercise the one and only construction path that exists.

def test_registry_construction_rejects_a_duplicate_identity():
    injection = REGISTRY.get("injection")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerRegistry((injection, injection))


def test_registry_construction_rejects_an_empty_registration_set():
    # The degenerate case a purely additive `_by_identity` dict comprehension
    # would happily accept: zero specs, zero errors, `select("all")`
    # silently returning `()` forever. Must fail exactly like every other
    # incomplete registration (missing 6 of 7, not merely missing 1).
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerRegistry(())


def test_registry_construction_rejects_a_missing_identity():
    specs = tuple(spec for spec in REGISTRY._all_specs() if spec.identity != "yara")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerRegistry(specs)


def test_registry_construction_rejects_reordered_registrations():
    specs = list(REGISTRY._all_specs())
    specs[0], specs[1] = specs[1], specs[0]
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerRegistry(tuple(specs))


def test_registry_construction_rejects_wrong_report_type():
    real = REGISTRY.get("injection")
    wrong = AnalyzerSpec(
        identity=real.identity, package=real.package,
        report_type=REGISTRY.get("hollowing").report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=real.full_scope_capable, targeted_capability=real.targeted_capability,
    )
    specs = tuple(wrong if s.identity == "injection" else s for s in REGISTRY._all_specs())
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerRegistry(specs)


def test_registry_construction_rejects_missing_grant_for_an_approved_identity():
    # Under-grant: an approved targeted identity with targeted_capability=None.
    real = REGISTRY.get("yara")
    stripped = AnalyzerSpec(
        identity=real.identity, package=real.package, report_type=real.report_type,
        builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
        option_names=real.option_names, provenance_hook=real.provenance_hook,
        full_scope_capable=True, targeted_capability=None,
    )
    specs = tuple(stripped if s.identity == "yara" else s for s in REGISTRY._all_specs())
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerRegistry(specs)


def test_analyzer_spec_itself_rejects_an_over_granted_identity():
    # Over-grant: injection declaring a non-None targeted_capability.
    # Since Findings #2/#3's fix, this is now caught at AnalyzerSpec
    # CONSTRUCTION time -- "injection" has no entry in
    # _EXPECTED_TARGETED_SCAN_UNITS/_COVERAGE_SOURCE_NAMES_BY_IDENTITY (by
    # design: those two mappings are keyed exactly by
    # _APPROVED_TARGETED_IDENTITIES), so the spec can no longer even be
    # built -- a strictly earlier, more fail-closed gate than the
    # registry-level exact-set-equality check below, which now only ever
    # sees specs that already passed this one.
    real = REGISTRY.get("injection")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=real.provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset()),
        )


def test_construct_unvalidated_skips_validation_but_is_never_the_default_path():
    # The test-only escape hatch a handful of select_targeted() tests above
    # rely on to build a deliberately partial synthetic registry -- proven
    # here to actually skip validation (unlike the real constructor,
    # immediately above), so its own existence doesn't quietly become the
    # thing standing between AnalyzerRegistry() and fail-closed behavior.
    injection = REGISTRY.get("injection")
    registry = AnalyzerRegistry._construct_unvalidated((injection, injection))
    # The exact bug report the real constructor now closes: select("all")
    # silently returns the duplicate TWICE (self._specs is never deduped),
    # while get() -- backed by the dict-collapsing _by_identity -- would
    # silently hide the very same duplication instead. Neither is caught;
    # that is what "unvalidated" means here.
    assert registry.select("all") == (injection, injection)
    assert registry.get("injection") is injection
    # ... which is exactly why production code (REGISTRY itself) must never
    # take this path -- enforced by
    # test_escape_hatches_are_never_referenced_outside_the_registry_module
    # below (which names `_construct_unvalidated` explicitly, not just
    # `_all_specs`) and by REGISTRY having been built through
    # AnalyzerRegistry(...) directly (dumpex/hunt/_registry.py's own
    # bottom-of-module singleton line).


def test_registry_snapshots_a_mutable_input_sequence():
    # `specs: tuple` is a type HINT, not a runtime-enforced constraint --
    # a caller passing a `list` (complete, correctly ordered, and
    # therefore accepted by _validate_registrations) used to leave the
    # constructed registry holding a live reference to that same list.
    # Mutating it afterward (even though the registry was already
    # "validated") silently desynced self._specs/select("all")/
    # _all_specs() from self._by_identity, which stayed correct (it's
    # built as a fresh dict comprehension) -- two internally-contradictory
    # views of the same "closed" registry.
    specs = list(REGISTRY._all_specs())
    registry = AnalyzerRegistry(specs)
    specs.pop()
    specs.clear()
    assert registry._all_specs() == REGISTRY._all_specs()
    assert len(registry.select("all")) == len(HUNTERS)
    assert registry.get("obfuscation") is REGISTRY.get("obfuscation")


def test_construct_unvalidated_also_snapshots_a_mutable_input_sequence():
    # Skipping CONTENT validation is the whole point of this escape hatch
    # -- but it must not additionally hold a live reference to a caller's
    # own mutable container, the same fix as the real constructor above.
    injection = REGISTRY.get("injection")
    specs = [injection, injection]
    registry = AnalyzerRegistry._construct_unvalidated(specs)
    specs.clear()
    assert registry._all_specs() == (injection, injection)
    assert registry.select("all") == (injection, injection)


def test_analyzer_registry_init_actually_calls_validate_registrations():
    # Both `type(REGISTRY) is AnalyzerRegistry` and `REGISTRY._all_specs()
    # == HUNTERS` are true of ANY correctly-ordered seven-spec tuple
    # regardless of whether __init__ actually validated it (and
    # `_construct_unvalidated` also uses `cls.__new__(cls)`, so `type(...)
    # is AnalyzerRegistry` holds for it too) -- an earlier version of this
    # test asserted exactly those two things and would still pass if
    # `__init__`'s own call to `_validate_registrations(specs)` (the P1
    # fix) were silently reverted to a no-op or deleted, since the real
    # coverage for THAT regression already comes entirely from the
    # `test_registry_construction_rejects_*`/`test_construct_unvalidated_*`
    # tests above, which fail on such a revert. This test instead proves
    # the wiring directly, the same AST technique
    # test_registry_module_has_no_bare_assert_statements already uses:
    # `AnalyzerRegistry.__init__`'s own body must contain a call whose
    # function is named `_validate_registrations`.
    registry_module = _REPO_ROOT / "dumpex" / "hunt" / "_registry.py"
    tree = ast.parse(registry_module.read_text(encoding="utf-8"), filename=str(registry_module))
    class_node = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "AnalyzerRegistry")
    init_node = next(
        node for node in ast.walk(class_node)
        if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    calls = {
        node.func.id for node in ast.walk(init_node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "_validate_registrations" in calls, (
        f"AnalyzerRegistry.__init__ no longer calls _validate_registrations() "
        f"directly -- found calls: {sorted(calls)}")


# ── option_names / signature validation (contract §7.1 failure #7) ──────

def test_resolve_and_validate_builder_rejects_over_declared_option_names():
    from dumpex.hunt._registry import _resolve_and_validate_builder
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_builder("_build_injection_report", {"not_a_real_kwarg": None})


def test_resolve_and_validate_builder_rejects_under_declared_option_names():
    from dumpex.hunt._registry import _resolve_and_validate_builder
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_builder("_build_stomping_report", {})


def test_resolve_and_validate_builder_accepts_the_real_signature():
    from dumpex.hunt._registry import _resolve_and_validate_builder
    builder = _resolve_and_validate_builder("_build_stomping_report", {"ref_dir": None})
    assert callable(builder)


# ── Malformed adapter shapes a name-only check would have missed ────────
# Each of these previously passed a check that only compared parameter
# NAMES and would only raise TypeError the first time some caller actually
# invoked the adapter -- possibly after a dump was already open. Installed
# onto the real dumpex.hunt module (never a fake stand-in module) and
# resolved through the exact same _resolve_and_validate_* entry points
# real registration uses, then removed by monkeypatch's own teardown.

def test_resolve_and_validate_builder_rejects_a_missing_mf_parameter(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_builder

    def bad_builder():
        pass

    monkeypatch.setattr(hunt_pkg, "_fake_builder", bad_builder, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_builder("_fake_builder", {})


def test_resolve_and_validate_builder_rejects_an_open_kwargs_catch_all(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_builder

    def bad_builder(mf, **kwargs):
        pass

    monkeypatch.setattr(hunt_pkg, "_fake_builder", bad_builder, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_builder("_fake_builder", {})


def test_resolve_and_validate_builder_rejects_a_required_option(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_builder

    def bad_builder(mf, ref_dir):
        pass

    monkeypatch.setattr(hunt_pkg, "_fake_builder", bad_builder, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_builder("_fake_builder", {"ref_dir": None})


def test_resolve_and_validate_builder_rejects_an_unexpected_default_value(monkeypatch):
    # Finding: a builder option with SOME default (so the old "has a
    # default" check alone would accept it) but not the contract-frozen
    # one -- ref_dir must default to exactly None, not "unexpected".
    from dumpex.hunt._registry import _resolve_and_validate_builder

    def bad_builder(mf, ref_dir="unexpected"):
        pass

    monkeypatch.setattr(hunt_pkg, "_fake_builder", bad_builder, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_builder("_fake_builder", {"ref_dir": None})


def test_resolve_and_validate_renderer_rejects_an_unexpected_verbose_default(monkeypatch):
    # Same gap, for the renderer's verbose parameter: must default to
    # exactly False, not merely "have a default".
    from dumpex.hunt._registry import _resolve_and_validate_renderer

    def bad_renderer(report, verbose=True):
        pass

    monkeypatch.setattr(hunt_pkg, "_fake_renderer", bad_renderer, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_renderer("_fake_renderer")


def test_resolve_and_validate_projector_rejects_keyword_only_report(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_projector

    def bad_projector(*, report):
        pass

    monkeypatch.setattr(hunt_pkg, "_fake_projector", bad_projector, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_projector("_fake_projector")


def test_resolve_and_validate_renderer_rejects_keyword_only_params(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_renderer

    def bad_renderer(*, report, verbose=False):
        pass

    monkeypatch.setattr(hunt_pkg, "_fake_renderer", bad_renderer, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_renderer("_fake_renderer")


def test_resolve_and_validate_renderer_rejects_verbose_without_a_default(monkeypatch):
    from dumpex.hunt._registry import _resolve_and_validate_renderer

    def bad_renderer(report, verbose):
        pass

    monkeypatch.setattr(hunt_pkg, "_fake_renderer", bad_renderer, raising=False)
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_renderer("_fake_renderer")


# ── scan_unit is bound to identity, not just type-checked ───────────────

def test_analyzer_spec_rejects_a_mismatched_scan_unit_for_stomping():
    # stomping's own gap vocabulary is region-shaped (contract §1/§3) --
    # registering it with SEGMENT (cs-beacon's/yara's shape) must fail,
    # not merely pass an isinstance(scan_unit, TargetedScanUnit) check.
    real = REGISTRY.get("stomping")
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=real.provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.SEGMENT, frozenset()))


@pytest.mark.parametrize("identity,expected_unit", [
    ("pipe", TargetedScanUnit.REGION),
    ("stomping", TargetedScanUnit.REGION),
    ("cs-beacon", TargetedScanUnit.SEGMENT),
    ("yara", TargetedScanUnit.SEGMENT),
    ("obfuscation", TargetedScanUnit.REGION_LAYER),
])
def test_real_registrations_use_the_contract_frozen_scan_unit(identity, expected_unit):
    assert REGISTRY.get(identity).targeted_capability.scan_unit is expected_unit


# ── A missing per-identity mapping entry fails closed, not open ─────────
# Both checks below fire even though `grants` stays EMPTY (this release's
# actual shipped state for every targeted-capable identity) -- proving the
# gate does not silently wait for a populated grant before it starts
# validating. A `.get(identity)` that only ran inside a `for grant in
# grants:` loop would never fire here, reproducing exactly the fail-open
# gap this pair of tests exists to close.

def test_analyzer_spec_fails_closed_when_scan_unit_mapping_is_missing(monkeypatch):
    import dumpex.hunt._registry as registry_mod
    real = REGISTRY.get("pipe")
    patched = dict(registry_mod._EXPECTED_TARGETED_SCAN_UNITS)
    del patched["pipe"]
    monkeypatch.setattr(registry_mod, "_EXPECTED_TARGETED_SCAN_UNITS", patched)
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=real.provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset()))


def test_analyzer_spec_fails_closed_when_source_vocabulary_mapping_is_missing(monkeypatch):
    import dumpex.hunt._registry as registry_mod
    real = REGISTRY.get("stomping")
    patched = dict(registry_mod._COVERAGE_SOURCE_NAMES_BY_IDENTITY)
    del patched["stomping"]
    monkeypatch.setattr(registry_mod, "_COVERAGE_SOURCE_NAMES_BY_IDENTITY", patched)
    with pytest.raises(InvalidAnalyzerSpec):
        AnalyzerSpec(
            identity=real.identity, package=real.package, report_type=real.report_type,
            builder=real.builder, renderer=real.renderer, record_projector=real.record_projector,
            option_names=real.option_names, provenance_hook=real.provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset()))


def test_module_level_mappings_are_complete_against_approved_identities():
    from dumpex.hunt._registry import (
        _APPROVED_TARGETED_IDENTITIES, _COVERAGE_SOURCE_NAMES_BY_IDENTITY,
        _EXPECTED_TARGETED_SCAN_UNITS,
    )
    assert set(_EXPECTED_TARGETED_SCAN_UNITS) == _APPROVED_TARGETED_IDENTITIES
    assert set(_COVERAGE_SOURCE_NAMES_BY_IDENTITY) == _APPROVED_TARGETED_IDENTITIES
    # injection/hollowing must never appear in either mapping.
    for identity in ("injection", "hollowing"):
        assert identity not in _EXPECTED_TARGETED_SCAN_UNITS
        assert identity not in _COVERAGE_SOURCE_NAMES_BY_IDENTITY


# ── COVERAGE_SOURCE_NAMES drift guard ────────────────────────────────────
# Each `COVERAGE_SOURCE_NAMES` constant in a hunter's report_facts.py is a
# hand-maintained duplicate of the literal keys `project_coverage_report()`
# actually builds once a scan has run. These tests catch the day the two
# drift apart, in either direction. Each hunter's REAL "evaluated" branch
# is exercised directly against a minimal but real CoverageSnapshot --
# never through empty_mf(), which produces the *not-evaluated* placeholder
# branch for four of these five (see the last test below): that
# placeholder uses its own single-source sentinel and is deliberately NOT
# part of this public vocabulary, per each report_facts.py's own
# COVERAGE_SOURCE_NAMES docstring.

def test_pipe_coverage_source_names_match_the_real_evaluated_sources():
    from dumpex.hunt.pipe.domain import CoverageSnapshot
    from dumpex.hunt.pipe.report_facts import COVERAGE_SOURCE_NAMES, project_coverage_report
    report = project_coverage_report(CoverageSnapshot(memory_info_stream=True, handle_data_stream=True))
    assert frozenset(report.sources) == COVERAGE_SOURCE_NAMES


def test_stomping_coverage_source_names_match_the_real_evaluated_sources():
    from dumpex.hunt.stomping.domain import CoverageSnapshot
    from dumpex.hunt.stomping.report_facts import COVERAGE_SOURCE_NAMES, project_coverage_report
    report = project_coverage_report(CoverageSnapshot(memory_info_stream=True, module_list_stream=True))
    assert frozenset(report.sources) == COVERAGE_SOURCE_NAMES


def test_cs_beacon_coverage_source_names_match_the_real_evaluated_sources():
    from dumpex.hunt.cs_beacon.domain import CoverageSnapshot, ScanDiagnostics
    from dumpex.hunt.cs_beacon.report_facts import COVERAGE_SOURCE_NAMES, project_coverage_report
    coverage = CoverageSnapshot(scan=ScanDiagnostics(segment_count=1), mem_info_available=True)
    report = project_coverage_report(coverage)
    assert frozenset(report.sources) == COVERAGE_SOURCE_NAMES


def test_yara_coverage_source_names_match_the_real_evaluated_sources():
    from dumpex.hunt.yara_hunt.domain import (
        CoverageSnapshot, RulesDiagnostics, ScanDiagnostics, YaraReport)
    from dumpex.hunt.yara_hunt.report_facts import COVERAGE_SOURCE_NAMES, project_coverage_report
    coverage = CoverageSnapshot(
        rules=RulesDiagnostics(yara_available=True, rules_dir="x", attempted=True, compiled_ok=1),
        scan=ScanDiagnostics(segment_count=1))
    report = project_coverage_report(YaraReport(coverage=coverage))
    assert frozenset(report.sources) == COVERAGE_SOURCE_NAMES


def test_obfuscation_coverage_source_names_match_the_real_evaluated_sources():
    from dumpex.hunt.encoding.domain import CoverageSnapshot
    from dumpex.hunt.encoding.report_facts import COVERAGE_SOURCE_NAMES, project_coverage_report
    report = project_coverage_report(CoverageSnapshot(memory_info_stream=True))
    assert frozenset(report.sources) == COVERAGE_SOURCE_NAMES


def test_not_evaluated_placeholder_sources_are_not_part_of_the_vocabulary():
    # The NOT_EVALUATED branch's own single-source sentinel must never be
    # mistaken for -- or drift into -- this hunter's real, targetable
    # public source vocabulary.
    from dumpex.hunt.cs_beacon.domain import CoverageSnapshot as CsCov, ScanDiagnostics as CsScan
    from dumpex.hunt.cs_beacon.report_facts import (
        COVERAGE_SOURCE_NAMES as cs_names, project_coverage_report as cs_pcr)
    not_evaluated = cs_pcr(CsCov(scan=CsScan(segment_count=0)))
    assert "memory64_list" not in cs_names
    assert set(not_evaluated.sources) == {"memory64_list"}

    from dumpex.hunt.yara_hunt.domain import CoverageSnapshot as YaraCov, YaraReport
    from dumpex.hunt.yara_hunt.report_facts import (
        COVERAGE_SOURCE_NAMES as yara_names, project_coverage_report as yara_pcr)
    not_evaluated = yara_pcr(YaraReport(coverage=YaraCov()))
    assert "yara_scan" not in yara_names
    assert set(not_evaluated.sources) == {"yara_scan"}


# ── scope drift guard (finding: _SCOPED_TARGETED_SOURCES's premise was ──
#    stated too broadly, and its allowed-scopes value was hard-wired ────
#    rather than carried per-entry -- had no drift guard either way) ────
# Symmetric with the COVERAGE_SOURCE_NAMES drift guard above: drive each
# targeted-capable hunter's real `project_coverage_report()` down every
# scope-emitting completeness-check branch it has, and confirm the set of
# emitted `CoverageLimitation.scope` values matches what `_registry`
# believes that identity's grantable-scope vocabulary is -- empty for
# pipe/stomping/yara/cs-beacon (none of the four is in
# `_SCOPED_TARGETED_SOURCES`, so their real, budget-kind/sub-signal
# `scope` values exist but have no closed constant to validate against
# yet -- a real, current, and *correctly* unenforced gap, not an
# oversight), non-empty (`OVERSIZE_SCAN_LAYERS`) for obfuscation's own
# `encoding_scan` source.

def _scan_target(size_limit=None):
    from dumpex.output.coverage import ScanTarget, ScanTargetKind
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000,
                       size=0x100, size_limit=size_limit)


def _emitted_scopes(coverage_report) -> set:
    # `"dump"` is excluded deliberately: `dumpex.output.coverage.
    # _derive_required_source_limitation` hardcodes `scope=req.scope or
    # "dump"` for ANY SourceRequirement/EvaluationRequirement-derived
    # "this whole source is absent" limitation, across every hunter that
    # uses that shared machinery (confirmed here for stomping's own
    # `reference_files`-not-supplied case) -- a generic "the entire dump
    # lacks this source" sentinel, unrelated to and orthogonal to the
    # real, analyzer-specific SUB-signal scope tags (pipe's own
    # "c2_context"/"pipe_name", obfuscation's own decode layers) this
    # drift guard exists to check `_registry.py`'s belief against. Folding
    # it in would make every hunter with any absent-source completeness
    # check look "scoped" for a reason that has nothing to do with
    # targeted-scan sub-source granularity.
    return {cl.scope for cl in coverage_report.limitations
            if cl.scope is not None and cl.scope != "dump"}


def test_pipe_scope_emitting_branches_are_not_in_the_registrys_scoped_mapping():
    from dumpex.hunt._registry import _SCOPED_TARGETED_SOURCES
    from dumpex.hunt.pipe.domain import CoverageSnapshot
    from dumpex.hunt.pipe.report_facts import project_coverage_report
    coverage = CoverageSnapshot(
        memory_info_stream=True, handle_data_stream=True,
        c2_budget_exhausted=True, c2_budget_reason="deadline",
        pipe_name_budget_exhausted=True, pipe_name_budget_reason="deadline")
    emitted = _emitted_scopes(project_coverage_report(coverage))
    assert emitted == {"c2_context", "pipe_name"}
    assert "pipe" not in _SCOPED_TARGETED_SOURCES


def test_yara_scope_emitting_branches_are_not_in_the_registrys_scoped_mapping():
    from dumpex.hunt._registry import _SCOPED_TARGETED_SOURCES
    from dumpex.hunt.yara_hunt.domain import CoverageSnapshot, RulesDiagnostics, ScanDiagnostics, YaraReport
    from dumpex.hunt.yara_hunt.report_facts import project_coverage_report
    scan = ScanDiagnostics(
        segment_count=1,
        truncated=True, truncated_targets=(_scan_target(),), truncated_budget_limit=100,
        budget_exhausted=True, budget_exhausted_targets=(_scan_target(),),
        budget_exhausted_kind="scan_deadline_seconds",
        budget_exhausted_limit=10, budget_exhausted_consumed=10)
    coverage = CoverageSnapshot(
        rules=RulesDiagnostics(yara_available=True, rules_dir="x", attempted=True, compiled_ok=1),
        scan=scan)
    emitted = _emitted_scopes(project_coverage_report(YaraReport(coverage=coverage)))
    assert emitted == {"max_total_hits", "scan_deadline_seconds"}
    assert "yara" not in _SCOPED_TARGETED_SOURCES


def test_cs_beacon_scope_emitting_branches_are_not_in_the_registrys_scoped_mapping():
    from dumpex.hunt._registry import _SCOPED_TARGETED_SOURCES
    from dumpex.hunt.cs_beacon.domain import CoverageSnapshot, ScanDiagnostics
    from dumpex.hunt.cs_beacon.report_facts import project_coverage_report
    scan = ScanDiagnostics(
        segment_count=1, budget_exhausted=True, budget_exhausted_targets=(_scan_target(),),
        budget_exhausted_kind="scan_deadline_seconds", budget_reason="x",
        budget_exhausted_limit=10, budget_exhausted_consumed=10)
    coverage = CoverageSnapshot(scan=scan, mem_info_available=True)
    emitted = _emitted_scopes(project_coverage_report(coverage))
    assert emitted == {"scan_deadline_seconds"}
    assert "cs-beacon" not in _SCOPED_TARGETED_SOURCES


def test_stomping_has_no_scope_emitting_branches_at_all():
    from dumpex.hunt._registry import _SCOPED_TARGETED_SOURCES
    from dumpex.hunt.stomping.domain import CoverageSnapshot
    from dumpex.hunt.stomping.report_facts import project_coverage_report
    coverage = CoverageSnapshot(memory_info_stream=True, module_list_stream=True)
    emitted = _emitted_scopes(project_coverage_report(coverage))
    assert emitted == set()
    assert "stomping" not in _SCOPED_TARGETED_SOURCES


def test_obfuscation_scope_emitting_branches_match_the_registrys_scoped_mapping():
    from dumpex.hunt._registry import _SCOPED_TARGETED_SOURCES
    from dumpex.hunt.encoding.domain import CoverageSnapshot, OVERSIZE_SCAN_LAYERS
    from dumpex.hunt.encoding.report_facts import project_coverage_report
    target = _scan_target(size_limit=0x10)
    coverage = CoverageSnapshot(
        memory_info_stream=True,
        sleep_mask_oversized=(target,), entropy_oversized=(target,), decode_oversized=(target,))
    emitted = _emitted_scopes(project_coverage_report(coverage))
    assert emitted == set(OVERSIZE_SCAN_LAYERS)
    assert _SCOPED_TARGETED_SOURCES["obfuscation"] == ("encoding_scan", frozenset(OVERSIZE_SCAN_LAYERS))


def test_scoped_targeted_sources_keys_are_a_subset_of_approved_identities():
    from dumpex.hunt._registry import _APPROVED_TARGETED_IDENTITIES, _SCOPED_TARGETED_SOURCES
    assert set(_SCOPED_TARGETED_SOURCES) <= _APPROVED_TARGETED_IDENTITIES


def test_scoped_targeted_sources_each_source_is_real_for_its_identity():
    from dumpex.hunt._registry import _COVERAGE_SOURCE_NAMES_BY_IDENTITY, _SCOPED_TARGETED_SOURCES
    for identity, (source, scopes) in _SCOPED_TARGETED_SOURCES.items():
        assert source in _COVERAGE_SOURCE_NAMES_BY_IDENTITY[identity]
        assert isinstance(scopes, frozenset) and scopes
        assert all(isinstance(s, str) for s in scopes)


# ── _validate_scoped_sources() itself: the enforcement, not just the ────
#    data (finding: the two tests above assert what the real mapping ─────
#    contains, not that anything would reject a bad one) ────────────────

def test_validate_scoped_sources_accepts_an_empty_mapping():
    # The exact case that used to crash with a bare `NameError:
    # name '_identity' is not defined` from a module-level `for` loop's
    # own leaked control variable and its trailing `del` -- a function's
    # local variables have no such failure mode.
    from dumpex.hunt._registry import _validate_scoped_sources
    _validate_scoped_sources({})


def test_validate_scoped_sources_rejects_a_source_outside_the_identitys_vocabulary():
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"pipe": ("not_a_real_source", frozenset({"x"}))})


def test_validate_scoped_sources_rejects_a_key_outside_approved_identities():
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"injection": ("hidden_pe_scan", frozenset({"x"}))})


def test_validate_scoped_sources_rejects_empty_scopes():
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"obfuscation": ("encoding_scan", frozenset())})


# ── _validate_scoped_sources() malformed entries: no bare unpacking ─────
#    exception may leak (finding: a malformed VALUE crashed with a bare ──
#    ValueError/TypeError from the `for identity, (source, scopes) in` ──
#    tuple-unpacking itself, before any InvalidAnalyzerSpec check ran) ──

@pytest.mark.parametrize("bad_entry", [
    "encoding_scan",                                  # bare string, not a 2-tuple
    ("encoding_scan",),                                # 1-tuple
    ("encoding_scan", frozenset(), "extra"),           # 3-tuple
    None,                                               # not a tuple at all
    ["encoding_scan", frozenset({"sleep_mask"})],      # a list, not a tuple
])
def test_validate_scoped_sources_rejects_a_malformed_entry_shape(bad_entry):
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"obfuscation": bad_entry})


def test_validate_scoped_sources_rejects_a_non_string_source():
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"obfuscation": (123, frozenset({"sleep_mask"}))})


def test_validate_scoped_sources_rejects_an_empty_string_source():
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"obfuscation": ("", frozenset({"sleep_mask"}))})


def test_validate_scoped_sources_rejects_a_non_frozenset_scopes():
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"obfuscation": ("encoding_scan", ["sleep_mask"])})


def test_validate_scoped_sources_rejects_scopes_with_a_non_string_member():
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"obfuscation": ("encoding_scan", frozenset({"sleep_mask", 1}))})


def test_validate_scoped_sources_rejects_scopes_with_an_empty_string_member():
    from dumpex.hunt._registry import _validate_scoped_sources
    with pytest.raises(InvalidAnalyzerSpec):
        _validate_scoped_sources({"obfuscation": ("encoding_scan", frozenset({"sleep_mask", ""}))})


def test_require_subset_raises_invalid_analyzer_spec_not_assertion_error():
    # _require_subset's own sibling coverage to
    # test_require_equal_sets_raises_invalid_analyzer_spec_not_assertion_error
    # -- the same python -O rationale (_require_subset is a real
    # if/raise, not a bare assert; test_registry_module_has_no_bare_assert_
    # statements covers that structurally, this covers the behavior).
    from dumpex.hunt._registry import _require_subset
    with pytest.raises(InvalidAnalyzerSpec):
        _require_subset({"a", "b"}, {"a"}, "test mismatch")
    # No exception when actual is a genuine subset (including equal).
    _require_subset({"a"}, {"a", "b"}, "test subset")
    _require_subset(set(), {"a"}, "test empty subset")


def test_module_actually_calls_validate_scoped_sources_at_import_time():
    # The `_validate_scoped_sources({...})`/`_require_subset(...)` unit
    # tests above prove the FUNCTIONS reject bad input -- they do NOT
    # prove either is actually invoked at import time (mutation-verified:
    # deleting the module-level `_validate_scoped_sources(
    # _SCOPED_TARGETED_SOURCES)` call left every test above still passing,
    # the same enforcement-vs-test gap the original P1 finding named for
    # `_validate_registrations`). Proven directly here via the same AST
    # technique `test_analyzer_registry_init_actually_calls_validate_
    # registrations` already uses: the module's own top-level statements
    # must contain a call to `_validate_scoped_sources`.
    registry_module = _REPO_ROOT / "dumpex" / "hunt" / "_registry.py"
    tree = ast.parse(registry_module.read_text(encoding="utf-8"), filename=str(registry_module))
    top_level_calls = {
        node.value.func.id for node in tree.body
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
    }
    assert "_validate_scoped_sources" in top_level_calls, (
        f"dumpex/hunt/_registry.py no longer calls _validate_scoped_sources() "
        f"at module (import) time -- found top-level calls: {sorted(top_level_calls)}")


def test_a_second_scoped_identity_is_validated_against_its_own_vocabulary_not_obfuscations(monkeypatch):
    # Finding: the allowed-scopes value used to be hard-wired to
    # OVERSIZE_SCAN_LAYERS inside the validation loop regardless of which
    # identity/source matched, so a second entry (e.g. a future
    # "pipe": "pipe_name_scan") would have been checked against
    # obfuscation's own vocabulary instead of its own -- accepting
    # obfuscation's real "sleep_mask" scope value under PIPE, and
    # rejecting pipe's own real "pipe_name" scope value under pipe. Both
    # directions are proven closed here, against a SYNTHETIC second scoped
    # identity whose own vocabulary is deliberately disjoint from
    # OVERSIZE_SCAN_LAYERS.
    import dumpex.hunt._registry as registry_mod
    patched = dict(registry_mod._SCOPED_TARGETED_SOURCES)
    patched["pipe"] = ("pipe_name_scan", frozenset({"pipe_name", "c2_context"}))
    monkeypatch.setattr(registry_mod, "_SCOPED_TARGETED_SOURCES", patched)

    real_pipe = REGISTRY.get("pipe")

    def _pipe_spec_with_grant(scopes):
        return AnalyzerSpec(
            identity=real_pipe.identity, package=real_pipe.package,
            report_type=real_pipe.report_type, builder=real_pipe.builder,
            renderer=real_pipe.renderer, record_projector=real_pipe.record_projector,
            option_names=real_pipe.option_names, provenance_hook=real_pipe.provenance_hook,
            full_scope_capable=real_pipe.full_scope_capable,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.REGION,
                frozenset({TargetedGrant("pipe_name_scan", scopes)})))

    # pipe's own real scope value: accepted under pipe's own vocabulary.
    _pipe_spec_with_grant(frozenset({"pipe_name"}))
    # obfuscation's real scope value is NOT in pipe's own vocabulary:
    # rejected -- proves pipe is not silently validated against
    # OVERSIZE_SCAN_LAYERS.
    with pytest.raises(InvalidAnalyzerSpec):
        _pipe_spec_with_grant(frozenset({"sleep_mask"}))

    # And obfuscation's own real scope value must still be validated
    # against obfuscation's own (unpatched) vocabulary, not pipe's.
    real_obfuscation = REGISTRY.get("obfuscation")
    AnalyzerSpec(
        identity=real_obfuscation.identity, package=real_obfuscation.package,
        report_type=real_obfuscation.report_type, builder=real_obfuscation.builder,
        renderer=real_obfuscation.renderer, record_projector=real_obfuscation.record_projector,
        option_names=real_obfuscation.option_names, provenance_hook=real_obfuscation.provenance_hook,
        full_scope_capable=real_obfuscation.full_scope_capable,
        targeted_capability=TargetedCapability(
            TargetedScanUnit.REGION_LAYER,
            frozenset({TargetedGrant("encoding_scan", frozenset({"sleep_mask"}))})))


# ── Import-time invariants survive `python -O` (finding: bare `assert`) ──
# `assert` statements are stripped entirely under `-O`/`PYTHONOPTIMIZE`,
# which would silently turn an import-time roster/mapping-completeness
# check into a no-op. `_require_equal_sets` replaces every such `assert`
# in _registry.py with a real `if`/`raise` -- verified here directly
# (never relying on `assert is stripped` semantics, which pytest itself
# runs without -O and so could never observe) and by an AST sweep proving
# no bare `assert` remains at module level in _registry.py.

def test_require_equal_sets_raises_invalid_analyzer_spec_not_assertion_error():
    from dumpex.hunt._registry import _require_equal_sets
    with pytest.raises(InvalidAnalyzerSpec):
        _require_equal_sets({"a"}, {"b"}, "test mismatch")
    # No exception for a genuine match.
    _require_equal_sets({"a", "b"}, {"b", "a"}, "test match")


def test_registry_module_has_no_bare_assert_statements():
    # A regression guard: a future edit that reaches for `assert` again
    # for an import-time invariant would be silently defeated under
    # `python -O`, exactly the gap this file's own _require_equal_sets
    # helper exists to close.
    registry_module = _REPO_ROOT / "dumpex" / "hunt" / "_registry.py"
    tree = ast.parse(registry_module.read_text(encoding="utf-8"), filename=str(registry_module))
    asserts = [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]
    assert not asserts, (
        f"dumpex/hunt/_registry.py must not use bare `assert` for its own "
        f"import-time invariants (stripped under python -O) -- found "
        f"{len(asserts)} at line(s) {[n.lineno for n in asserts]}")


# ── P3 cleanups: undefined dispatcher attr, and a read-only registry dict ─

def test_resolve_callable_rejects_an_undefined_dispatcher_attribute():
    from dumpex.hunt._registry import _resolve_and_validate_builder
    # A typo'd/removed facade name must fail as InvalidAnalyzerSpec, never
    # surface as a bare AttributeError -- the module's own header promises
    # "One exception type per §7 failure family".
    with pytest.raises(InvalidAnalyzerSpec):
        _resolve_and_validate_builder("_no_such_dispatcher_attribute", {})


def test_registry_by_identity_is_read_only():
    import types
    assert isinstance(REGISTRY._by_identity, types.MappingProxyType)
    with pytest.raises(TypeError):
        REGISTRY._by_identity["yara"] = REGISTRY.get("injection")


# ── Architecture boundary: registry/test-only escape hatches ────────────
# `_all_specs()` (unfiltered by capability) and `_construct_unvalidated()`
# (skips `_validate_registrations()` entirely) are BOTH the same class of
# hazard the contract's own leading-underscore convention names but does
# not itself enforce (contract §6: "the leading underscore alone is a
# convention, not an enforcement mechanism") -- a production reference to
# either one would silently reopen exactly the fail-open door #71 exists
# to close. An earlier version of this suite covered only `_all_specs()`;
# the addition of `_construct_unvalidated()` as this round's own P1 fix
# needed a matching guard, not just a test-file comment asserting one
# existed.

_TEST_ONLY_ESCAPE_HATCHES = ("_all_specs", "_construct_unvalidated")


def _production_python_files():
    for path in (_REPO_ROOT / "dumpex").rglob("*.py"):
        yield path


def test_escape_hatches_are_never_referenced_outside_the_registry_module():
    registry_module = _REPO_ROOT / "dumpex" / "hunt" / "_registry.py"
    offenders = []
    for path in _production_python_files():
        if path == registry_module:
            continue
        source = path.read_text(encoding="utf-8")
        if not any(name in source for name in _TEST_ONLY_ESCAPE_HATCHES):
            continue
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in _TEST_ONLY_ESCAPE_HATCHES:
                offenders.append((str(path.relative_to(_REPO_ROOT)), node.attr))
            elif isinstance(node, ast.Name) and node.id in _TEST_ONLY_ESCAPE_HATCHES:
                offenders.append((str(path.relative_to(_REPO_ROOT)), node.id))
    assert not offenders, (
        f"{_TEST_ONLY_ESCAPE_HATCHES} must only be referenced from "
        f"dumpex/hunt/_registry.py itself -- production callers must use "
        f"select()/select_targeted()/the real AnalyzerRegistry(...) "
        f"constructor instead, found reference(s) in: {offenders}")

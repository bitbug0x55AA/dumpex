"""
Direct regression tests for `dumpex.hunt._execute_full_scope()` (issue #72)
-- the internal executor both `collect_hunt()` and `cmd_hunt()` route
through. The existing call-count tests (`test_collect_hunt_single_scan.py`),
golden freezes (`test_hunt_compat_freeze.py`/`test_hunt_cli_compat_freeze.py`),
and provenance test (`test_yara_provenance_attribution.py`) all prove the
CUTOVER produced byte-identical *output* -- none of them calls
`_execute_full_scope()` directly or asserts on the registry seam itself, so
none of them can fail if a future edit reintroduces a two-build regression
(contract `docs/hunt_analyzer_registry_contract.md` §8's own "same-instance
invariant" warning: `spec.renderer(spec.builder(mf))` followed by
`spec.record_projector(spec.builder(mf))` still satisfies every call-count
fixture -- each *symbol* is still called once per statement -- while
silently building TWO separate Report instances from two separate scans).
These tests pin the executor's own invariants directly:

- every selected spec's builder is called exactly once, and the SAME
  Report instance that call returns is what `record_projector` and (when
  `render=True`) `renderer` each receive;
- `render=False` (`collect_hunt()`'s path) never calls a selected spec's
  `renderer` at all -- not merely "its return value goes unused";
- each spec receives only the option keyword(s) it declares
  (`spec.option_names`) -- stomping's builder never sees `rules_dir`,
  yara's never sees `ref_dir`, and the five option-less analyzers never
  see either;
- `execution.provenance` reflects THIS call's own report, never a stale
  one from a prior call;
- both a single-identity selection and `selected="all"` are resolved via
  `_registry.REGISTRY.select()`, never a re-implemented ad hoc chain.
"""
import tempfile
from pathlib import Path

import pytest

from tests.fixtures.fakes import empty_mf as _empty_mf

import dumpex.hunt as hunt_pkg
from dumpex.hunt._registry import REGISTRY
from dumpex.output.records import HUNTERS

_BUILDER_ATTR = {
    "injection": "_build_injection_report",
    "hollowing": "_build_hollowing_report",
    "stomping": "_build_stomping_report",
    "pipe": "_build_pipe_report",
    "cs-beacon": "_build_cs_beacon_report",
    "yara": "_build_yara_report",
    "obfuscation": "_build_encoding_report",
}
_RENDERER_ATTR = {
    "injection": "_render_injection_console",
    "hollowing": "_render_hollowing_console",
    "stomping": "_render_stomping_console",
    "pipe": "_render_pipe_console",
    "cs-beacon": "_render_cs_beacon_console",
    "yara": "_render_yara_console",
    "obfuscation": "_render_encoding_console",
}
_PROJECTOR_ATTR = {
    "injection": "_record_from_injection_report",
    "hollowing": "_record_from_hollowing_report",
    "stomping": "_record_from_stomping_report",
    "pipe": "_record_from_pipe_report",
    "cs-beacon": "_record_from_cs_beacon_report",
    "yara": "_record_from_yara_report",
    "obfuscation": "_record_from_encoding_report",
}


def _spy_same_instance(monkeypatch):
    """Wrap every hunter's builder/renderer/record_projector binding as
    seen ON `dumpex.hunt` -- the exact seam `_registry._late_bound()`
    resolves at call time -- so each call is logged as `id()` of the
    Report object involved: the object the builder just RETURNED, and the
    object the renderer/projector each RECEIVED. Three per-identity call
    logs are returned; the real functions still run underneath, so this
    changes no behavior, only observes it (same pattern as
    `test_collect_hunt_single_scan.py`'s own `_patch_counters()`)."""
    builder_calls = {h: [] for h in HUNTERS}
    renderer_calls = {h: [] for h in HUNTERS}
    projector_calls = {h: [] for h in HUNTERS}

    def make_builder_wrapper(hunter, real_fn):
        def wrapper(*args, **kwargs):
            report = real_fn(*args, **kwargs)
            builder_calls[hunter].append(id(report))
            return report
        return wrapper

    def make_renderer_wrapper(hunter, real_fn):
        def wrapper(report, verbose):
            renderer_calls[hunter].append(id(report))
            return real_fn(report, verbose)
        return wrapper

    def make_projector_wrapper(hunter, real_fn):
        def wrapper(report):
            projector_calls[hunter].append(id(report))
            return real_fn(report)
        return wrapper

    for hunter, attr in _BUILDER_ATTR.items():
        monkeypatch.setattr(hunt_pkg, attr, make_builder_wrapper(hunter, getattr(hunt_pkg, attr)))
    for hunter, attr in _RENDERER_ATTR.items():
        monkeypatch.setattr(hunt_pkg, attr, make_renderer_wrapper(hunter, getattr(hunt_pkg, attr)))
    for hunter, attr in _PROJECTOR_ATTR.items():
        monkeypatch.setattr(hunt_pkg, attr, make_projector_wrapper(hunter, getattr(hunt_pkg, attr)))

    return builder_calls, renderer_calls, projector_calls


@pytest.mark.parametrize("selected", HUNTERS)
def test_same_report_instance_feeds_renderer_and_projector(monkeypatch, selected):
    builder_calls, renderer_calls, projector_calls = _spy_same_instance(monkeypatch)

    execution = hunt_pkg._execute_full_scope(_empty_mf(), selected, render=True)

    assert len(builder_calls[selected]) == 1, "builder must be called exactly once"
    built_id = builder_calls[selected][0]
    assert renderer_calls[selected] == [built_id], (
        "renderer must receive the exact same Report instance the builder just built, "
        "not a second, separately-built one")
    assert projector_calls[selected] == [built_id], (
        "record_projector must receive the exact same Report instance the builder "
        "just built, not a second, separately-built one")
    assert execution.records[0].hunter == selected
    assert selected in execution.results


def test_all_uses_one_report_instance_per_analyzer(monkeypatch):
    builder_calls, renderer_calls, projector_calls = _spy_same_instance(monkeypatch)

    execution = hunt_pkg._execute_full_scope(_empty_mf(), "all", render=True)

    for hunter in HUNTERS:
        assert len(builder_calls[hunter]) == 1, f"{hunter}: builder must be called exactly once"
        built_id = builder_calls[hunter][0]
        assert renderer_calls[hunter] == [built_id], f"{hunter}: renderer got a different instance"
        assert projector_calls[hunter] == [built_id], f"{hunter}: record_projector got a different instance"
    assert tuple(r.hunter for r in execution.records) == HUNTERS


@pytest.mark.parametrize("selected", HUNTERS)
def test_render_false_never_calls_the_renderer(monkeypatch, selected):
    """`collect_hunt()`'s own console-silence guarantee, pinned at the
    executor seam directly: this proves the renderer function itself is
    never invoked for a selected spec when `render=False`, not merely
    that whatever it would have printed happened to be empty (the
    property `tests/integration/test_collect_hunt_is_silent.py` observes
    from the outside, via captured stdout)."""
    _builder_calls, renderer_calls, _projector_calls = _spy_same_instance(monkeypatch)

    hunt_pkg._execute_full_scope(_empty_mf(), selected, render=False)

    assert renderer_calls[selected] == []


def test_stomping_receives_only_ref_dir_never_rules_dir(monkeypatch):
    seen = {}
    real_fn = hunt_pkg._build_stomping_report

    def fake_stomping_builder(mf, ref_dir=None):
        seen["kwargs"] = {"ref_dir": ref_dir}
        return real_fn(mf, ref_dir=ref_dir)
    monkeypatch.setattr(hunt_pkg, "_build_stomping_report", fake_stomping_builder)

    hunt_pkg._execute_full_scope(_empty_mf(), "stomping", ref_dir="/some/dir", yara_dir="/other/dir")

    assert seen["kwargs"] == {"ref_dir": "/some/dir"}


def test_yara_receives_only_rules_dir_never_ref_dir(monkeypatch):
    seen = {}
    real_fn = hunt_pkg._build_yara_report

    def fake_yara_builder(mf, rules_dir=None):
        seen["kwargs"] = {"rules_dir": rules_dir}
        return real_fn(mf, rules_dir=rules_dir)
    monkeypatch.setattr(hunt_pkg, "_build_yara_report", fake_yara_builder)

    hunt_pkg._execute_full_scope(_empty_mf(), "yara", ref_dir="/some/dir", yara_dir="/other/dir")

    assert seen["kwargs"] == {"rules_dir": "/other/dir"}


@pytest.mark.parametrize("selected", [h for h in HUNTERS if h not in ("stomping", "yara")])
def test_analyzers_without_declared_options_receive_no_option_kwargs(monkeypatch, selected):
    """injection/hollowing/pipe/cs-beacon/obfuscation each declare an
    EMPTY `option_names` (contract §3) -- the normalized `{ref_dir,
    rules_dir}` option view must never leak either keyword to one of
    these builders, even though both are non-`None` on this call."""
    attr = _BUILDER_ATTR[selected]
    real_fn = getattr(hunt_pkg, attr)
    seen = {}

    def wrapper(mf, **kwargs):
        seen["kwargs"] = kwargs
        return real_fn(mf, **kwargs)
    monkeypatch.setattr(hunt_pkg, attr, wrapper)

    hunt_pkg._execute_full_scope(_empty_mf(), selected, ref_dir="/some/dir", yara_dir="/other/dir")

    assert seen["kwargs"] == {}


def test_provenance_reflects_this_invocations_own_report_not_a_stale_one(monkeypatch):
    """Two back-to-back `_execute_full_scope()` calls using DIFFERENT
    YARA rules directories must each carry only their own provenance in
    `execution.provenance["yara"]` -- the exact hazard
    `test_yara_provenance_attribution.py` already proves end to end at
    the `cmd_hunt()`/`V2Output` layer; this pins it directly at the
    executor seam that produces `execution.provenance` in the first
    place, with no intervening `cmd_hunt()`/`V2Output` plumbing that
    could coincidentally mask a regression here."""
    pytest.importorskip("yara")
    from tests.fixtures.fakes import Segment, FakeReader, FakeStream, FakeMF

    def _mf_with_segment():
        seg_va, seg_fo = 0x81000, 0x8100
        data = b'\x00' * 0x100
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})
        return MF()

    with tempfile.TemporaryDirectory() as d_a, tempfile.TemporaryDirectory() as d_b:
        (Path(d_a) / "a.yar").write_text('rule RuleA { condition: true }')
        (Path(d_b) / "b.yar").write_text('rule RuleB { condition: true }')

        execution_a = hunt_pkg._execute_full_scope(_mf_with_segment(), "yara", yara_dir=d_a)
        execution_b = hunt_pkg._execute_full_scope(_mf_with_segment(), "yara", yara_dir=d_b)

    assert execution_a.provenance["yara"]["rules_dir"] == d_a
    assert [f["name"] for f in execution_a.provenance["yara"]["files"]] == ["a.yar"]
    assert execution_b.provenance["yara"]["rules_dir"] == d_b
    assert [f["name"] for f in execution_b.provenance["yara"]["files"]] == ["b.yar"]


def test_provenance_hook_receives_the_same_report_object_the_builder_built(monkeypatch):
    """The two provenance tests above (`_reflects_this_invocations_own_
    report_not_a_stale_one`, and `_absent_for_analyzers_with_no_
    provenance_hook`) only compare VALUES -- neither would fail if
    `provenance_hook` were fed a second, separately-built (but content-
    identical) Report, or even a shallow/deep COPY of the exact Report
    `record_projector`/`renderer` consumed, instead of that literal
    object. An earlier version of this test tried to prove identity by
    mutating an attribute on the builder's returned Report (via
    `object.__setattr__`, bypassing `RulesProvenance`'s frozen fields) and
    then checking whether the mutated value showed up in `execution.
    provenance["yara"]` -- but that mutation happens BEFORE
    `_execute_full_scope()` ever sees the report, so a
    `copy.deepcopy(report)` taken afterward would carry the mutated value
    right along with it and pass this test regardless, proving nothing
    about identity. This version asserts identity directly instead
    (`is`), using a disposable, one-spec synthetic `AnalyzerRegistry` (the
    `_construct_unvalidated()` test-only escape hatch `_registry.py`
    itself documents for exactly this kind of test) whose `builder`/
    `renderer`/`record_projector`/`provenance_hook` are spies that each
    record the exact object they were called with -- `spec.provenance_hook`
    is a plain function reference baked directly into the frozen
    `AnalyzerSpec` at import time (`_registry.py`'s own
    `_yara_provenance_hook`, never late-bound via `dumpex.hunt` the way
    `builder`/`renderer`/`record_projector` are), so it cannot be
    intercepted with the `_spy_same_instance()` wrapper pattern above --
    only a synthetic spec lets a test observe what THIS field specifically
    receives."""
    from dumpex.hunt import _registry as registry_module
    from dumpex.hunt._registry import AnalyzerRegistry, AnalyzerSpec

    built_report = object()   # a real, distinguishable object -- copy.copy()/
                               # copy.deepcopy() of it would produce a DIFFERENT
                               # object (`is` False), unlike an attribute-value
                               # comparison, which a copy would still pass.
    captured = {}

    def spy_builder(mf, **kwargs):
        return built_report

    def spy_renderer(report, verbose):
        captured["renderer"] = report
        return {}

    def spy_projector(report):
        captured["record_projector"] = report
        return object()

    def spy_provenance_hook(report):
        captured["provenance_hook"] = report
        return {}

    synthetic_spec = AnalyzerSpec(
        identity="yara", package="dumpex.hunt.yara_hunt", report_type=object,
        builder=spy_builder, renderer=spy_renderer, record_projector=spy_projector,
        option_names=frozenset(), provenance_hook=spy_provenance_hook,
        full_scope_capable=True, targeted_capability=None)
    monkeypatch.setattr(
        registry_module, "REGISTRY", AnalyzerRegistry._construct_unvalidated((synthetic_spec,)))

    hunt_pkg._execute_full_scope(object(), "yara", render=True)

    assert captured["renderer"] is built_report
    assert captured["record_projector"] is built_report
    assert captured["provenance_hook"] is built_report


def test_provenance_absent_for_analyzers_with_no_provenance_hook(monkeypatch):
    execution = hunt_pkg._execute_full_scope(_empty_mf(), "all")
    assert set(execution.provenance) == {"yara"}


@pytest.mark.parametrize("selected", HUNTERS)
def test_single_identity_selection_routes_through_registry_select(monkeypatch, selected):
    calls = []
    real_select = REGISTRY.select

    def spy_select(sel):
        calls.append(sel)
        return real_select(sel)
    monkeypatch.setattr(REGISTRY, "select", spy_select)

    hunt_pkg._execute_full_scope(_empty_mf(), selected)

    assert calls == [selected]


def test_all_selection_routes_through_registry_select_in_hunters_order(monkeypatch):
    calls = []
    real_select = REGISTRY.select

    def spy_select(sel):
        calls.append(sel)
        return real_select(sel)
    monkeypatch.setattr(REGISTRY, "select", spy_select)

    execution = hunt_pkg._execute_full_scope(_empty_mf(), "all")

    assert calls == ["all"]
    assert tuple(r.hunter for r in execution.records) == HUNTERS

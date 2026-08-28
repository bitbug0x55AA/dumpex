"""Validation and immutability of the per-invocation HuntRequest."""
import dataclasses
import pathlib

import pytest

from dumpex.core.va_range import VirtualRange
from dumpex.hunt import _registry
from dumpex.hunt._registry import (
    REGISTRY,
    UnknownAnalyzerIdentity,
    UnsupportedTargetedCapability,
    UnsupportedTargetedScope,
    UnsupportedTargetedSource,
)
from dumpex.hunt._request import HuntOptions, HuntRequest, HuntScopeKind
from dumpex.output.records import HUNTERS

_OBF_LAYERS = frozenset({"sleep_mask", "entropy", "decode"})


def _range(size):
    return VirtualRange(0x10000000, size)


def _ceiling(identity):
    return REGISTRY.get(identity).targeted_capability.request_ceiling


# ── full-scope construction ────────────────────────────────────────────

@pytest.mark.parametrize("selected", HUNTERS + ("all",))
def test_full_accepts_every_hunter_and_all(selected):
    request = HuntRequest.full(selected)
    assert request.scope is HuntScopeKind.FULL
    assert request.selected == selected
    assert request.is_targeted is False
    assert request.targeted_source is None
    assert request.targeted_scopes == frozenset()
    assert request.target_range is None


def test_full_rejects_an_unknown_selection():
    with pytest.raises(ValueError):
        HuntRequest.full("not-a-hunter")


def test_full_threads_options_into_the_option_view():
    request = HuntRequest.full("stomping", ref_dir="/ref", rules_dir="/rules")
    assert request.options == HuntOptions(ref_dir="/ref", rules_dir="/rules")
    assert request.options.as_option_view() == {"ref_dir": "/ref", "rules_dir": "/rules"}


# ── HuntOptions normalization: an unset/empty directory option ────────

def test_hunt_options_normalizes_falsy_to_none():
    assert HuntOptions(ref_dir="").ref_dir is None
    assert HuntOptions(rules_dir="").rules_dir is None
    assert HuntOptions(ref_dir=None).ref_dir is None


def test_hunt_options_accepts_a_pathlike():
    opts = HuntOptions(ref_dir=pathlib.PurePosixPath("/ref"))
    assert opts.ref_dir == "/ref"


def test_hunt_options_rejects_a_non_str_non_pathlike():
    with pytest.raises(ValueError):
        HuntOptions(ref_dir=123)


def test_empty_option_string_produces_the_none_request():
    assert HuntRequest.full("stomping", ref_dir="").options.ref_dir is None
    assert HuntRequest.full("yara", rules_dir="").options.rules_dir is None


# ── targeted construction ──────────────────────────────────────────────

def test_targeted_resolves_a_granted_unscoped_source():
    request = HuntRequest.targeted("pipe", "pipe_name_scan", _range(0x1000))
    assert request.scope is HuntScopeKind.TARGETED
    assert request.is_targeted is True
    assert request.selected == "pipe"
    assert request.targeted_source == "pipe_name_scan"
    assert request.targeted_scopes == frozenset()
    assert request.target_range == _range(0x1000)


def test_targeted_obfuscation_defaults_to_all_three_layers():
    # No `scopes` -> the granted set, resolved from the registry (the caller
    # never restates obfuscation's three layers).
    request = HuntRequest.targeted("obfuscation", "encoding_scan", _range(0x1000))
    assert request.targeted_scopes == _OBF_LAYERS
    # ... and an explicit full set is accepted as a redundant assertion.
    assert HuntRequest.targeted(
        "obfuscation", "encoding_scan", _range(0x1000), scopes=_OBF_LAYERS
    ).targeted_scopes == _OBF_LAYERS


def test_targeted_obfuscation_rejects_a_partial_layer_set():
    with pytest.raises(UnsupportedTargetedScope):
        HuntRequest.targeted("obfuscation", "encoding_scan", _range(0x1000),
                             scopes={"entropy"})


def test_targeted_unscoped_source_rejects_a_scope_set():
    with pytest.raises(UnsupportedTargetedScope):
        HuntRequest.targeted("pipe", "pipe_name_scan", _range(0x1000), scopes={"x"})


def test_targeted_passes_through_registry_failures():
    with pytest.raises(UnknownAnalyzerIdentity):
        HuntRequest.targeted("not-a-hunter", "x", _range(0x1000))
    with pytest.raises(UnsupportedTargetedCapability):
        HuntRequest.targeted("injection", "anything", _range(0x1000))
    with pytest.raises(UnsupportedTargetedSource):
        HuntRequest.targeted("stomping", "reference_files", _range(0x1000))


def test_targeted_requires_a_virtual_range():
    with pytest.raises(ValueError):
        HuntRequest.targeted("pipe", "pipe_name_scan", (0x1000, 0x2000))


@pytest.mark.parametrize("identity,source,scopes", [
    ("pipe", "pipe_name_scan", None),
    ("stomping", "ioc_string_scan", None),
    ("cs-beacon", "segment_scan", None),
    ("yara", "segment_scan", None),
    ("obfuscation", "encoding_scan", _OBF_LAYERS),
])
def test_targeted_enforces_the_ceiling_from_the_capability(identity, source, scopes):
    ceiling = _ceiling(identity)
    HuntRequest.targeted(identity, source, VirtualRange(0x10000000, ceiling), scopes=scopes)
    with pytest.raises(ValueError):
        HuntRequest.targeted(identity, source, VirtualRange(0x10000000, ceiling + 1),
                             scopes=scopes)


def test_obfuscation_ceiling_is_lower_than_the_others():
    assert _ceiling("obfuscation") < _ceiling("yara")


def test_request_validation_reads_registry_lazily(monkeypatch):
    # A test patching `_registry.REGISTRY` must affect request validation
    # the same way it affects execution.
    real = REGISTRY.get("pipe")
    single = _registry.AnalyzerRegistry._construct_unvalidated((real,))
    monkeypatch.setattr(_registry, "REGISTRY", single)
    with pytest.raises(UnknownAnalyzerIdentity):
        HuntRequest.targeted("stomping", "ioc_string_scan", _range(0x1000))


# ── shape and immutability ─────────────────────────────────────────────

def test_request_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        HuntRequest.full("all").selected = "pipe"


def test_raw_constructor_rejects_a_full_request_carrying_targeted_fields():
    with pytest.raises(ValueError):
        HuntRequest(scope=HuntScopeKind.FULL, selected="pipe", options=HuntOptions(),
                    targeted_source="pipe_name_scan")


def test_raw_constructor_rejects_a_targeted_request_without_a_range():
    with pytest.raises(ValueError):
        HuntRequest(scope=HuntScopeKind.TARGETED, selected="pipe", options=HuntOptions(),
                    targeted_source="pipe_name_scan", target_range=None)


def test_raw_constructor_rejects_all_for_a_targeted_request():
    with pytest.raises(UnknownAnalyzerIdentity):
        HuntRequest(scope=HuntScopeKind.TARGETED, selected="all", options=HuntOptions(),
                    targeted_source="segment_scan", target_range=_range(0x1000))


def _raw_targeted(selected, source, target_range, scopes=frozenset()):
    return HuntRequest(
        scope=HuntScopeKind.TARGETED, selected=selected, options=HuntOptions(),
        targeted_source=source, targeted_scopes=frozenset(scopes), target_range=target_range)


def test_raw_constructor_enforces_capability_for_an_unsupported_analyzer():
    with pytest.raises(UnsupportedTargetedCapability):
        _raw_targeted("injection", "bogus", _range(0x1000))


def test_raw_constructor_enforces_an_ungranted_source():
    with pytest.raises(UnsupportedTargetedSource):
        _raw_targeted("stomping", "reference_files", _range(0x1000))


def test_raw_constructor_auto_fills_an_empty_scope_set_then_validates():
    # An empty set on the raw constructor also resolves to "the granted set".
    assert _raw_targeted("obfuscation", "encoding_scan", _range(0x1000)).targeted_scopes == _OBF_LAYERS
    with pytest.raises(UnsupportedTargetedScope):
        _raw_targeted("obfuscation", "encoding_scan", _range(0x1000), scopes={"decode"})


def test_raw_constructor_enforces_the_size_ceiling():
    with pytest.raises(ValueError):
        _raw_targeted("obfuscation", "encoding_scan",
                      VirtualRange(0x10000000, _ceiling("obfuscation") + 1), scopes=_OBF_LAYERS)

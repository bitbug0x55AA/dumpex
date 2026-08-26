"""Shared behavioral contracts for canonical hunter domain models."""

import dataclasses

import pytest

from dumpex.hunt._domain import CheckResult
from dumpex.hunt._finding import (
    CONFIDENCE_HIGH,
    TAG_DETECTION,
    TAG_OBSERVATION,
    lead_count,
    overall_confidence,
    review_priority,
    verdict_level,
)
from tests.hunt import (
    test_encoding_domain as encoding,
    test_hollowing_domain as hollowing,
    test_injection_domain as injection,
    test_pipe_domain as pipe,
    test_stomping_domain as stomping,
)


_HUNTERS = (
    ("obfuscation", encoding),
    ("hollowing", hollowing),
    ("injection", injection),
    ("pipe", pipe),
    ("stomping", stomping),
)

_DOMAIN_TYPES = tuple(
    pytest.param(domain_type, id=f"{hunter}-{domain_type.__name__}")
    for hunter, module in _HUNTERS
    for domain_type in module.DOMAIN_TYPES + getattr(module, "EVIDENCE_TYPES", [])
)


@pytest.mark.parametrize("domain_type", _DOMAIN_TYPES)
def test_domain_types_are_frozen_dataclasses(domain_type):
    assert dataclasses.is_dataclass(domain_type)
    assert domain_type.__dataclass_params__.frozen is True


@pytest.mark.parametrize("hunter,module", _HUNTERS, ids=[item[0] for item in _HUNTERS])
def test_reports_expose_no_mutable_reachable_state(hunter, module):
    for value in module._reachable(module._populated_report()):
        assert not isinstance(value, (list, set, dict, bytearray)), (
            f"{hunter}: mutable {type(value).__name__} is reachable from the report")
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            assert value.__dataclass_params__.frozen is True, (
                f"{hunter}: non-frozen {type(value).__name__} is reachable from the report")


_POISON_CASES = tuple(
    pytest.param(module, poison, id=f"{hunter}-{index}")
    for hunter, module in _HUNTERS
    for index, poison in enumerate(module._POISON)
)


@pytest.mark.parametrize("module,poison", _POISON_CASES)
def test_check_result_evidence_rejects_non_evidence_objects(module, poison):
    with pytest.raises(TypeError):
        module._check(evidence=(poison,))


@pytest.mark.parametrize("hunter,module", _HUNTERS, ids=[item[0] for item in _HUNTERS])
def test_check_result_evidence_rejects_non_frozen_dataclasses(hunter, module):
    with pytest.raises(TypeError):
        module._check(evidence=(module._MutableEvidence(),))


@pytest.mark.parametrize("hunter,module", _HUNTERS, ids=[item[0] for item in _HUNTERS])
@pytest.mark.parametrize("kind", ["dict", "string", "generator", "set"])
def test_evidence_requires_a_list_or_tuple(hunter, module, kind):
    sample = module._populated_report().results[0].evidence[0]
    invalid = {
        "dict": {"evidence": sample},
        "string": "evidence",
        "generator": iter((sample,)),
        "set": {sample},
    }[kind]
    with pytest.raises(TypeError):
        module._check(evidence=invalid)


@pytest.mark.parametrize("hunter,module", _HUNTERS, ids=[item[0] for item in _HUNTERS])
def test_judgment_fields_use_the_shared_reducers(hunter, module):
    report = module._populated_report()
    assert report.max_score == module.MAX_SCORE
    assert report.confidence == overall_confidence(report.results, report.score)
    assert report.verdict_level == verdict_level(
        report.score, module.VERDICT_LEVEL_BY_SCORE, status=report.status)
    assert report.lead_count == lead_count(report.results)
    assert report.review_priority == review_priority(
        report.results, report.score, report.status)


@pytest.mark.parametrize("hunter,module", _HUNTERS, ids=[item[0] for item in _HUNTERS])
def test_score_above_each_hunters_ceiling_is_rejected(hunter, module):
    with pytest.raises(ValueError):
        module._report(score=module.MAX_SCORE + 1)


@pytest.mark.parametrize("hunter,module", _HUNTERS, ids=[item[0] for item in _HUNTERS])
def test_check_result_severity_is_derived(hunter, module):
    assert module._check(tag=TAG_OBSERVATION, confidence=CONFIDENCE_HIGH).severity == "info"
    assert module._check(tag=TAG_DETECTION, confidence=CONFIDENCE_HIGH).severity == "critical"
    assert "severity" not in {field.name for field in dataclasses.fields(CheckResult)}

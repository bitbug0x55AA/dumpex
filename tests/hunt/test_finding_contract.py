"""
Contract tests for dumpex.hunt._finding.Finding itself -- distinct from
tests/hunt/test_finding_invariants.py (which covers a cross-hunter
DETECTED/tag=detection invariant). Covers two review-round regressions:

  1. Any Finding that successfully CONSTRUCTS must also validate against
     the current schema's own `$defs/finding` (unchanged since v2.5) -- the schema and
     Finding.__post_init__ must never drift apart (a review found several
     gaps: inference/rationale left unvalidated, technique_ids format/
     uniqueness unchecked, rule_version accepting a non-str).
  2. Finding.id must not collide for two findings that differ in any of
     the fields id's own hash basis covers (check/rule_id/rule_version/
     tag/confidence/technique_ids/evidence_refs/iocs/facts) -- a prior
     version hashed only check/rule_id/confidence/facts, so a finding
     that was later re-tagged from a lead to a detection, or whose
     rule_version changed after a rules.yaml update, silently kept the
     SAME id as the finding it superseded.
"""
import json

import pytest

from dumpex.hunt._finding import (
    Finding, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION,
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH, severity_for,
)

jsonschema = pytest.importorskip("jsonschema")
from dumpex.schemas import schema_path


@pytest.fixture(scope="module")
def finding_validator():
    with schema_path("dumpex-output-v2.10.schema.json") as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/finding", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


def _base_kwargs(**overrides):
    kwargs = dict(check="x.y", facts=["VA=0x1000"], inference="it means something",
                  confidence=CONFIDENCE_LOW, rationale="because reasons", tag=TAG_OBSERVATION)
    kwargs.update(overrides)
    return kwargs


# ── every constructible Finding validates against the schema ────────────

@pytest.mark.parametrize("tag,confidence", [
    (TAG_OBSERVATION, CONFIDENCE_LOW), (TAG_OBSERVATION, CONFIDENCE_MEDIUM),
    (TAG_OBSERVATION, CONFIDENCE_HIGH),
    (TAG_LEAD, CONFIDENCE_LOW), (TAG_LEAD, CONFIDENCE_MEDIUM), (TAG_LEAD, CONFIDENCE_HIGH),
    (TAG_DETECTION, CONFIDENCE_LOW), (TAG_DETECTION, CONFIDENCE_MEDIUM),
    (TAG_DETECTION, CONFIDENCE_HIGH),
])
def test_every_tag_confidence_combo_validates(finding_validator, tag, confidence):
    f = Finding(**_base_kwargs(tag=tag, confidence=confidence))
    errors = list(finding_validator.iter_errors(f.to_dict()))
    assert errors == [], errors


def test_full_shape_with_all_optional_fields_populated_validates(finding_validator):
    f = Finding(**_base_kwargs(
        tag=TAG_DETECTION, confidence=CONFIDENCE_HIGH,
        limitations=["known gap"], technique_ids=["T1055", "T1559.001"],
        evidence_refs=["region:0x1000", "tid:99"], iocs=["198.51.100.7"],
        rule_id="pipe.framework_match", rule_version="a" * 64,
    ))
    errors = list(finding_validator.iter_errors(f.to_dict()))
    assert errors == [], errors


def test_minimal_shape_with_no_optional_fields_validates(finding_validator):
    f = Finding(**_base_kwargs())
    errors = list(finding_validator.iter_errors(f.to_dict()))
    assert errors == [], errors


@pytest.mark.parametrize("bad_id", [
    "x", "finding-deadbeef", "not-a-hash",
    "finding-" + "A" * 32,        # uppercase hex
    "finding-" + "a" * 31,        # one char short
    "finding-" + "a" * 33,        # one char long
    "finding-" + "a" * 32 + "\n",  # trailing newline
])
def test_schema_rejects_malformed_finding_id(finding_validator, bad_id):
    # A real Finding always produces "finding-" + 32 lowercase hex chars;
    # the schema must reject anything else -- proves this independently
    # of Finding.__post_init__, for any producer that isn't this
    # codebase's own dataclass.
    d = Finding(**_base_kwargs()).to_dict()
    d["id"] = bad_id
    errors = list(finding_validator.iter_errors(d))
    assert errors, f"schema should reject id={bad_id!r} but accepted it"


def test_schema_accepts_a_real_finding_id(finding_validator):
    d = Finding(**_base_kwargs()).to_dict()
    errors = list(finding_validator.iter_errors(d))
    assert errors == [], errors


@pytest.mark.parametrize("bad_id", ["T1055\n", "T1559.001\n"])
def test_schema_rejects_technique_id_with_trailing_newline(finding_validator, bad_id):
    # Schema-level counterpart to test_rejects_technique_id_with_trailing_
    # newline above -- Finding itself can never produce this shape (its
    # own __post_init__ already rejects it), so this hand-builds the dict
    # directly to prove the SCHEMA closes the same gap independently, for
    # any producer that isn't this codebase's own Finding dataclass. The
    # `finding` $def's own `technique_ids` items (unchanged since v2.5) use two fixed-length oneOf
    # branches (pattern + exact minLength/maxLength) specifically because
    # a bare "^...$"-anchored pattern alone has the same Python re
    # trailing-newline gap `jsonschema`'s pattern check inherits.
    d = Finding(**_base_kwargs()).to_dict()
    d["technique_ids"] = [bad_id]
    errors = list(finding_validator.iter_errors(d))
    assert errors, f"schema should reject technique_ids={[bad_id]!r} but accepted it"


# ── construction-time validation (must fail BEFORE reaching to_dict()) ──

def test_rejects_bad_tag():
    with pytest.raises(ValueError, match="tag"):
        Finding(**_base_kwargs(tag="bogus"))


def test_rejects_bad_confidence():
    with pytest.raises(ValueError, match="confidence"):
        Finding(**_base_kwargs(confidence="bogus"))


def test_rejects_empty_check():
    with pytest.raises(ValueError, match="check"):
        Finding(**_base_kwargs(check=""))


def test_rejects_non_string_inference():
    with pytest.raises(ValueError, match="inference"):
        Finding(**_base_kwargs(inference=1))


def test_rejects_none_rationale():
    with pytest.raises(ValueError, match="rationale"):
        Finding(**_base_kwargs(rationale=None))


def test_rejects_empty_string_rule_id():
    with pytest.raises(ValueError, match="rule_id"):
        Finding(**_base_kwargs(rule_id=""))


def test_rejects_non_string_rule_version():
    with pytest.raises(ValueError, match="rule_version"):
        Finding(**_base_kwargs(rule_version=1))


def test_rejects_malformed_technique_id():
    with pytest.raises(ValueError, match="technique_ids"):
        Finding(**_base_kwargs(technique_ids=["not-a-technique"]))


@pytest.mark.parametrize("bad_id", ["T1055\n", "T1559.001\n"])
def test_rejects_technique_id_with_trailing_newline(bad_id):
    # Review finding: Python's `$` matches just before a trailing
    # newline, not only at the true end of string -- a bare
    # "^T[0-9]{4}(\.[0-9]{3})?$" pattern with match()/search() would
    # incorrectly accept "T1055\n". is_valid_technique_id() uses
    # fullmatch() specifically to close this.
    with pytest.raises(ValueError, match="technique_ids"):
        Finding(**_base_kwargs(technique_ids=[bad_id]))


def test_rejects_duplicate_technique_ids():
    with pytest.raises(ValueError, match="technique_ids"):
        Finding(**_base_kwargs(technique_ids=["T1055", "T1055"]))


def test_severity_is_not_settable_by_caller():
    with pytest.raises(TypeError):
        Finding(**_base_kwargs(), severity="critical")


def test_id_is_not_settable_by_caller():
    with pytest.raises(TypeError):
        Finding(**_base_kwargs(), id="finding-deadbeef")


# ── frozen/immutability regressions ──────────────────────────────────────
# A review found that init=False alone only stops severity/id from being
# passed as constructor kwargs -- it does not stop `f.tag = "detection"`
# after construction (which would invalidate the already-derived id/
# severity without recomputing them), nor `f.facts.append(...)` on a list
# the caller handed in and kept a reference to. Finding is now a frozen
# dataclass with every list field normalized to a tuple, closing both.

def test_cannot_reassign_any_field_after_construction():
    import dataclasses
    f = Finding(**_base_kwargs())
    for attr, value in [("tag", TAG_DETECTION), ("confidence", CONFIDENCE_HIGH),
                         ("check", "y.z"), ("id", "finding-" + "b" * 32),
                         ("severity", "critical"), ("facts", ["x"])]:
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(f, attr, value)


def test_list_fields_are_tuples_and_reject_in_place_mutation():
    f = Finding(**_base_kwargs(facts=["a"], limitations=["b"],
                                technique_ids=["T1055"], evidence_refs=["c"], iocs=["d"],
                                verbose_facts=["e"]))
    for attr in ("facts", "limitations", "technique_ids", "evidence_refs", "iocs", "verbose_facts"):
        value = getattr(f, attr)
        assert isinstance(value, tuple)
        with pytest.raises(AttributeError):
            value.append("late")


def test_mutating_the_callers_original_list_does_not_affect_the_finding():
    facts = ["a", "b"]
    f = Finding(**_base_kwargs(facts=facts))
    facts.append("c")
    facts[0] = "tampered"
    assert f.facts == ("a", "b")


# ── verbose_facts (console-only field, not part of the wire contract) ──
# See tests/hunt/test_finding_print.py for verbose_facts' actual console
# rendering behavior -- these cover the Finding-construction-level
# contract only: tuple normalization, defensive copy, dataclasses.replace()
# round-tripping, string validation, exclusion from to_dict()/id/eq/hash.

def test_verbose_facts_rejects_empty_strings():
    # Unlike facts/limitations (permissive on "" for v2.5 wire-contract
    # compatibility reasons -- see _require_list_of_str's own comment),
    # verbose_facts is console-only and was never part of the schema, so
    # there is no compatibility reason to accept an empty bullet line.
    # Uses _require_str_list (same non-empty validator as technique_ids/
    # evidence_refs/iocs), not the permissive _require_list_of_str.
    with pytest.raises(ValueError, match="verbose_facts"):
        Finding(**_base_kwargs(verbose_facts=["", "VA=0x1000 File_offset=0x500"]))


def test_verbose_facts_rejects_non_string_items():
    with pytest.raises(ValueError, match="verbose_facts"):
        Finding(**_base_kwargs(verbose_facts=[1]))


def test_verbose_facts_is_a_tuple_and_rejects_in_place_mutation():
    f = Finding(**_base_kwargs(verbose_facts=["VA=0x1000"]))
    assert isinstance(f.verbose_facts, tuple)
    with pytest.raises(AttributeError):
        f.verbose_facts.append("late")


def test_mutating_the_callers_original_verbose_facts_list_does_not_affect_the_finding():
    verbose_facts = ["VA=0x1000"]
    f = Finding(**_base_kwargs(verbose_facts=verbose_facts))
    verbose_facts.append("VA=0x2000")
    verbose_facts[0] = "tampered"
    assert f.verbose_facts == ("VA=0x1000",)


def test_dataclasses_replace_round_trips_verbose_facts(finding_validator):
    import dataclasses
    f = Finding(**_base_kwargs(verbose_facts=["VA=0x1000 File_offset=0x500"]))
    updated = dataclasses.replace(f, confidence=CONFIDENCE_MEDIUM)
    assert updated.verbose_facts == ("VA=0x1000 File_offset=0x500",)
    errors = list(finding_validator.iter_errors(updated.to_dict()))
    assert errors == [], errors


def test_verbose_facts_is_never_part_of_to_dict(finding_validator):
    f = Finding(**_base_kwargs(verbose_facts=["VA=0x1000 File_offset=0x500"]))
    d = f.to_dict()
    assert "verbose_facts" not in d
    errors = list(finding_validator.iter_errors(d))
    assert errors == [], errors


def test_verbose_facts_does_not_affect_finding_id():
    f1 = Finding(**_base_kwargs(verbose_facts=[]))
    f2 = Finding(**_base_kwargs(verbose_facts=["VA=0x1000 File_offset=0x500"]))
    assert f1.id == f2.id


def test_verbose_facts_does_not_affect_equality_or_hash():
    # Deliberately consistent with verbose_facts' exclusion from `id`'s
    # hash basis (see Finding's own docstring): two Findings differing
    # ONLY in verbose_facts are the same finding for every purpose except
    # console rendering, so __eq__/__hash__ must not treat them as
    # different either -- field(compare=False) on verbose_facts is what
    # this test pins down.
    f1 = Finding(**_base_kwargs(verbose_facts=[]))
    f2 = Finding(**_base_kwargs(verbose_facts=["VA=0x1000 File_offset=0x500"]))
    assert f1 == f2
    assert hash(f1) == hash(f2)


def test_dataclasses_replace_round_trips(finding_validator):
    # Review finding: __post_init__ normalizes every list field to a
    # tuple, so dataclasses.replace() -- the standard way to derive an
    # updated copy of a frozen dataclass -- reconstructs a Finding by
    # re-passing the CURRENT (already-tuple) field values back through
    # __init__/__post_init__. The list-only validators used to reject
    # that round-trip outright; they now accept list OR tuple.
    import dataclasses
    f = Finding(**_base_kwargs(technique_ids=["T1055"]))
    updated = dataclasses.replace(f, confidence=CONFIDENCE_MEDIUM)

    assert updated.confidence == CONFIDENCE_MEDIUM
    assert updated.severity == severity_for(updated.tag, updated.confidence)
    assert updated.id != f.id
    assert updated.technique_ids == ("T1055",)
    errors = list(finding_validator.iter_errors(updated.to_dict()))
    assert errors == [], errors


# ── id collision regressions ─────────────────────────────────────────────

def test_id_does_not_collide_across_delimiter_ambiguous_facts():
    f1 = Finding(**_base_kwargs(facts=["alpha|beta", "gamma"]))
    f2 = Finding(**_base_kwargs(facts=["alpha", "beta|gamma"]))
    assert f1.id != f2.id


def test_id_does_not_collide_when_only_tag_and_confidence_differ():
    # Same check/rule_id/facts, but one is an unscored observation and
    # the other is a corroborated detection -- these must never share an
    # id, or a SIEM would dedup away the upgraded (materially different)
    # alert as "already seen".
    f1 = Finding(**_base_kwargs(tag=TAG_OBSERVATION, confidence=CONFIDENCE_LOW))
    f2 = Finding(**_base_kwargs(tag=TAG_DETECTION, confidence=CONFIDENCE_MEDIUM))
    assert f1.id != f2.id


def test_id_does_not_collide_when_only_technique_ids_differ():
    f1 = Finding(**_base_kwargs(technique_ids=[]))
    f2 = Finding(**_base_kwargs(technique_ids=["T1055"]))
    assert f1.id != f2.id


def test_id_does_not_collide_when_only_rule_version_differs():
    f1 = Finding(**_base_kwargs(rule_version="a" * 64))
    f2 = Finding(**_base_kwargs(rule_version="b" * 64))
    assert f1.id != f2.id


def test_id_stable_when_technique_ids_or_iocs_built_in_different_order():
    # Order within technique_ids/evidence_refs/iocs is not semantically
    # meaningful (they're sets); the id must not change just because two
    # calls happened to append the same values in a different order.
    f1 = Finding(**_base_kwargs(technique_ids=["T1055", "T1559.001"]))
    f2 = Finding(**_base_kwargs(technique_ids=["T1559.001", "T1055"]))
    assert f1.id == f2.id


def test_id_deterministic_across_construction_for_identical_input():
    f1 = Finding(**_base_kwargs())
    f2 = Finding(**_base_kwargs())
    assert f1.id == f2.id

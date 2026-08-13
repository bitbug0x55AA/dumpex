"""Architecture/contract tests for the YARA hunter's immutable domain model
(dumpex/hunt/yara_hunt/domain.py, models.py) and its projectors
(report_facts.py/report_legacy.py/report_record.py/report_console.py).
Mirrors tests/hunt/test_cs_beacon_domain.py (the completed reference
pilot's own test suite): proves recursive immutability, constructor-input-
mutation isolation, poison-object rejection, and that every projector is a
pure, order-independent function of an already-built Report.
"""
import dataclasses

import pytest

from dumpex.hunt.yara_hunt.domain import (
    CoverageSnapshot, RulesDiagnostics, ScanDiagnostics, YaraEvidence, YaraReport,
)
from dumpex.hunt.yara_hunt.models import RuleFileDiagnostic, RuleMatchEvidence, RulesProvenance, \
    StringEvidence
from dumpex.hunt.yara_hunt.report_console import render_console_lines
from dumpex.hunt.yara_hunt.report_legacy import project_legacy_dict
from dumpex.hunt.yara_hunt.report_record import project_hunter_record


def _string(var="$a", offset=0, va=0x1000, fo=0x1000, data=b"hit") -> StringEvidence:
    return StringEvidence(var=var, offset=offset, va=va, fo=fo, data=data)


def _match(rule="HitRule", seg_va=0x1000, context_unverified=False, strings=None,
           file="hit.yar", namespace="default", string_count=None,
           backing_module=None) -> RuleMatchEvidence:
    strings = strings if strings is not None else (_string(va=seg_va, fo=seg_va),)
    return RuleMatchEvidence(
        rule=rule, file=file, namespace=namespace, tags=("suspicious",),
        meta=(("description", "test rule"), ("mitre", "T1055")),
        seg_va=seg_va, seg_fo=seg_va, seg_size=0x100,
        strings=strings, string_count=string_count if string_count is not None else len(strings),
        backing_module=backing_module, memory_context="private",
        context_unverified=context_unverified)


def _ready_rules(compiled_ok=1, compile_failed=0) -> RulesDiagnostics:
    return RulesDiagnostics(yara_available=True, rules_dir="/rules", attempted=True,
                             compiled_ok=compiled_ok, compile_failed=compile_failed)


def _detected_report(n_matches=1) -> YaraReport:
    matches = tuple(_match(seg_va=0x1000 * (i + 1)) for i in range(n_matches))
    coverage = CoverageSnapshot(rules=_ready_rules(), scan=ScanDiagnostics(segment_count=1, scanned=1))
    return YaraReport(coverage=coverage, evidence=YaraEvidence(matches=matches))


# ── Frozen / recursively immutable ──────────────────────────────────────

@pytest.mark.parametrize("report_type", [
    YaraReport, CoverageSnapshot, ScanDiagnostics, RulesDiagnostics, YaraEvidence,
    RuleMatchEvidence, StringEvidence, RuleFileDiagnostic, RulesProvenance,
])
def test_domain_types_are_frozen_dataclasses(report_type):
    assert dataclasses.is_dataclass(report_type)
    assert report_type.__dataclass_params__.frozen is True


def test_report_top_level_attributes_reject_reassignment():
    report = _detected_report()
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.coverage = CoverageSnapshot()


def test_evidence_container_rejects_reassignment():
    report = _detected_report()
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.evidence.matches = ()


# ── Constructor-input mutation isolation ────────────────────────────────

def test_constructor_input_list_mutation_does_not_reach_the_report():
    match = _match()
    matches_list = [match]
    evidence = YaraEvidence(matches=matches_list)
    matches_list.append(_match(seg_va=0x2000))
    assert len(evidence.matches) == 1


def test_string_tuple_mutation_does_not_reach_the_match():
    strings_list = [_string()]
    match = RuleMatchEvidence(rule="R", file="r.yar", seg_va=1, seg_fo=1, seg_size=1,
                               strings=strings_list, string_count=1)
    strings_list.append(_string(var="$b"))
    assert len(match.strings) == 1


# ── Poison-object / mutable-payload rejection ───────────────────────────

def test_string_evidence_rejects_mutable_data():
    with pytest.raises(TypeError):
        StringEvidence(var="$a", offset=0, va=1, fo=1, data=bytearray(b"x"))


def test_rule_match_evidence_rejects_a_raw_dict_string():
    with pytest.raises(TypeError):
        RuleMatchEvidence(rule="R", file="r.yar", seg_va=1, seg_fo=1, seg_size=1,
                           strings=({"var": "$a"},))


def test_evidence_bucket_rejects_a_non_dataclass_item():
    with pytest.raises(TypeError):
        YaraEvidence(matches=(object(),))


def test_evidence_rejects_a_true_identity_duplicate():
    """The exact same `(rule, namespace, file, seg_va)` identity cannot
    legitimately appear twice (see `YaraEvidence`'s own docstring) --
    scanner.py's loop structure never produces one, so seeing one at all
    means the evidence was poisoned some other way."""
    with pytest.raises(ValueError, match="cannot legitimately appear twice"):
        YaraEvidence(matches=(_match(rule="R", seg_va=0x1000), _match(rule="R", seg_va=0x1000)))


def test_evidence_keeps_same_rule_same_seg_va_from_different_files():
    """The regression this migration's first pass introduced: two
    different rule FILES defining a same-named rule, both matching the
    SAME region, must both survive as distinct evidence -- not collapse
    to one entry. This is exactly what a naive `(rule, seg_va)` dedup
    would (incorrectly) reject as a duplicate."""
    a = _match(rule="HitRule", seg_va=0x1000, file="a.yar")
    b = _match(rule="HitRule", seg_va=0x1000, file="b.yar")
    evidence = YaraEvidence(matches=(a, b))
    assert len(evidence.matches) == 2
    assert {m.file for m in evidence.matches} == {"a.yar", "b.yar"}


def test_evidence_keeps_same_rule_same_seg_va_from_different_namespaces():
    a = _match(rule="HitRule", seg_va=0x1000, namespace="ns1")
    b = _match(rule="HitRule", seg_va=0x1000, namespace="ns2")
    evidence = YaraEvidence(matches=(a, b))
    assert len(evidence.matches) == 2


def test_report_rejects_a_match_poisoned_before_construction():
    """A `RuleMatchEvidence` that validated cleanly at ITS OWN construction
    can still be poisoned afterward via `object.__setattr__` (the
    documented escape hatch) -- only `YaraReport.__post_init__`'s own
    final whole-graph `require_recursively_immutable` sweep catches it."""
    match = _match()
    evidence = YaraEvidence(matches=(match,))
    object.__setattr__(match, "tags", ["suspicious"])   # tuple -> live list
    coverage = CoverageSnapshot(rules=_ready_rules(), scan=ScanDiagnostics(segment_count=1))
    with pytest.raises(TypeError):
        YaraReport(coverage=coverage, evidence=evidence)


def test_report_rejects_matches_without_an_actual_scan():
    evidence = YaraEvidence(matches=(_match(),))
    with pytest.raises(ValueError, match="cannot exist without an actual scan"):
        YaraReport(coverage=CoverageSnapshot(), evidence=evidence)


def test_rules_diagnostics_rejects_attempted_without_rules_dir():
    with pytest.raises(ValueError, match="rules_dir is None"):
        RulesDiagnostics(yara_available=True, rules_dir=None, attempted=True, compiled_ok=1)


def test_rules_diagnostics_rejects_counts_without_attempted():
    with pytest.raises(ValueError, match="counts require an actual attempt"):
        RulesDiagnostics(yara_available=True, rules_dir="/x", attempted=False, compiled_ok=1)


def test_coverage_snapshot_rejects_scanned_segments_without_ready_rules():
    with pytest.raises(ValueError, match="rules is not ready"):
        CoverageSnapshot(rules=RulesDiagnostics(), scan=ScanDiagnostics(segment_count=1))


# ── Score/status/verdict derivation ─────────────────────────────────────

def test_score_is_distinct_triggered_rule_count():
    report = _detected_report(n_matches=1)
    assert report.score == 1
    assert report.triggered_rules == ("HitRule",)
    assert report.status == "DETECTED"


def test_unverified_only_hit_is_inconclusive_not_detected():
    coverage = CoverageSnapshot(rules=_ready_rules(), scan=ScanDiagnostics(segment_count=1))
    evidence = YaraEvidence(matches=(_match(context_unverified=True),))
    report = YaraReport(coverage=coverage, evidence=evidence)
    assert report.score == 0
    assert report.triggered_rules == ()
    assert report.unverified_rules == ("HitRule",)
    assert report.status == "INCONCLUSIVE"
    assert report.coverage_status == "partial"


def test_not_evaluated_report_has_zero_score_and_no_hits():
    report = YaraReport()
    assert report.score == 0
    assert report.has_hits is False
    assert report.status == "NOT_EVALUATED"
    assert report.coverage_status == "not_evaluated"
    assert report.verdict_level == "not_evaluated"


def test_high_verdict_at_three_distinct_rules():
    matches = tuple(_match(rule=f"Rule{i}", seg_va=0x1000 * (i + 1)) for i in range(3))
    coverage = CoverageSnapshot(rules=_ready_rules(), scan=ScanDiagnostics(segment_count=1))
    report = YaraReport(coverage=coverage, evidence=YaraEvidence(matches=matches))
    assert report.score == 3
    assert report.verdict_level == "high"


# ── Projectors are pure and order-independent ───────────────────────────

def test_projectors_do_not_mutate_the_report_or_disagree_with_each_other():
    report = _detected_report(n_matches=2)
    before = repr(report)

    legacy_a = project_legacy_dict(report)
    record_a = project_hunter_record(report)
    console_a = render_console_lines(report, verbose=True)

    console_b = render_console_lines(report, verbose=True)
    record_b = project_hunter_record(report)
    legacy_b = project_legacy_dict(report)

    assert repr(report) == before
    assert legacy_a == legacy_b
    assert record_a.to_dict() == record_b.to_dict()
    assert console_a == console_b
    assert legacy_a["score"] == record_a.score == report.score


@pytest.mark.parametrize("width", [80, 100, 120])
def test_console_renders_at_every_supported_width_without_crashing(width):
    report = _detected_report(n_matches=1)
    for verbose in (False, True):
        lines = render_console_lines(report, verbose=verbose, width=width)
        assert lines
        assert all(isinstance(line, str) for line in lines)


def test_hunter_record_findings_and_score_fields_stay_null_for_yara():
    record = project_hunter_record(_detected_report())
    assert record.findings == []
    assert record.max_score is None
    assert record.confidence is None
    assert record.lead_count is None
    assert record.review_priority is None


def test_legacy_dict_omits_coverage_key_when_not_evaluated():
    doc = project_legacy_dict(YaraReport())
    assert "coverage" not in doc
    assert "scan_complete" not in doc
    assert "rules_hit" not in doc
    assert doc["matches"] == []


# ── String-evidence truncation is visible (P1 review fix) ────────────────

def test_strings_truncated_is_derived_correctly():
    m = _match(strings=(_string(),), string_count=1)
    assert m.strings_truncated is False
    m = _match(strings=(_string(),), string_count=5)
    assert m.strings_truncated is True


def test_rule_match_evidence_rejects_string_count_below_kept_strings():
    with pytest.raises(ValueError, match="cannot be less than"):
        RuleMatchEvidence(rule="R", file="r.yar", seg_va=1, seg_fo=1, seg_size=1,
                           strings=(_string(), _string(var="$b")), string_count=1)


def test_verbose_console_shows_truncated_string_count():
    from dumpex.hunt.yara_hunt.report_console import render_console_lines
    m = _match(strings=(_string(),), string_count=7)
    coverage = CoverageSnapshot(rules=_ready_rules(), scan=ScanDiagnostics(segment_count=1))
    report = YaraReport(coverage=coverage, evidence=YaraEvidence(matches=(m,)))
    lines = render_console_lines(report, verbose=True)
    joined = "\n".join(lines)
    assert "6 more string instance(s) not shown" in joined
    assert "7 total" in joined


# `namespace`/`string_count`/`strings_truncated` are real facts on the
# frozen domain model (used by report_console.py's own verbose rendering,
# see above) but must NOT leak into the public JSON shape -- issue #11's
# own Compatibility section freezes "current YaraDetails shape" and "No
# public schema change occurs unless separately planned against the
# then-current schema" (P1 review fix: an earlier pass added them to
# match_dict() as a side effect of the truncation-visibility fix above,
# which is exactly the kind of unplanned shape change that promise
# forbids). This is an exact key-set test, not a subset check, so a
# future key added to `models.RuleMatchEvidence` must be a deliberate
# choice about match_dict() too, not an accidental leak.

_LEGACY_MATCH_KEYS = frozenset({
    "rule", "file", "tags", "meta", "seg_va", "seg_fo", "seg_size", "strings",
    "context_unverified", "memory_context",
})
_STRING_KEYS = frozenset({"var", "offset", "va", "fo", "data"})


def test_match_dict_key_set_is_unchanged_by_the_migration():
    m = _match(strings=(_string(),), string_count=7, namespace="ns1", backing_module="legit.dll")
    coverage = CoverageSnapshot(rules=_ready_rules(), scan=ScanDiagnostics(segment_count=1))
    report = YaraReport(coverage=coverage, evidence=YaraEvidence(matches=(m,)))

    legacy_match = project_legacy_dict(report)["matches"][0]
    assert set(legacy_match.keys()) == _LEGACY_MATCH_KEYS
    assert set(legacy_match["strings"][0].keys()) == _STRING_KEYS

    record_match = project_hunter_record(report).details.matches[0]
    assert set(record_match.keys()) == _LEGACY_MATCH_KEYS
    assert set(record_match["strings"][0].keys()) == _STRING_KEYS

    # The domain model itself still carries the facts -- only the public
    # projection omits them.
    assert m.namespace == "ns1"
    assert m.string_count == 7
    assert m.strings_truncated is True


# ── WHY THIS VERDICT reflects real context, never a blanket claim ────────
# (P1 review fix -- it used to always claim "could not be attributed to a
# known, legitimately loaded module" even when backing_module was set)

def test_why_this_verdict_does_not_fabricate_module_attribution_claim():
    from dumpex.hunt.yara_hunt.report_console import render_console_lines
    m = _match(backing_module="legit.dll")
    coverage = CoverageSnapshot(rules=_ready_rules(), scan=ScanDiagnostics(segment_count=1))
    report = YaraReport(coverage=coverage, evidence=YaraEvidence(matches=(m,)))
    lines = render_console_lines(report, verbose=False)
    joined = "\n".join(lines)
    assert "could not be attributed to a known" not in joined
    assert "legit.dll" in joined


def test_why_this_verdict_states_unattributed_when_truly_unbacked():
    from dumpex.hunt.yara_hunt.report_console import render_console_lines
    m = _match(backing_module=None)
    coverage = CoverageSnapshot(rules=_ready_rules(), scan=ScanDiagnostics(segment_count=1))
    report = YaraReport(coverage=coverage, evidence=YaraEvidence(matches=(m,)))
    lines = render_console_lines(report, verbose=False)
    # Normalize word-wrap: a wrapped line may split the phrase this
    # asserts on across a newline+indent boundary.
    why_section = " ".join(" ".join(lines).split("WHY THIS VERDICT", 1)[1].split())
    assert "not a known loaded module" in why_section or "could not be resolved" in why_section


# ── models.py validator branches (restores this file's own coverage gate ──
# to its pre-migration 95% threshold -- see .github/workflows/tests.yml) ──

@pytest.mark.parametrize("factory, kwargs, exc, match", [
    pytest.param(StringEvidence, dict(var="$a", offset=0, va=1, fo=1, data=b"x"),
                 None, None, id="string-evidence-ok"),
    pytest.param(RuleFileDiagnostic, dict(name=1, sha256=None, compiled=True, error=None),
                 TypeError, "must be a str", id="rulefile-non-str-name"),
    pytest.param(RuleFileDiagnostic, dict(name="a.yar", sha256=None, compiled="yes", error=None),
                 TypeError, "must be a bool", id="rulefile-non-bool-compiled"),
    pytest.param(RuleFileDiagnostic, dict(name="a.yar", sha256=None, compiled=True, error="x"),
                 ValueError, "must be None when compiled is True", id="rulefile-error-set-when-ok"),
    pytest.param(RuleFileDiagnostic, dict(name="a.yar", sha256=None, compiled=False, error=None),
                 ValueError, "must be set when compiled is False", id="rulefile-error-missing-when-failed"),
    pytest.param(RulesProvenance,
                 dict(rules_dir="/x", files=(object(),), aggregate_sha256="a", compiled_ok=0,
                      compile_failed=1),
                 TypeError, "must be a RuleFileDiagnostic", id="provenance-non-diagnostic-file"),
    pytest.param(RulesProvenance,
                 dict(rules_dir="/x",
                      files=(RuleFileDiagnostic(name="b.yar", sha256=None, compiled=True, error=None),
                             RuleFileDiagnostic(name="a.yar", sha256=None, compiled=True, error=None)),
                      aggregate_sha256="a", compiled_ok=2, compile_failed=0),
                 ValueError, "must be sorted by name", id="provenance-unsorted-files"),
    pytest.param(RulesProvenance,
                 dict(rules_dir="/x", files=(), aggregate_sha256="a", compiled_ok=1, compile_failed=0),
                 ValueError, "must equal the number of", id="provenance-compiled-ok-mismatch"),
    pytest.param(RulesProvenance,
                 dict(rules_dir="/x", files=(), aggregate_sha256="a", compiled_ok=0, compile_failed=1),
                 ValueError, "must equal the number", id="provenance-compile-failed-mismatch"),
])
def test_models_field_validators_reject_bad_values(factory, kwargs, exc, match):
    if exc is None:
        factory(**kwargs)   # the "ok" control case -- must NOT raise
        return
    with pytest.raises(exc, match=match):
        factory(**kwargs)


def test_require_bool_rejects_non_bool():
    with pytest.raises(TypeError, match="must be a bool"):
        RuleMatchEvidence(rule="R", file="r.yar", seg_va=1, seg_fo=1, seg_size=1,
                           context_unverified="yes")


def test_require_int_rejects_non_int():
    with pytest.raises(TypeError, match="must be an int"):
        RuleMatchEvidence(rule="R", file="r.yar", seg_va="not-an-int", seg_fo=1, seg_size=1)


def test_require_nonneg_int_rejects_negative():
    with pytest.raises(ValueError, match="must be >= 0"):
        RuleMatchEvidence(rule="R", file="r.yar", seg_va=-1, seg_fo=1, seg_size=1)


def test_require_str_rejects_non_str():
    with pytest.raises(TypeError, match="must be a str"):
        RuleMatchEvidence(rule=123, file="r.yar", seg_va=1, seg_fo=1, seg_size=1)


def test_require_bytes_rejects_non_bytes():
    with pytest.raises(TypeError, match="must be bytes"):
        StringEvidence(var="$a", offset=0, va=1, fo=1, data="not-bytes")


@pytest.mark.parametrize("meta, exc, match", [
    pytest.param((("a", "b", "c"),), TypeError, "must be a .key, value. pair", id="meta-not-a-pair"),
    pytest.param(((1, "b"),), TypeError, "must be a str", id="meta-non-str-key"),
    pytest.param((("a", object()),), TypeError, "must be a str, int, or bool", id="meta-bad-value-type"),
    pytest.param((("b", 1), ("a", 2)), ValueError, "must be sorted by key", id="meta-unsorted"),
])
def test_meta_items_validator_rejects_bad_values(meta, exc, match):
    with pytest.raises(exc, match=match):
        RuleMatchEvidence(rule="R", file="r.yar", seg_va=1, seg_fo=1, seg_size=1, meta=meta)

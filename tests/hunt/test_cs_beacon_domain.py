"""Architecture/contract tests for the CS Beacon hunter's immutable domain
model (dumpex/hunt/cs_beacon/domain.py, models.py) and its projectors
(report_facts.py/report_legacy.py/report_record.py/report_console.py).
Mirrors tests/hunt/test_hollowing_domain.py/test_hollowing_projectors.py
(the completed reference pilots' own test suites): proves recursive
immutability, constructor-input-mutation isolation, poison-object
rejection, the evidence-citation invariant, and that every projector is a
pure, order-independent function of an already-built Report.
"""
import dataclasses

import pytest

from tests.fixtures.fakes import Region, Segment, FakeMF, FakeReader, FakeStream, \
    cs_beacon_config_bytes

import dumpex.hunt.cs_beacon as cs_beacon
from dumpex.hunt._domain import CheckResult
from dumpex.hunt._finding import CONFIDENCE_HIGH, TAG_DETECTION
from dumpex.hunt.cs_beacon.domain import (
    CoverageSnapshot, CSBeaconEvidence, CSBeaconReport, ScanDiagnostics,
)
from dumpex.hunt.cs_beacon.models import (
    ConfigEvidence, ConfigField, CorroborationEvidence, RegionRef, region_ref,
)
from dumpex.hunt.cs_beacon.report_console import render_console_lines
from dumpex.hunt.cs_beacon.report_legacy import project_legacy_dict
from dumpex.hunt.cs_beacon.report_record import project_hunter_record


def _hit(field_id=0x0001, hit_va=0x1000) -> ConfigEvidence:
    return ConfigEvidence(
        xor_key=0x69, hit_va=hit_va, hit_fo=hit_va, cs_version="3.x",
        fields=(ConfigField(field_id=field_id, name="BeaconType", type=1, value=0, raw=b"\x00\x00"),))


def _detected_report(n_hits=1, corroborated=False) -> CSBeaconReport:
    hits = tuple(_hit(hit_va=0x1000 * (i + 1)) for i in range(n_hits))
    corroborations = tuple(CorroborationEvidence(hit=h, reasons=("test reason",))
                            for h in hits) if corroborated else ()
    results = [
        CheckResult(check="cs_beacon.structural_config",
                    evidence=(h,) if not corroborated else (h, corroborations[i]),
                    inference="Structurally-valid Cobalt Strike beacon configuration found.",
                    confidence=CONFIDENCE_HIGH if corroborated else "medium",
                    rationale="test rationale", tag=TAG_DETECTION)
        for i, h in enumerate(hits)
    ]
    evidence = CSBeaconEvidence(hits=hits, corroborations=corroborations)
    return CSBeaconReport(
        score=2 if corroborated else 1,
        coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=1),
                                   mem_info_available=True,
                                   thread_list_stream_available=True,
                                   threads_total=1, contexts_parsed=1),
        results=tuple(results), evidence=evidence)


# ── Frozen / recursively immutable ──────────────────────────────────────

@pytest.mark.parametrize("report_type", [CSBeaconReport, CoverageSnapshot, ScanDiagnostics,
                                          CSBeaconEvidence, ConfigEvidence, ConfigField,
                                          CorroborationEvidence])
def test_domain_types_are_frozen_dataclasses(report_type):
    assert dataclasses.is_dataclass(report_type)
    assert report_type.__dataclass_params__.frozen is True


def test_report_top_level_attributes_reject_reassignment():
    report = _detected_report()
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.score = 99


def test_evidence_container_rejects_reassignment():
    report = _detected_report()
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.evidence.hits = ()


# ── Constructor-input mutation isolation ────────────────────────────────

def test_constructor_input_list_mutation_does_not_reach_the_report():
    hit = _hit()
    hits_list = [hit]
    evidence = CSBeaconEvidence(hits=hits_list)
    hits_list.append(_hit(hit_va=0x2000))
    assert len(evidence.hits) == 1


def test_config_field_tuple_mutation_does_not_reach_the_hit():
    fields_list = [ConfigField(field_id=1, name="BeaconType", type=1, value=0, raw=b"")]
    hit = ConfigEvidence(xor_key=0x69, hit_va=1, hit_fo=1, cs_version="3.x", fields=fields_list)
    fields_list.append(ConfigField(field_id=7, name="PublicKey", type=3, value="x", raw=b"x"))
    assert len(hit.fields) == 1


# ── Poison-object / mutable-payload rejection ───────────────────────────

def test_config_field_rejects_mutable_raw():
    with pytest.raises(TypeError):
        ConfigField(field_id=1, name="BeaconType", type=1, value=0, raw=bytearray(b"\x00"))


def test_config_evidence_rejects_a_raw_dict_field():
    with pytest.raises(TypeError):
        ConfigEvidence(xor_key=0x69, hit_va=1, hit_fo=1, cs_version="3.x",
                        fields=({"field_id": 1, "name": "BeaconType", "type": 1, "value": 0},))


def test_evidence_bucket_rejects_a_non_dataclass_item():
    with pytest.raises(TypeError):
        CSBeaconEvidence(hits=(object(),))


def test_corroboration_evidence_requires_at_least_one_reason():
    with pytest.raises(ValueError):
        CorroborationEvidence(hit=_hit(), reasons=())


# ── Field validators (models.py's own two-layer defense: exact TYPE check
# + require_recursively_immutable) ──────────────────────────────────────

@pytest.mark.parametrize("factory, kwargs, exc", [
    pytest.param(RegionRef, dict(base_address=True, allocation_base=None, size=0,
                                  state="MEM_COMMIT", protect="PAGE_READWRITE", type="MEM_PRIVATE"),
                 TypeError, id="region-bool-base-address"),
    pytest.param(RegionRef, dict(base_address=0, allocation_base=None, size=-1,
                                  state="MEM_COMMIT", protect="PAGE_READWRITE", type="MEM_PRIVATE"),
                 ValueError, id="region-negative-size"),
    pytest.param(RegionRef, dict(base_address=0, allocation_base=None, size=0,
                                  state=123, protect="PAGE_READWRITE", type="MEM_PRIVATE"),
                 TypeError, id="region-non-str-state"),
    pytest.param(ConfigField, dict(field_id=1, name="BeaconType", type=99, value=0, raw=b""),
                 ValueError, id="config-field-unknown-type"),
    pytest.param(ConfigField, dict(field_id=1, name="BeaconType", type=1, value=True, raw=b""),
                 TypeError, id="config-field-bool-value"),
    pytest.param(CorroborationEvidence, dict(hit=object(), reasons=("x",)),
                 TypeError, id="corroboration-non-config-evidence-hit"),
])
def test_models_field_validators_reject_bad_values(factory, kwargs, exc):
    with pytest.raises(exc):
        factory(**kwargs)


def test_config_evidence_rejects_duplicate_field_ids():
    """parser.py's own duplicate-field-id check should already reject this
    before a `ConfigEvidence` is ever built -- this is the domain model's
    own belt-and-suspenders re-check of that invariant."""
    fields = (
        ConfigField(field_id=1, name="BeaconType", type=1, value=0, raw=b""),
        ConfigField(field_id=1, name="BeaconType", type=1, value=1, raw=b""),
    )
    with pytest.raises(ValueError, match="duplicates field_id"):
        ConfigEvidence(xor_key=0x69, hit_va=1, hit_fo=1, cs_version="3.x", fields=fields)


def test_region_ref_of_an_uncovered_hit_is_none():
    """The hit VA is not covered by MemoryInfoListStream at all -- `region`
    is `None`, not a poisoned/placeholder `RegionRef`."""
    assert region_ref(None) is None


def test_region_ref_allows_a_missing_allocation_base():
    ref = RegionRef(base_address=0x1000, allocation_base=None, size=0x1000,
                     state="MEM_COMMIT", protect="PAGE_READWRITE", type="MEM_PRIVATE")
    assert ref.allocation_base is None


def test_report_rejects_a_hit_poisoned_before_construction():
    """A `ConfigEvidence` that validated cleanly at ITS OWN construction
    can still be poisoned two levels down afterward, via
    `object.__setattr__` (the documented, unavoidable escape hatch
    `require_recursively_immutable`'s own docstring names), and then
    reach `CSBeaconReport()` inside an otherwise perfectly well-formed
    `evidence`/`results` pair -- every existing identity/pairing/type
    check above still passes (the poisoned hit is still the SAME object
    every one of them compares against), so only a check that re-walks
    the WHOLE attached graph can catch it. `CSBeaconReport.__post_init__`'s
    own final `require_recursively_immutable(self, ...)` sweep does."""
    hit = _hit()
    # Both `result` and `evidence` are built while `hit` is still clean --
    # CheckResult.__post_init__'s own `require_recursively_immutable` check
    # (and CSBeaconEvidence's) pass here, exactly as they would for a
    # legitimate Report.
    result = CheckResult(check="cs_beacon.structural_config", evidence=(hit,),
                          inference="x", confidence="medium", rationale="x", tag=TAG_DETECTION)
    evidence = CSBeaconEvidence(hits=(hit,))
    # Poisoned AFTER both already reference it, in place -- the same `hit`
    # object both `result.evidence[0]` and `evidence.hits[0]` still point
    # at, unchanged by identity.
    object.__setattr__(hit, "fields", [hit.fields[0]])   # tuple -> live list
    with pytest.raises(TypeError):
        CSBeaconReport(score=1, coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=1)),
                       results=(result,), evidence=evidence)


# ── Evidence-citation invariant ─────────────────────────────────────────

def test_report_rejects_a_result_citing_foreign_evidence():
    hit = _hit()
    foreign_hit = _hit(hit_va=0x9999)   # never added to this Report's own evidence
    result = CheckResult(check="cs_beacon.structural_config", evidence=(foreign_hit,),
                          inference="x", confidence="medium", rationale="x", tag=TAG_DETECTION)
    with pytest.raises(ValueError, match="not one of this Report's own evidence"):
        CSBeaconReport(score=1, coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=1)),
                       results=(result,), evidence=CSBeaconEvidence(hits=(hit,)))


def test_report_rejects_hit_count_result_count_mismatch():
    """The structural replacement for the pre-migration console-layer
    `zip(hit_records, structural_config_findings, strict=True)` runtime
    check (dumpex/hunt/cs_beacon/presentation.py, now deleted): a Report
    with two hits but only one `cs_beacon.structural_config` result must
    be rejected at CONSTRUCTION time, not silently under- or over-render
    in the console."""
    hit1, hit2 = _hit(hit_va=0x1000), _hit(hit_va=0x2000)
    result = CheckResult(check="cs_beacon.structural_config", evidence=(hit1,),
                          inference="x", confidence="medium", rationale="x", tag=TAG_DETECTION)
    with pytest.raises(ValueError, match="cs_beacon.structural_config result"):
        CSBeaconReport(score=1, coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=1)),
                       results=(result,), evidence=CSBeaconEvidence(hits=(hit1, hit2)))


def test_report_rejects_a_result_citing_the_wrong_hit_out_of_order():
    """Same count, but position 0's result cites `hits[1]` instead of
    `hits[0]` -- a silent reordering that would pair the WRONG config with
    the WRONG Finding in the console/typed record."""
    hit1, hit2 = _hit(hit_va=0x1000), _hit(hit_va=0x2000)
    result_for_hit2 = CheckResult(check="cs_beacon.structural_config", evidence=(hit2,),
                                   inference="x", confidence="medium", rationale="x",
                                   tag=TAG_DETECTION)
    result_for_hit1 = CheckResult(check="cs_beacon.structural_config", evidence=(hit1,),
                                   inference="x", confidence="medium", rationale="x",
                                   tag=TAG_DETECTION)
    with pytest.raises(ValueError, match="does not cite evidence.hits"):
        CSBeaconReport(score=1, coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=1)),
                       results=(result_for_hit2, result_for_hit1),
                       evidence=CSBeaconEvidence(hits=(hit1, hit2)))


def test_report_rejects_nonzero_score_with_no_hits():
    with pytest.raises(ValueError):
        CSBeaconReport(score=1, coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=1)))


def test_report_rejects_corroboration_without_max_score():
    hit = _hit()
    corroboration = CorroborationEvidence(hit=hit, reasons=("x",))
    result = CheckResult(check="cs_beacon.structural_config", evidence=(hit, corroboration),
                          inference="x", confidence="high", rationale="x", tag=TAG_DETECTION)
    with pytest.raises(ValueError, match="must be 2"):
        CSBeaconReport(score=1, coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=1)),
                       results=(result,),
                       evidence=CSBeaconEvidence(hits=(hit,), corroborations=(corroboration,)))


# ── Projectors are pure and order-independent ───────────────────────────

def test_projectors_do_not_mutate_the_report_or_disagree_with_each_other():
    report = _detected_report(n_hits=2, corroborated=True)
    before = repr(report)

    legacy_a = project_legacy_dict(report)
    record_a = project_hunter_record(report)
    console_a = render_console_lines(report, verbose=True)

    # Order reversed -- every projector must be a pure function of `report`
    # alone, so calling them in the opposite order must not change any of
    # their own results either.
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
    report = _detected_report(n_hits=1, corroborated=True)
    for verbose in (False, True):
        lines = render_console_lines(report, verbose=verbose, width=width)
        assert lines
        assert all(isinstance(line, str) for line in lines)


def test_coverage_reasons_render_exactly_once():
    """The COVERAGE section must not repeat a reason it already stated --
    each gap is one fact, rendered once (issue #9's own console scope)."""
    hit = _hit()
    result = CheckResult(check="cs_beacon.structural_config", evidence=(hit,),
                          inference="x", confidence="medium", rationale="x", tag=TAG_DETECTION)
    report = CSBeaconReport(
        score=1,
        coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=1),
                                   mem_info_available=True,
                                   thread_list_stream_available=False),
        results=(result,), evidence=CSBeaconEvidence(hits=(hit,)))
    lines = render_console_lines(report, verbose=False)
    coverage_index = next(i for i, l in enumerate(lines) if "COVERAGE" in l)
    coverage_lines = lines[coverage_index:]
    joined = "\n".join(coverage_lines)
    for reason in ("ThreadListStream",):
        assert joined.count(reason) <= 1


def test_verbose_key_signals_do_not_repeat_the_coverage_gap_per_hit():
    """Two uncorroborated hits, no ThreadListStream at all -- each hit's
    own `CheckResult.limitation` restates the SAME gap COVERAGE already
    states once. --json/the typed record must keep that limitation text
    (current-contract freeze: it was there pre-migration too), but
    --verbose console rendering must show it exactly once, in COVERAGE,
    not once per hit as well (issue #9: "Render coverage reasons/impacts
    exactly once")."""
    seg1_va, seg1_fo = 0x50000, 0x5000
    seg2_va, seg2_fo = 0x60000, 0x6000
    config1 = cs_beacon_config_bytes(0x69)
    config2 = cs_beacon_config_bytes(0x2e)
    pad = b"\x00" * 0x100
    data1 = pad + config1 + pad
    data2 = pad + config2 + pad
    seg1 = Segment(seg1_va, seg1_fo, len(data1))
    seg2 = Segment(seg2_va, seg2_fo, len(data2))
    regions = [
        Region(seg1_va, seg1_va, len(data1), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(seg2_va, seg2_va, len(data2), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg1, seg2], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg1_va: data1, seg2_va: data2})

    report = cs_beacon._build_cs_beacon_report(MF())
    assert len(report.evidence.hits) == 2
    assert report.any_corroborated is False

    # The wire-contract limitation text is untouched -- still on every
    # result, for --json/the typed record.
    for result in report.results:
        assert any("ThreadListStream missing from this dump" in l for l in result.limitations)

    lines = render_console_lines(report, verbose=True)
    joined = "\n".join(lines)
    coverage_index = next(i for i, l in enumerate(lines) if "COVERAGE" in l)
    before_coverage = "\n".join(lines[:coverage_index])
    coverage_section = "\n".join(lines[coverage_index:])
    assert "ThreadListStream missing from this dump" not in before_coverage
    assert joined.count("ThreadListStream missing from this dump") == 1
    assert "ThreadListStream missing from this dump" in coverage_section


@pytest.mark.parametrize("verbose", [False, True])
def test_beacon_configs_section_truncates_with_an_explicit_count(verbose):
    from dumpex.hunt.cs_beacon.report_console import MAX_DISPLAYED_CONFIGS
    report = _detected_report(n_hits=MAX_DISPLAYED_CONFIGS + 3, corroborated=False)
    lines = render_console_lines(report, verbose=verbose)
    joined = "\n".join(lines)
    assert "Beacon config #1" in joined
    assert f"Beacon config #{MAX_DISPLAYED_CONFIGS}" in joined
    # The cap applies in BOTH modes -- --verbose only expands the DETAIL
    # shown for each already-displayed config, never how many are shown.
    assert f"Beacon config #{MAX_DISPLAYED_CONFIGS + 1}" not in joined
    assert "... and 3 more config(s)" in joined
    assert "see --json for the full list" in joined
    # Must not promise --verbose shows the rest -- it doesn't (see the
    # assertion above).
    assert "--verbose" not in joined.split("more config(s)", 1)[1].split("\n", 1)[0]
    # Truncation is console-only -- every hit still reaches --json/the
    # typed record.
    assert project_hunter_record(report).details.config_count == MAX_DISPLAYED_CONFIGS + 3
    assert project_legacy_dict(report)["config_count"] == MAX_DISPLAYED_CONFIGS + 3


# ── End-to-end: the real scan/aggregate pipeline builds a Report whose ───
# corroborated hits sort first for display (issue #9's own console scope),
# without touching `report.results`/`evidence.hits` construction order.

def test_corroborated_config_sorts_first_for_display_only():
    seg1_va, seg1_fo = 0x50000, 0x5000
    seg2_va, seg2_fo = 0x60000, 0x6000
    config1 = cs_beacon_config_bytes(0x69)
    config2 = cs_beacon_config_bytes(0x2e)
    pad = b"\x00" * 0x100
    data1 = pad + config1 + pad
    data2 = pad + config2 + pad
    seg1 = Segment(seg1_va, seg1_fo, len(data1))
    seg2 = Segment(seg2_va, seg2_fo, len(data2))
    # seg1 (constructed FIRST) is the ordinary, uncorroborated region;
    # seg2 (constructed SECOND) is executable+private -- the OPPOSITE of
    # display order, so a passing test proves the sort is real.
    regions = [
        Region(seg1_va, seg1_va, len(data1), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(seg2_va, seg2_va, len(data2), "MEM_COMMIT",
               "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
    ]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg1, seg2], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg1_va: data1, seg2_va: data2})

    report = cs_beacon._build_cs_beacon_report(MF())
    # Construction order (report.results / evidence.hits) is untouched:
    # seg1's hit comes first, exactly as scanned.
    assert report.evidence.hits[0].hit_va < report.evidence.hits[1].hit_va
    assert report.evidence.corroboration_for(report.evidence.hits[0]) is None
    assert report.evidence.corroboration_for(report.evidence.hits[1]) is not None

    lines = render_console_lines(report, verbose=False)
    joined = "\n".join(lines)
    key_signals = joined.split("KEY SIGNALS", 1)[1].split("WHY THIS VERDICT", 1)[0]
    # The corroborated config (seg2, scanned SECOND) must be the FIRST
    # KEY SIGNAL entry shown.
    first_va_pos = key_signals.find(f"0x{report.evidence.hits[1].hit_va:x}")
    second_va_pos = key_signals.find(f"0x{report.evidence.hits[0].hit_va:x}")
    assert first_va_pos != -1 and second_va_pos != -1
    assert first_va_pos < second_va_pos

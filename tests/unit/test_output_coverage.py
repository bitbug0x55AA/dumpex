"""
Table-driven tests for dumpex.output.coverage -- the first-class
coverage/provenance core extracted from the ad hoc bool(mf.X)-check
pattern every recon command used to hand-roll independently. Validated
directly here against every coverage rule already hand-built for list/
modules/threads/sysinfo/pid this session (see build_coverage_report's
own docstring), including scenarios (multi-source key mismatch,
SOURCE_FAILED, evaluation_sources != completeness_required_sources) that
no currently-migrated command exercises yet -- this is deliberately
testing the model's generality ahead of the threads/comparison migration
that will need it, not just what list/modules use today.

A second theme covers the review fix that motivated this file's rework:
build_coverage_report() must derive required-source limitations itself
from `sources`, not trust a caller-supplied limitations list -- so every
required-source test below passes NO limitation at all and asserts the
reducer still produces one.
"""
import pytest

from dumpex.output.coverage import (
    SourceObservation, observe_source, CoverageLimitation, render_limitation,
    CoverageReport, build_coverage_report, exit_code_for,
    SourceState, CoverageStatus, LimitationCode,
    SOURCE_ABSENT, SOURCE_PRESENT_EMPTY, SOURCE_PRESENT, SOURCE_FAILED,
    LIMITATION_SOURCE_ABSENT, LIMITATION_SOURCE_FAILED, LIMITATION_SOURCE_KEY_MISMATCH,
    COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_NOT_EVALUATED,
    EXIT_OK, EXIT_PARTIAL, EXIT_NOT_EVALUATED,
)


# ── observe_source ─────────────────────────────────────────────────────

def test_observe_source_absent():
    obs = observe_source("modules", present=False)
    assert obs.state == SOURCE_ABSENT
    assert obs.record_count is None


def test_observe_source_present_empty():
    obs = observe_source("modules", present=True, items=[])
    assert obs.state == SOURCE_PRESENT_EMPTY
    assert obs.record_count == 0


def test_observe_source_present_with_items():
    obs = observe_source("modules", present=True, items=[1, 2, 3])
    assert obs.state == SOURCE_PRESENT
    assert obs.record_count == 3


def test_observe_source_present_true_items_none_defaults_to_empty():
    obs = observe_source("modules", present=True)   # items omitted
    assert obs.state == SOURCE_PRESENT_EMPTY
    assert obs.record_count == 0


# ── enum/string interop: existing call sites compare against bare strings ─

def test_source_state_enum_members_equal_plain_strings():
    assert SOURCE_ABSENT == "absent"
    assert SOURCE_PRESENT_EMPTY == "present_empty"
    assert SOURCE_PRESENT == "present"
    assert SOURCE_FAILED == "failed"


def test_coverage_status_enum_members_equal_plain_strings():
    assert COVERAGE_COMPLETE == "complete"
    assert COVERAGE_PARTIAL == "partial"
    assert COVERAGE_NOT_EVALUATED == "not_evaluated"


# ── SourceObservation: state/record_count invariant validation ──────────

@pytest.mark.parametrize("state,record_count", [
    (SourceState.ABSENT, 0),          # ABSENT must be None, not 0
    (SourceState.ABSENT, 5),
    (SourceState.FAILED, 0),          # FAILED must be None, not 0
    (SourceState.PRESENT_EMPTY, 1),   # PRESENT_EMPTY must be exactly 0
    (SourceState.PRESENT_EMPTY, None),
    (SourceState.PRESENT, 0),         # PRESENT must be > 0
    (SourceState.PRESENT, None),
])
def test_source_observation_rejects_state_record_count_mismatch(state, record_count):
    with pytest.raises(ValueError):
        SourceObservation(name="modules", state=state, record_count=record_count)


def test_source_observation_rejects_invalid_state():
    with pytest.raises(ValueError):
        SourceObservation(name="modules", state="totally_bogus_state")


def test_source_observation_accepts_bare_string_state():
    # Existing call sites (observe_source, this module's own aliases)
    # pass/compare bare strings, not SourceState members -- must keep working.
    obs = SourceObservation(name="modules", state="absent")
    assert obs.state == SourceState.ABSENT


def test_source_observation_is_frozen():
    obs = SourceObservation(name="modules", state=SourceState.ABSENT)
    with pytest.raises(Exception):
        obs.name = "other"


# ── CoverageLimitation: code is a closed vocabulary, source stays open ──

def test_coverage_limitation_rejects_invalid_code():
    with pytest.raises(ValueError):
        CoverageLimitation(code="SOME_FUTURE_CODE", source="modules")


def test_coverage_limitation_rejects_empty_source():
    with pytest.raises(ValueError):
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="")


def test_coverage_limitation_accepts_list_for_unavailable_fields_and_normalizes_to_tuple():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="modules",
                                     unavailable_fields=["a", "b"])
    assert limitation.unavailable_fields == ("a", "b")


def test_coverage_limitation_is_frozen():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules")
    with pytest.raises(Exception):
        limitation.source = "other"


# ── build_coverage_report: single required source, all 4 states,
# NO caller-supplied limitation -- the reducer must derive it itself ─────

@pytest.mark.parametrize("state,record_count,expected_status", [
    (SOURCE_ABSENT,        None, COVERAGE_NOT_EVALUATED),
    (SOURCE_PRESENT_EMPTY, 0,    COVERAGE_COMPLETE),
    (SOURCE_PRESENT,       3,    COVERAGE_COMPLETE),
    (SOURCE_FAILED,        None, COVERAGE_PARTIAL),
])
def test_single_required_source_state_drives_status_without_manual_limitation(
        state, record_count, expected_status):
    obs = SourceObservation(name="modules", state=state, record_count=record_count)
    report = build_coverage_report(
        {"modules": obs},
        evaluation_sources={"modules"},
        completeness_required_sources={"modules"},
    )
    assert report.status == expected_status


def test_source_failed_required_is_partial_not_not_evaluated_and_reasons_non_empty():
    # The exact P1 reproduction from review: a required source that FAILED
    # must not collapse onto not_evaluated (as-if never there), and must
    # not silently report complete just because no limitation was passed
    # in by hand -- the reducer derives one itself from source.state.
    obs = SourceObservation(name="modules", state=SOURCE_FAILED)
    report = build_coverage_report(
        {"modules": obs},
        evaluation_sources={"modules"},
        completeness_required_sources={"modules"},
    )
    assert report.status == COVERAGE_PARTIAL
    assert report.status != COVERAGE_NOT_EVALUATED
    assert report.reasons == ["ModuleListStream present but could not be read"]


def test_source_failed_required_carries_detail_into_derived_limitation():
    obs = SourceObservation(name="modules", state=SOURCE_FAILED, detail="AttributeError: bad record")
    report = build_coverage_report(
        {"modules": obs},
        evaluation_sources={"modules"},
        completeness_required_sources={"modules"},
    )
    assert report.reasons == [
        "ModuleListStream present but could not be read: AttributeError: bad record"]


# ── build_coverage_report: multiple required sources (threads/pid shape) ─

def test_all_required_sources_absent_is_not_evaluated_without_manual_limitations():
    obs_a = SourceObservation(name="threads", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="thread_info", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"threads": obs_a, "thread_info": obs_b},
        evaluation_sources={"threads", "thread_info"},
        completeness_required_sources={"threads", "thread_info"},
    )
    assert report.status == COVERAGE_NOT_EVALUATED
    assert len(report.reasons) == 2


def test_only_one_of_several_required_sources_absent_is_partial_without_manual_limitation():
    # The other P1 reproduction from review: one of several required
    # sources absent, with no limitation constructed by the caller --
    # must still be partial with a non-empty reason, not complete.
    obs_a = SourceObservation(name="threads", state=SOURCE_PRESENT, record_count=2)
    obs_b = SourceObservation(name="thread_info", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"threads": obs_a, "thread_info": obs_b},
        evaluation_sources={"threads", "thread_info"},
        completeness_required_sources={"threads", "thread_info"},
    )
    assert report.status == COVERAGE_PARTIAL
    assert report.reasons == ["ThreadInfoListStream not present in this dump"]


def test_empty_required_sources_never_forces_not_evaluated():
    # sysinfo's shape: even if every one of its sources is absent, it's
    # never not_evaluated because it always has something else (e.g.
    # dump_file) to report -- modeled by an empty evaluation_sources set.
    sources = {name: SourceObservation(name=name, state=SOURCE_ABSENT)
               for name in ("sysinfo", "misc_info", "peb", "threads", "modules")}
    report = build_coverage_report(
        sources,
        evaluation_sources=set(),
        completeness_required_sources=set(sources),
    )
    assert report.status == COVERAGE_PARTIAL   # never not_evaluated
    assert len(report.reasons) == 5


def test_no_sources_and_no_required_sources_is_complete():
    report = build_coverage_report({})
    assert report.status == COVERAGE_COMPLETE
    assert report.reasons == []


def test_evaluation_sources_and_completeness_required_sources_can_differ():
    # evaluation_sources gates "was there anything to look at" (only
    # matters when ALL listed are absent); completeness_required_sources
    # gates "is what we found the full picture" independently -- a source
    # can be required for completeness without being one of the sources
    # that determines not_evaluated.
    obs_a = SourceObservation(name="a", state=SOURCE_PRESENT, record_count=1)
    obs_b = SourceObservation(name="b", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"a": obs_a, "b": obs_b},
        evaluation_sources={"a"},              # "a" present -> not not_evaluated
        completeness_required_sources={"a", "b"},   # "b" absent -> still partial
    )
    assert report.status == COVERAGE_PARTIAL
    assert report.reasons == ["b not present in this dump"]


# ── multi-source key mismatch (the threads/comparison shape) ────────────

def test_multi_source_key_mismatch_is_partial():
    # Two sources that describe the same entities (e.g. threads.py's
    # ThreadListStream vs ThreadInfoListStream) disagree on which keys
    # exist. Neither source is itself absent/failed -- this is a
    # genuinely different limitation kind, one the reducer cannot infer
    # from source state alone, so it's still caller-supplied via
    # extra_limitations.
    obs_a = SourceObservation(name="source_a", state=SOURCE_PRESENT, record_count=3)
    obs_b = SourceObservation(name="source_b", state=SOURCE_PRESENT, record_count=2)
    limitation = CoverageLimitation(
        code=LIMITATION_SOURCE_KEY_MISMATCH, source="source_b", scope="item",
        affected_count=1, unavailable_fields=["extra_field"])
    report = build_coverage_report(
        {"source_a": obs_a, "source_b": obs_b},
        extra_limitations=[limitation],
    )
    assert report.status == COVERAGE_PARTIAL
    assert report.reasons == ["1 item(s) missing from source_b (extra_field unavailable for those)"]


def test_key_mismatch_with_no_display_name_falls_back_to_raw_source_name():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="source_b",
                                     scope="item", affected_count=2)
    text = render_limitation(limitation)
    assert "source_b" in text
    assert "2 item(s)" in text


# ── render_limitation: must match the exact strings list/modules ship ────

def test_render_limitation_matches_list_cmd_wording():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="memory_info", scope="dump")
    assert render_limitation(limitation) == "MemoryInfoListStream not present in this dump"


def test_render_limitation_matches_modules_wording():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules", scope="dump")
    assert render_limitation(limitation) == "ModuleListStream not present in this dump"


def test_render_limitation_source_failed_without_detail():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_FAILED, source="modules", scope="dump")
    assert render_limitation(limitation) == "ModuleListStream present but could not be read"


def test_render_limitation_source_failed_with_detail():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_FAILED, source="modules",
                                     scope="dump", detail="AttributeError: bad record")
    assert render_limitation(limitation) == (
        "ModuleListStream present but could not be read: AttributeError: bad record")


def test_render_limitation_unknown_source_falls_back_to_raw_name():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="some_future_stream",
                                     scope="dump")
    assert render_limitation(limitation) == "some_future_stream not present in this dump"


def test_coverage_report_reasons_property_renders_every_limitation_in_order():
    report = CoverageReport(status=COVERAGE_PARTIAL, limitations=[
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="memory_info", scope="dump"),
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules", scope="dump"),
    ])
    assert report.reasons == [
        "MemoryInfoListStream not present in this dump",
        "ModuleListStream not present in this dump",
    ]


# ── CoverageReport.status: closed vocabulary, validated + normalized ────

def test_coverage_report_rejects_invalid_status():
    with pytest.raises(ValueError, match="unknown coverage status"):
        CoverageReport(status="bogus")


def test_coverage_report_normalizes_bare_string_status():
    report = CoverageReport(status="complete")
    assert report.status == CoverageStatus.COMPLETE
    assert isinstance(report.status, CoverageStatus)


# ── build_coverage_report: input validation at the boundary ─────────────

def test_build_coverage_report_rejects_source_absent_in_extra_limitations():
    # A caller putting SOURCE_ABSENT into extra_limitations for a source
    # also in completeness_required_sources would duplicate the
    # reducer's own derived limitation -- rejected outright rather than
    # silently producing two copies of the same reason.
    obs = SourceObservation(name="modules", state=SOURCE_ABSENT)
    with pytest.raises(ValueError, match="SOURCE_ABSENT"):
        build_coverage_report(
            {"modules": obs},
            completeness_required_sources={"modules"},
            extra_limitations=[CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules")],
        )


def test_build_coverage_report_rejects_source_failed_in_extra_limitations():
    obs = SourceObservation(name="modules", state=SOURCE_FAILED)
    with pytest.raises(ValueError, match="SOURCE_FAILED"):
        build_coverage_report(
            {"modules": obs},
            completeness_required_sources={"modules"},
            extra_limitations=[CoverageLimitation(code=LIMITATION_SOURCE_FAILED, source="modules")],
        )


def test_build_coverage_report_rejects_source_absent_in_extra_limitations_even_without_policy():
    # The rejection is unconditional -- SOURCE_ABSENT/SOURCE_FAILED are
    # reserved codes in extra_limitations regardless of whether the
    # source happens to also be in completeness_required_sources.
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    with pytest.raises(ValueError, match="SOURCE_ABSENT"):
        build_coverage_report(
            {"modules": obs},
            extra_limitations=[CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules")],
        )


def test_build_coverage_report_rejects_unknown_source_in_evaluation_sources():
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    with pytest.raises(ValueError, match="unknown source"):
        build_coverage_report({"modules": obs}, evaluation_sources={"nonexistent"})


def test_build_coverage_report_rejects_unknown_source_in_completeness_required_sources():
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    with pytest.raises(ValueError, match="unknown source"):
        build_coverage_report({"modules": obs}, completeness_required_sources={"nonexistent"})


def test_build_coverage_report_rejects_sources_key_name_mismatch():
    # sources dict key and SourceObservation.name diverging would let
    # evaluation_sources/completeness_required_sources silently key off
    # the wrong observation.
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    with pytest.raises(ValueError, match="modules"):
        build_coverage_report({"wrong_key": obs}, completeness_required_sources={"wrong_key"})


def test_build_coverage_report_key_mismatch_still_valid_with_no_policy_refs():
    # extra_limitations-only usage (e.g. threads' key-mismatch shape)
    # doesn't reference `sources` by key at all, but the name/key
    # consistency check still runs against every entry in `sources`.
    obs = SourceObservation(name="wrong_name", state=SOURCE_PRESENT, record_count=1)
    with pytest.raises(ValueError, match="wrong_name"):
        build_coverage_report({"source_a": obs})


# ── exit_code_for ────────────────────────────────────────────────────────

@pytest.mark.parametrize("status,expected_code", [
    (COVERAGE_COMPLETE, EXIT_OK),
    (COVERAGE_PARTIAL, EXIT_PARTIAL),
    (COVERAGE_NOT_EVALUATED, EXIT_NOT_EVALUATED),
])
def test_exit_code_for_known_statuses(status, expected_code):
    assert exit_code_for(status) == expected_code


def test_exit_code_for_known_status_as_plain_string():
    # cli.py/collector.py pass CoverageReport.status through, which may
    # arrive as a bare string (e.g. "complete") rather than a CoverageStatus
    # member -- both must resolve identically.
    assert exit_code_for("complete") == EXIT_OK
    assert exit_code_for("partial") == EXIT_PARTIAL
    assert exit_code_for("not_evaluated") == EXIT_NOT_EVALUATED


def test_exit_code_values_are_distinct():
    assert len({EXIT_OK, EXIT_PARTIAL, EXIT_NOT_EVALUATED}) == 3
    assert EXIT_OK == 0


def test_exit_code_for_unknown_status_raises():
    with pytest.raises(ValueError, match="unknown coverage status"):
        exit_code_for("totally_bogus_status")

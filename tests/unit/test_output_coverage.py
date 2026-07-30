"""
Table-driven tests for dumpex.output.coverage -- the first-class
coverage/provenance core extracted from the ad hoc bool(mf.X)-check
pattern every recon command used to hand-roll independently.

Two structural themes drive this file, both from the code review that
motivated this rework:

1. build_coverage_report() must derive required-source limitations
   itself from `sources` via `completeness_checks` (bare source names or
   SourceRequirement), never trust a caller-supplied limitation object
   for SOURCE_ABSENT/SOURCE_FAILED -- so every required-source test below
   passes a plain source name (or SourceRequirement), never a hand-built
   CoverageLimitation, and asserts the reducer still produces one.
2. Every limitation is fully structured -- no free-text escape hatch.
   Tests assert not just the rendered text but limitation.code/source/
   counterpart_source/affected_count/unavailable_fields/related_sources
   directly, proving a consumer could act on the structured fields alone.
"""
import pytest

from dumpex.output.coverage import (
    SourceObservation, observe_source, CoverageLimitation, render_limitation,
    CoverageReport, SourceRequirement, build_coverage_report, exit_code_for,
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


def test_coverage_limitation_accepts_list_for_available_fields_and_related_sources():
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="threads",
                                     available_fields=["TID"],
                                     related_sources=["threads", "thread_info"])
    assert limitation.available_fields == ("TID",)
    assert limitation.related_sources == ("threads", "thread_info")


def test_coverage_limitation_group_absent_requires_two_or_more_related_sources():
    with pytest.raises(ValueError, match="related_sources"):
        CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="threads",
                            related_sources=("threads",))


def test_coverage_limitation_is_frozen():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules")
    with pytest.raises(Exception):
        limitation.source = "other"


# ── SourceRequirement ─────────────────────────────────────────────────

def test_source_requirement_defaults_to_plain_source_absent():
    req = SourceRequirement(source="modules")
    assert req.absent_code == LimitationCode.SOURCE_ABSENT
    assert req.unavailable_fields == ()
    assert req.available_fields == ()


def test_source_requirement_rejects_invalid_absent_code():
    with pytest.raises(ValueError):
        SourceRequirement(source="modules", absent_code="BOGUS")


def test_source_requirement_normalizes_field_lists_to_tuples():
    req = SourceRequirement(source="thread_info", unavailable_fields=["a", "b"],
                             available_fields=["c"])
    assert req.unavailable_fields == ("a", "b")
    assert req.available_fields == ("c",)


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
        evaluation_sources=("modules",),
        completeness_checks=["modules"],
    )
    assert report.status == expected_status


def test_source_failed_required_is_partial_not_not_evaluated_and_structured():
    # A required source that FAILED must not collapse onto not_evaluated
    # (as-if never there), and must not silently report complete just
    # because no limitation was passed in by hand -- the reducer derives
    # one itself from source.state, using a bare source-name string.
    obs = SourceObservation(name="modules", state=SOURCE_FAILED, detail="boom")
    report = build_coverage_report(
        {"modules": obs},
        evaluation_sources=("modules",),
        completeness_checks=["modules"],
    )
    assert report.status == COVERAGE_PARTIAL
    assert report.status != COVERAGE_NOT_EVALUATED
    assert len(report.limitations) == 1
    limitation = report.limitations[0]
    assert limitation.code == LimitationCode.SOURCE_FAILED
    assert limitation.source == "modules"
    assert limitation.detail == "boom"
    assert report.reasons == ["ModuleListStream present but could not be read: boom"]


# ── build_coverage_report: multiple evaluation sources (threads shape) ──

def test_all_evaluation_sources_absent_is_not_evaluated_with_structured_group_limitation():
    obs_a = SourceObservation(name="threads", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="thread_info", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"threads": obs_a, "thread_info": obs_b},
        evaluation_sources=("threads", "thread_info"),
    )
    assert report.status == COVERAGE_NOT_EVALUATED
    assert len(report.limitations) == 1
    limitation = report.limitations[0]
    assert limitation.code == LimitationCode.SOURCE_GROUP_ABSENT
    assert limitation.related_sources == ("threads", "thread_info")
    assert report.reasons == ["Neither ThreadListStream nor ThreadInfoListStream present in this dump"]


def test_single_evaluation_source_absent_renders_plain_source_absent_not_group():
    # A 1-element evaluation_sources group must render identically to the
    # plain SOURCE_ABSENT template (list/modules' existing wording), not
    # SOURCE_GROUP_ABSENT's "Neither/None of" phrasing.
    obs = SourceObservation(name="memory_info", state=SOURCE_ABSENT)
    report = build_coverage_report({"memory_info": obs}, evaluation_sources=("memory_info",))
    assert report.status == COVERAGE_NOT_EVALUATED
    limitation = report.limitations[0]
    assert limitation.code == LimitationCode.SOURCE_ABSENT
    assert report.reasons == ["MemoryInfoListStream not present in this dump"]


def test_only_one_of_several_evaluation_sources_absent_is_partial_via_completeness_checks():
    obs_a = SourceObservation(name="threads", state=SOURCE_PRESENT, record_count=2)
    obs_b = SourceObservation(name="thread_info", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"threads": obs_a, "thread_info": obs_b},
        evaluation_sources=("threads", "thread_info"),
        completeness_checks=["thread_info"],
    )
    assert report.status == COVERAGE_PARTIAL
    limitation = report.limitations[0]
    assert limitation.code == LimitationCode.SOURCE_ABSENT
    assert limitation.source == "thread_info"
    assert report.reasons == ["ThreadInfoListStream not present in this dump"]


def test_source_requirement_field_impact_variant_renders_and_is_structured():
    obs = SourceObservation(name="thread_info", state=SOURCE_ABSENT)
    req = SourceRequirement("thread_info", unavailable_fields=("StartAddress", "CreateTime"),
                             available_fields=("TID", "Priority"))
    report = build_coverage_report(
        {"thread_info": obs},
        completeness_checks=[req],
    )
    assert report.status == COVERAGE_PARTIAL
    limitation = report.limitations[0]
    assert limitation.code == LimitationCode.SOURCE_ABSENT
    assert limitation.unavailable_fields == ("StartAddress", "CreateTime")
    assert limitation.available_fields == ("TID", "Priority")
    assert report.reasons == [
        "ThreadInfoListStream not present; StartAddress/CreateTime unavailable (TID/Priority only)"]


def test_source_requirement_counterpart_variant_renders_and_is_structured():
    # A source that's fully ABSENT can still be reported with the "N
    # present in COUNTERPART but missing from SOURCE" wording (threads.py's
    # ThreadListStream shape) -- code stays SOURCE_ABSENT (the source
    # really is absent), not SOURCE_KEY_MISMATCH.
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_PRESENT, record_count=2)
    req = SourceRequirement("a", counterpart_source="b", scope="widget", affected_count=2,
                             unavailable_fields=("x", "y"))
    report = build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[req])
    limitation = report.limitations[0]
    assert limitation.code == LimitationCode.SOURCE_ABSENT
    assert limitation.counterpart_source == "b"
    assert limitation.affected_count == 2
    assert limitation.unavailable_fields == ("x", "y")
    assert report.reasons == ["2 widget(s) present in b but missing from a (x/y unavailable for those)"]


def test_source_requirement_dedicated_code_variant():
    obs = SourceObservation(name="modules", state=SOURCE_ABSENT)
    req = SourceRequirement("modules", absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE)
    report = build_coverage_report({"modules": obs}, completeness_checks=[req])
    limitation = report.limitations[0]
    assert limitation.code == LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE
    assert report.reasons == [
        "ModuleListStream not present; thread backing-module classification unavailable "
        "(cannot confirm whether a start address is backed by a known module)"]


def test_no_sources_and_no_checks_is_complete():
    report = build_coverage_report({})
    assert report.status == COVERAGE_COMPLETE
    assert report.reasons == []


def test_completeness_checks_present_source_contributes_nothing():
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    report = build_coverage_report({"modules": obs}, completeness_checks=["modules"])
    assert report.status == COVERAGE_COMPLETE
    assert report.limitations == []


def test_completeness_checks_preserve_caller_order():
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    key_mismatch = CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="b",
                                       affected_count=1)
    obs_b = SourceObservation(name="b", state=SOURCE_PRESENT, record_count=1)
    report = build_coverage_report(
        {"a": obs_a, "b": obs_b},
        completeness_checks=[key_mismatch, "a"],   # key-mismatch declared FIRST
    )
    assert [l.code for l in report.limitations] == [
        LimitationCode.SOURCE_KEY_MISMATCH, LimitationCode.SOURCE_ABSENT]


# ── build_coverage_report: input validation at the boundary ─────────────

def test_build_coverage_report_rejects_prebuilt_source_absent_in_completeness_checks():
    # A caller must not hand-build a SOURCE_ABSENT CoverageLimitation and
    # smuggle it into completeness_checks -- only a bare source name or
    # SourceRequirement may produce that code, so it's always derived
    # from the SourceObservation itself.
    obs = SourceObservation(name="modules", state=SOURCE_ABSENT)
    prebuilt = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules")
    with pytest.raises(ValueError, match="SOURCE_ABSENT"):
        build_coverage_report({"modules": obs}, completeness_checks=[prebuilt])


def test_build_coverage_report_rejects_prebuilt_source_failed_in_completeness_checks():
    obs = SourceObservation(name="modules", state=SOURCE_FAILED)
    prebuilt = CoverageLimitation(code=LIMITATION_SOURCE_FAILED, source="modules")
    with pytest.raises(ValueError, match="SOURCE_FAILED"):
        build_coverage_report({"modules": obs}, completeness_checks=[prebuilt])


def test_build_coverage_report_rejects_unknown_source_in_evaluation_sources():
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    with pytest.raises(ValueError, match="unknown source"):
        build_coverage_report({"modules": obs}, evaluation_sources=("nonexistent",))


def test_build_coverage_report_rejects_unknown_source_in_completeness_checks():
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    with pytest.raises(ValueError, match="unknown source"):
        build_coverage_report({"modules": obs}, completeness_checks=["nonexistent"])


def test_build_coverage_report_rejects_sources_key_name_mismatch():
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    with pytest.raises(ValueError, match="modules"):
        build_coverage_report({"wrong_key": obs}, completeness_checks=["wrong_key"])


def test_build_coverage_report_rejects_prebuilt_module_classification_even_if_present():
    # Only SOURCE_KEY_MISMATCH may be hand-built into completeness_checks
    # -- a caller must not be able to force a MODULE_CLASSIFICATION_UNAVAILABLE
    # limitation (or any other code) regardless of the source's real
    # state, bypassing the check the reducer would otherwise perform.
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    prebuilt = CoverageLimitation(code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE, source="modules")
    with pytest.raises(ValueError, match="MODULE_CLASSIFICATION_UNAVAILABLE"):
        build_coverage_report({"modules": obs}, completeness_checks=[prebuilt])


def test_build_coverage_report_rejects_prebuilt_source_group_absent():
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_ABSENT)
    prebuilt = CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="a",
                                   related_sources=("a", "b"))
    with pytest.raises(ValueError, match="SOURCE_GROUP_ABSENT"):
        build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[prebuilt])


def test_source_requirement_rejects_semantically_wrong_absent_code():
    # SOURCE_KEY_MISMATCH describes a PRESENT source's partial mismatch,
    # not an absence -- selecting it as absent_code would render nonsense
    # ("some dump(s) missing from ModuleListStream") if the source turned
    # out absent.
    with pytest.raises(ValueError, match="absent_code"):
        SourceRequirement(source="modules", absent_code=LimitationCode.SOURCE_KEY_MISMATCH)


def test_source_requirement_rejects_source_group_absent_as_absent_code():
    with pytest.raises(ValueError, match="absent_code"):
        SourceRequirement(source="modules", absent_code=LimitationCode.SOURCE_GROUP_ABSENT)


def test_source_requirement_module_classification_requires_modules_source():
    with pytest.raises(ValueError, match="modules"):
        SourceRequirement(source="threads", absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE)


def test_coverage_limitation_module_classification_requires_modules_source():
    with pytest.raises(ValueError, match="modules"):
        CoverageLimitation(code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE, source="threads")


def test_build_coverage_report_rejects_unknown_counterpart_source():
    obs = SourceObservation(name="threads", state=SOURCE_ABSENT)
    req = SourceRequirement("threads", counterpart_source="nonexistent")
    with pytest.raises(ValueError, match="unknown source"):
        build_coverage_report({"threads": obs}, completeness_checks=[req])


def test_build_coverage_report_rejects_unknown_counterpart_source_on_prebuilt_limitation():
    obs_a = SourceObservation(name="a", state=SOURCE_PRESENT, record_count=1)
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="a",
                                     counterpart_source="nonexistent")
    with pytest.raises(ValueError, match="unknown source"):
        build_coverage_report({"a": obs_a}, completeness_checks=[limitation])


# ── multi-source key mismatch (the threads shape) ────────────────────────

def test_two_way_key_mismatch_is_structured_and_renders_with_counterpart():
    obs_a = SourceObservation(name="threads", state=SOURCE_PRESENT, record_count=3)
    obs_b = SourceObservation(name="thread_info", state=SOURCE_PRESENT, record_count=2)
    limitation = CoverageLimitation(
        code=LIMITATION_SOURCE_KEY_MISMATCH, source="thread_info", counterpart_source="threads",
        scope="thread", affected_count=2, unavailable_fields=("StartAddress", "CreateTime"))
    report = build_coverage_report({"threads": obs_a, "thread_info": obs_b},
                                    completeness_checks=[limitation])
    assert report.status == COVERAGE_PARTIAL
    got = report.limitations[0]
    assert got.counterpart_source == "threads"
    assert got.affected_count == 2
    assert got.unavailable_fields == ("StartAddress", "CreateTime")
    assert report.reasons == [
        "2 thread(s) present in ThreadListStream but missing from ThreadInfoListStream "
        "(StartAddress/CreateTime unavailable for those)"]


def test_key_mismatch_without_counterpart_uses_generic_missing_from_wording():
    obs_a = SourceObservation(name="source_a", state=SOURCE_PRESENT, record_count=3)
    obs_b = SourceObservation(name="source_b", state=SOURCE_PRESENT, record_count=2)
    limitation = CoverageLimitation(
        code=LIMITATION_SOURCE_KEY_MISMATCH, source="source_b", scope="item",
        affected_count=1, unavailable_fields=["extra_field"])
    report = build_coverage_report({"source_a": obs_a, "source_b": obs_b},
                                    completeness_checks=[limitation])
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


def test_render_limitation_group_absent_three_sources_uses_none_of_wording():
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="misc_info",
                                     related_sources=("misc_info", "threads", "exception"))
    assert render_limitation(limitation) == "None of MiscInfo stream, ThreadListStream, Exception stream present in this dump"


def test_coverage_report_reasons_property_renders_every_limitation_in_order():
    report = CoverageReport(status=COVERAGE_PARTIAL, limitations=[
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="memory_info", scope="dump"),
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules", scope="dump"),
    ])
    assert report.reasons == [
        "MemoryInfoListStream not present in this dump",
        "ModuleListStream not present in this dump",
    ]


# ── exit_code_for ────────────────────────────────────────────────────────

@pytest.mark.parametrize("status,expected_code", [
    (COVERAGE_COMPLETE, EXIT_OK),
    (COVERAGE_PARTIAL, EXIT_PARTIAL),
    (COVERAGE_NOT_EVALUATED, EXIT_NOT_EVALUATED),
])
def test_exit_code_for_known_statuses(status, expected_code):
    assert exit_code_for(status) == expected_code


def test_exit_code_for_known_status_as_plain_string():
    assert exit_code_for("complete") == EXIT_OK
    assert exit_code_for("partial") == EXIT_PARTIAL
    assert exit_code_for("not_evaluated") == EXIT_NOT_EVALUATED


def test_exit_code_values_are_distinct():
    assert len({EXIT_OK, EXIT_PARTIAL, EXIT_NOT_EVALUATED}) == 3
    assert EXIT_OK == 0


def test_exit_code_for_unknown_status_raises():
    with pytest.raises(ValueError, match="unknown coverage status"):
        exit_code_for("totally_bogus_status")


# ── CoverageReport.status: closed vocabulary, validated + normalized ────

def test_coverage_report_rejects_invalid_status():
    with pytest.raises(ValueError, match="unknown coverage status"):
        CoverageReport(status="bogus")


def test_coverage_report_normalizes_bare_string_status():
    report = CoverageReport(status="complete")
    assert report.status == CoverageStatus.COMPLETE
    assert isinstance(report.status, CoverageStatus)

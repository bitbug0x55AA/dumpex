"""
Table-driven tests for dumpex.output.coverage -- the first-class
coverage/provenance core extracted from the ad hoc bool(mf.X)-check
pattern every recon command used to hand-roll independently. Validated
directly here against every coverage rule already hand-built for list/
modules/threads/sysinfo/pid this session (see build_coverage_report's
own docstring), including scenarios (multi-source key mismatch,
SOURCE_FAILED) that no currently-migrated command exercises yet -- this
is deliberately testing the model's generality ahead of the threads/
comparison migration that will need it, not just what list/modules use
today.
"""
import pytest

from dumpex.output.coverage import (
    SourceObservation, observe_source, CoverageLimitation, render_limitation,
    CoverageReport, build_coverage_report, exit_code_for,
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


# ── build_coverage_report: single required source, all 4 states ────────

@pytest.mark.parametrize("state,expected_status", [
    (SOURCE_ABSENT,       COVERAGE_NOT_EVALUATED),
    (SOURCE_PRESENT_EMPTY, COVERAGE_COMPLETE),
    (SOURCE_PRESENT,       COVERAGE_COMPLETE),
    (SOURCE_FAILED,        COVERAGE_PARTIAL),
])
def test_single_required_source_state_drives_status(state, expected_status):
    obs = SourceObservation(name="modules", state=state,
                             record_count=None if state == SOURCE_ABSENT else 0)
    limitations = []
    if state == SOURCE_ABSENT:
        limitations.append(CoverageLimitation(code=LIMITATION_SOURCE_ABSENT,
                                               source="modules", scope="dump"))
    elif state == SOURCE_FAILED:
        limitations.append(CoverageLimitation(code=LIMITATION_SOURCE_FAILED,
                                               source="modules", scope="dump"))
    report = build_coverage_report({"modules": obs}, limitations, required_sources={"modules"})
    assert report.status == expected_status


def test_source_failed_required_is_partial_not_not_evaluated():
    # A required source that FAILED (was there, reading it errored) must
    # not collapse onto the same status as a source that was never there
    # at all -- evaluation was attempted.
    obs = SourceObservation(name="modules", state=SOURCE_FAILED)
    limitations = [CoverageLimitation(code=LIMITATION_SOURCE_FAILED, source="modules")]
    report = build_coverage_report({"modules": obs}, limitations, required_sources={"modules"})
    assert report.status == COVERAGE_PARTIAL
    assert report.status != COVERAGE_NOT_EVALUATED


# ── build_coverage_report: multiple required sources (threads/pid shape) ─

def test_all_required_sources_absent_is_not_evaluated():
    obs_a = SourceObservation(name="threads", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="thread_info", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"threads": obs_a, "thread_info": obs_b},
        [CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="threads"),
         CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="thread_info")],
        required_sources={"threads", "thread_info"})
    assert report.status == COVERAGE_NOT_EVALUATED


def test_only_one_of_several_required_sources_absent_is_partial_not_not_evaluated():
    obs_a = SourceObservation(name="threads", state=SOURCE_PRESENT, record_count=2)
    obs_b = SourceObservation(name="thread_info", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"threads": obs_a, "thread_info": obs_b},
        [CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="thread_info")],
        required_sources={"threads", "thread_info"})
    assert report.status == COVERAGE_PARTIAL


def test_empty_required_sources_never_forces_not_evaluated():
    # sysinfo's shape: even if every one of its sources is absent, it's
    # never not_evaluated because it always has something else (e.g.
    # dump_file) to report -- modeled by passing an empty required set.
    sources = {name: SourceObservation(name=name, state=SOURCE_ABSENT)
               for name in ("sysinfo", "misc_info", "peb", "threads", "modules")}
    limitations = [CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source=name)
                   for name in sources]
    report = build_coverage_report(sources, limitations, required_sources=set())
    assert report.status == COVERAGE_PARTIAL   # never not_evaluated
    assert len(report.reasons) == 5


def test_no_limitations_and_no_required_sources_is_complete():
    report = build_coverage_report({}, [], required_sources=None)
    assert report.status == COVERAGE_COMPLETE
    assert report.reasons == []


# ── multi-source key mismatch (the threads/comparison shape) ────────────

def test_multi_source_key_mismatch_is_partial():
    # Two sources that describe the same entities (e.g. threads.py's
    # ThreadListStream vs ThreadInfoListStream) disagree on which keys
    # exist. Neither source is itself absent -- this is a genuinely
    # different limitation kind from SOURCE_ABSENT/SOURCE_FAILED.
    obs_a = SourceObservation(name="source_a", state=SOURCE_PRESENT, record_count=3)
    obs_b = SourceObservation(name="source_b", state=SOURCE_PRESENT, record_count=2)
    limitation = CoverageLimitation(
        code=LIMITATION_SOURCE_KEY_MISMATCH, source="source_b", scope="item",
        affected_count=1, unavailable_fields=["extra_field"])
    report = build_coverage_report({"source_a": obs_a, "source_b": obs_b}, [limitation],
                                    required_sources=set())
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


def test_render_limitation_unknown_code_uses_detail_or_generic_fallback():
    limitation = CoverageLimitation(code="SOME_FUTURE_CODE", source="modules", detail="custom text")
    assert render_limitation(limitation) == "custom text"

    limitation_no_detail = CoverageLimitation(code="SOME_FUTURE_CODE", source="modules")
    assert "SOME_FUTURE_CODE" in render_limitation(limitation_no_detail)


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


def test_exit_code_values_are_distinct():
    assert len({EXIT_OK, EXIT_PARTIAL, EXIT_NOT_EVALUATED}) == 3
    assert EXIT_OK == 0


def test_exit_code_for_unknown_status_raises():
    with pytest.raises(ValueError, match="unknown coverage status"):
        exit_code_for("totally_bogus_status")

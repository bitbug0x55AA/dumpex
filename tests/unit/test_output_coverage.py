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

from dumpex.output.records import hex_address
from dumpex.output.coverage import (
    ScanTarget, ScanTargetKind, scan_target_noun,
    SourceObservation, observe_source, CoverageLimitation, render_limitation,
    CoverageReport, SourceRequirement, EvaluationRequirement, build_coverage_report,
    combine_coverage_reports, exit_code_for,
    SourceState, CoverageStatus, LimitationCode,
    SOURCE_ABSENT, SOURCE_PRESENT_EMPTY, SOURCE_PRESENT, SOURCE_FAILED,
    LIMITATION_SOURCE_ABSENT, LIMITATION_SOURCE_FAILED, LIMITATION_SOURCE_KEY_MISMATCH,
    COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_NOT_EVALUATED,
    EXIT_OK, EXIT_PARTIAL, EXIT_NOT_EVALUATED,
    _FIXED_SOURCE_CODES, _CODE_SPECS, _ABSENT_CAPABLE_CODES, _display_name,
)

# _FIXED_SOURCE_CODES now also covers caller_buildable/group_capable-only
# codes (e.g. PID_NO_USABLE_FALLBACK) whose fixed source is enforced at
# CoverageLimitation-construction time but which SourceRequirement/
# EvaluationRequirement must never accept regardless of source (they're
# not absent_capable) -- filtered down to the subset actually selectable
# through those two for the parametrized tests below that exercise them.
_ABSENT_CAPABLE_FIXED_SOURCE_CODES = [
    (code, source) for code, source in _FIXED_SOURCE_CODES.items() if code in _ABSENT_CAPABLE_CODES
]


# ── _CODE_SPECS registry ─────────────────────────────────────────────────
# Mechanically catches "added a new LimitationCode member but forgot to
# register its spec" -- it does NOT catch a wrong spec (wrong fixed_source,
# missing validate_fields, etc.): a new code's own source/field/state
# contract still needs its own dedicated tests, following the existing
# PID_*/SYSINFO_* tests below as the pattern.
def test_every_limitation_code_has_a_registered_spec():
    assert set(_CODE_SPECS) == set(LimitationCode)


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

# What actually has to hold is that these compare equal to the bare
# strings call sites use -- i.e. they stay str-subclass enums. Written
# against each member's own `.value` rather than a re-typed copy of the
# strings: the values themselves are pinned where they carry real
# information, against the schema enums that close over them, in
# tests/unit/test_record_schema_alignment.py.

@pytest.mark.parametrize("member", list(SourceState))
def test_source_state_members_are_str_subclass_enums(member):
    assert isinstance(member, str)
    assert member == member.value


@pytest.mark.parametrize("member", list(CoverageStatus))
def test_coverage_status_members_are_str_subclass_enums(member):
    assert isinstance(member, str)
    assert member == member.value


def test_module_level_aliases_point_at_the_enum_members():
    # The SOURCE_*/COVERAGE_* aliases are what most call sites import;
    # they must be the enum members themselves, not copies of the values.
    assert (SOURCE_ABSENT, SOURCE_PRESENT_EMPTY, SOURCE_PRESENT, SOURCE_FAILED) == (
        SourceState.ABSENT, SourceState.PRESENT_EMPTY, SourceState.PRESENT, SourceState.FAILED)
    assert (COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_NOT_EVALUATED) == (
        CoverageStatus.COMPLETE, CoverageStatus.PARTIAL, CoverageStatus.NOT_EVALUATED)


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


@pytest.mark.parametrize("state,record_count", [
    (SourceState.PRESENT, True),         # bool is a subclass of int (True > 0 passes
                                           # a naive positivity check) -- must still reject
    (SourceState.PRESENT_EMPTY, False),   # False == 0 passes a naive equality check
])
def test_source_observation_rejects_bool_record_count(state, record_count):
    with pytest.raises(ValueError, match="bool"):
        SourceObservation(name="modules", state=state, record_count=record_count)


def test_source_observation_rejects_float_record_count():
    # A float (e.g. 1.5) passes every existing "!= 0"/"<= 0"/truthiness
    # comparison but is not a real int -- the JSON Schema's "integer"
    # type rejects it.
    with pytest.raises(ValueError, match="record_count"):
        SourceObservation(name="modules", state=SourceState.PRESENT, record_count=1.5)


def test_source_observation_rejects_non_string_detail():
    with pytest.raises(ValueError, match="detail"):
        SourceObservation(name="modules", state=SourceState.FAILED, detail=123)


def test_source_observation_rejects_empty_name():
    with pytest.raises(ValueError, match="name"):
        SourceObservation(name="", state=SourceState.ABSENT)


def test_source_observation_is_frozen():
    obs = SourceObservation(name="modules", state=SourceState.ABSENT)
    with pytest.raises(Exception):
        obs.name = "other"


def test_source_observation_to_dict_excludes_name():
    obs = SourceObservation(name="modules", state=SourceState.PRESENT, record_count=3)
    assert obs.to_dict() == {"state": "present", "record_count": 3, "detail": None}
    assert "name" not in obs.to_dict()


def test_source_observation_to_dict_failed_includes_detail():
    obs = SourceObservation(name="peb", state=SourceState.FAILED, detail="parse boom")
    assert obs.to_dict() == {"state": "failed", "record_count": None, "detail": "parse boom"}


# ── CoverageLimitation: code is a closed vocabulary, source stays open ──

def test_coverage_limitation_rejects_invalid_code():
    with pytest.raises(ValueError):
        CoverageLimitation(code="SOME_FUTURE_CODE", source="modules")


def test_coverage_limitation_rejects_empty_source():
    with pytest.raises(ValueError):
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="")


def test_coverage_limitation_rejects_bool_affected_count():
    # bool is a subclass of int (True <= 0 is False, so a naive
    # positivity check would silently accept it) -- must still reject,
    # since the JSON Schema's "integer" type rejects true/false.
    with pytest.raises(ValueError, match="affected_count"):
        CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="modules",
                            counterpart_source="threads", affected_count=True)


def test_coverage_limitation_rejects_non_positive_affected_count():
    with pytest.raises(ValueError, match="affected_count"):
        CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="modules",
                            counterpart_source="threads", affected_count=0)


def test_coverage_limitation_rejects_non_string_scope():
    with pytest.raises(ValueError, match="scope"):
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules", scope=123)


def test_coverage_limitation_rejects_non_string_counterpart_source():
    with pytest.raises(ValueError, match="counterpart_source"):
        CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="modules",
                            counterpart_source=123)


def test_coverage_limitation_rejects_non_string_detail():
    with pytest.raises(ValueError, match="detail"):
        CoverageLimitation(code=LIMITATION_SOURCE_FAILED, source="modules", detail=123)


def test_coverage_limitation_rejects_non_string_element_in_unavailable_fields():
    with pytest.raises(ValueError, match="unavailable_fields"):
        CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="modules",
                            unavailable_fields=[123])


def test_coverage_limitation_rejects_non_string_element_in_related_sources():
    with pytest.raises(ValueError, match="related_sources"):
        CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="threads",
                            related_sources=["threads", 123])


def test_coverage_limitation_rejects_bare_string_as_unavailable_fields():
    # A bare string is iterable -- tuple("ab") would silently become
    # ('a', 'b') instead of raising on what's almost certainly a
    # forgotten [ ] at the call site.
    with pytest.raises(ValueError, match="unavailable_fields"):
        CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="modules",
                            unavailable_fields="ab")


def test_coverage_limitation_rejects_set_as_unavailable_fields():
    # set iteration order is hash-randomized per process in Python (for
    # str keys) -- silently accepting one here would let the rendered
    # reason text, the JSON array, and any frozen-output test drift
    # between runs/processes for no reason visible in the source.
    with pytest.raises(ValueError, match="unavailable_fields"):
        CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="modules",
                            unavailable_fields={"CreateTime", "ExitTime"})


def test_coverage_limitation_rejects_generator_as_related_sources():
    with pytest.raises(ValueError, match="related_sources"):
        CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="threads",
                            related_sources=(s for s in ["threads", "thread_info"]))


def test_coverage_limitation_rejects_set_as_related_tids():
    with pytest.raises(ValueError, match="related_tids"):
        CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                            counterpart_source="threads", related_tids={9, 10})


def test_coverage_limitation_accepts_list_for_unavailable_fields_and_normalizes_to_tuple():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_KEY_MISMATCH, source="modules",
                                     unavailable_fields=["a", "b"])
    assert limitation.unavailable_fields == ("a", "b")


def test_coverage_limitation_accepts_list_for_available_fields_and_normalizes_to_tuple():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules",
                                     unavailable_fields=["StartAddress"], available_fields=["TID"])
    assert limitation.available_fields == ("TID",)


def test_coverage_limitation_accepts_list_for_related_sources_and_normalizes_to_tuple():
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="threads",
                                     related_sources=["threads", "thread_info"])
    assert limitation.related_sources == ("threads", "thread_info")


def test_coverage_limitation_group_absent_requires_two_or_more_related_sources():
    with pytest.raises(ValueError, match="related_sources"):
        CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="threads",
                            related_sources=("threads",))


def test_coverage_limitation_is_frozen():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules")
    with pytest.raises(Exception):
        limitation.source = "other"


def test_coverage_limitation_to_dict_minimal_emits_every_field():
    limitation = CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules")
    assert limitation.to_dict() == {
        "code": "SOURCE_ABSENT", "source": "modules", "scope": None,
        "affected_count": None, "unavailable_fields": [], "available_fields": [],
        "counterpart_source": None, "related_sources": [], "related_tids": [],
        "thread_id": None, "detail": None, "targets": [],
        "budget_limit": None, "budget_consumed": None,
    }


def test_coverage_limitation_to_dict_converts_tuples_to_lists():
    limitation = CoverageLimitation(
        code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
        counterpart_source="threads", related_tids=(9, 10))
    d = limitation.to_dict()
    assert d["related_tids"] == [9, 10]
    assert isinstance(d["related_tids"], list)
    assert d["counterpart_source"] == "threads"


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


# ── build_coverage_report: retain_completeness_checks_when_not_evaluated ─

def test_not_evaluated_drops_prebuilt_limitations_by_default():
    obs = SourceObservation(name="process_identity", state=SOURCE_ABSENT)
    region_obs = SourceObservation(name="requested_region", state=SOURCE_PRESENT, record_count=1)
    prebuilt = CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED,
                                   source="requested_region")
    report = build_coverage_report(
        {"process_identity": obs, "requested_region": region_obs},
        evaluation_sources=("process_identity",),
        completeness_checks=[prebuilt],
    )
    assert report.status == COVERAGE_NOT_EVALUATED
    assert len(report.limitations) == 1
    assert report.limitations[0].code == LimitationCode.SOURCE_ABSENT
    assert prebuilt not in report.limitations


def test_not_evaluated_retains_prebuilt_limitations_when_opted_in():
    obs_identity = SourceObservation(name="process_identity", state=SOURCE_ABSENT)
    obs_misc = SourceObservation(name="misc_info", state=SOURCE_FAILED, detail="boom")
    region_obs = SourceObservation(name="requested_region", state=SOURCE_PRESENT, record_count=1)
    prebuilt = CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED,
                                   source="requested_region")
    report = build_coverage_report(
        {"process_identity": obs_identity, "misc_info": obs_misc, "requested_region": region_obs},
        evaluation_sources=("process_identity",),
        completeness_checks=[prebuilt, "misc_info"],
        retain_completeness_checks_when_not_evaluated=True,
    )
    assert report.status == COVERAGE_NOT_EVALUATED
    # Order: the group's own limitation first, then the retained pre-built
    # entries in caller-declared order, then the FAILED-source limitations
    # the reducer already re-surfaces today.
    assert len(report.limitations) == 3
    assert report.limitations[0].code == LimitationCode.SOURCE_ABSENT
    assert report.limitations[0].source == "process_identity"
    assert report.limitations[1] is prebuilt
    assert report.limitations[2].code == LimitationCode.SOURCE_FAILED
    assert report.limitations[2].source == "misc_info"


def test_not_evaluated_retain_flag_never_resurfaces_an_absent_bare_source():
    # A FAILED source is re-surfaced either way (existing behavior); an
    # ABSENT one outside the group is not -- the flag only changes what
    # happens to pre-built CoverageLimitation entries.
    obs_identity = SourceObservation(name="process_identity", state=SOURCE_ABSENT)
    obs_peb = SourceObservation(name="peb", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"process_identity": obs_identity, "peb": obs_peb},
        evaluation_sources=("process_identity",),
        completeness_checks=["peb"],
        retain_completeness_checks_when_not_evaluated=True,
    )
    assert report.status == COVERAGE_NOT_EVALUATED
    assert len(report.limitations) == 1
    assert report.limitations[0].source == "process_identity"


def test_not_evaluated_retain_flag_is_noop_when_no_group_fires():
    # The flag only changes anything on the not_evaluated short-circuit
    # path -- an ordinary partial/complete result is unaffected.
    obs = SourceObservation(name="modules", state=SOURCE_PRESENT, record_count=1)
    report = build_coverage_report(
        {"modules": obs},
        evaluation_sources=("modules",),
        completeness_checks=[],
        retain_completeness_checks_when_not_evaluated=True,
    )
    assert report.status == COVERAGE_COMPLETE
    assert report.limitations == []


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


# ── EvaluationRequirement: group-level all_absent_code override ─────────

def test_evaluation_requirement_single_source_dedicated_code():
    # A single-source group can still select a dedicated code (e.g. a
    # future PEB migration's PEB_UNAVAILABLE) instead of the plain
    # SOURCE_ABSENT default -- proven here with an existing dedicated
    # code (MODULE_CLASSIFICATION_UNAVAILABLE) so this test doesn't
    # depend on a future command's vocabulary.
    obs = SourceObservation(name="modules", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"modules": obs},
        evaluation_sources=EvaluationRequirement(
            sources=("modules",), all_absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE),
    )
    assert report.status == COVERAGE_NOT_EVALUATED
    limitation = report.limitations[0]
    assert limitation.code == LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE
    assert report.reasons == [
        "ModuleListStream not present; thread backing-module classification unavailable "
        "(cannot confirm whether a start address is backed by a known module)"]


def test_evaluation_requirement_explicit_group_absent_matches_automatic_default():
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_ABSENT)
    auto = build_coverage_report({"a": obs_a, "b": obs_b}, evaluation_sources=("a", "b"))
    explicit = build_coverage_report(
        {"a": obs_a, "b": obs_b},
        evaluation_sources=EvaluationRequirement(sources=("a", "b"),
                                                  all_absent_code=LimitationCode.SOURCE_GROUP_ABSENT))
    assert auto.reasons == explicit.reasons
    assert auto.limitations[0].code == explicit.limitations[0].code == LimitationCode.SOURCE_GROUP_ABSENT


def test_evaluation_requirement_group_code_not_pinned_to_first_source():
    # The whole point of EvaluationRequirement: a group-level code must
    # not depend on which source happens to be sources[0] -- reordering
    # the tuple must not change which code applies.
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_ABSENT)
    forward = build_coverage_report(
        {"a": obs_a, "b": obs_b},
        evaluation_sources=EvaluationRequirement(sources=("a", "b"),
                                                  all_absent_code=LimitationCode.SOURCE_GROUP_ABSENT))
    backward = build_coverage_report(
        {"a": obs_a, "b": obs_b},
        evaluation_sources=EvaluationRequirement(sources=("b", "a"),
                                                  all_absent_code=LimitationCode.SOURCE_GROUP_ABSENT))
    assert forward.limitations[0].code == backward.limitations[0].code == LimitationCode.SOURCE_GROUP_ABSENT


def test_evaluation_requirement_rejects_invalid_all_absent_code():
    with pytest.raises(ValueError, match="all_absent_code"):
        EvaluationRequirement(sources=("a", "b"), all_absent_code=LimitationCode.SOURCE_KEY_MISMATCH)


def test_evaluation_requirement_normalizes_list_sources_to_tuple():
    req = EvaluationRequirement(sources=["a", "b"])
    assert req.sources == ("a", "b")


# ── EvaluationRequirement: source-count/code combination validation ─────
# Each of these reproduces a real bug: a single-source-only code (which
# renders from `source` alone, ignoring every other group member) used
# with a 2+-source group would silently drop everything but the first
# source from the rendered text.

def test_evaluation_requirement_rejects_single_source_code_for_multi_source_group():
    with pytest.raises(ValueError, match="not valid for 2 source"):
        EvaluationRequirement(sources=("peb", "threads"),
                               all_absent_code=LimitationCode.PEB_UNAVAILABLE)


def test_evaluation_requirement_rejects_plain_source_absent_for_multi_source_group():
    with pytest.raises(ValueError, match="not valid for 2 source"):
        EvaluationRequirement(sources=("peb", "threads"),
                               all_absent_code=LimitationCode.SOURCE_ABSENT)


def test_evaluation_requirement_rejects_group_code_for_single_source():
    with pytest.raises(ValueError, match="not valid for 1 source"):
        EvaluationRequirement(sources=("peb",), all_absent_code=LimitationCode.SOURCE_GROUP_ABSENT)


def test_evaluation_requirement_rejects_duplicate_sources():
    with pytest.raises(ValueError, match="duplicates"):
        EvaluationRequirement(sources=("peb", "peb"))


def test_evaluation_requirement_rejects_empty_string_source():
    with pytest.raises(ValueError, match="non-empty strings"):
        EvaluationRequirement(sources=("peb", ""))


def test_evaluation_requirement_rejects_non_string_source():
    # `not s` alone would accept a truthy non-string (e.g. 123) -- must
    # reject anything that isn't actually a str, not just falsy values.
    with pytest.raises(ValueError, match="non-empty strings"):
        EvaluationRequirement(sources=(123,))


def test_coverage_limitation_rejects_non_string_source():
    with pytest.raises(ValueError, match="non-empty string"):
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source=123)


def test_evaluation_requirement_rejects_all_absent_code_with_empty_sources():
    with pytest.raises(ValueError, match="empty sources"):
        EvaluationRequirement(sources=(), all_absent_code=LimitationCode.PEB_UNAVAILABLE)


def test_evaluation_requirement_empty_sources_with_no_code_is_fine():
    # sysinfo's shape: no evaluation group at all, no code to select.
    req = EvaluationRequirement(sources=())
    assert req.sources == ()
    assert req.all_absent_code is None


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


def test_source_requirement_counterpart_variant_with_zero_affected_count_is_suppressed():
    # If the counterpart genuinely has zero entries, nothing was actually
    # affected by this source's absence -- no real coverage gap, so no
    # limitation at all (not a "0 thing(s) present..." nonsense reason).
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_PRESENT_EMPTY, record_count=0)
    req = SourceRequirement("a", counterpart_source="b", affected_count=0)
    report = build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[req])
    assert report.status == COVERAGE_COMPLETE
    assert report.limitations == []


def test_source_requirement_counterpart_variant_with_omitted_affected_count_and_empty_counterpart_is_suppressed():
    # Same suppression as above, but the caller didn't explicitly assert
    # affected_count=0 -- omitting it entirely while the counterpart
    # genuinely has zero entries must reach the same "nothing to report"
    # conclusion, not attempt to derive and construct affected_count=0
    # directly (which CoverageLimitation's own shape check would reject).
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_PRESENT_EMPTY, record_count=0)
    req = SourceRequirement("a", counterpart_source="b")
    report = build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[req])
    assert report.status == COVERAGE_COMPLETE
    assert report.limitations == []


@pytest.mark.parametrize("bad_count", [-1, "bad", True])
def test_source_requirement_rejects_invalid_affected_count_shape(bad_count):
    # Caught at SourceRequirement construction time, before it ever
    # reaches _derive_required_source_limitation's own == 0 / != 0
    # comparisons -- a bool would otherwise silently coerce (True == 1),
    # and a negative int or a string would otherwise reach comparisons
    # that were never designed to validate an arbitrary caller value.
    with pytest.raises(ValueError, match="affected_count"):
        SourceRequirement("a", counterpart_source="b", affected_count=bad_count)


def test_build_coverage_report_rejects_nonzero_affected_count_against_present_empty_counterpart():
    # Exact repro from review: a positive affected_count must not be
    # silently swallowed by present_empty suppression just because it
    # isn't literally 0 -- a caller explicitly claiming "5 affected" when
    # the counterpart itself reports zero records is a real
    # inconsistency, not something to treat as "nothing to report".
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_PRESENT_EMPTY, record_count=0)
    req = SourceRequirement("a", counterpart_source="b", affected_count=5)
    with pytest.raises(ValueError, match="present_empty"):
        build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[req])


def test_zero_affected_count_suppression_rejects_counterpart_with_real_records():
    # affected_count=0 must be corroborated by the counterpart's OWN
    # SourceObservation, not taken on faith -- a counterpart that's
    # genuinely PRESENT with real records contradicts "nothing affected"
    # and must not silently suppress a genuine absence.
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_PRESENT, record_count=1)
    req = SourceRequirement("a", counterpart_source="b", affected_count=0)
    with pytest.raises(ValueError, match="present_empty"):
        build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[req])


def test_zero_affected_count_suppression_rejects_failed_counterpart():
    # A FAILED counterpart tells us nothing about how many entries it
    # would have had -- it must not be treated as confirming zero.
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_FAILED)
    req = SourceRequirement("a", counterpart_source="b", affected_count=0)
    with pytest.raises(ValueError, match="not present"):
        build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[req])


def test_zero_affected_count_suppression_rejects_absent_counterpart():
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_ABSENT)
    req = SourceRequirement("a", counterpart_source="b", affected_count=0)
    with pytest.raises(ValueError, match="not present"):
        build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[req])


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


# ── _FIXED_SOURCE_CODES: every fixed-sentence code, checked at EVERY
# construction path (SourceRequirement, EvaluationRequirement, and
# CoverageLimitation itself) -- a caller must not be able to pair one of
# these codes with the wrong source through any of the three, since doing
# so produces dump-content-dependent behavior (silently "complete" when
# the mismatched source happens to be present, a ValueError buried deep
# inside CoverageLimitation construction only when it's absent).
#
# The four tests below use _ABSENT_CAPABLE_FIXED_SOURCE_CODES rather than
# the full _FIXED_SOURCE_CODES: PID_NO_USABLE_FALLBACK/PID_THREAD_LIST_
# FALLBACK/PID_EXCEPTION_TID_FALLBACK/PID_SOURCES_ABSENT also pin a fixed
# source (checked at CoverageLimitation-construction time, see the
# dedicated PID_* tests further down) but are caller_buildable/
# group_capable-only, never selectable via SourceRequirement.absent_code
# or a single-source EvaluationRequirement.all_absent_code -- passing them
# here would test the wrong rejection reason (not-absent-capable, not
# wrong-source).

@pytest.mark.parametrize("code,correct_source", _ABSENT_CAPABLE_FIXED_SOURCE_CODES)
def test_source_requirement_rejects_mismatched_fixed_source_code(code, correct_source):
    wrong_source = "definitely_not_" + correct_source
    with pytest.raises(ValueError, match=correct_source):
        SourceRequirement(source=wrong_source, absent_code=code)


@pytest.mark.parametrize("code,correct_source", _ABSENT_CAPABLE_FIXED_SOURCE_CODES)
def test_source_requirement_accepts_correct_fixed_source_code(code, correct_source):
    req = SourceRequirement(source=correct_source, absent_code=code)
    assert req.absent_code == code


@pytest.mark.parametrize("code,correct_source", _ABSENT_CAPABLE_FIXED_SOURCE_CODES)
def test_evaluation_requirement_rejects_mismatched_fixed_source_code(code, correct_source):
    wrong_source = "definitely_not_" + correct_source
    with pytest.raises(ValueError, match=correct_source):
        EvaluationRequirement(sources=(wrong_source,), all_absent_code=code)


@pytest.mark.parametrize("code,correct_source", _ABSENT_CAPABLE_FIXED_SOURCE_CODES)
def test_evaluation_requirement_accepts_correct_fixed_source_code(code, correct_source):
    req = EvaluationRequirement(sources=(correct_source,), all_absent_code=code)
    assert req.all_absent_code == code


@pytest.mark.parametrize("code,correct_source", list(_FIXED_SOURCE_CODES.items()))
def test_coverage_limitation_rejects_mismatched_fixed_source_code(code, correct_source):
    wrong_source = "definitely_not_" + correct_source
    with pytest.raises(ValueError, match=correct_source):
        CoverageLimitation(code=code, source=wrong_source)


def test_bug_repro_source_requirement_with_wrong_code_no_longer_silently_diverges():
    # The exact reproduction from review: constructing this used to
    # succeed, then behave differently depending on whether `modules`
    # happened to be present (silent complete) or absent (crash deep in
    # CoverageLimitation) in the dump being analyzed.
    with pytest.raises(ValueError, match="sysinfo"):
        SourceRequirement("modules", absent_code=LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE)


def test_coverage_limitation_module_classification_requires_modules_source():
    with pytest.raises(ValueError, match="modules"):
        CoverageLimitation(code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE, source="threads")


def test_coverage_limitation_peb_unavailable_requires_peb_source():
    with pytest.raises(ValueError, match="peb"):
        CoverageLimitation(code=LimitationCode.PEB_UNAVAILABLE, source="modules")


# ── PID-specific codes: field-combination validation ─────────────────────

def test_coverage_limitation_pid_thread_list_fallback_requires_related_tids():
    with pytest.raises(ValueError, match="related_tids"):
        CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                            counterpart_source="threads")


def test_coverage_limitation_pid_exception_tid_fallback_requires_thread_id():
    with pytest.raises(ValueError, match="thread_id"):
        CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception")


def test_coverage_limitation_normalizes_list_related_tids_to_tuple():
    limitation = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                                     counterpart_source="threads", related_tids=[1, 2, 3])
    assert limitation.related_tids == (1, 2, 3)


def test_render_limitation_pid_sources_absent():
    limitation = CoverageLimitation(code=LimitationCode.PID_SOURCES_ABSENT, source="misc_info",
                                     related_sources=("misc_info", "threads", "exception"))
    assert render_limitation(limitation) == (
        "MiscInfo, thread list, and exception stream are all absent from this "
        "dump; PID could not be evaluated")


def test_render_limitation_pid_thread_list_fallback_truncates_after_eight():
    limitation = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                                     counterpart_source="threads",
                                     related_tids=tuple(range(1, 11)))   # 10 tids
    text = render_limitation(limitation)
    assert text == (
        "MiscInfo stream absent — PID not directly recoverable from thread list.\n"
        "    10 thread(s) found: 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 …")


def test_render_limitation_pid_exception_tid_fallback():
    limitation = CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception",
                                     thread_id=9)
    assert render_limitation(limitation) == (
        "Exception stream present: faulting TID = 0x9 (this is a Thread ID, not a Process ID)")


def test_render_limitation_pid_no_usable_fallback():
    limitation = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info")
    assert render_limitation(limitation) == (
        "PID not found in MINIDUMP_MISC_INFO, and no usable cross-check data "
        "was available from the thread list or exception stream")


# ── _CodeSpec.allowed_fields: machine fields must not contradict the
# rendered text -- a code whose renderer never reads a field must reject
# that field being set, not silently ignore it.

def test_coverage_limitation_pid_no_usable_fallback_rejects_contradictory_bundle():
    # Exact repro from review: PID_NO_USABLE_FALLBACK's own enum comment
    # says "fully fixed sentence, no fields" -- nothing previously
    # enforced that, so this combination used to construct successfully,
    # get accepted by the reducer, validate against the schema, and
    # render the fixed sentence while silently ignoring every field below.
    # (Which specific field trips the check first isn't the point here --
    # see the two tests below for source/scope isolated individually, per
    # review round 2's ask.)
    with pytest.raises(ValueError):
        CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="modules",
                            scope="module", affected_count=7,
                            unavailable_fields=("BogusField",), detail="contradictory")


def test_coverage_limitation_pid_no_usable_fallback_rejects_wrong_source_alone():
    # Isolated from scope/affected_count/etc: source="modules" alone (a
    # real source name, just not the one this fixed sentence claims) must
    # be rejected on its own, not only when bundled with other bad fields.
    with pytest.raises(ValueError, match="misc_info"):
        CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="modules")


def test_coverage_limitation_pid_no_usable_fallback_rejects_scope_alone():
    # Isolated from source/affected_count/etc: with the correct source,
    # scope alone must still be rejected -- unlike SOURCE_ABSENT/SOURCE_
    # FAILED/the group codes, this code is never reached via auto-
    # derivation (which is the only thing that ever sets scope), so it
    # has no legitimate use for it.
    with pytest.raises(ValueError, match="scope"):
        CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info",
                            scope="module")


# ── REGION_READ_TRUNCATED (P1-4 remediation): --extract/--strings' own
# short-read gap -- read_region() returned fewer bytes than requested,
# the source itself stays PRESENT (there IS data), same caller_buildable/
# fixed_source/no-allowed_fields shape as PID_NO_USABLE_FALLBACK above. ──

def test_render_limitation_region_read_truncated():
    limitation = CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED,
                                     source="requested_region")
    assert render_limitation(limitation) == "Requested memory region was only partially read"


def test_coverage_limitation_region_read_truncated_rejects_wrong_source():
    with pytest.raises(ValueError, match="requested_region"):
        CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED, source="modules")


def test_coverage_limitation_region_read_truncated_rejects_scope():
    # Never auto-derived (the source stays PRESENT, so build_coverage_
    # report's own derivation path -- the only thing that ever sets
    # scope -- never reaches this code) -- no legitimate use for it.
    with pytest.raises(ValueError, match="scope"):
        CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED,
                            source="requested_region", scope="dump")


def test_build_coverage_report_with_region_read_truncated_completeness_check_is_partial():
    source = SourceObservation(name="requested_region", state=SourceState.PRESENT, record_count=1)
    limitation = CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED,
                                     source="requested_region")
    report = build_coverage_report(
        {"requested_region": source},
        evaluation_sources=("requested_region",),
        completeness_checks=["requested_region", limitation])
    assert report.status == "partial"
    assert report.sources["requested_region"].state == SourceState.PRESENT
    assert report.limitations == [limitation]


@pytest.mark.parametrize("field_name,kwargs", [
    ("counterpart_source", dict(counterpart_source="threads")),
    ("affected_count", dict(affected_count=1)),
    ("unavailable_fields", dict(unavailable_fields=("X",))),
    ("available_fields", dict(available_fields=("X",))),
    ("related_sources", dict(related_sources=("a", "b"))),
    ("related_tids", dict(related_tids=(1,))),
    ("thread_id", dict(thread_id=1)),
    ("detail", dict(detail="x")),
])
def test_coverage_limitation_peb_unavailable_rejects_every_unrelated_field(field_name, kwargs):
    with pytest.raises(ValueError, match=field_name):
        CoverageLimitation(code=LimitationCode.PEB_UNAVAILABLE, source="peb", **kwargs)


def test_coverage_limitation_source_key_mismatch_rejects_related_tids():
    # SOURCE_KEY_MISMATCH is caller_buildable like the PID fallback codes,
    # but shares none of their fields -- related_tids belongs only to
    # PID_THREAD_LIST_FALLBACK.
    with pytest.raises(ValueError, match="related_tids"):
        CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="a", related_tids=(1,))


def test_coverage_limitation_source_group_absent_rejects_affected_count():
    with pytest.raises(ValueError, match="affected_count"):
        CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="a",
                            related_sources=("a", "b"), affected_count=1)


def test_coverage_limitation_sysinfo_fixed_text_code_rejects_detail():
    with pytest.raises(ValueError, match="detail"):
        CoverageLimitation(code=LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE, source="misc_info",
                            detail="should not be allowed")


# ── SOURCE_ABSENT: field-combination validation (review round 2, P2) ─────
# allowed_fields alone only says WHICH fields a code may touch, not which
# COMBINATIONS are coherent -- affected_count/available_fields only mean
# anything paired with their counterpart field, and counterpart_source
# claims a fact about another source that must be independently checked
# against that source's own real state.

def test_coverage_limitation_source_absent_rejects_affected_count_without_counterpart():
    with pytest.raises(ValueError, match="counterpart_source"):
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules", affected_count=3)


def test_coverage_limitation_source_absent_rejects_available_fields_without_unavailable_fields():
    with pytest.raises(ValueError, match="unavailable_fields"):
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules",
                            available_fields=("TID",))


def test_coverage_limitation_source_absent_rejects_source_equal_to_counterpart():
    with pytest.raises(ValueError, match="counterpart_source"):
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="modules",
                            counterpart_source="modules")


def test_build_coverage_report_rejects_source_absent_counterpart_not_actually_present():
    # SourceRequirement's counterpart_source claims "N present in
    # COUNTERPART but missing from SOURCE" -- if the counterpart is
    # itself absent (tells us nothing, contradicts the claim outright),
    # that must be caught, not silently rendered as a confident count.
    modules_obs = SourceObservation(name="modules", state=SOURCE_ABSENT)
    other_obs = SourceObservation(name="other", state=SOURCE_ABSENT)
    req = SourceRequirement("modules", counterpart_source="other", affected_count=2)
    with pytest.raises(ValueError, match="not present"):
        build_coverage_report({"modules": modules_obs, "other": other_obs},
                               completeness_checks=[req])


def test_build_coverage_report_allows_source_absent_with_counterpart_genuinely_present():
    modules_obs = SourceObservation(name="modules", state=SOURCE_ABSENT)
    other_obs = SourceObservation(name="other", state=SOURCE_PRESENT, record_count=2)
    req = SourceRequirement("modules", counterpart_source="other", affected_count=2)
    report = build_coverage_report({"modules": modules_obs, "other": other_obs},
                                    completeness_checks=[req])
    assert report.status == COVERAGE_PARTIAL


def test_build_coverage_report_rejects_source_absent_affected_count_mismatching_counterpart():
    # source is entirely absent -- EVERY record in a genuinely-present
    # counterpart is, by definition, affected. affected_count is never
    # derived from counterpart_obs.record_count automatically (it's
    # whatever the caller passed), so nothing else keeps the two in sync.
    modules_obs = SourceObservation(name="modules", state=SOURCE_ABSENT)
    other_obs = SourceObservation(name="other", state=SOURCE_PRESENT, record_count=2)
    req = SourceRequirement("modules", counterpart_source="other", affected_count=99)
    with pytest.raises(ValueError, match="record_count"):
        build_coverage_report({"modules": modules_obs, "other": other_obs},
                               completeness_checks=[req])


def test_build_coverage_report_derives_affected_count_from_counterpart_when_omitted():
    # affected_count is optional with a real counterpart_source -- the
    # reducer DERIVES the exact count from counterpart_obs.record_count
    # rather than leaving it None (source is entirely absent, so every
    # one of the counterpart's records is, by definition, affected).
    # scope stays None when the caller doesn't supply one (no forced
    # "dump" default in this branch), so the rendered text falls back to
    # the renderer's own generic "item" wording.
    modules_obs = SourceObservation(name="modules", state=SOURCE_ABSENT)
    other_obs = SourceObservation(name="other", state=SOURCE_PRESENT, record_count=2)
    req = SourceRequirement("modules", counterpart_source="other")
    report = build_coverage_report({"modules": modules_obs, "other": other_obs},
                                    completeness_checks=[req])
    assert report.status == COVERAGE_PARTIAL
    limitation = report.limitations[0]
    assert limitation.affected_count == 2
    assert limitation.scope is None
    assert report.reasons == ["2 item(s) present in other but missing from ModuleListStream"]


def test_coverage_limitation_source_absent_rejects_available_fields_with_counterpart_source():
    # Exact repro from review round 3: _render_source_absent branches on
    # counterpart_source FIRST, so available_fields is silently ignored
    # whenever it's set, regardless of unavailable_fields also being set.
    with pytest.raises(ValueError, match="counterpart_source"):
        CoverageLimitation(code=LIMITATION_SOURCE_ABSENT, source="threads",
                            counterpart_source="thread_info",
                            unavailable_fields=("StartAddress",), available_fields=("TID",))


def test_coverage_limitation_scope_allowed_for_auto_derived_fixed_sentence_code():
    # Unlike PID_NO_USABLE_FALLBACK (never auto-derived, never allows
    # scope -- see above), SYSINFO_MISC_INFO_UNAVAILABLE IS reached via
    # SourceRequirement -> _derive_required_source_limitation, which
    # unconditionally sets scope="dump" regardless of code -- so it must
    # allow scope even though its own renderer never reads it either.
    limitation = CoverageLimitation(code=LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE,
                                     source="misc_info", scope="dump")
    assert limitation.scope == "dump"


def test_build_coverage_report_allows_pid_fallback_codes_with_absent_source():
    # Unlike SOURCE_KEY_MISMATCH, PID_THREAD_LIST_FALLBACK's source
    # (misc_info) is EXPECTED to not have yielded a usable PID -- that's
    # the fallback's entire trigger condition, not an error.
    misc_info_obs = SourceObservation(name="misc_info", state=SOURCE_ABSENT)
    threads_obs = SourceObservation(name="threads", state=SOURCE_PRESENT, record_count=1)
    limitation = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                                     counterpart_source="threads", related_tids=(1,))
    report = build_coverage_report({"misc_info": misc_info_obs, "threads": threads_obs},
                                    completeness_checks=[limitation])
    assert report.status == COVERAGE_PARTIAL


def test_evaluation_requirement_pid_sources_absent_valid_for_three_sources():
    req = EvaluationRequirement(sources=("misc_info", "threads", "exception"),
                                 all_absent_code=LimitationCode.PID_SOURCES_ABSENT)
    assert req.all_absent_code == LimitationCode.PID_SOURCES_ABSENT


def test_evaluation_requirement_rejects_pid_sources_absent_with_wrong_source_set():
    # PID_SOURCES_ABSENT's sentence names MiscInfo/thread list/exception
    # stream specifically -- any other 2+ source combination must not be
    # allowed to select it (it would render a sentence naming streams
    # that aren't the ones actually being described).
    with pytest.raises(ValueError, match="PID_SOURCES_ABSENT"):
        EvaluationRequirement(sources=("a", "b"), all_absent_code=LimitationCode.PID_SOURCES_ABSENT)


def test_coverage_limitation_pid_sources_absent_requires_exact_related_sources():
    with pytest.raises(ValueError, match="PID_SOURCES_ABSENT"):
        CoverageLimitation(code=LimitationCode.PID_SOURCES_ABSENT, source="misc_info",
                            related_sources=("a", "b"))


def test_coverage_limitation_pid_sources_absent_requires_source_consistent_with_related_sources():
    # related_sources alone being correct isn't enough -- `source` must
    # also agree with it, or the object is internally self-contradictory
    # even though nothing in the normal reducer path would ever produce it.
    with pytest.raises(ValueError, match="misc_info"):
        CoverageLimitation(code=LimitationCode.PID_SOURCES_ABSENT, source="wrong",
                            related_sources=("misc_info", "threads", "exception"))


def test_coverage_limitation_pid_thread_list_fallback_requires_correct_source():
    with pytest.raises(ValueError, match="misc_info"):
        CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="threads",
                            counterpart_source="threads", related_tids=(1,))


def test_coverage_limitation_pid_thread_list_fallback_requires_correct_counterpart():
    with pytest.raises(ValueError, match="counterpart_source"):
        CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                            counterpart_source="exception", related_tids=(1,))


def test_coverage_limitation_pid_thread_list_fallback_rejects_non_integer_tid():
    with pytest.raises(ValueError, match="positive integers"):
        CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                            counterpart_source="threads", related_tids=("x",))


def test_coverage_limitation_pid_thread_list_fallback_rejects_negative_tid():
    with pytest.raises(ValueError, match="positive integers"):
        CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                            counterpart_source="threads", related_tids=(-1,))


def test_coverage_limitation_pid_exception_tid_fallback_requires_correct_source():
    with pytest.raises(ValueError, match="exception"):
        CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="threads",
                            thread_id=9)


def test_coverage_limitation_pid_exception_tid_fallback_rejects_non_integer():
    with pytest.raises(ValueError, match="positive integer"):
        CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception",
                            thread_id="x")


def test_coverage_limitation_rejects_related_tids_on_non_matching_code():
    with pytest.raises(ValueError, match="related_tids"):
        CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception",
                            thread_id=9, related_tids=(1, 2))


def test_coverage_limitation_rejects_thread_id_on_non_matching_code():
    with pytest.raises(ValueError, match="thread_id"):
        CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                            counterpart_source="threads", related_tids=(1,), thread_id=9)


def test_build_coverage_report_rejects_pid_thread_list_fallback_when_threads_absent():
    misc_info_obs = SourceObservation(name="misc_info", state=SOURCE_ABSENT)
    threads_obs = SourceObservation(name="threads", state=SOURCE_ABSENT)
    limitation = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                                     counterpart_source="threads", related_tids=(1,))
    with pytest.raises(ValueError, match="requires threads to be present"):
        build_coverage_report({"misc_info": misc_info_obs, "threads": threads_obs},
                               completeness_checks=[limitation])


def test_build_coverage_report_rejects_pid_thread_list_fallback_count_mismatch():
    misc_info_obs = SourceObservation(name="misc_info", state=SOURCE_ABSENT)
    threads_obs = SourceObservation(name="threads", state=SOURCE_PRESENT, record_count=3)
    limitation = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                                     counterpart_source="threads", related_tids=(1, 2))   # only 2, not 3
    with pytest.raises(ValueError, match="record_count"):
        build_coverage_report({"misc_info": misc_info_obs, "threads": threads_obs},
                               completeness_checks=[limitation])


def test_build_coverage_report_rejects_pid_exception_tid_fallback_when_exception_absent():
    exception_obs = SourceObservation(name="exception", state=SOURCE_ABSENT)
    limitation = CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception",
                                     thread_id=9)
    with pytest.raises(ValueError, match="requires exception to be present"):
        build_coverage_report({"exception": exception_obs}, completeness_checks=[limitation])


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


def test_build_coverage_report_rejects_key_mismatch_with_absent_source():
    # A mismatch claims both sides are genuinely present but disagree on
    # keys -- if `source` is actually ABSENT, that's not a mismatch, it's
    # an absence, and must go through SourceRequirement auto-derivation
    # (the exact bug the threads-absent fix closed) instead of being
    # smuggled in as a hand-built SOURCE_KEY_MISMATCH.
    obs_a = SourceObservation(name="a", state=SOURCE_ABSENT)
    obs_b = SourceObservation(name="b", state=SOURCE_PRESENT, record_count=1)
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="a",
                                     counterpart_source="b", affected_count=1)
    with pytest.raises(ValueError, match="a.*absent"):
        build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[limitation])


def test_build_coverage_report_rejects_key_mismatch_with_failed_source():
    obs_a = SourceObservation(name="a", state=SOURCE_FAILED)
    obs_b = SourceObservation(name="b", state=SOURCE_PRESENT, record_count=1)
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="a",
                                     counterpart_source="b")
    with pytest.raises(ValueError, match="a.*failed"):
        build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[limitation])


def test_build_coverage_report_rejects_key_mismatch_with_absent_counterpart():
    obs_a = SourceObservation(name="a", state=SOURCE_PRESENT, record_count=1)
    obs_b = SourceObservation(name="b", state=SOURCE_ABSENT)
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="a",
                                     counterpart_source="b", affected_count=1)
    with pytest.raises(ValueError, match="b.*absent"):
        build_coverage_report({"a": obs_a, "b": obs_b}, completeness_checks=[limitation])


def test_build_coverage_report_rejects_key_mismatch_with_zero_affected_count():
    # Now caught at CoverageLimitation construction time itself (a
    # generic, code-independent invariant) rather than only once it
    # reaches build_coverage_report -- fails at the earliest possible
    # point instead of letting an invalid object exist even transiently.
    with pytest.raises(ValueError, match="affected_count"):
        CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="a",
                            affected_count=0)


def test_build_coverage_report_rejects_key_mismatch_with_negative_affected_count():
    with pytest.raises(ValueError, match="affected_count"):
        CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="a",
                            affected_count=-1)


def test_build_coverage_report_accepts_key_mismatch_with_none_affected_count():
    # None ("some item(s)...") remains legitimate -- only a given
    # non-positive count is rejected.
    obs_a = SourceObservation(name="a", state=SOURCE_PRESENT, record_count=1)
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_KEY_MISMATCH, source="a")
    report = build_coverage_report({"a": obs_a}, completeness_checks=[limitation])
    assert report.reasons == ["some item(s) missing from a"]


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


def test_render_limitation_source_failed_with_unavailable_fields():
    # comparison.py's thread diff customizes a FAILED target.modules this
    # way (scope="thread" + unavailable_fields) -- same wording convention
    # SOURCE_ABSENT's own unavailable_fields clause already uses.
    limitation = CoverageLimitation(
        code=LIMITATION_SOURCE_FAILED, source="modules", scope="thread", detail="boom",
        unavailable_fields=("backing_module_after", "backing_module_context"))
    assert render_limitation(limitation) == (
        "ModuleListStream present but could not be read: boom; "
        "backing_module_after/backing_module_context unavailable")


def test_render_limitation_source_failed_with_unavailable_and_available_fields():
    limitation = CoverageLimitation(
        code=LIMITATION_SOURCE_FAILED, source="modules", scope="thread",
        unavailable_fields=("backing_module_after",), available_fields=("tid",))
    assert render_limitation(limitation) == (
        "ModuleListStream present but could not be read; "
        "backing_module_after unavailable (tid only)")


def test_coverage_limitation_source_failed_rejects_available_fields_without_unavailable():
    with pytest.raises(ValueError, match="requires unavailable_fields"):
        CoverageLimitation(code=LIMITATION_SOURCE_FAILED, source="modules",
                            available_fields=("tid",))


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


# ── _display_name: dotted entity-namespaced source names (Phase C, PR2) ──
# Introduced for a future comparison command's "baseline.modules"/
# "target.modules"-style source names -- none of today's six recon
# commands' source names contain a literal ".", so this is a pure
# extension for them.

def test_display_name_bare_source_unchanged():
    assert _display_name("modules") == "ModuleListStream"


def test_display_name_bare_unknown_source_falls_back_to_raw_string():
    assert _display_name("totally_unknown") == "totally_unknown"


def test_display_name_dotted_known_suffix_renders_prefixed():
    assert _display_name("baseline.modules") == "baseline ModuleListStream"
    assert _display_name("target.thread_info") == "target ThreadInfoListStream"


def test_display_name_dotted_unknown_suffix_falls_back_to_raw_string():
    # Only a RECOGNIZED suffix is re-derived -- an unknown one is never
    # guessed at (no blanket dot-to-space replacement).
    assert _display_name("baseline.custom_source") == "baseline.custom_source"


# ── build_coverage_report: evaluation_groups (Phase C, PR2) ─────────────
# Multiple INDEPENDENT single-source groups, each evaluated on its own --
# the comparison-command shape, where "baseline.modules" being entirely
# absent must make the whole entity not_evaluated even if
# "target.modules" is present, with its OWN distinguishable limitation
# (not merged into one group-level fact naming only one side).

def test_evaluation_groups_rejects_evaluation_sources_together():
    obs = SourceObservation(name="a", state=SOURCE_ABSENT)
    with pytest.raises(ValueError, match="at most one"):
        build_coverage_report({"a": obs}, evaluation_sources=("a",),
                               evaluation_groups=[EvaluationRequirement(("a",))])


def test_evaluation_groups_rejects_non_list_tuple():
    obs = SourceObservation(name="a", state=SOURCE_ABSENT)
    with pytest.raises(TypeError, match="list or tuple"):
        build_coverage_report({"a": obs}, evaluation_groups=EvaluationRequirement(("a",)))


def test_evaluation_groups_rejects_non_evaluation_requirement_entries():
    obs = SourceObservation(name="a", state=SOURCE_ABSENT)
    with pytest.raises(TypeError, match="EvaluationRequirement"):
        build_coverage_report({"a": obs}, evaluation_groups=[("a",)])


def test_evaluation_groups_one_group_absent_other_present_is_not_evaluated_with_one_limitation():
    baseline_absent = SourceObservation(name="baseline.modules", state=SOURCE_ABSENT)
    target_present = SourceObservation(name="target.modules", state=SOURCE_PRESENT, record_count=3)
    report = build_coverage_report(
        {"baseline.modules": baseline_absent, "target.modules": target_present},
        evaluation_groups=[EvaluationRequirement(("baseline.modules",)),
                            EvaluationRequirement(("target.modules",))])
    assert report.status == COVERAGE_NOT_EVALUATED
    assert len(report.limitations) == 1
    assert report.limitations[0].source == "baseline.modules"
    assert report.reasons == ["baseline ModuleListStream not present in this dump"]


def test_evaluation_groups_both_absent_produces_two_distinct_limitations():
    baseline_absent = SourceObservation(name="baseline.modules", state=SOURCE_ABSENT)
    target_absent = SourceObservation(name="target.modules", state=SOURCE_ABSENT)
    report = build_coverage_report(
        {"baseline.modules": baseline_absent, "target.modules": target_absent},
        evaluation_groups=[EvaluationRequirement(("baseline.modules",)),
                            EvaluationRequirement(("target.modules",))])
    assert report.status == COVERAGE_NOT_EVALUATED
    assert [l.source for l in report.limitations] == ["baseline.modules", "target.modules"]
    assert report.reasons == [
        "baseline ModuleListStream not present in this dump",
        "target ModuleListStream not present in this dump",
    ]


def test_evaluation_groups_neither_absent_is_evaluated_normally():
    baseline_present = SourceObservation(name="baseline.modules", state=SOURCE_PRESENT_EMPTY,
                                          record_count=0)
    target_present = SourceObservation(name="target.modules", state=SOURCE_PRESENT, record_count=5)
    report = build_coverage_report(
        {"baseline.modules": baseline_present, "target.modules": target_present},
        evaluation_groups=[EvaluationRequirement(("baseline.modules",)),
                            EvaluationRequirement(("target.modules",))])
    assert report.status == COVERAGE_COMPLETE
    assert report.limitations == []


def test_evaluation_groups_empty_list_is_evaluated_normally():
    obs = SourceObservation(name="a", state=SOURCE_ABSENT)
    report = build_coverage_report({"a": obs}, evaluation_groups=[])
    assert report.status == COVERAGE_COMPLETE
    assert report.limitations == []


@pytest.mark.parametrize("state,record_count", [
    (SOURCE_ABSENT, None), (SOURCE_PRESENT_EMPTY, 0), (SOURCE_PRESENT, 3),
])
def test_evaluation_groups_single_group_matches_equivalent_evaluation_sources_call(
        state, record_count):
    # Backward-compat proof: evaluation_groups=[single group] must desugar
    # to the IDENTICAL CoverageReport a bare evaluation_sources call
    # produces, across every source state -- the multi-group
    # generalization must not change today's single-group behavior at all.
    obs = SourceObservation(name="memory_info", state=state, record_count=record_count)
    via_sources = build_coverage_report({"memory_info": obs}, evaluation_sources=("memory_info",),
                                         completeness_checks=["memory_info"])
    via_groups = build_coverage_report(
        {"memory_info": obs}, evaluation_groups=[EvaluationRequirement(("memory_info",))],
        completeness_checks=["memory_info"])
    assert via_sources.status == via_groups.status
    assert via_sources.reasons == via_groups.reasons
    assert ([l.to_dict() for l in via_sources.limitations]
            == [l.to_dict() for l in via_groups.limitations])


# ── combine_coverage_reports (Phase C, PR2) ──────────────────────────────
# Pure cross-entity reduction, e.g. a future comparison command's
# --diff-scope all combining collect_module_diff/collect_thread_diff/
# collect_memory_diff's three independent CoverageReports into one.

def _report(status, source_name="x", record_count=1):
    if status == COVERAGE_NOT_EVALUATED:
        obs = SourceObservation(name=source_name, state=SOURCE_ABSENT)
        return build_coverage_report({source_name: obs}, evaluation_sources=(source_name,))
    obs = SourceObservation(name=source_name, state=SOURCE_PRESENT, record_count=record_count)
    if status == COVERAGE_COMPLETE:
        return build_coverage_report({source_name: obs})
    # PARTIAL: the named source is present, but another required source
    # (this report's own, non-shared "other" companion) is absent.
    absent_name = source_name + "_other"
    absent_obs = SourceObservation(name=absent_name, state=SOURCE_ABSENT)
    return build_coverage_report(
        {source_name: obs, absent_name: absent_obs}, completeness_checks=[absent_name])


def test_combine_coverage_reports_rejects_empty_list():
    with pytest.raises(ValueError, match="at least one"):
        combine_coverage_reports([])


def test_combine_coverage_reports_unanimous_not_evaluated_is_not_evaluated():
    combined = combine_coverage_reports([
        _report(COVERAGE_NOT_EVALUATED, "a"), _report(COVERAGE_NOT_EVALUATED, "b")])
    assert combined.status == COVERAGE_NOT_EVALUATED


def test_combine_coverage_reports_unanimous_complete_is_complete():
    combined = combine_coverage_reports([
        _report(COVERAGE_COMPLETE, "a"), _report(COVERAGE_COMPLETE, "b")])
    assert combined.status == COVERAGE_COMPLETE


def test_combine_coverage_reports_one_not_evaluated_among_complete_is_partial_not_not_evaluated():
    # The confirmed cross-entity rule: one weak entity among otherwise-
    # fine ones must not drag the whole result down to not_evaluated --
    # unanimity is required for not_evaluated.
    combined = combine_coverage_reports([
        _report(COVERAGE_NOT_EVALUATED, "a"), _report(COVERAGE_COMPLETE, "b")])
    assert combined.status == COVERAGE_PARTIAL


def test_combine_coverage_reports_mixed_partial_and_complete_is_partial():
    combined = combine_coverage_reports([
        _report(COVERAGE_PARTIAL, "a"), _report(COVERAGE_COMPLETE, "b")])
    assert combined.status == COVERAGE_PARTIAL


def test_combine_coverage_reports_merges_sources_and_concatenates_limitations_in_order():
    combined = combine_coverage_reports([
        _report(COVERAGE_NOT_EVALUATED, "a"), _report(COVERAGE_NOT_EVALUATED, "b")])
    assert set(combined.sources) == {"a", "b"}
    assert [l.source for l in combined.limitations] == ["a", "b"]


def test_combine_coverage_reports_allows_identical_duplicate_source_observation():
    # The SAME physical source can legitimately be read by more than one
    # entity's collector (e.g. a comparison's thread diff also consults
    # target.modules to resolve a backing module, the same stream the
    # module diff itself already reads as its own primary source) --
    # two reports naming it identically must merge cleanly, not collide.
    r1 = _report(COVERAGE_COMPLETE, "shared", record_count=3)
    r2 = _report(COVERAGE_COMPLETE, "shared", record_count=3)
    combined = combine_coverage_reports([r1, r2])
    assert combined.sources["shared"].record_count == 3


def test_combine_coverage_reports_rejects_conflicting_source_observation():
    # Two reports naming the SAME source but disagreeing on its state is
    # a real bug (the same underlying stream can't disagree with itself)
    # -- unlike the identical-duplicate case above, this must be rejected
    # rather than letting one silently overwrite the other.
    r1 = _report(COVERAGE_COMPLETE, "shared", record_count=1)
    r2 = _report(COVERAGE_COMPLETE, "shared", record_count=2)
    with pytest.raises(ValueError, match="conflicting"):
        combine_coverage_reports([r1, r2])


def test_combine_coverage_reports_deduplicates_identical_limitations():
    # Two entities independently reading the SAME physical FAILED source
    # (e.g. a comparison's module diff and thread diff both attempting
    # target.modules) derive the exact same CoverageLimitation from it --
    # SOURCE_FAILED's rendered text never varies by scope (unlike SOURCE_
    # ABSENT, which a caller CAN differentiate via unavailable_fields/a
    # custom scope). A byte-identical limitation is one fact, not two, and
    # must not be reported twice.
    obs = SourceObservation(name="shared", state=SourceState.FAILED, detail="boom")
    r1 = build_coverage_report({"shared": obs}, completeness_checks=["shared"])
    r2 = build_coverage_report({"shared": obs}, completeness_checks=["shared"])
    combined = combine_coverage_reports([r1, r2])
    assert len(combined.limitations) == 1
    assert combined.limitations[0].code == LimitationCode.SOURCE_FAILED


def test_combine_coverage_reports_preserves_distinct_limitations_for_shared_source():
    # The dedup above must never conflate two GENUINELY different facts
    # about the same source -- e.g. module diff's plain SOURCE_ABSENT vs
    # thread diff's own differentiated one (custom scope/unavailable_
    # fields, exactly comparison.py's own target.modules pattern) both
    # survive, since they are not equal as CoverageLimitation values.
    absent_obs = SourceObservation(name="shared", state=SourceState.ABSENT)
    other_obs = SourceObservation(name="other", state=SourceState.PRESENT, record_count=1)
    r1 = build_coverage_report(
        {"shared": absent_obs}, completeness_checks=["shared"])
    r2 = build_coverage_report(
        {"shared": absent_obs, "other": other_obs},
        completeness_checks=[SourceRequirement(
            "shared", scope="thread", unavailable_fields=("x",))])
    combined = combine_coverage_reports([r1, r2])
    assert len(combined.limitations) == 2
    assert {l.scope for l in combined.limitations} == {"dump", "thread"}


def test_build_coverage_report_surfaces_failed_source_even_when_another_group_not_evaluated():
    # A FAILED source outside every all-absent evaluation group must not
    # silently vanish just because a DIFFERENT group's plain absence
    # already short-circuits the result to not_evaluated -- sources[name]
    # still records state=FAILED either way, but limitations/reasons
    # (and therefore the console/JSON) previously never mentioned the
    # read failure at all in this combination.
    baseline_obs = SourceObservation(name="baseline.x", state=SourceState.FAILED, detail="boom")
    target_obs = SourceObservation(name="target.x", state=SourceState.ABSENT)
    coverage = build_coverage_report(
        {"baseline.x": baseline_obs, "target.x": target_obs},
        evaluation_groups=[EvaluationRequirement(("baseline.x",)),
                            EvaluationRequirement(("target.x",))],
        completeness_checks=["baseline.x", "target.x"],
    )
    assert coverage.status == COVERAGE_NOT_EVALUATED
    codes_and_sources = {(l.code, l.source) for l in coverage.limitations}
    assert codes_and_sources == {
        (LimitationCode.SOURCE_ABSENT, "target.x"),
        (LimitationCode.SOURCE_FAILED, "baseline.x"),
    }


def test_build_coverage_report_not_evaluated_never_duplicates_absent_source_as_failed_check():
    # The FAILED-surfacing fix above must stay scoped to FAILED only -- an
    # ABSENT completeness_check source is already fully represented by
    # the group's own SOURCE_ABSENT limitation; re-deriving it a second
    # time here would just duplicate that same fact.
    obs = SourceObservation(name="x", state=SourceState.ABSENT)
    coverage = build_coverage_report(
        {"x": obs}, evaluation_sources=("x",), completeness_checks=["x"])
    assert coverage.status == COVERAGE_NOT_EVALUATED
    assert len(coverage.limitations) == 1


# ── REPORT_STRING_SCAN_INCOMPLETE / REPORT_STRING_SCAN_TRUNCATED
#    (RevFix2-P1a) ─────────────────────────────────────────────────────────
# Distinct codes/wording for two distinct facts about --report-string's
# own memory-wide scan: INCOMPLETE is regions skipped entirely (couldn't
# read anything); TRUNCATED is regions read but only partially (bytes
# read < bytes requested) -- see dumpex.commands.report.StringSearchStats'
# own docstring for why these must never share one limitation.

def test_coverage_limitation_report_string_scan_incomplete_rejects_wrong_source():
    with pytest.raises(ValueError, match="string_search"):
        CoverageLimitation(code=LimitationCode.REPORT_STRING_SCAN_INCOMPLETE,
                            source="wrong_source", affected_count=3)


def test_coverage_limitation_report_string_scan_truncated_rejects_wrong_source():
    with pytest.raises(ValueError, match="string_search"):
        CoverageLimitation(code=LimitationCode.REPORT_STRING_SCAN_TRUNCATED,
                            source="wrong_source", affected_count=3)


def test_coverage_limitation_report_string_scan_incomplete_valid_shape_accepted():
    limitation = CoverageLimitation(
        code=LimitationCode.REPORT_STRING_SCAN_INCOMPLETE, source="string_search",
        affected_count=3)
    assert "skipped 3 region(s) it could not read" in render_limitation(limitation)


def test_coverage_limitation_report_string_scan_incomplete_rejects_missing_affected_count():
    # affected_count=None passes the GENERIC shape check (None is a valid
    # affected_count in general -- most codes never set it), so this
    # code's own validate_fields hook is what specifically requires a
    # real count here (a "some regions were skipped" fact with no count
    # at all would be meaningless for this code).
    with pytest.raises(ValueError, match="REPORT_STRING_SCAN_INCOMPLETE.*positive integer"):
        CoverageLimitation(code=LimitationCode.REPORT_STRING_SCAN_INCOMPLETE, source="string_search")


def test_coverage_limitation_report_string_scan_truncated_valid_shape_accepted():
    limitation = CoverageLimitation(
        code=LimitationCode.REPORT_STRING_SCAN_TRUNCATED, source="string_search",
        affected_count=2)
    assert "only partially read 2 region(s)" in render_limitation(limitation)


def test_coverage_limitation_report_string_scan_truncated_rejects_missing_affected_count():
    with pytest.raises(ValueError, match="REPORT_STRING_SCAN_TRUNCATED.*positive integer"):
        CoverageLimitation(code=LimitationCode.REPORT_STRING_SCAN_TRUNCATED, source="string_search")


def test_coverage_limitation_report_string_scan_truncated_rejects_non_positive_affected_count():
    # Caught by the generic affected_count shape check (shared across
    # every code), not this code's own validate_fields hook -- still a
    # ValueError either way, just a different message than the "missing"
    # case above.
    with pytest.raises(ValueError, match="positive int"):
        CoverageLimitation(code=LimitationCode.REPORT_STRING_SCAN_TRUNCATED,
                            source="string_search", affected_count=0)


# ── v2.4 hunt migration (PR2a): PE_HEADER_READ_FAILED/_SHORT_READ, ────────
# THREAD_CONTEXT_UNAVAILABLE/_PARTIAL

def test_pe_header_read_failed_renders_and_validates():
    limitation = CoverageLimitation(
        code=LimitationCode.PE_HEADER_READ_FAILED, source="hidden_pe_scan", affected_count=2)
    assert render_limitation(limitation) == (
        "2 region(s) failed to read while checking for hidden PE headers")


def test_pe_header_read_failed_rejects_non_positive_affected_count():
    with pytest.raises(ValueError, match="positive int"):
        CoverageLimitation(code=LimitationCode.PE_HEADER_READ_FAILED,
                            source="hidden_pe_scan", affected_count=0)


def test_pe_header_short_read_renders_and_validates():
    limitation = CoverageLimitation(
        code=LimitationCode.PE_HEADER_SHORT_READ, source="hidden_pe_scan", affected_count=1)
    assert render_limitation(limitation) == (
        "1 region(s) returned fewer bytes than requested while checking for hidden PE "
        "headers (short read) -- not fully examined")


def test_pe_header_short_read_rejects_non_positive_affected_count():
    with pytest.raises(ValueError, match="positive int"):
        CoverageLimitation(code=LimitationCode.PE_HEADER_SHORT_READ,
                            source="hidden_pe_scan", affected_count=-1)


def test_thread_context_unavailable_renders_fixed_sentence():
    limitation = CoverageLimitation(
        code=LimitationCode.THREAD_CONTEXT_UNAVAILABLE, source="thread_context")
    assert render_limitation(limitation) == (
        "No per-thread CONTEXT (RIP/EIP) available -- live-execution correlation "
        "could not run")


def test_thread_context_unavailable_selectable_as_source_requirement_absent_code():
    sources = {"thread_context": observe_source("thread_context", present=False)}
    report = build_coverage_report(
        sources, completeness_checks=[SourceRequirement(
            source="thread_context",
            absent_code=LimitationCode.THREAD_CONTEXT_UNAVAILABLE)])
    assert report.status == CoverageStatus.PARTIAL
    assert report.limitations[0].code == LimitationCode.THREAD_CONTEXT_UNAVAILABLE


def test_thread_context_partial_renders_and_validates():
    limitation = CoverageLimitation(
        code=LimitationCode.THREAD_CONTEXT_PARTIAL, source="thread_context", affected_count=3)
    assert render_limitation(limitation) == (
        "3 thread(s) had no parsed CONTEXT -- live-execution correlation ran, but not "
        "for every thread")


def test_thread_context_partial_rejects_non_positive_affected_count():
    with pytest.raises(ValueError, match="positive int"):
        CoverageLimitation(code=LimitationCode.THREAD_CONTEXT_PARTIAL,
                            source="thread_context", affected_count=0)


# ── ScanTarget / SCAN_REGION_OVERSIZED_SKIPPED targets ────────────────────
# The typed skipped-target reference (schema_version 2.8): a limitation
# saying a scan skipped something must name WHAT it skipped, or a "partial"
# result gives an investigator nothing to act on.

def _region_target(base=0x1000, size=32 * 1024, limit=16 * 1024, **kw):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                       size=size, size_limit=limit, **kw)


def test_scan_target_to_dict_uses_fixed_width_hex_and_byte_offsets():
    target = _region_target(base=0x7ff000001000, file_offset=4096,
                             allocation_base=0x7ff000000000, state="MEM_COMMIT",
                             type="MEM_PRIVATE", protection="PAGE_EXECUTE_READWRITE")
    assert target.to_dict() == {
        "kind": "memory_region",
        "base_address": "0x00007ff000001000",
        "size": 32 * 1024,
        "size_limit": 16 * 1024,
        # A position inside the .dmp file, not an address -- stays a plain
        # int rather than being hex-formatted like the two addresses above.
        "file_offset": 4096,
        "allocation_base": "0x00007ff000000000",
        "state": "MEM_COMMIT",
        "type": "MEM_PRIVATE",
        "protection": "PAGE_EXECUTE_READWRITE",
        "captured_size": None,
        "capture_state": None,
    }


def test_scan_target_hex_matches_the_records_module_hex_convention():
    # coverage.py cannot import records.py (records.py imports THIS
    # module), so its address formatter is a deliberate second copy --
    # this is what keeps the two from drifting.
    target = _region_target(base=0x7ff000001000, allocation_base=0x40)
    assert target.to_dict()["base_address"] == hex_address(0x7ff000001000)
    assert target.to_dict()["allocation_base"] == hex_address(0x40)


def test_scan_target_accepts_the_maximum_legal_uint64_address():
    # 0xffffffffffffffff is the largest value _hex_address()'s
    # f"0x{n:016x}" still renders as exactly 16 hex digits -- the
    # boundary the schema's hexAddress pattern (^0x[0-9a-f]{16}$) itself
    # draws. Must construct cleanly and round-trip through to_dict().
    max_addr = 0xffffffffffffffff
    target = _region_target(base=max_addr, allocation_base=max_addr)
    d = target.to_dict()
    assert d["base_address"] == "0xffffffffffffffff"
    assert d["allocation_base"] == "0xffffffffffffffff"
    assert len(d["base_address"]) == len(d["allocation_base"]) == 18   # "0x" + 16 hex digits


def test_scan_target_rejects_the_first_illegal_address_past_uint64_max():
    # One past the boundary: _hex_address() would render 17 hex digits,
    # which fails the schema's own hexAddress pattern downstream -- must
    # be caught here, at construction, not later at serialization/schema
    # validation time.
    over_max = 0xffffffffffffffff + 1
    with pytest.raises(ValueError, match="uint64"):
        _region_target(base=over_max)
    with pytest.raises(ValueError, match="uint64"):
        _region_target(allocation_base=over_max)


def test_scan_target_rejects_negative_addresses():
    with pytest.raises(ValueError, match="uint64"):
        _region_target(base=-1)
    with pytest.raises(ValueError, match="uint64"):
        _region_target(allocation_base=-1)


def test_scan_target_requires_size_to_exceed_its_own_limit():
    # A target that fits inside the cap is evidence AGAINST the oversized
    # skip it would be attached to -- almost always the wrong region.
    with pytest.raises(ValueError, match="must exceed size_limit"):
        _region_target(size=1024, limit=1024)
    with pytest.raises(ValueError, match="must exceed size_limit"):
        _region_target(size=512, limit=1024)


def test_scan_target_size_limit_none_skips_the_oversize_check(): # issue #28
    # A read-failed/short-read/scan-truncated target was never skipped for
    # being oversized -- no cap to compare `size` against, so any size,
    # including one smaller than an ordinary oversize cap, is legal.
    target = _region_target(size=64, limit=None)
    assert target.size_limit is None
    assert target.to_dict()["size_limit"] is None


def test_scan_target_describe_omits_the_limit_clause_when_size_limit_is_none():
    target = _region_target(base=0x1000, size=4096, limit=None)
    described = target.describe()
    assert described == "0x0000000000001000 (4 KB)"
    assert ">" not in described


def test_scan_target_capture_state_none_when_captured_size_not_set():
    target = _region_target()
    assert target.captured_size is None
    assert target.capture_state is None


def test_scan_target_capture_state_none_when_captured_size_is_zero():
    target = _region_target(captured_size=0)
    assert target.capture_state == "none"


def test_scan_target_capture_state_complete_when_captured_size_equals_size():
    target = _region_target(size=4096, limit=None, file_offset=100, captured_size=4096)
    assert target.capture_state == "complete"


def test_scan_target_capture_state_partial_when_captured_size_between_zero_and_size():
    target = _region_target(size=4096, limit=None, file_offset=100, captured_size=1024)
    assert target.capture_state == "partial"


def test_scan_target_rejects_captured_size_larger_than_size():
    with pytest.raises(ValueError, match="must not exceed size"):
        _region_target(size=4096, limit=None, captured_size=4097)


def test_scan_target_rejects_positive_captured_size_with_no_file_offset():
    # captured_size > 0 claims SOME bytes are in the .dmp -- that can only
    # be true if the start address itself resolves to a file offset.
    with pytest.raises(ValueError, match="requires file_offset"):
        ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=4096,
                    captured_size=1024, file_offset=None)


def test_scan_target_to_dict_includes_captured_size_and_capture_state():
    target = _region_target(size=4096, limit=None, file_offset=100, captured_size=2048)
    d = target.to_dict()
    assert d["captured_size"] == 2048
    assert d["capture_state"] == "partial"


def test_memory_segment_target_rejects_memory_info_fields():
    with pytest.raises(ValueError, match="carries no MemoryInfo"):
        ScanTarget(kind=ScanTargetKind.MEMORY_SEGMENT, base_address=0x1000,
                    size=2048, size_limit=1024, state="MEM_COMMIT")
    segment = ScanTarget(kind=ScanTargetKind.MEMORY_SEGMENT, base_address=0x1000,
                          size=2048, size_limit=1024, file_offset=0x200)
    assert segment.to_dict()["state"] is None
    assert segment.to_dict()["file_offset"] == 0x200


def test_oversized_skipped_limitation_requires_targets_that_agree_with_the_count():
    with pytest.raises(ValueError, match="non-empty targets"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="pipe_name_scan", affected_count=1)
    with pytest.raises(ValueError, match=r"must equal len\(targets\)"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="pipe_name_scan", affected_count=2,
                            targets=[_region_target()])


def test_oversized_skipped_limitation_rejects_a_target_with_no_size_limit():
    # A target attached to an oversized-skip limitation but carrying
    # size_limit=None would claim "skipped for being too big" without
    # recording the cap that made it too big -- caught here, at
    # construction, not only later when SkipRelationship rejects it.
    with pytest.raises(ValueError, match="size_limit set"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="pipe_name_scan", affected_count=1,
                            targets=[_region_target(limit=None)])


@pytest.mark.parametrize("code,source", [
    (LimitationCode.SCAN_REGION_READ_FAILED, "pipe_name_scan"),
    (LimitationCode.SCAN_REGION_SHORT_READ, "pipe_name_scan"),
    (LimitationCode.PE_HEADER_READ_FAILED, "hidden_pe_scan"),
    (LimitationCode.PE_HEADER_SHORT_READ, "hidden_pe_scan"),
    (LimitationCode.PE_HEADER_SCAN_TRUNCATED, "hidden_pe_scan"),
    (LimitationCode.PE_HEADER_SCAN_NOT_STARTED, "hidden_pe_scan"),
])
def test_read_failed_family_rejects_a_target_carrying_size_limit(code, source):
    # The inverse of the oversized-skip check above: none of these six
    # causes involves a size cap, so a target claiming one is wrong.
    # `limit` must stay below the target's own default size (32 KB) --
    # ScanTarget itself requires size > size_limit whenever size_limit is
    # set, regardless of which code will end up attached to it.
    with pytest.raises(ValueError, match="size_limit=None"):
        CoverageLimitation(code=code, source=source, affected_count=1,
                            targets=[_region_target(limit=1024)])


def test_targets_are_rejected_on_codes_that_do_not_use_them():
    with pytest.raises(ValueError, match="does not use targets"):
        CoverageLimitation(code=LimitationCode.MODULE_HEADER_READ_FAILED,
                            source="module_headers", affected_count=1,
                            targets=[_region_target()])


# ── targets on the read-failed/short-read/scan-truncated codes (issue #28) ─
# Unlike SCAN_REGION_OVERSIZED_SKIPPED, targets is OPTIONAL on these five --
# a bare affected_count (the pre-#28 shape) stays legal -- but when supplied
# it must still account for every affected item exactly.

@pytest.mark.parametrize("code,source", [
    (LimitationCode.SCAN_REGION_READ_FAILED, "pipe_name_scan"),
    (LimitationCode.SCAN_REGION_SHORT_READ, "pipe_name_scan"),
    (LimitationCode.PE_HEADER_READ_FAILED, "hidden_pe_scan"),
    (LimitationCode.PE_HEADER_SHORT_READ, "hidden_pe_scan"),
    (LimitationCode.PE_HEADER_SCAN_TRUNCATED, "hidden_pe_scan"),
    (LimitationCode.PE_HEADER_SCAN_NOT_STARTED, "hidden_pe_scan"),
])
def test_read_failed_short_read_scan_truncated_targets_are_optional(code, source):
    # Bare count, no targets -- the pre-#28 shape, still legal.
    bare = CoverageLimitation(code=code, source=source, affected_count=2)
    assert bare.targets == ()

    # A read-failed/short-read/scan-truncated target was never oversized --
    # size_limit stays None, unlike an oversized-skip target's own.
    target = _region_target(limit=None)
    with_targets = CoverageLimitation(code=code, source=source, affected_count=1,
                                       targets=[target])
    assert with_targets.targets == (target,)
    assert with_targets.targets[0].size_limit is None


@pytest.mark.parametrize("code,source", [
    (LimitationCode.SCAN_REGION_READ_FAILED, "pipe_name_scan"),
    (LimitationCode.PE_HEADER_READ_FAILED, "hidden_pe_scan"),
])
def test_read_failed_targets_must_match_affected_count_when_non_empty(code, source):
    with pytest.raises(ValueError, match=r"must equal len\(targets\)"):
        CoverageLimitation(code=code, source=source, affected_count=2,
                            targets=[_region_target(limit=None)])


def test_targets_must_be_scan_target_instances_exactly():
    class SneakyTarget(ScanTarget):
        def to_dict(self):
            return {"anything": "at all"}

    with pytest.raises(ValueError, match="only ScanTarget instances"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="pipe_name_scan", affected_count=1,
                            targets=[SneakyTarget(kind=ScanTargetKind.MEMORY_REGION,
                                                    base_address=0x1000, size=2048,
                                                    size_limit=1024)])


def test_oversized_skipped_renders_va_size_and_threshold():
    limitation = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="pipe_name_scan",
        affected_count=1,
        targets=[_region_target(base=0x1000, size=16 * 1024 * 1024,
                                 limit=8 * 1024 * 1024)])
    assert render_limitation(limitation) == (
        "1 oversized region(s) skipped: 0x0000000000001000 (16 MB > 8 MB limit)")


def test_oversized_skipped_names_the_scan_layer_when_scoped():
    limitation = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="encoding_scan",
        scope="decode", affected_count=1,
        targets=[_region_target(base=0x2000, size=4 * 1024 * 1024,
                                 limit=2 * 1024 * 1024)])
    assert render_limitation(limitation) == (
        "1 oversized region(s) skipped by the decode scan: "
        "0x0000000000002000 (4 MB > 2 MB limit)")


def test_oversized_skipped_console_preview_is_bounded_but_json_is_complete():
    targets = [_region_target(base=0x1000 * (i + 1)) for i in range(6)]
    limitation = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="pipe_name_scan",
        affected_count=6, targets=targets)
    text = render_limitation(limitation)
    assert "region(s)" in text
    assert text.count("(32 KB > 16 KB limit)") == 3
    assert "+3 more (see coverage.limitations[].targets in --json output)" in text
    # ...while the machine-readable side keeps every one of them.
    assert len(limitation.to_dict()["targets"]) == 6


def _segment_target(base=0x1000, size=32 * 1024, limit=16 * 1024, **kw):
    return ScanTarget(kind=ScanTargetKind.MEMORY_SEGMENT, base_address=base,
                       size=size, size_limit=limit, **kw)


def test_oversized_skipped_renders_segment_not_region_for_segment_scan():
    # cs-beacon/YARA attach this code to Memory64List/MemoryList segments,
    # not MemoryInfo regions -- the rendered noun must say so, not the
    # fixed "region(s)" the code's own NAME (SCAN_REGION_OVERSIZED_SKIPPED)
    # would suggest.
    limitation = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="segment_scan",
        affected_count=1,
        targets=[_segment_target(base=0x50000, size=0x9000, limit=0x8000,
                                  file_offset=0x5000)])
    text = render_limitation(limitation)
    assert "segment(s)" in text
    assert "region(s)" not in text


def test_oversized_skipped_segment_preview_bounded_json_complete():
    targets = [_segment_target(base=0x1000 * (i + 1)) for i in range(5)]
    limitation = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="segment_scan",
        affected_count=5, targets=targets)
    text = render_limitation(limitation)
    assert "5 oversized segment(s) skipped" in text
    assert text.count("(32 KB > 16 KB limit)") == 3
    assert "+2 more (see coverage.limitations[].targets in --json output)" in text
    assert len(limitation.to_dict()["targets"]) == 5


def test_scan_target_noun_is_neutral_for_mixed_kinds():
    mixed = [_region_target(), _segment_target(base=0x9000)]
    assert scan_target_noun(mixed) == "target(s)"


def test_oversized_skipped_rejects_wrong_target_kind_for_known_source():
    # segment_scan (cs-beacon/YARA) can only ever produce memory_segment
    # targets -- a memory_region target attached to it is a caller bug,
    # not a legal combination, even though it would otherwise pass the
    # generic count/non-empty checks.
    with pytest.raises(ValueError, match="requires every target's kind to be 'memory_segment'"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="segment_scan", affected_count=1,
                            targets=[_region_target()])
    # ...and the reverse: pipe_name_scan/encoding_scan only ever produce
    # memory_region targets.
    with pytest.raises(ValueError, match="requires every target's kind to be 'memory_region'"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="pipe_name_scan", affected_count=1,
                            targets=[_segment_target()])


def test_oversized_skipped_rejects_scope_for_source_that_never_scopes():
    with pytest.raises(ValueError, match="requires scope to be"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="segment_scan", scope="unexpected",
                            affected_count=1, targets=[_segment_target()])
    with pytest.raises(ValueError, match="requires scope to be"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="pipe_name_scan", scope="unexpected",
                            affected_count=1, targets=[_region_target()])


def test_oversized_skipped_requires_a_real_layer_scope_for_encoding_scan():
    # encoding_scan (obfuscation) runs three named layers over overlapping
    # region sets -- unscoped, or a misspelled/unknown layer name, must
    # not silently pass: that ambiguity is exactly what per-layer scope
    # exists to close (see dumpex.hunt.encoding.aggregate).
    with pytest.raises(ValueError, match="requires scope to be"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="encoding_scan", affected_count=1,
                            targets=[_region_target()])
    with pytest.raises(ValueError, match="requires scope to be"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="encoding_scan", scope="sleepmask",
                            affected_count=1, targets=[_region_target()])
    for layer in ("sleep_mask", "entropy", "decode"):
        limitation = CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="encoding_scan",
            scope=layer, affected_count=1, targets=[_region_target()])
        assert f"by the {layer} scan" in render_limitation(limitation)


def test_oversized_skipped_ioc_string_scan_is_region_kinded_and_unscoped():
    # stomping's unscored IOC-string scan (dumpex.hunt.stomping.memory_scan)
    # is a single loop over MemoryInfo regions, so it carries region targets
    # and no scope -- the same contract as pipe_name_scan.
    limitation = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="ioc_string_scan",
        affected_count=1, targets=[_region_target()])
    assert "region(s)" in render_limitation(limitation)
    with pytest.raises(ValueError, match="requires every target's kind to be 'memory_region'"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="ioc_string_scan", affected_count=1,
                            targets=[_segment_target()])
    with pytest.raises(ValueError, match="requires scope to be"):
        CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                            source="ioc_string_scan", scope="unexpected",
                            affected_count=1, targets=[_region_target()])


def test_oversized_skipped_unknown_source_is_not_kind_or_scope_constrained():
    # `source` stays an open vocabulary for this code (see its own enum
    # comment) -- a future hunter using a source name not in the known
    # contract table must not be blocked from using this code at all.
    limitation = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="future_scan",
        scope="anything", affected_count=1, targets=[_segment_target()])
    assert render_limitation(limitation)


# ── --process (issue #40 / docs/recon_process_sysinfo_handles_contract.md
# §6.1) -- PROCESS_*/IAT_* limitation codes ──────────────────────────────

def test_process_sources_absent_is_absent_capable_single_source():
    req = EvaluationRequirement(sources=("process_identity",),
                                 all_absent_code=LimitationCode.PROCESS_SOURCES_ABSENT)
    sources = {"process_identity": SourceObservation(name="process_identity", state=SOURCE_ABSENT)}
    coverage = build_coverage_report(sources, evaluation_sources=req)
    assert coverage.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(coverage.status.value) == 4
    assert len(coverage.limitations) == 1
    limitation = coverage.limitations[0]
    assert limitation.code == LimitationCode.PROCESS_SOURCES_ABSENT
    assert limitation.source == "process_identity"
    assert "no usable process identity evidence" in render_limitation(limitation)


@pytest.mark.parametrize("code,source", [
    (LimitationCode.PROCESS_MISC_INFO_UNAVAILABLE, "misc_info"),
    (LimitationCode.PROCESS_PEB_UNAVAILABLE, "peb"),
    (LimitationCode.PROCESS_MODULE_FALLBACK_UNAVAILABLE, "modules"),
])
def test_process_absent_capable_codes_via_source_requirement(code, source):
    req = SourceRequirement(source=source, absent_code=code)
    sources = {source: SourceObservation(name=source, state=SOURCE_ABSENT)}
    coverage = build_coverage_report(sources, completeness_checks=[req])
    assert coverage.status == CoverageStatus.PARTIAL
    assert len(coverage.limitations) == 1
    assert coverage.limitations[0].code == code
    assert render_limitation(coverage.limitations[0])


def test_process_absent_capable_codes_reject_wrong_fixed_source():
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=LimitationCode.PROCESS_PEB_UNAVAILABLE, source="misc_info")


@pytest.mark.parametrize("code,expected_text", [
    (LimitationCode.PROCESS_PID_UNAVAILABLE, "does not supply a usable ProcessId"),
    (LimitationCode.PROCESS_START_TIME_UNSET, "is zero (not recorded)"),
    (LimitationCode.PROCESS_START_TIME_INVALID, "not a valid 32-bit timestamp"),
])
def test_process_misc_info_field_level_codes(code, expected_text):
    limitation = CoverageLimitation(code=code, source="misc_info")
    assert expected_text in render_limitation(limitation)
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=code, source="peb")


@pytest.mark.parametrize("code,expected_text", [
    (LimitationCode.PROCESS_PATH_UNAVAILABLE, "no process path available"),
    (LimitationCode.PROCESS_COMMAND_LINE_UNAVAILABLE, "CommandLine is empty"),
    (LimitationCode.PROCESS_IMAGE_BASE_UNAVAILABLE, "ImageBaseAddress is not set"),
    (LimitationCode.PROCESS_IMAGE_BASE_INVALID, "not a plausible mapped image base"),
])
def test_process_peb_field_level_codes(code, expected_text):
    limitation = CoverageLimitation(code=code, source="peb")
    assert expected_text in render_limitation(limitation)
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=code, source="misc_info")


@pytest.mark.parametrize("code,expected_text", [
    (LimitationCode.PROCESS_MAIN_IMAGE_READ_FAILED, "could not read the PE header"),
    (LimitationCode.PROCESS_MAIN_IMAGE_SHORT_READ, "read fewer bytes than required"),
    (LimitationCode.PROCESS_MAIN_IMAGE_PE_INVALID, "not structurally valid"),
])
def test_process_main_image_codes(code, expected_text):
    limitation = CoverageLimitation(code=code, source="main_image")
    assert expected_text in render_limitation(limitation)
    assert limitation.affected_count is None


def test_process_field_level_codes_reject_extra_fields():
    with pytest.raises(ValueError, match="does not use"):
        CoverageLimitation(code=LimitationCode.PROCESS_PID_UNAVAILABLE, source="misc_info",
                            affected_count=1)


def test_iat_directory_table_incomplete_with_known_count():
    limitation = CoverageLimitation(code=LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE,
                                     source="iat", affected_count=10)
    text = render_limitation(limitation)
    assert "10 declared data directory entr(y/ies) were not captured" in text


def test_iat_directory_table_incomplete_without_known_count():
    limitation = CoverageLimitation(code=LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE, source="iat")
    text = render_limitation(limitation)
    assert text == ("the data directory table was not captured; import/IAT directory "
                     "presence is undetermined")


def test_iat_directory_table_incomplete_rejects_zero_or_negative_count():
    with pytest.raises(ValueError):
        CoverageLimitation(code=LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE,
                            source="iat", affected_count=0)


@pytest.mark.parametrize("code,expected_text", [
    (LimitationCode.IAT_DIRECTORY_READ_FAILED, "could not read the IAT directory"),
    (LimitationCode.IAT_UNTERMINATED_TABLE, "no null terminator found"),
    (LimitationCode.IAT_CYCLE_DETECTED, "a repeated address was found"),
    (LimitationCode.IAT_BOUNDS_EXCEEDED, "exceeds plausible bounds"),
    (LimitationCode.IAT_DIRECTORY_SHORT_READ, "read fewer bytes than declared"),
])
def test_iat_fixed_text_codes(code, expected_text):
    limitation = CoverageLimitation(code=code, source="iat")
    assert expected_text in render_limitation(limitation)


@pytest.mark.parametrize("code,expected_text", [
    (LimitationCode.IAT_DESCRIPTOR_READ_FAILED, "import descriptor(s) could not be read"),
    (LimitationCode.IAT_DESCRIPTOR_SHORT_READ, "import descriptor(s) read short"),
    (LimitationCode.IAT_THUNK_READ_FAILED, "IAT/INT thunk slot(s) could not be read"),
    (LimitationCode.IAT_THUNK_SHORT_READ, "IAT/INT thunk slot(s) read short"),
    (LimitationCode.IAT_NAME_READ_FAILED, "DLL or import name string(s) could not be read"),
])
def test_iat_affected_count_codes(code, expected_text):
    limitation = CoverageLimitation(code=code, source="iat", affected_count=3)
    text = render_limitation(limitation)
    assert "3" in text
    assert expected_text in text
    with pytest.raises(ValueError, match="positive integer"):
        CoverageLimitation(code=code, source="iat")


def test_iat_entries_truncated_requires_all_three_budget_fields():
    limitation = CoverageLimitation(
        code=LimitationCode.IAT_ENTRIES_TRUNCATED, source="iat",
        scope="iat_bytes_read", budget_limit=16 * 1024 * 1024, budget_consumed=16 * 1024 * 1024)
    text = render_limitation(limitation)
    assert "budget: iat_bytes_read, limit=16777216 consumed=16777216" in text

    with pytest.raises(ValueError, match="requires scope, budget_limit, and budget_consumed"):
        CoverageLimitation(code=LimitationCode.IAT_ENTRIES_TRUNCATED, source="iat")
    with pytest.raises(ValueError, match="requires scope, budget_limit, and budget_consumed"):
        CoverageLimitation(code=LimitationCode.IAT_ENTRIES_TRUNCATED, source="iat", scope="iat_dlls")


def test_iat_entries_truncated_rejects_unknown_scope():
    with pytest.raises(ValueError, match="must be one of"):
        CoverageLimitation(code=LimitationCode.IAT_ENTRIES_TRUNCATED, source="iat",
                            scope="not_a_real_budget", budget_limit=1, budget_consumed=1)


def test_process_and_iat_codes_are_all_registered_and_render():
    process_and_iat_codes = [c for c in LimitationCode if c.value.startswith(("PROCESS_", "IAT_"))]
    assert len(process_and_iat_codes) == 26
    for code in process_and_iat_codes:
        assert code in _CODE_SPECS


# ── --sysinfo (issue #41 / docs/recon_process_sysinfo_handles_contract.md
# §6.1) -- ENVIRONMENT_* limitation codes ─────────────────────────────────

@pytest.mark.parametrize("code", [
    LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED,
    LimitationCode.ENVIRONMENT_BLOCK_UNREADABLE,
])
def test_environment_detail_codes_require_detail(code):
    with pytest.raises(ValueError, match="non-empty string"):
        CoverageLimitation(code=code, source="environment_block")
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=code, source="peb", detail="x")


def test_environment_architecture_unsupported_renders():
    limitation = CoverageLimitation(code=LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED,
                                     source="environment_block", detail="ARM64")
    text = render_limitation(limitation)
    assert text == ("environment block not walked: unsupported processor architecture "
                     "(ARM64)")


def test_environment_architecture_unsupported_names_unavailable_fields():
    # P2 regression: collect_sysinfo() suppresses peb.current_directory
    # whenever this code fires (read through the same untrustworthy
    # wrong-offset PEB parse) -- unavailable_fields makes that visible.
    limitation = CoverageLimitation(code=LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED,
                                     source="environment_block", detail="ARM64",
                                     unavailable_fields=("current_directory",))
    text = render_limitation(limitation)
    assert text == ("environment block not walked: unsupported processor architecture "
                     "(ARM64); current_directory unavailable")


def test_environment_block_unreadable_renders():
    limitation = CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_UNREADABLE,
                                     source="environment_block", detail="TEB->PEB pointer unreadable: boom")
    text = render_limitation(limitation)
    assert text == ("environment block pointers could not be read: TEB->PEB pointer "
                     "unreadable: boom")


def test_environment_block_unparseable_is_fixed_text():
    limitation = CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE,
                                     source="environment_block")
    text = render_limitation(limitation)
    assert text == ("environment block present but no entries could be parsed (malformed, "
                     "or no terminator found)")
    with pytest.raises(ValueError, match="does not use"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE,
                            source="environment_block", detail="x")
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE, source="peb")


@pytest.mark.parametrize("scope,budget_limit,budget_consumed", [
    ("environment_bytes", 65536, 65536),
    ("environment_entries", 2048, 2048),
])
def test_environment_block_truncated_budget_scopes_require_budget_fields(scope, budget_limit, budget_consumed):
    limitation = CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED,
                                     source="environment_block", affected_count=5, scope=scope,
                                     budget_limit=budget_limit, budget_consumed=budget_consumed)
    text = render_limitation(limitation)
    assert "5 entry(ies) kept" in text
    assert f"budget: {scope}, limit={budget_limit} consumed={budget_consumed}" in text

    with pytest.raises(ValueError, match="requires budget_limit and budget_consumed"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED,
                            source="environment_block", affected_count=5, scope=scope)


@pytest.mark.parametrize("scope", ["captured_segment", "undecodable_entry"])
def test_environment_block_truncated_non_budget_scopes_omit_budget_clause(scope):
    limitation = CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED,
                                     source="environment_block", affected_count=1, scope=scope)
    text = render_limitation(limitation)
    assert text == "environment block capture ended before a terminator was found; 1 entry(ies) kept"

    with pytest.raises(ValueError, match="requires budget_limit and budget_consumed to be None"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED,
                            source="environment_block", affected_count=1, scope=scope,
                            budget_limit=1, budget_consumed=1)


def test_environment_block_truncated_rejects_unknown_scope():
    with pytest.raises(ValueError, match="must be one of"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED,
                            source="environment_block", affected_count=1, scope="not_a_real_scope")


def test_environment_block_truncated_rejects_non_positive_affected_count():
    with pytest.raises(ValueError, match="positive int"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED,
                            source="environment_block", affected_count=0, scope="captured_segment")


def test_environment_block_truncated_rejects_missing_affected_count():
    # P3 regression: unlike IAT_DIRECTORY_TABLE_INCOMPLETE,
    # affected_count is REQUIRED here (§6.1) -- omitting it entirely
    # (not just passing 0/negative) must be rejected too.
    with pytest.raises(ValueError, match="requires affected_count to be a positive integer"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED,
                            source="environment_block", scope="captured_segment")


def test_environment_precondition_inconsistent_is_fixed_text():
    limitation = CoverageLimitation(code=LimitationCode.ENVIRONMENT_PRECONDITION_INCONSISTENT,
                                     source="environment_block")
    text = render_limitation(limitation)
    assert text == ("a captured process environment block source exists without the "
                     "system/thread evidence needed to interpret it; the environment "
                     "block was never walked")
    assert "mf.peb" not in text   # domain language only, never a Python attribute name
    with pytest.raises(ValueError, match="does not use"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_PRECONDITION_INCONSISTENT,
                            source="environment_block", detail="x")
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=LimitationCode.ENVIRONMENT_PRECONDITION_INCONSISTENT, source="peb")


def test_environment_codes_are_all_registered_and_render():
    environment_codes = [c for c in LimitationCode if c.value.startswith("ENVIRONMENT_")]
    assert len(environment_codes) == 5
    for code in environment_codes:
        assert code in _CODE_SPECS


# ── --sysinfo's DUMP section (§4.2) -- SYSINFO_DUMP_FILE_UNREADABLE ──────

def test_sysinfo_dump_file_unreadable_requires_detail_and_its_own_source():
    # The OS error is the whole point of the line: it tells an analyst
    # whether the evidence file was deleted, is on an unmounted share, or
    # is simply unreadable by this user. A detail-less construction would
    # render a sentence that names no cause at all.
    with pytest.raises(ValueError, match="non-empty string"):
        CoverageLimitation(code=LimitationCode.SYSINFO_DUMP_FILE_UNREADABLE, source="dump_file")
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=LimitationCode.SYSINFO_DUMP_FILE_UNREADABLE,
                            source="sysinfo", detail="x")


def test_sysinfo_dump_file_unreadable_renders_the_os_error():
    limitation = CoverageLimitation(
        code=LimitationCode.SYSINFO_DUMP_FILE_UNREADABLE, source="dump_file",
        detail="FileNotFoundError: [Errno 2] No such file or directory: 'x.dmp'")
    assert render_limitation(limitation) == (
        "dump file could not be read for size/SHA-256: FileNotFoundError: "
        "[Errno 2] No such file or directory: 'x.dmp'")


def test_sysinfo_dump_file_source_has_a_display_name():
    # Not consumed by SYSINFO_DUMP_FILE_UNREADABLE's own fixed template,
    # but _display_name() must still resolve the source rather than
    # leaking the raw key if any generic template ever renders over it.
    assert _display_name("dump_file") == "Dump file"


# ── --handles (issue #42 / docs/recon_process_sysinfo_handles_contract.md
# §5.5/§6.1) -- HANDLE*/HANDLES_* limitation codes ────────────────────────

_HANDLE_GROUP_CODES = (
    LimitationCode.HANDLES_UNAVAILABLE,
    LimitationCode.HANDLES_PARSE_FAILED,
    LimitationCode.HANDLES_ALL_DESCRIPTORS_INVALID,
)
_HANDLE_COUNT_CODES = (
    LimitationCode.HANDLE_DESCRIPTOR_INVALID,
    LimitationCode.HANDLE_STRING_READ_FAILED,
    LimitationCode.HANDLE_STREAM_TRUNCATED,
)


@pytest.mark.parametrize("code,expected", [
    (LimitationCode.HANDLES_UNAVAILABLE,
     "HandleDataStream not present in this dump (not captured with handle data)"),
    (LimitationCode.HANDLES_PARSE_FAILED,
     "HandleDataStream is present in this dump but could not be parsed"),
    (LimitationCode.HANDLES_ALL_DESCRIPTORS_INVALID,
     "HandleDataStream present but no descriptor could be normalized"),
])
def test_handle_group_codes_render_their_frozen_sentence(code, expected):
    assert render_limitation(
        CoverageLimitation(code=code, source="handle_records")) == expected


@pytest.mark.parametrize("code", _HANDLE_GROUP_CODES)
def test_handle_group_codes_are_absent_capable_over_handle_records(code):
    # --handles selects among these three at call time for ONE
    # single-source evaluation group, so each must be usable as an
    # all_absent_code -- and only over its own fixed source.
    assert code in _ABSENT_CAPABLE_CODES
    EvaluationRequirement(sources=("handle_records",), all_absent_code=code)
    with pytest.raises(ValueError, match="requires sources\[0\]"):
        EvaluationRequirement(sources=("handles",), all_absent_code=code)
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=code, source="handles")


@pytest.mark.parametrize("code", _HANDLE_GROUP_CODES)
def test_handle_group_codes_carry_no_interpolated_field(code):
    # build_coverage_report()'s all-absent branch sets only scope/
    # related_sources -- a template reading affected_count/detail would
    # render "None" in real output, so neither field may be attachable.
    for field in ("affected_count", "detail"):
        with pytest.raises(ValueError, match="does not use"):
            CoverageLimitation(code=code, source="handle_records", **{field: 3 if field ==
                                "affected_count" else "x"})


@pytest.mark.parametrize("code,expected", [
    (LimitationCode.HANDLE_DESCRIPTOR_INVALID,
     "4 handle descriptor(s) could not be normalized"),
    (LimitationCode.HANDLE_STRING_READ_FAILED,
     "4 handle(s) have a type or object name that could not be read or decoded"),
    (LimitationCode.HANDLE_STREAM_TRUNCATED,
     "HandleDataStream declares more descriptors than dumpex will parse; "
     "4 descriptor(s) were not read"),
])
def test_handle_count_codes_render_their_frozen_sentence(code, expected):
    assert render_limitation(
        CoverageLimitation(code=code, source="handles", affected_count=4)) == expected


@pytest.mark.parametrize("code", _HANDLE_COUNT_CODES)
def test_handle_count_codes_require_a_positive_count_over_handles(code):
    # A bare, count-free construction renders "None descriptor(s)" -- it
    # is rejected at construction instead.
    with pytest.raises(ValueError, match="requires affected_count to be a positive integer"):
        CoverageLimitation(code=code, source="handles")
    # 0 is caught one level earlier, by the shared field validator.
    with pytest.raises(ValueError, match="must be None or a plain positive int"):
        CoverageLimitation(code=code, source="handles", affected_count=0)
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=code, source="handle_records", affected_count=1)
    # Caller-buildable only: these are per-descriptor facts the reducer
    # cannot infer from source state, and none of them describes absence.
    assert code not in _ABSENT_CAPABLE_CODES


def test_handles_source_renders_its_stream_name():
    # §1.7: without this entry a SOURCE_FAILED over the handle stream
    # would render the raw key "handles".
    assert _display_name("handles") == "HandleDataStream"
    limitation = CoverageLimitation(code=LimitationCode.SOURCE_FAILED, source="handles",
                                     detail="HandleStreamFramingError: boom")
    assert render_limitation(limitation) == (
        "HandleDataStream present but could not be read: HandleStreamFramingError: boom")


def test_handle_codes_are_all_registered_and_render():
    handle_codes = [c for c in LimitationCode if c.value.startswith("HANDLE")]
    assert len(handle_codes) == 6
    for code in handle_codes:
        assert code in _CODE_SPECS

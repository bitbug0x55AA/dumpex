"""
§3.7.3 `retain_completeness_checks_when_not_evaluated` -- reference model
for the NOT-YET-IMPLEMENTED design (#38), plus the shipped default.

Split out of test_recon_contract_semantics.py, which is now strictly
about executing contract rules against PRODUCTION code. Most of this
file is not that, and keeping the two mixed made the coverage claim hard
to read:

  * test_retention_default_false_matches_todays_shipped_behavior() calls
    the REAL build_coverage_report(). It is a genuine check of shipped
    behavior -- today's documented default (pre-built CoverageLimitations
    are dropped under not_evaluated) cannot change silently.

  * Every other test here exercises _prototype_with_retention(), a
    TEST-ONLY model of a flag dumpex.output.coverage does not implement.
    They make §3.7.3's frozen ordering/retention rules executable ahead
    of the implementation; they prove nothing about shipped behavior and
    must NOT be read as coverage of it.

When #38 lands, _prototype_with_retention() should be deleted and these
tests repointed at build_coverage_report(..., retain_completeness_checks_
when_not_evaluated=True) -- at which point they become real tests and
belong back alongside the rest of the coverage suite.

Scoped to the single-source-EvaluationRequirement shape --process/
--handles actually use (§3.7.2/§5.5). The --handles-specific
instantiation (HANDLES_PARSE_FAILED/HANDLES_ALL_DESCRIPTORS_INVALID over
the derived `handle_records` source) landed with #42 and is exercised
against the real command in tests/unit/test_handles_cmd.py.
"""
import pytest

from dumpex.output.coverage import (
    SourceObservation, CoverageLimitation, CoverageReport, SourceRequirement,
    build_coverage_report, SourceState, CoverageStatus, LimitationCode,
    exit_code_for, EXIT_NOT_EVALUATED,
    _validate_limitation_against_sources,
)


# ── §3.7.3: reducer-retention prototype ─────────────────────────────────

_PREBUILT_REGION = CoverageLimitation(
    code=LimitationCode.REGION_READ_TRUNCATED, source="requested_region")
_PREBUILT_PID = CoverageLimitation(
    code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info")


def _base_sources():
    return {
        "process_identity": SourceObservation(name="process_identity", state=SourceState.ABSENT),
        "peb": SourceObservation(name="peb", state=SourceState.FAILED, detail="boom"),
        "modules": SourceObservation(name="modules", state=SourceState.ABSENT),
        "requested_region": SourceObservation(name="requested_region", state=SourceState.PRESENT,
                                               record_count=1),
        "misc_info": SourceObservation(name="misc_info", state=SourceState.PRESENT, record_count=1),
    }


def _prototype_with_retention(sources, evaluation_sources, completeness_checks):
    """Test-only prototype of §3.7.3's frozen
    `retain_completeness_checks_when_not_evaluated=True` design. NOT
    implemented in dumpex.output.coverage yet (#38 territory) -- this
    reference model exists only to make the frozen ordering/retention
    rules executable now, so a rule regression is caught by pytest
    rather than by prose review.

    Scoped to the single-group shape --process/--handles actually use
    (a bare `evaluation_sources` tuple, which build_coverage_report()
    auto-wraps into exactly one EvaluationRequirement, contributing at
    most one group limitation) -- matching §3.7.2/§5.5 exactly. A
    caller passing `evaluation_groups` (multiple independent groups)
    is out of scope for this prototype.
    """
    # Production already does everything right EXCEPT retaining pre-built
    # CoverageLimitations under not_evaluated -- so call it once with the
    # FULL checks list. If the group didn't fire, production's ordinary
    # (non-not_evaluated) path already keeps pre-built entries in place;
    # that result is correct as-is. If it DID fire, production's
    # not_evaluated branch already dropped every pre-built entry, so
    # `baseline.limitations` is exactly [group..., failed...] with none
    # of them -- the correct base to splice retained entries into.
    baseline = build_coverage_report(sources, evaluation_sources=evaluation_sources,
                                      completeness_checks=completeness_checks)
    if baseline.status != CoverageStatus.NOT_EVALUATED:
        return baseline

    group_limitations = baseline.limitations[:1]
    failed_limitations = baseline.limitations[1:]
    retained = [c for c in completeness_checks if isinstance(c, CoverageLimitation)]
    for lim in retained:
        _validate_limitation_against_sources(lim, sources)   # "relaxes nothing about correctness"

    return CoverageReport(status=CoverageStatus.NOT_EVALUATED, sources=baseline.sources,
                           limitations=group_limitations + retained + failed_limitations)


def test_retention_default_false_matches_todays_shipped_behavior():
    """Default False: byte-for-byte today's build_coverage_report()
    behavior. This calls the REAL production function, not the
    prototype -- pre-built CoverageLimitations are dropped under
    not_evaluated, exactly as documented in §3.7.3's "Default False"
    bullet."""
    sources = _base_sources()
    checks = ["peb", SourceRequirement(source="modules"), _PREBUILT_REGION]
    report = build_coverage_report(sources, evaluation_sources=("process_identity",),
                                    completeness_checks=checks)
    assert report.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(report.status) == EXIT_NOT_EVALUATED
    codes = [l.code for l in report.limitations]
    assert codes == [LimitationCode.SOURCE_ABSENT, LimitationCode.SOURCE_FAILED]
    assert LimitationCode.REGION_READ_TRUNCATED not in codes


def test_retention_true_orders_group_then_retained_then_failed():
    """True: group limitation first, then retained pre-built
    CoverageLimitations in caller-declared order, then the re-surfaced
    FAILED-source limitation(s) -- exactly §3.7.3's frozen order. Two
    distinct pre-built codes (in reverse-of-declaration order relative
    to the bare checks) prove ordering is caller order, not code order
    or source-alphabetical order."""
    sources = _base_sources()
    checks = ["peb", _PREBUILT_PID, SourceRequirement(source="modules"), _PREBUILT_REGION]
    report = _prototype_with_retention(sources, ("process_identity",), checks)

    assert report.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(report.status) == EXIT_NOT_EVALUATED
    codes = [l.code for l in report.limitations]
    assert codes == [
        LimitationCode.SOURCE_ABSENT,          # 1. the group's own limitation
        LimitationCode.PID_NO_USABLE_FALLBACK,  # 2. retained pre-built, caller order
        LimitationCode.REGION_READ_TRUNCATED,   # 2. retained pre-built, caller order
        LimitationCode.SOURCE_FAILED,           # 3. re-surfaced FAILED source
    ]
    # Bare-name/SourceRequirement ABSENT checks keep today's behavior:
    # never resurfaced, retention flag or not.
    assert not any(l.source == "modules" for l in report.limitations)


def test_retention_true_result_still_not_evaluated_exit_4():
    """§3.7.3: "status is still not_evaluated and the exit code is still
    4 -- the flag changes which limitations are reported, never the
    status." """
    sources = _base_sources()
    checks = ["peb", _PREBUILT_REGION]
    report = _prototype_with_retention(sources, ("process_identity",), checks)
    assert report.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(report.status) == EXIT_NOT_EVALUATED


def test_retention_prototype_no_group_fired_returns_baseline_unchanged():
    """When the evaluation group does NOT fire (something was actually
    evaluated), retention is moot -- the prototype must fall through to
    ordinary partial/complete behavior, matching production exactly."""
    sources = _base_sources()
    sources["process_identity"] = SourceObservation(
        name="process_identity", state=SourceState.PRESENT, record_count=1)
    checks = ["peb", _PREBUILT_REGION]
    report = _prototype_with_retention(sources, ("process_identity",), checks)
    direct = build_coverage_report(sources, evaluation_sources=("process_identity",),
                                    completeness_checks=checks)
    assert report.status == direct.status == CoverageStatus.PARTIAL
    assert [l.code for l in report.limitations] == [l.code for l in direct.limitations]


def test_retention_prototype_still_validates_retained_limitations_against_sources():
    """"Every retained limitation still passes
    _validate_limitation_against_sources(). The flag relaxes nothing
    about correctness." -- a pre-built limitation that is internally
    well-formed but cross-source-invalid for THESE sources must still
    raise, retention or not."""
    sources = {
        "process_identity": SourceObservation(name="process_identity", state=SourceState.ABSENT),
        "exception": SourceObservation(name="exception", state=SourceState.ABSENT),
    }
    # PID_EXCEPTION_TID_FALLBACK's cross-source rule requires "exception"
    # to be PRESENT; it's ABSENT here, so this is well-formed at
    # construction time but must fail at retention/validation time.
    bad_prebuilt = CoverageLimitation(
        code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception", thread_id=999)
    with pytest.raises(ValueError, match="requires exception to be present"):
        _prototype_with_retention(sources, ("process_identity",), [bad_prebuilt])

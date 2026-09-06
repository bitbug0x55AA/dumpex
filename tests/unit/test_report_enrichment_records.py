"""Validation contracts for the report-enrichment wire records.

Collector tests exercise the successful projections.  These tests pin the
record boundary itself: malformed or internally inconsistent enrichment must
be rejected before it can reach JSON output.
"""
from dataclasses import replace

import pytest

from dumpex.output.records import (
    ENRICHMENT_COMPLETE,
    ENRICHMENT_MISSING,
    ENRICHMENT_TEXT_CAP,
    EnrichmentSection,
    ReportAddressContext,
    ReportAllocationNeighborhood,
    ReportCorrelatedHandle,
    ReportEnvironmentSummary,
    ReportEnvironmentValue,
    ReportExceptionContext,
    ReportExceptionEntry,
    ReportHandleCorrelation,
    ReportHandleSummary,
    ReportHandleTypeCount,
    ReportIdentityConflict,
    ReportNeighborRegion,
    ReportProcessEnrichment,
    ReportStringContext,
    ReportStringContextEntry,
    ReportTokenCapability,
)


def _section(name, scope, *, included=0, total=None):
    if total is None:
        total = included
    return EnrichmentSection(
        name=name,
        scope=scope,
        status=ENRICHMENT_COMPLETE,
        total=total,
        included=included,
        cap=8,
        truncated=included < total,
    )


def _environment(*entries):
    return ReportEnvironmentSummary(
        section=_section("environment", "process", included=len(entries)),
        entries=entries,
    )


def _handle_summary(*rows):
    return ReportHandleSummary(
        section=_section("handles", "process", included=len(rows)),
        total_handles=sum(row.count for row in rows),
        by_type=rows,
    )


def _process_enrichment():
    return ReportProcessEnrichment(
        section=_section("process", "process", included=1),
        pid=None,
        process_name=None,
        process_path=None,
        path_source=None,
        command_line=None,
        process_start_utc=None,
        image_base_address=None,
        module_match_state=None,
        environment=_environment(),
        handles=_handle_summary(),
        token=ReportTokenCapability(
            stream_present=False,
            parser_state=None,
            status="unavailable",
            detail="TokenStream not captured",
        ),
    )


def _address(address="0x0000000000001000"):
    return ReportAddressContext(
        address=address,
        region_base=None,
        region_size=None,
        protection=None,
        type=None,
        module_owner=None,
    )


def _exception(**overrides):
    values = {
        "index": 0,
        "thread_id": None,
        "exception_code": None,
        "exception_code_name": None,
        "exception_flags": None,
        "exception_address": None,
        "parameters": (),
        "parameters_truncated": False,
        "selection_reason": "process_exception",
    }
    values.update(overrides)
    return ReportExceptionEntry(**values)


def _neighbor(base="0x0000000000001000", *, relation="anchor", distance=0):
    return ReportNeighborRegion(
        base_address=base,
        size=0x1000,
        state="MEM_COMMIT",
        type="MEM_PRIVATE",
        protection="PAGE_READWRITE",
        allocation_base="0x0000000000001000",
        relation=relation,
        distance=distance,
    )


def _correlated_handle(handle="0x0000000000000040"):
    return ReportCorrelatedHandle(
        handle=handle,
        type_name="File",
        object_name=r"\Device\NamedPipe\demo",
        granted_access=0x12019F,
        selection_reason="object_name_in_anchor_strings",
    )


def _string_entry(offset=0x10, *, reason="query_match", distance=None):
    return ReportStringContextEntry(
        address=f"0x{0x1000 + offset:016x}",
        offset=offset,
        encoding="ASCII",
        text="needle in captured text",
        text_truncated=False,
        selection_reason=reason,
        distance=distance,
    )


def _string_context(*entries, query_text="needle", bytes_read=0x40):
    return ReportStringContext(
        section=_section("string_context", "card", included=len(entries)),
        anchor_address="0x0000000000001000",
        distance_anchor_address="0x0000000000001010",
        query_text=query_text,
        examined_base_address="0x0000000000001000",
        examined_size=0x1000,
        requested_bytes=0x40,
        bytes_read=bytes_read,
        total_strings=len(entries),
        entries=entries,
    )


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"name": ""}, "name must be a non-empty string"),
        ({"scope": "invocation"}, "scope must be one of"),
        ({"status": "unknown"}, "status must be one of"),
        ({"provenance": ("",)}, "provenance must be a sequence"),
        ({"limitations": (1,)}, "limitations must be a sequence"),
        ({"included": 2, "total": 2, "cap": 1}, "included must not exceed cap"),
    ],
)
def test_enrichment_section_rejects_malformed_metadata(overrides, match):
    values = {
        "name": "exception",
        "scope": "card",
        "status": ENRICHMENT_COMPLETE,
        "total": 1,
        "included": 1,
        "cap": 4,
        "truncated": False,
    }
    values.update(overrides)
    with pytest.raises(ValueError, match=match):
        EnrichmentSection(**values)


@pytest.mark.parametrize(
    "section, match",
    [
        (object(), "must be an EnrichmentSection"),
        (_section("environment", "card"), "scope must be 'process'"),
        (_section("handles", "process"), "name must be 'environment'"),
    ],
)
def test_nested_records_require_their_exact_section_contract(section, match):
    with pytest.raises((TypeError, ValueError), match=match):
        ReportEnvironmentSummary(section=section)


def test_environment_records_validate_values_and_entry_counts():
    with pytest.raises(ValueError, match="value must be a str"):
        ReportEnvironmentValue("USERNAME", 1, False)
    with pytest.raises(ValueError, match="value must be at most"):
        ReportEnvironmentValue("USERNAME", "x" * (ENRICHMENT_TEXT_CAP + 1), True)

    entry = ReportEnvironmentValue("USERNAME", "analyst", False)
    assert entry.to_dict() == {
        "name": "USERNAME",
        "value": "analyst",
        "truncated": False,
    }
    with pytest.raises(TypeError, match="must be ReportEnvironmentValue"):
        ReportEnvironmentSummary(_section("environment", "process", included=1), (object(),))
    with pytest.raises(ValueError, match="length must equal section.included"):
        ReportEnvironmentSummary(_section("environment", "process", included=1))


def test_handle_summary_rejects_impossible_rows_and_missing_counts():
    with pytest.raises(ValueError, match="count must be positive"):
        ReportHandleTypeCount("File", 0)
    row = ReportHandleTypeCount("File", 1)
    with pytest.raises(TypeError, match="must be ReportHandleTypeCount"):
        ReportHandleSummary(_section("handles", "process", included=1), 1, (object(),))
    with pytest.raises(ValueError, match="length must equal section.included"):
        ReportHandleSummary(_section("handles", "process", included=1), 1)
    missing = EnrichmentSection(
        "handles", "process", ENRICHMENT_MISSING, None, 0, 8, False
    )
    with pytest.raises(ValueError, match="must be None when the handle stream is missing"):
        ReportHandleSummary(missing, 0)
    assert _handle_summary(row).to_dict()["by_type"] == [row.to_dict()]


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"parser_state": "broken"}, "parser_state must be None or one of"),
        ({"stream_present": True}, "must be set exactly when stream_present"),
        ({"status": "unknown"}, "status must be one of"),
    ],
)
def test_token_capability_rejects_inconsistent_states(overrides, match):
    values = {
        "stream_present": False,
        "parser_state": None,
        "status": "unavailable",
        "detail": "TokenStream not captured",
    }
    values.update(overrides)
    with pytest.raises(ValueError, match=match):
        ReportTokenCapability(**values)


def test_identity_conflicts_use_the_closed_severity_vocabulary():
    with pytest.raises(ValueError, match="severity must be one of"):
        ReportIdentityConflict("PROCESS_IDENTITY_MISMATCH", "error", "sources disagree")
    conflict = ReportIdentityConflict(
        "PROCESS_IDENTITY_MISMATCH", "warning", "sources disagree"
    )
    assert conflict.to_dict()["severity"] == "warning"


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"path_source": "header", "process_path": "demo.exe"}, "path_source must be"),
        ({"path_source": "peb"}, "requires a resolved process_path"),
        ({"module_match_state": "ambiguous"}, "module_match_state must be"),
        ({"environment": object()}, "environment must be"),
        ({"handles": object()}, "handles must be"),
        ({"token": object()}, "token must be"),
        ({"identity_conflicts": (object(),)}, "identity_conflicts must be"),
        (
            {
                "identity_conflicts": (
                    ReportIdentityConflict("PROCESS_IDENTITY_MISMATCH", "warning", "conflict"),
                ),
                "identity_conflicts_total": 0,
            },
            "must count every conflict",
        ),
        ({"process_path": "x" * (ENRICHMENT_TEXT_CAP + 1)}, "must be at most"),
        ({"command_line_truncated": True}, "requires a command_line"),
    ],
)
def test_process_enrichment_rejects_inconsistent_nested_evidence(overrides, match):
    with pytest.raises((TypeError, ValueError), match=match):
        replace(_process_enrichment(), **overrides)


def test_address_context_requires_its_own_region_and_owner_evidence():
    with pytest.raises(ValueError, match="requires a module_owner"):
        replace(_address(), module_owner_truncated=True)
    with pytest.raises(ValueError, match="region facts require a resolved region_base"):
        replace(_address(), region_size=0x1000)


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"exception_code": "c0000005"}, "must be None or a '0x' hex string"),
        ({"access_type": "modify"}, "access_type must be None or one of"),
        ({"address_context": object()}, "must be None or a ReportAddressContext"),
        ({"address_context": _address()}, "requires the address it resolves"),
        (
            {
                "exception_address": "0x0000000000002000",
                "address_context": _address(),
            },
            "must be the address it resolves",
        ),
        ({"parameters": ("not-hex",)}, "parameters must be '0x' hex strings"),
        ({"selection_reason": "nearest"}, "selection_reason must be one of"),
    ],
)
def test_exception_entry_rejects_malformed_or_unrelated_evidence(overrides, match):
    with pytest.raises((TypeError, ValueError), match=match):
        _exception(**overrides)


def test_exception_context_rejects_wrong_counts_and_duplicate_stream_indexes():
    entry = _exception()
    with pytest.raises(TypeError, match="must be ReportExceptionEntry"):
        ReportExceptionContext(_section("exception", "card", included=1), (object(),))
    with pytest.raises(ValueError, match="length must equal section.included"):
        ReportExceptionContext(_section("exception", "card", included=1))
    with pytest.raises(ValueError, match="deduplicated by stream index"):
        ReportExceptionContext(_section("exception", "card", included=2), (entry, entry))


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"module_owner_truncated": True}, "requires a module_owner"),
        ({"relation": "overlapping"}, "relation must be one of"),
        ({"distance": 1}, "distance must be 0 for the anchor"),
    ],
)
def test_neighbor_region_rejects_inconsistent_relationships(overrides, match):
    with pytest.raises(ValueError, match=match):
        replace(_neighbor(), **overrides)


def test_allocation_neighborhood_requires_ordered_unique_region_records():
    low = _neighbor()
    high = _neighbor("0x0000000000002000", relation="following", distance=0)
    with pytest.raises(TypeError, match="must be ReportNeighborRegion"):
        ReportAllocationNeighborhood(
            _section("allocation", "card", included=1), None, (object(),)
        )
    with pytest.raises(ValueError, match="length must equal section.included"):
        ReportAllocationNeighborhood(_section("allocation", "card", included=1), None)
    with pytest.raises(ValueError, match="ascending address order"):
        ReportAllocationNeighborhood(
            _section("allocation", "card", included=2), None, (high, low)
        )
    with pytest.raises(ValueError, match="deduplicated by base address"):
        ReportAllocationNeighborhood(
            _section("allocation", "card", included=2), None, (low, low)
        )


def test_correlated_handles_require_a_valid_reason_and_a_present_type_when_truncated():
    with pytest.raises(ValueError, match="requires a type_name"):
        replace(_correlated_handle(), type_name=None, type_name_truncated=True)
    with pytest.raises(ValueError, match="selection_reason must be one of"):
        replace(_correlated_handle(), selection_reason="same_value")


def test_handle_correlation_rejects_wrong_counts_and_duplicate_handles():
    entry = _correlated_handle()
    with pytest.raises(TypeError, match="must be ReportCorrelatedHandle"):
        ReportHandleCorrelation(
            _section("handle_correlation", "card", included=1), (object(),)
        )
    with pytest.raises(ValueError, match="length must equal section.included"):
        ReportHandleCorrelation(_section("handle_correlation", "card", included=1))
    with pytest.raises(ValueError, match="deduplicated by handle"):
        ReportHandleCorrelation(
            _section("handle_correlation", "card", included=2), (entry, entry)
        )


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"encoding": "UTF-8"}, "encoding must be one of"),
        ({"selection_reason": "nearby"}, "selection_reason must be one of"),
        ({"distance": 0}, "distance must be None exactly for a 'query_match'"),
    ],
)
def test_string_context_entry_rejects_ambiguous_selection_metadata(overrides, match):
    with pytest.raises(ValueError, match=match):
        replace(_string_entry(), **overrides)


def test_string_context_rejects_impossible_read_and_entry_relationships():
    query = _string_entry()
    adjacent = _string_entry(0x18, reason="adjacent_to_anchor", distance=8)

    with pytest.raises(ValueError, match="bytes_read must not exceed requested_bytes"):
        _string_context(query, bytes_read=0x41)
    with pytest.raises(TypeError, match="must be ReportStringContextEntry"):
        _string_context(object())
    with pytest.raises(ValueError, match="length must equal section.included"):
        replace(_string_context(query), entries=())
    with pytest.raises(ValueError, match="address must equal the examined base"):
        _string_context(replace(query, address="0x0000000000001020"))
    with pytest.raises(ValueError, match="offset must fall inside the bytes actually read"):
        _string_context(_string_entry(0x40), bytes_read=0x40)
    with pytest.raises(ValueError, match="at most one 'query_match'"):
        _string_context(query, _string_entry(0x18))
    with pytest.raises(ValueError, match="query_text is required"):
        _string_context(query, query_text=None)
    with pytest.raises(ValueError, match="must not describe the same offset twice"):
        _string_context(
            replace(query, selection_reason="ioc_pattern", distance=0x10),
            replace(adjacent, address=query.address, offset=query.offset),
            query_text=None,
        )

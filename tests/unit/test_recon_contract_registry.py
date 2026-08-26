"""Production conformance checks for the Recon coverage-code registry.

The Markdown contract documents the registry but is not an executable source of
truth. These tests exercise the live enum, `_CodeSpec` metadata, construction,
source restrictions, derivation, and rendering directly.
"""
import pytest

from dumpex.output.coverage import (
    CoverageLimitation,
    LimitationCode,
    SourceObservation,
    SourceRequirement,
    SourceState,
    _CODE_SPECS,
    _ENV_TRUNCATION_SCOPES,
    _IAT_TRUNCATION_SCOPES,
    _STRUCTURED_FIELD_DEFAULTS,
    _derive_required_source_limitation,
    render_limitation,
)


_RECON_SPECS = {
    "PROCESS_SOURCES_ABSENT": ("process_identity", {"scope"}),
    "PROCESS_MISC_INFO_UNAVAILABLE": ("misc_info", {"scope"}),
    "PROCESS_PEB_UNAVAILABLE": ("peb", {"scope"}),
    "PROCESS_PID_UNAVAILABLE": ("misc_info", set()),
    "PROCESS_START_TIME_UNSET": ("misc_info", set()),
    "PROCESS_START_TIME_INVALID": ("misc_info", set()),
    "PROCESS_PATH_UNAVAILABLE": ("peb", set()),
    "PROCESS_COMMAND_LINE_UNAVAILABLE": ("peb", set()),
    "PROCESS_IMAGE_BASE_UNAVAILABLE": ("peb", set()),
    "PROCESS_MODULE_FALLBACK_UNAVAILABLE": ("modules", {"scope"}),
    "PROCESS_IMAGE_BASE_INVALID": ("peb", set()),
    "PROCESS_MAIN_IMAGE_READ_FAILED": ("main_image", set()),
    "PROCESS_MAIN_IMAGE_SHORT_READ": ("main_image", set()),
    "PROCESS_MAIN_IMAGE_PE_INVALID": ("main_image", set()),
    "IAT_DIRECTORY_TABLE_INCOMPLETE": ("iat", {"affected_count"}),
    "IAT_DIRECTORY_READ_FAILED": ("iat", set()),
    "IAT_DIRECTORY_SHORT_READ": ("iat", set()),
    "IAT_DESCRIPTOR_READ_FAILED": ("iat", {"affected_count"}),
    "IAT_DESCRIPTOR_SHORT_READ": ("iat", {"affected_count"}),
    "IAT_THUNK_READ_FAILED": ("iat", {"affected_count"}),
    "IAT_THUNK_SHORT_READ": ("iat", {"affected_count"}),
    "IAT_NAME_READ_FAILED": ("iat", {"affected_count"}),
    "IAT_UNTERMINATED_TABLE": ("iat", set()),
    "IAT_CYCLE_DETECTED": ("iat", set()),
    "IAT_BOUNDS_EXCEEDED": ("iat", set()),
    "IAT_ENTRIES_TRUNCATED": ("iat", {"scope", "budget_limit", "budget_consumed"}),
    "ENVIRONMENT_ARCHITECTURE_UNSUPPORTED": (
        "environment_block", {"detail", "unavailable_fields"}),
    "ENVIRONMENT_BLOCK_UNREADABLE": ("environment_block", {"detail"}),
    "ENVIRONMENT_BLOCK_UNPARSEABLE": ("environment_block", set()),
    "ENVIRONMENT_BLOCK_TRUNCATED": (
        "environment_block", {"affected_count", "scope", "budget_limit",
                              "budget_consumed"}),
    "ENVIRONMENT_PRECONDITION_INCONSISTENT": ("environment_block", set()),
    "SYSINFO_DUMP_FILE_UNREADABLE": ("dump_file", {"detail"}),
    "HANDLES_UNAVAILABLE": ("handle_records", {"scope"}),
    "HANDLES_PARSE_FAILED": ("handle_records", {"scope"}),
    "HANDLES_ALL_DESCRIPTORS_INVALID": ("handle_records", {"scope"}),
    "HANDLE_DESCRIPTOR_INVALID": ("handles", {"affected_count"}),
    "HANDLE_STRING_READ_FAILED": ("handles", {"affected_count"}),
    "HANDLE_STREAM_TRUNCATED": ("handles", {"affected_count"}),
}


def _kwargs_for(code: LimitationCode) -> dict:
    fields = set(_CODE_SPECS[code].allowed_fields)
    kwargs = {}
    if "affected_count" in fields:
        kwargs["affected_count"] = None if code is \
            LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE else 3
    if "detail" in fields:
        kwargs["detail"] = "TEST_DETAIL"
    if "unavailable_fields" in fields:
        kwargs["unavailable_fields"] = ("current_directory",)
    if "scope" in fields:
        if code is LimitationCode.IAT_ENTRIES_TRUNCATED:
            kwargs["scope"] = sorted(_IAT_TRUNCATION_SCOPES)[0]
        elif code is LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED:
            kwargs["scope"] = "environment_bytes"
        else:
            kwargs["scope"] = "dump"
    if "budget_limit" in fields:
        kwargs["budget_limit"] = 10
        kwargs["budget_consumed"] = 10
    return kwargs


@pytest.mark.parametrize("name", sorted(_RECON_SPECS))
def test_recon_code_metadata_matches_current_contract(name):
    source, allowed_fields = _RECON_SPECS[name]
    code = LimitationCode[name]
    spec = _CODE_SPECS[code]
    assert spec.fixed_source == source
    assert set(spec.allowed_fields) == allowed_fields
    assert not spec.group_capable
    assert spec.absent_capable != spec.caller_buildable


@pytest.mark.parametrize("name", sorted(_RECON_SPECS))
def test_every_recon_code_constructs_and_renders_through_production(name):
    source, _fields = _RECON_SPECS[name]
    limitation = CoverageLimitation(
        code=LimitationCode[name], source=source, **_kwargs_for(LimitationCode[name]))
    rendered = render_limitation(limitation)
    assert isinstance(rendered, str) and rendered
    assert "{" not in rendered and "}" not in rendered


@pytest.mark.parametrize("name", sorted(_RECON_SPECS))
def test_fixed_source_codes_reject_a_different_source(name):
    code = LimitationCode[name]
    with pytest.raises(ValueError, match="source must be"):
        CoverageLimitation(code=code, source="wrong_source", **_kwargs_for(code))


@pytest.mark.parametrize("name", sorted(_RECON_SPECS))
def test_recon_codes_reject_an_unused_structured_field(name):
    code = LimitationCode[name]
    allowed = set(_CODE_SPECS[code].allowed_fields)
    candidates = {
        "detail": "EXTRA",
        "affected_count": 1,
        "scope": "dump",
        "unavailable_fields": ("field",),
        "counterpart_source": "other",
    }
    field = next(key for key in candidates if key not in allowed)
    kwargs = _kwargs_for(code)
    kwargs[field] = candidates[field]
    with pytest.raises(ValueError, match="does not use"):
        CoverageLimitation(code=code, source=_RECON_SPECS[name][0], **kwargs)


_ABSENT_CAPABLE_CODES = sorted(
    (code for code, spec in _CODE_SPECS.items() if spec.absent_capable),
    key=lambda code: code.name,
)


@pytest.mark.parametrize("code", _ABSENT_CAPABLE_CODES, ids=lambda code: code.name)
def test_absent_capable_codes_render_cleanly_through_derivation(code):
    name = _CODE_SPECS[code].fixed_source or "some_source"
    observation = SourceObservation(name=name, state=SourceState.ABSENT)
    limitation = _derive_required_source_limitation(
        observation,
        SourceRequirement(source=name, absent_code=code),
        {name: observation},
    )
    assert limitation is not None
    rendered = render_limitation(limitation)
    assert "None" not in rendered
    assert "{" not in rendered and "}" not in rendered


def test_iat_directory_table_incomplete_has_count_free_rendering():
    limitation = CoverageLimitation(
        code=LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE,
        source="iat",
        affected_count=None,
    )
    assert render_limitation(limitation) == (
        "the data directory table was not captured; import/IAT directory "
        "presence is undetermined"
    )


@pytest.mark.parametrize(
    "scope",
    sorted(_ENV_TRUNCATION_SCOPES - {"environment_bytes", "environment_entries"}),
)
def test_environment_truncation_non_budget_scopes_omit_budget_clause(scope):
    limitation = CoverageLimitation(
        code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED,
        source="environment_block",
        affected_count=3,
        scope=scope,
    )
    assert render_limitation(limitation) == (
        "environment block capture ended before a terminator was found; "
        "3 entry(ies) kept"
    )


def test_environment_architecture_rendering_includes_unavailable_fields():
    limitation = CoverageLimitation(
        code=LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED,
        source="environment_block",
        detail="ARM64",
        unavailable_fields=("current_directory",),
    )
    assert render_limitation(limitation) == (
        "environment block not walked: unsupported processor architecture "
        "(ARM64); current_directory unavailable"
    )


def test_structured_field_registry_is_closed():
    assert set(_STRUCTURED_FIELD_DEFAULTS) == {
        "scope", "affected_count", "unavailable_fields", "available_fields",
        "counterpart_source", "related_sources", "related_tids", "thread_id",
        "detail", "targets", "budget_limit", "budget_consumed",
    }

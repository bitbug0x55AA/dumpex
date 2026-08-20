"""
Field-set alignment between dumpex.output.records and the JSON schema.

Every record `$def` in the current schema is closed
(`additionalProperties: false`) and total (`required` lists every
property), so a record's `to_dict()` key set and its schema def's
property set have to be *equal* -- an extra key makes the document fail
validation, a missing key makes it fail `required`.

That equality is what these tests assert. It is the general form of the
one-off "field X must not be in to_dict()" assertion: a test naming a
single removed field only ever catches that field coming back, and
cannot fail for the far more likely regression of some OTHER field being
added to a record and never reaching the schema (or vice versa). It also
means the assertion carries information neither side contains alone --
the schema is a separate artifact, so this fails when only one of the
two is edited.

Integration coverage validates real command output against the same
schema (tests/integration/test_json_schema_v2.py), but only for shapes an
actual run produces on the test dumps; these run per record class, so a
record type no fixture happens to emit is still pinned.
"""
import json

import pytest

from dumpex.output.coverage import (
    CoverageStatus, ScanTarget, ScanTargetKind, SourceObservation, SourceState,
)
from dumpex.output.records import (
    HuntRegionRef, HuntThreadRef, HuntThreadRegionHit,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_DIFF_ADDED,
    MEMORY_DIFF_PROTECTION_CHANGED, SEVERITY_ERROR, SEVERITY_WARNING, THREAD_DIFF_ADDED,
    Artifact, Diagnostic, ExtractRecord, MemoryDiffRecord, MemoryRegionRecord,
    ModuleDiffRecord, ModuleRecord, ReportIocString,
    ReportRegionInfo, ReportThreadInfo, StringRecord, SysInfoRecord, ThreadDiffRecord,
    ThreadRecord, hex_address,
    ProcessRecord, IatRecord, ImportEntryRecord, ProcessDiagnosticRecord, HandleRecord,
    ProfileRecord, ProfileMemoryCapture, ProfileStreamEntry, ProfileCapabilityEntry,
    CapabilityLimitation, StreamParserState, CapabilityStatus, CAPABILITY_IDS, CAPABILITY_BY_ID,
)
from dumpex.schemas import CURRENT_SCHEMA, schema_path

_ADDR = hex_address(0x1000)
_ADDR2 = hex_address(0x2000)

_IAT_ENTRY = ImportEntryRecord(
    dll="KERNEL32.dll", import_by="name", symbol="CreateFileW", ordinal=None,
    iat_slot_va=_ADDR, resolved_target_va=_ADDR2, slot_in_bounds=True)

_PROCESS_DIAGNOSTIC = ProcessDiagnosticRecord(
    code="PROCESS_MODULE_BASE_CONFLICT", severity="warning",
    message="a module named a.exe is loaded elsewhere", affected_count=1,
    details={"name": "a.exe", "module_base": _ADDR, "peb_base": _ADDR2})


def _capability_entry_for(capability_id: str) -> ProfileCapabilityEntry:
    """A generically valid 'unavailable' ProfileCapabilityEntry for ANY
    capability in CAPABILITY_REGISTRY, regardless of its own required-
    group shape: blocking every member of the capability's own FIRST
    required group with REQUIRED_SOURCE_ABSENT always satisfies
    ProfileCapabilityEntry.__post_init__'s 'unavailable' rules (at least
    one whole required group fully blocked; every other group left fully
    unblocked, since it carries zero limitations)."""
    definition = CAPABILITY_BY_ID[capability_id]
    first_group = definition.required_source_groups[0]
    limitations = tuple(
        CapabilityLimitation(code="REQUIRED_SOURCE_ABSENT", source=name) for name in first_group)
    return ProfileCapabilityEntry(
        capability_id=capability_id, status=CapabilityStatus.UNAVAILABLE.value,
        required_source_groups=definition.required_source_groups,
        required_sources=definition.required_sources,
        optional_sources=definition.optional_sources,
        limitations=limitations)


def _full_schema():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _schema_defs():
    return _full_schema()["$defs"]


# Every record built with the fields POPULATED rather than left at their
# defaults where a default exists: to_dict() is allowed to shape optional
# fields differently, and a key that only appears when a field is set
# would slip past a records-are-all-None probe.
_RECORDS = {
    "memoryRegionRecord": lambda: MemoryRegionRecord(
        base_address=_ADDR, size=0x2000, state="MEM_COMMIT",
        protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE", suspicious=True),
    "moduleRecord": lambda: ModuleRecord(
        name="a.dll", full_path=r"C:\a.dll", base_address=_ADDR, end_address=_ADDR2,
        size=0x1000, compiled_utc="2026-01-01T00:00:00Z", file_version="1.0.0.0",
        checksum=1234, anomaly_flags=["NO_NAME"]),
    "threadRecord": lambda: ThreadRecord(
        tid=4660, start_address=_ADDR, backing_module="a.dll",
        module_context=MODULE_CONTEXT_RESOLVED, create_time="2026-01-01T00:00:00Z",
        exit_time=None, exit_status=None, kernel_time_100ns=100, user_time_100ns=200,
        suspend_count=0, priority=8, teb=_ADDR2, flags=["SUSPENDED"]),
    "sysInfoRecord": lambda: SysInfoRecord(
        dump_file="sample.dmp", hostname="HOST", username="user", os="Windows",
        os_version="10.0.26200", architecture="x64", product_type="workstation",
        processors=8, cpu_vendor="GenuineIntel", cpu_current_mhz=2400, cpu_max_mhz=3600,
        thread_count=12, module_count=40, current_directory=r"C:\work",
        environment_variables=[{"name": "PATH", "value": r"C:\windows"}]),
    "importEntryRecord": lambda: _IAT_ENTRY,
    "processDiagnosticRecord": lambda: _PROCESS_DIAGNOSTIC,
    "iatRecord": lambda: IatRecord(
        table_present=True, table_va=_ADDR, table_size=0x100,
        import_directory_present=True, import_directory_va=_ADDR2, import_directory_size=0x28,
        has_entries=True, dll_count=1, entry_count=1, entries=(_IAT_ENTRY,),
        diagnostics=(_PROCESS_DIAGNOSTIC,)),
    "processRecord": lambda: ProcessRecord(
        process_name="a.exe", pid=4242, process_path=r"C:\a.exe",
        command_line=r"C:\a.exe --flag", process_start_utc="2026-01-01T00:00:00Z",
        image_base_address=_ADDR,
        iat=IatRecord(
            table_present=True, table_va=_ADDR, table_size=0x100,
            import_directory_present=True, import_directory_va=_ADDR2, import_directory_size=0x28,
            has_entries=True, dll_count=1, entry_count=1, entries=(_IAT_ENTRY,),
            diagnostics=(_PROCESS_DIAGNOSTIC,)),
        identity_evidence={
            "misc_info_claim": {"pid": 4242, "process_create_time_utc": "2026-01-01T00:00:00Z",
                                 "raw_pid": None, "raw_process_create_time": None},
            "peb_claim": {"image_base_address": _ADDR, "image_path": r"C:\a.exe", "name": "a.exe",
                          "raw_image_base_address": None, "raw_image_path": None,
                          "raw_command_line": None},
            "module_claim": {"match_state": "resolved", "base_address": _ADDR, "name": "a.exe",
                              "path": r"C:\a.exe",
                              "name_matched_candidate": {"base_address": _ADDR, "name": "a.exe",
                                                          "path": r"C:\a.exe"},
                              "name_matched_candidate_ambiguous": False},
            "main_image_pe": {"checked": True, "valid": True, "reason": None},
            "selected_path_source": "peb",
            "diagnostics": [_PROCESS_DIAGNOSTIC.to_dict()],
        },
        peb_extended={"peb_address": _ADDR, "being_debugged": False, "window_title": "a",
                      "dll_path": r"C:\windows\system32", "standard_input": _ADDR,
                      "standard_output": _ADDR, "standard_error": _ADDR}),
    "handleRecord": lambda: HandleRecord(
        handle=_ADDR, type_name="File", type_name_status="ok",
        object_name=r"\Device\HarddiskVolume1\x", object_name_status="ok",
        attributes=0x40, granted_access=0x12019f, handle_count=1, pointer_count=1),
    "capabilityLimitation": lambda: CapabilityLimitation(
        code="REQUIRED_SOURCE_ABSENT", source="handles"),
    "profileMemoryCapture": lambda: ProfileMemoryCapture(
        full_memory_flag_set=True, memory64_list_present=True, memory_list_present=False,
        captured_segment_count=2, captured_bytes_total=0x2000),
    "profileStreamEntry": lambda: ProfileStreamEntry(
        directory_index=0, stream_type_id=7, stream_type_name="ModuleListStream",
        parser_state=StreamParserState.PARSED.value, record_count=3, detail=None),
    "profileCapabilityEntry": lambda: _capability_entry_for("handle_analysis"),
    "profileRecord": lambda: ProfileRecord(
        architecture="AMD64", raw_flags=0x2, recognized_flags=("MiniDumpWithDataSegs",),
        unrecognized_flag_bits=0,
        memory_capture=ProfileMemoryCapture(
            full_memory_flag_set=True, memory64_list_present=True, memory_list_present=False,
            captured_segment_count=2, captured_bytes_total=0x2000),
        streams=(ProfileStreamEntry(
            directory_index=0, stream_type_id=7, stream_type_name="ModuleListStream",
            parser_state=StreamParserState.PARSED.value, record_count=3, detail=None),),
        capabilities=tuple(_capability_entry_for(cid) for cid in CAPABILITY_IDS)),
    "extractRecord": lambda: ExtractRecord(
        requested_address=_ADDR, requested_size=64, auto_sized=False, bytes_read=64,
        mz_header_detected=True),
    "stringRecord": lambda: StringRecord(
        offset=16, address=_ADDR, encoding="ASCII", text="hello", matched_grep=True),
    "moduleDiffRecord": lambda: ModuleDiffRecord(
        change_type=MODULE_DIFF_ADDED, name="a.dll", full_path_before=None,
        full_path_after=r"C:\a.dll", base_address_before=None, base_address_after=_ADDR),
    "threadDiffRecord": lambda: ThreadDiffRecord(
        change_type=THREAD_DIFF_ADDED, tid=4660, start_address_before=None,
        start_address_after=_ADDR, backing_module_after="a.dll",
        backing_module_context=MODULE_CONTEXT_RESOLVED),
    "memoryDiffRecord": lambda: MemoryDiffRecord(
        change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address=_ADDR, size_before=0x1000,
        size_after=0x1000, protect_before="PAGE_READWRITE",
        protect_after="PAGE_EXECUTE_READWRITE", type_before="MEM_PRIVATE",
        type_after="MEM_PRIVATE", suspicious_before=False, suspicious_after=True),
    "reportThreadInfo": lambda: ReportThreadInfo(
        tid=4660, start_address=_ADDR, backing_module="a.dll",
        module_context=MODULE_CONTEXT_RESOLVED, kernel_time_100ns=100, user_time_100ns=200,
        backing_module_base=_ADDR, backing_module_end=_ADDR2),
    "reportRegionInfo": lambda: ReportRegionInfo(
        base_address=_ADDR, size=0x1000, protect="PAGE_EXECUTE_READWRITE",
        type="MEM_PRIVATE", module_owner=None, file_offset=0x400, is_rwx_private=True,
        module_context=MODULE_CONTEXT_UNREGISTERED, mz_header_detected=True,
        has_injected_pe=True, protection_suspicious=True),
    "reportIocString": lambda: ReportIocString(
        offset=16, address=_ADDR, encoding="ASCII", text="http://c2.example",
        is_network_pattern=True, context_hex="4d5a90000300", context_base_address=_ADDR,
        context_hit_offset=2),
    "artifact": lambda: Artifact(
        id="extract_output", kind="extracted_region", path=r"C:\case\out.bin",
        size_bytes=64, sha256="a" * 64, description="Bytes extracted from 0x1000"),
    "diagnosticEntry": lambda: Diagnostic(
        severity=SEVERITY_WARNING, message="something was skipped", code="SKIPPED"),
    "sourceObservation": lambda: SourceObservation(
        name="modules", state=SourceState.PRESENT, record_count=3),
    # ScanTarget takes raw uint64s and formats them on the way out, so
    # this one is built from plain ints rather than hex_address() strings.
    "scanTarget": lambda: ScanTarget(
        kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=0x200000,
        size_limit=0x100000, file_offset=0x400, allocation_base=0x1000,
        state="MEM_COMMIT", type="MEM_PRIVATE", protection="PAGE_EXECUTE_READWRITE",
        captured_size=0x1000),
    "huntRegionRef": lambda: HuntRegionRef(
        base_address=_ADDR, allocation_base=_ADDR, size=0x1000, type="MEM_PRIVATE",
        protect="PAGE_EXECUTE_READWRITE"),
    "huntThreadRef": lambda: HuntThreadRef(
        tid=4660, start_address=_ADDR, ip=_ADDR2, ip_reg="rip"),
    "huntThreadRegionHit": lambda: HuntThreadRegionHit(
        thread=HuntThreadRef(tid=4660, start_address=_ADDR, ip=_ADDR2, ip_reg="rip"),
        region=HuntRegionRef(base_address=_ADDR, allocation_base=_ADDR, size=0x1000,
                              type="MEM_PRIVATE", protect="PAGE_EXECUTE_READWRITE")),
}


# --sysinfo's live record shape moved ahead of the schema in issue #41
# (pid/command_line/image_path/process_* dropped, environment_variables
# added); #43's atomic v2.13 cutover caught the public schema up (see
# tests/integration/test_json_schema_v2.py, whose matching xfail marker
# was dropped in the same commit).
_KEY_SET_PARAMS = sorted(_RECORDS)


@pytest.mark.parametrize("def_name", _KEY_SET_PARAMS)
def test_record_to_dict_keys_match_the_schema_def_exactly(def_name):
    schema_def = _schema_defs()[def_name]
    assert set(_RECORDS[def_name]().to_dict()) == set(schema_def["properties"])


# processRecord is the ONE $def in the whole schema with an optional
# property (`peb_extended`, present only under `--process --verbose` --
# see docs/recon_process_sysinfo_handles_contract.md §3.6/§7.3) -- every
# other record $def keeps `required == properties`, enforced below.
_OPTIONAL_PROPERTIES = {"processRecord": {"peb_extended"}}


@pytest.mark.parametrize("def_name", sorted(_RECORDS))
def test_record_schema_def_stays_closed_and_total(def_name):
    """The premise the test above rests on. If a def is ever opened
    (`additionalProperties: true`) or stops requiring every OTHER
    property, an extra or missing record field silently starts
    validating, and the key-set equality asserted above would be pinning
    a contract the schema no longer enforces on real output."""
    schema_def = _schema_defs()[def_name]
    assert schema_def["additionalProperties"] is False
    optional = _OPTIONAL_PROPERTIES.get(def_name, set())
    assert set(schema_def["required"]) == set(schema_def["properties"]) - optional
    assert optional <= set(schema_def["properties"])


# ── value-level: every fixture must actually PASS the schema it aligns ───
# The two tests above only compare KEY SETS -- a fixture whose values
# violate a cross-field allOf rule (a code paired with the wrong details
# keys, a status paired with the wrong limitations, ...) has the right
# keys and still fails real validation. This is exactly the gap that let
# `_PROCESS_DIAGNOSTIC` above sit invalid (a "PROCESS_MODULE_BASE_CONFLICT"
# built with only a `name` key, when that code requires `name`/
# `module_base`/`peb_base`) while every other test in this file stayed
# green. Wrapped as its own root document (a $ref sibling to $defs,
# matching test_json_schema_v2.py's own _fragment_validator) rather than
# validated as an extracted dict directly, since several of these defs
# (moduleDiffRecord, iatRecord, processRecord, ...) contain
# "#/$defs/..." $refs that only resolve when $defs stays reachable from
# the document actually being validated.

def _record_fragment_validator(def_name):
    jsonschema = pytest.importorskip("jsonschema")
    schema = _full_schema()
    wrapper = {"$schema": schema["$schema"], "$ref": f"#/$defs/{def_name}", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


@pytest.mark.parametrize("def_name", _KEY_SET_PARAMS)
def test_record_to_dict_value_actually_validates_against_the_schema(def_name):
    validator = _record_fragment_validator(def_name)
    doc = _RECORDS[def_name]().to_dict()
    errors = list(validator.iter_errors(doc))
    assert not errors, "\n".join(str(e) for e in errors)


# ── wire-value constants ↔ the schema enums that close over them ─────────
# Same argument one level down: these constants ARE the strings that land
# in the document, so the values a producer can emit and the values the
# schema accepts must be the same set. Asserted against the enum, not
# against a re-typed list of the strings -- adding a member to the Python
# side without widening the schema (or the reverse) is the failure worth
# catching, and a literal copy here cannot see it.

def test_source_state_members_match_the_schema_enum():
    node = _schema_defs()["sourceObservation"]["properties"]["state"]
    assert {member.value for member in SourceState} == set(node["enum"])


def test_coverage_status_members_match_the_schema_enum():
    node = _schema_defs()["result"]["properties"]["coverage"]["properties"]["status"]
    assert {member.value for member in CoverageStatus} == set(node["enum"])
    # hunterRecord carries its own coverage block; the two must not drift
    hunter_node = _schema_defs()["hunterRecord"]["properties"]["coverage"]["properties"]["status"]
    assert set(hunter_node["enum"]) == set(node["enum"])


def test_execution_status_constants_match_the_schema_enum():
    from dumpex.output.envelope import (
        EXECUTION_COMPLETED, EXECUTION_FAILED, EXECUTION_PARTIAL,
    )
    node = _schema_defs()["result"]["properties"]["execution_status"]
    assert {EXECUTION_COMPLETED, EXECUTION_PARTIAL, EXECUTION_FAILED} == set(node["enum"])


def test_diagnostic_severity_constants_match_the_schema_enum():
    node = _schema_defs()["diagnosticEntry"]["properties"]["severity"]
    assert {SEVERITY_WARNING, SEVERITY_ERROR} == set(node["enum"])

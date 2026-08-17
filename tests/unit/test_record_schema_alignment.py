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
    ModuleDiffRecord, ModuleRecord, PebRecord, PidRecord, ReportIocString,
    ReportRegionInfo, ReportThreadInfo, StringRecord, SysInfoRecord, ThreadDiffRecord,
    ThreadRecord, hex_address,
)
from dumpex.schemas import CURRENT_SCHEMA, schema_path

_ADDR = hex_address(0x1000)
_ADDR2 = hex_address(0x2000)


def _schema_defs():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)["$defs"]


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
    "pidRecord": lambda: PidRecord(pid=1234, source="handle_stream", thread_count=12, exc_tid=4660),
    "pebRecord": lambda: PebRecord(
        peb_address=_ADDR, image_base_address=_ADDR2, being_debugged=False,
        image_path=r"C:\a.exe", command_line=r"C:\a.exe --flag", window_title="a",
        dll_path=r"C:\windows\system32", current_directory=r"C:\work",
        standard_input=_ADDR, standard_output=_ADDR, standard_error=_ADDR,
        environment_variables=[{"name": "PATH", "value": r"C:\windows"}]),
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
# added) and the public schema catches up in #43's atomic cutover.
# strict=True, matching the xfail block in
# tests/integration/test_json_schema_v2.py: when v2.13 ships this test
# starts FAILING for passing unexpectedly, which is the reminder to drop
# the marker -- an xpass that no one notices is how a temporary
# divergence becomes permanent.
_KNOWN_DIVERGENCE = {
    "sysInfoRecord": pytest.mark.xfail(
        reason="SysInfoRecord shape changed in #41; CURRENT_SCHEMA stays v2.12 "
               "until #43's schema cutover", strict=True),
}

_KEY_SET_PARAMS = [
    pytest.param(name, marks=[_KNOWN_DIVERGENCE[name]] if name in _KNOWN_DIVERGENCE else [])
    for name in sorted(_RECORDS)
]


@pytest.mark.parametrize("def_name", _KEY_SET_PARAMS)
def test_record_to_dict_keys_match_the_schema_def_exactly(def_name):
    schema_def = _schema_defs()[def_name]
    assert set(_RECORDS[def_name]().to_dict()) == set(schema_def["properties"])


@pytest.mark.parametrize("def_name", sorted(_RECORDS))
def test_record_schema_def_stays_closed_and_total(def_name):
    """The premise the test above rests on. If a def is ever opened
    (`additionalProperties: true`) or stops requiring every property, an
    extra or missing record field silently starts validating, and the
    key-set equality asserted above would be pinning a contract the
    schema no longer enforces on real output."""
    schema_def = _schema_defs()[def_name]
    assert schema_def["additionalProperties"] is False
    assert set(schema_def["required"]) == set(schema_def["properties"])


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

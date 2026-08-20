"""
Unit tests for dumpex.output.records -- the v2 canonical record
dataclasses. Covers to_dict() shapes, the None-not-"" convention, and
hex_address()'s normalization (fixed-width, zero-padded, lowercase).
"""
import pytest

from dumpex.output.records import (
    MemoryRegionRecord, ModuleRecord, ThreadRecord, SysInfoRecord,
    ExtractRecord, StringRecord, Diagnostic, SEVERITY_WARNING, SEVERITY_ERROR, hex_address, Artifact,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
    ModuleDiffRecord, MODULE_DIFF_ADDED, MODULE_DIFF_REMOVED, MODULE_DIFF_REBASED,
    ThreadDiffRecord, THREAD_DIFF_ADDED, THREAD_DIFF_REMOVED,
    MemoryDiffRecord, MEMORY_DIFF_ADDED, MEMORY_DIFF_REMOVED, MEMORY_DIFF_PROTECTION_CHANGED,
    ReportIocString, ReportThreadInfo, ReportRegionInfo,
    ImportEntryRecord, ProcessDiagnosticRecord, IatRecord, ProcessRecord,
    HandleRecord, handle_name_display, HANDLE_NAME_STATUSES,
    HANDLE_NAME_STATUS_LABELS, HANDLE_RESERVED_NAME_LABELS,
    TriageCardRecord, TRIAGE_ANCHOR_TID, TRIAGE_ANCHOR_ADDRESS, TRIAGE_ANCHOR_STRING_HIT,
    _TRIAGE_FINDING_KEYS, _TRIAGE_VERDICTS,
)


# ── hex_address ────────────────────────────────────────────────────────

def test_hex_address_zero_pads_to_16_digits():
    assert hex_address(0x1000) == "0x0000000000001000"


def test_hex_address_none_stays_none():
    assert hex_address(None) is None


def test_hex_address_large_value_not_truncated():
    big = 0xFFFFFFFFFFFFFFFF
    assert hex_address(big) == "0x" + "f" * 16


# ── MemoryRegionRecord ───────────────────────────────────────────────────

def test_memory_region_record_to_dict_shape():
    rec = MemoryRegionRecord(base_address="0x1000", size=0x2000, state="MEM_COMMIT",
                              protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE",
                              suspicious=True)
    d = rec.to_dict()
    assert d == {
        "base_address": "0x1000", "size": 0x2000, "state": "MEM_COMMIT",
        "protect": "PAGE_EXECUTE_READWRITE", "type": "MEM_PRIVATE", "suspicious": True,
    }
    assert isinstance(d["size"], int)


# ── ModuleRecord ─────────────────────────────────────────────────────────

def test_module_record_missing_fields_are_none_not_empty_string():
    rec = ModuleRecord(name="a.dll", full_path=None, base_address="0x1000",
                        end_address="0x2000", size=0x1000, compiled_utc=None,
                        file_version=None, checksum=None)
    d = rec.to_dict()
    assert d["full_path"] is None
    assert d["file_version"] is None
    assert d["checksum"] is None
    assert d["anomaly_flags"] == []


def test_module_record_size_is_a_plain_int_not_a_hex_string():
    # The point the removed `"size_hex" not in to_dict()` assertion was
    # reaching for: size is emitted once, as an int. Which fields exist
    # at all is no longer asserted here one name at a time -- naming a
    # single removed field can only ever catch THAT field returning, and
    # says nothing about any other field drifting away from the schema.
    # tests/unit/test_record_schema_alignment.py pins the whole key set
    # of every record against its closed schema $def instead, which
    # catches size_hex and everything like it.
    rec = ModuleRecord(name="a.dll", full_path=None, base_address="0x1000",
                        end_address="0x2000", size=4096, compiled_utc=None,
                        file_version=None, checksum=None)
    d = rec.to_dict()
    assert d["size"] == 4096
    assert isinstance(d["size"], int) and not isinstance(d["size"], bool)


def test_module_record_anomaly_flags_is_a_list_not_joined_string():
    rec = ModuleRecord(name="a.dll", full_path=None, base_address="0x1000",
                        end_address="0x2000", size=4096, compiled_utc=None,
                        file_version=None, checksum=None,
                        anomaly_flags=["NO_NAME", "OLD_TIMESTAMP"])
    assert rec.to_dict()["anomaly_flags"] == ["NO_NAME", "OLD_TIMESTAMP"]


def test_module_record_anomaly_flags_is_defensively_copied():
    flags = ["NO_NAME"]
    rec = ModuleRecord(name="a.dll", full_path=None, base_address="0x1000",
                        end_address="0x2000", size=4096, compiled_utc=None,
                        file_version=None, checksum=None, anomaly_flags=flags)
    d = rec.to_dict()
    flags.append("MUTATED")
    assert d["anomaly_flags"] == ["NO_NAME"]


# ── ThreadRecord ───────────────────────────────────────────────────────

def test_thread_record_tid_and_durations_are_plain_ints():
    rec = ThreadRecord(tid=4660, start_address=None, backing_module=None, module_context=None,
                        create_time=None, exit_time=None, exit_status=None,
                        kernel_time_100ns=100, user_time_100ns=200,
                        suspend_count=0, priority=8, teb=None)
    d = rec.to_dict()
    assert isinstance(d["tid"], int) and d["tid"] == 4660
    assert isinstance(d["kernel_time_100ns"], int)
    assert isinstance(d["user_time_100ns"], int)
    assert d["suspend_count"] == 0   # zero must survive, not become None/""


def test_thread_record_addresses_are_hex_strings():
    rec = ThreadRecord(tid=1, start_address=hex_address(0x1000), backing_module=None,
                        module_context=MODULE_CONTEXT_RESOLVED,
                        create_time=None, exit_time=None, exit_status=None,
                        kernel_time_100ns=None, user_time_100ns=None,
                        suspend_count=None, priority=None, teb=hex_address(0x2000))
    d = rec.to_dict()
    assert d["start_address"] == "0x0000000000001000"
    assert d["teb"] == "0x0000000000002000"


def test_thread_record_flags_defaults_to_empty_list():
    rec = ThreadRecord(tid=1, start_address=None, backing_module=None, module_context=None,
                        create_time=None, exit_time=None, exit_status=None,
                        kernel_time_100ns=None, user_time_100ns=None,
                        suspend_count=None, priority=None, teb=None)
    assert rec.to_dict()["flags"] == []


def test_thread_record_module_context_distinguishes_confirmed_from_unavailable():
    # The whole point of this field: a confirmed "not in any module"
    # finding must never be indistinguishable from "we simply have no
    # module data to check against."
    confirmed = ThreadRecord(tid=1, start_address=hex_address(0x1000), backing_module=None,
                              module_context=MODULE_CONTEXT_UNREGISTERED,
                              create_time=None, exit_time=None, exit_status=None,
                              kernel_time_100ns=None, user_time_100ns=None,
                              suspend_count=None, priority=None, teb=None)
    unavailable = ThreadRecord(tid=2, start_address=hex_address(0x1000), backing_module=None,
                                module_context=MODULE_CONTEXT_UNAVAILABLE,
                                create_time=None, exit_time=None, exit_status=None,
                                kernel_time_100ns=None, user_time_100ns=None,
                                suspend_count=None, priority=None, teb=None)
    assert confirmed.to_dict()["module_context"] != unavailable.to_dict()["module_context"]
    assert confirmed.to_dict()["backing_module"] == unavailable.to_dict()["backing_module"] is None


# ── SysInfoRecord ──────────────────────────────────────────────────────
# Split from a single shared record type after review -- see the v2
# schema task: separate, tightly-typed record kinds instead of one with
# dozens of nulled-out fields per command. PidRecord/PebRecord (--pid/
# --peb's own records) were retired in issue #43's v2.13 cutover, which
# replaces both commands with ProcessRecord (see its own tests below).

def test_sysinfo_record_all_fields_default_to_none():
    rec = SysInfoRecord()
    for key, value in rec.to_dict().items():
        assert value is None, f"{key} should default to None, got {value!r}"


def test_sysinfo_record_partial_population_leaves_rest_none():
    rec = SysInfoRecord(thread_count=3, current_directory=r"C:\work")
    d = rec.to_dict()
    assert d["thread_count"] == 3
    assert d["current_directory"] == r"C:\work"
    assert d["hostname"] is None
    assert d["os"] is None
    assert d["environment_variables"] is None


def test_sysinfo_record_environment_variables_serialize_as_plain_dicts():
    rec = SysInfoRecord(environment_variables=({"name": "A", "value": "1"},
                                                {"name": "A", "value": "2"}))
    d = rec.to_dict()
    assert d["environment_variables"] == [{"name": "A", "value": "1"}, {"name": "A", "value": "2"}]


def test_sysinfo_record_environment_variables_empty_list_distinct_from_none():
    rec = SysInfoRecord(environment_variables=())
    assert rec.to_dict()["environment_variables"] == []


# ── ExtractRecord ──────────────────────────────────────────────────────

def test_extract_record_to_dict_shape():
    rec = ExtractRecord(requested_address="0x0000000000001000", requested_size=16,
                         auto_sized=False, bytes_read=16, mz_header_detected=False)
    assert rec.to_dict() == {
        "requested_address": "0x0000000000001000", "requested_size": 16,
        "auto_sized": False, "bytes_read": 16, "mz_header_detected": False,
    }


def test_extract_record_auto_sized_and_mz_flags_are_plain_bools():
    rec = ExtractRecord(requested_address="0x0000000000001000", requested_size=16,
                         auto_sized=True, bytes_read=16, mz_header_detected=True)
    d = rec.to_dict()
    assert d["auto_sized"] is True
    assert d["mz_header_detected"] is True


# ── StringRecord ─────────────────────────────────────────────────────────

def test_string_record_to_dict_shape():
    rec = StringRecord(offset=16, address="0x0000000000001010", encoding="ASCII",
                        text="hello", matched_grep=None)
    assert rec.to_dict() == {
        "offset": 16, "address": "0x0000000000001010", "encoding": "ASCII",
        "text": "hello", "matched_grep": None,
    }


def test_string_record_matched_grep_true_false_are_plain_bools():
    rec_true = StringRecord(offset=0, address="0x0000000000001000", encoding="UTF16", text="x",
                             matched_grep=True)
    rec_false = StringRecord(offset=0, address="0x0000000000001000", encoding="UTF16", text="x",
                              matched_grep=False)
    assert rec_true.to_dict()["matched_grep"] is True
    assert rec_false.to_dict()["matched_grep"] is False


# ── ExtractRecord/StringRecord __post_init__ validation (P2-1) ──────────

def test_extract_record_rejects_negative_bytes_read():
    with pytest.raises(ValueError, match="bytes_read"):
        ExtractRecord(requested_address="0x0000000000001000", requested_size=16,
                       auto_sized=False, bytes_read=-1, mz_header_detected=False)


def test_extract_record_rejects_bool_for_bytes_read():
    with pytest.raises(ValueError, match="bytes_read"):
        ExtractRecord(requested_address="0x0000000000001000", requested_size=16,
                       auto_sized=False, bytes_read=True, mz_header_detected=False)


def test_extract_record_rejects_bytes_read_exceeding_requested_size():
    with pytest.raises(ValueError, match="bytes_read"):
        ExtractRecord(requested_address="0x0000000000001000", requested_size=16,
                       auto_sized=False, bytes_read=17, mz_header_detected=False)


def test_extract_record_allows_bytes_read_below_requested_size():
    rec = ExtractRecord(requested_address="0x0000000000001000", requested_size=16,
                         auto_sized=False, bytes_read=3, mz_header_detected=False)
    assert rec.bytes_read == 3


def test_extract_record_rejects_non_bool_auto_sized():
    with pytest.raises(ValueError, match="auto_sized"):
        ExtractRecord(requested_address="0x0000000000001000", requested_size=16,
                       auto_sized=1, bytes_read=16, mz_header_detected=False)


def test_extract_record_rejects_malformed_requested_address():
    with pytest.raises(ValueError, match="requested_address"):
        ExtractRecord(requested_address="not-a-hex-address", requested_size=16,
                       auto_sized=False, bytes_read=16, mz_header_detected=False)


def test_extract_record_rejects_null_requested_address():
    # P2 remediation: a successful collect_extract() always knows the
    # exact address it read from -- allowing None here would let a
    # producer construct a shape the v2.2 schema itself rejects
    # (extractRecord.requested_address is non-nullable).
    with pytest.raises(ValueError, match="requested_address"):
        ExtractRecord(requested_address=None, requested_size=16,
                       auto_sized=False, bytes_read=16, mz_header_detected=False)


def test_extract_record_rejects_null_requested_size():
    with pytest.raises(ValueError, match="requested_size"):
        ExtractRecord(requested_address="0x0000000000001000", requested_size=None,
                       auto_sized=False, bytes_read=16, mz_header_detected=False)


def test_string_record_rejects_negative_offset():
    with pytest.raises(ValueError, match="offset"):
        StringRecord(offset=-1, address="0x0000000000001000", encoding="ASCII",
                      text="x", matched_grep=None)


def test_string_record_rejects_null_address():
    with pytest.raises(ValueError, match="address"):
        StringRecord(offset=0, address=None, encoding="ASCII", text="x", matched_grep=None)


def test_string_record_rejects_malformed_address():
    with pytest.raises(ValueError, match="address"):
        StringRecord(offset=0, address="0x123", encoding="ASCII", text="x", matched_grep=None)


def test_string_record_rejects_unknown_encoding():
    with pytest.raises(ValueError, match="encoding"):
        StringRecord(offset=0, address="0x0000000000001000", encoding="BOGUS",
                      text="x", matched_grep=None)


def test_string_record_rejects_non_str_text():
    with pytest.raises(ValueError, match="text"):
        StringRecord(offset=0, address="0x0000000000001000", encoding="ASCII",
                      text=123, matched_grep=None)


def test_string_record_rejects_non_bool_matched_grep():
    with pytest.raises(ValueError, match="matched_grep"):
        StringRecord(offset=0, address="0x0000000000001000", encoding="ASCII",
                      text="x", matched_grep="yes")


# ── Diagnostic ───────────────────────────────────────────────────────────

def test_diagnostic_to_dict():
    d = Diagnostic(severity=SEVERITY_WARNING, message="something", code="W001").to_dict()
    assert d == {"severity": "warning", "message": "something", "code": "W001"}
    # SEVERITY_ERROR's own value used to be re-asserted here as a bare
    # literal; both severities are pinned against diagnosticEntry's schema
    # enum in tests/unit/test_record_schema_alignment.py instead.


def test_diagnostic_code_defaults_to_none():
    d = Diagnostic(severity=SEVERITY_ERROR, message="boom").to_dict()
    assert d["code"] is None


def test_diagnostic_is_frozen():
    # Otherwise a valid Diagnostic could be mutated past its own
    # __post_init__ checks (e.g. d.severity = "critical") after
    # CommandResult's isinstance check already passed, reaching the wire
    # in a shape the schema rejects.
    d = Diagnostic(severity=SEVERITY_WARNING, message="x")
    with pytest.raises(Exception):
        d.severity = "critical"


def test_diagnostic_rejects_invalid_severity():
    with pytest.raises(ValueError, match="severity"):
        Diagnostic(severity="critical", message="boom")


def test_diagnostic_rejects_empty_message():
    with pytest.raises(ValueError, match="message"):
        Diagnostic(severity=SEVERITY_WARNING, message="")


def test_diagnostic_rejects_empty_code():
    with pytest.raises(ValueError, match="code"):
        Diagnostic(severity=SEVERITY_WARNING, message="x", code="")


# ── Artifact ──────────────────────────────────────────────────────────────

def test_artifact_is_frozen():
    a = Artifact(id="a1", kind="extracted_region", path="x.bin")
    with pytest.raises(Exception):
        a.size_bytes = True


def test_artifact_to_dict():
    a = Artifact(id="a1", kind="extracted_region", path="region_0x1000.bin",
                 size_bytes=4096, sha256="deadbeef", description="RWX region")
    assert a.to_dict() == {"id": "a1", "kind": "extracted_region",
                            "path": "region_0x1000.bin", "size_bytes": 4096,
                            "sha256": "deadbeef", "description": "RWX region"}


def test_artifact_optional_fields_default_to_none():
    a = Artifact(id="a1", kind="extracted_region", path="region_0x1000.bin")
    d = a.to_dict()
    assert d["size_bytes"] is None
    assert d["sha256"] is None
    assert d["description"] is None


@pytest.mark.parametrize("field_name", ["id", "kind", "path"])
def test_artifact_rejects_empty_required_field(field_name):
    kwargs = {"id": "a1", "kind": "extracted_region", "path": "x.bin"}
    kwargs[field_name] = ""
    with pytest.raises(ValueError, match=field_name):
        Artifact(**kwargs)


def test_artifact_rejects_bool_size_bytes():
    # bool is a subclass of int in Python -- explicitly excluded, since
    # the JSON Schema's "integer" type rejects `true`/`false`.
    with pytest.raises(ValueError, match="size_bytes"):
        Artifact(id="a1", kind="extracted_region", path="x.bin", size_bytes=True)


def test_artifact_rejects_negative_size_bytes():
    with pytest.raises(ValueError, match="size_bytes"):
        Artifact(id="a1", kind="extracted_region", path="x.bin", size_bytes=-1)


def test_artifact_rejects_empty_sha256():
    with pytest.raises(ValueError, match="sha256"):
        Artifact(id="a1", kind="extracted_region", path="x.bin", sha256="")


def test_artifact_rejects_non_string_description():
    with pytest.raises(ValueError, match="description"):
        Artifact(id="a1", kind="extracted_region", path="x.bin", description=123)


# ── ModuleDiffRecord / ThreadDiffRecord / MemoryDiffRecord (Phase C, PR2) ─
# Ported from dumpex.commands.diff's diff_modules/diff_threads/
# diff_memory -- entity_type is the tagged-union discriminator, present on
# every record regardless of change_type.

def test_module_diff_record_to_dict_shape_and_entity_type():
    rec = ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                            full_path_before=None, full_path_after="C:\\a.dll",
                            base_address_before=None, base_address_after=hex_address(0x1000))
    d = rec.to_dict()
    assert d["entity_type"] == "module"
    assert d["change_type"] == "added"
    assert d["name"] == "a.dll"
    assert d["full_path_before"] is None
    assert d["base_address_after"] == hex_address(0x1000)


def test_module_diff_record_added_has_no_before_values():
    rec = ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                            full_path_before=None, full_path_after="C:\\a.dll",
                            base_address_before=None, base_address_after=hex_address(0x1000))
    assert rec.full_path_before is None and rec.base_address_before is None


def test_module_diff_record_removed_has_no_after_values():
    rec = ModuleDiffRecord(change_type=MODULE_DIFF_REMOVED, name="a.dll",
                            full_path_before="C:\\a.dll", full_path_after=None,
                            base_address_before=hex_address(0x1000), base_address_after=None)
    assert rec.full_path_after is None and rec.base_address_after is None


def test_module_diff_record_rebased_has_both_before_and_after():
    rec = ModuleDiffRecord(change_type=MODULE_DIFF_REBASED, name="a.dll",
                            full_path_before="C:\\a.dll", full_path_after="C:\\a.dll",
                            base_address_before=hex_address(0x1000),
                            base_address_after=hex_address(0x9000))
    assert rec.base_address_before != rec.base_address_after
    assert rec.full_path_before is not None and rec.full_path_after is not None


def test_thread_diff_record_to_dict_shape_and_entity_type():
    rec = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=4,
                            start_address_before=None, start_address_after=hex_address(0x2000),
                            backing_module_after="ntdll.dll",
                            backing_module_context=MODULE_CONTEXT_RESOLVED)
    d = rec.to_dict()
    assert d["entity_type"] == "thread"
    assert d["change_type"] == "added"
    assert d["tid"] == 4
    assert d["backing_module_after"] == "ntdll.dll"
    assert d["backing_module_context"] == "resolved"


def test_thread_diff_record_removed_has_no_after_or_backing_module_fields():
    rec = ThreadDiffRecord(change_type=THREAD_DIFF_REMOVED, tid=4,
                            start_address_before=hex_address(0x2000), start_address_after=None)
    assert rec.start_address_after is None
    assert rec.backing_module_after is None
    assert rec.backing_module_context is None


def test_memory_diff_record_to_dict_shape_and_entity_type():
    rec = MemoryDiffRecord(change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address=hex_address(0x1000),
                            size_before=0x1000, size_after=0x1000,
                            protect_before="PAGE_READWRITE", protect_after="PAGE_EXECUTE_READWRITE",
                            type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
                            suspicious_before=False, suspicious_after=True)
    d = rec.to_dict()
    assert d["entity_type"] == "memory_region"
    assert d["change_type"] == "protection_changed"
    assert d["suspicious_before"] is False
    assert d["suspicious_after"] is True


def test_memory_diff_record_added_has_no_before_values():
    rec = MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address=hex_address(0x1000),
                            size_before=None, size_after=0x1000,
                            protect_before=None, protect_after="PAGE_READWRITE",
                            type_before=None, type_after="MEM_PRIVATE",
                            suspicious_before=None, suspicious_after=False)
    assert rec.size_before is None and rec.protect_before is None
    assert rec.type_before is None and rec.suspicious_before is None


def test_memory_diff_record_removed_has_no_after_values():
    rec = MemoryDiffRecord(change_type=MEMORY_DIFF_REMOVED, base_address=hex_address(0x1000),
                            size_before=0x1000, size_after=None,
                            protect_before="PAGE_READWRITE", protect_after=None,
                            type_before="MEM_PRIVATE", type_after=None,
                            suspicious_before=False, suspicious_after=None)
    assert rec.size_after is None and rec.protect_after is None
    assert rec.type_after is None and rec.suspicious_after is None


# ── Diff record __post_init__ validation (Phase C review round 1) ────────
# Frozen dataclasses -- a construction-time rejection is the ONLY way to
# get an invalid instance, since a valid one can no longer be mutated
# into an invalid one afterward.

def test_module_diff_record_is_frozen():
    rec = ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                            full_path_before=None, full_path_after="C:\\a.dll",
                            base_address_before=None, base_address_after=hex_address(0x1000))
    with pytest.raises(Exception):
        rec.entity_type = "bogus"
    with pytest.raises(Exception):
        rec.name = "b.dll"


def test_module_diff_record_rejects_invalid_change_type():
    with pytest.raises(ValueError, match="change_type"):
        ModuleDiffRecord(change_type="bogus", name="a.dll",
                          full_path_before=None, full_path_after=None,
                          base_address_before=None, base_address_after=hex_address(0x1000))


def test_module_diff_record_rejects_empty_name():
    with pytest.raises(ValueError, match="name"):
        ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="",
                          full_path_before=None, full_path_after=None,
                          base_address_before=None, base_address_after=hex_address(0x1000))


def test_module_diff_record_added_rejects_a_before_value():
    with pytest.raises(ValueError, match="added"):
        ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                          full_path_before="C:\\a.dll", full_path_after=None,
                          base_address_before=None, base_address_after=hex_address(0x1000))


def test_module_diff_record_added_requires_base_address_after():
    with pytest.raises(ValueError, match="base_address_after"):
        ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                          full_path_before=None, full_path_after=None,
                          base_address_before=None, base_address_after=None)


def test_module_diff_record_removed_rejects_an_after_value():
    with pytest.raises(ValueError, match="removed"):
        ModuleDiffRecord(change_type=MODULE_DIFF_REMOVED, name="a.dll",
                          full_path_before=None, full_path_after="C:\\a.dll",
                          base_address_before=hex_address(0x1000), base_address_after=None)


def test_module_diff_record_removed_requires_base_address_before():
    with pytest.raises(ValueError, match="base_address_before"):
        ModuleDiffRecord(change_type=MODULE_DIFF_REMOVED, name="a.dll",
                          full_path_before=None, full_path_after=None,
                          base_address_before=None, base_address_after=None)


def test_module_diff_record_rebased_requires_both_base_addresses():
    with pytest.raises(ValueError, match="rebased"):
        ModuleDiffRecord(change_type=MODULE_DIFF_REBASED, name="a.dll",
                          full_path_before=None, full_path_after=None,
                          base_address_before=hex_address(0x1000), base_address_after=None)


def test_thread_diff_record_is_frozen():
    rec = ThreadDiffRecord(change_type=THREAD_DIFF_REMOVED, tid=1,
                            start_address_before=hex_address(0x1000), start_address_after=None)
    with pytest.raises(Exception):
        rec.tid = 2


def test_thread_diff_record_rejects_invalid_change_type():
    with pytest.raises(ValueError, match="change_type"):
        ThreadDiffRecord(change_type="bogus", tid=1,
                          start_address_before=None, start_address_after=None)


def test_thread_diff_record_rejects_non_int_tid():
    with pytest.raises(ValueError, match="tid"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=True,
                          start_address_before=None, start_address_after=hex_address(0x1000))


def test_thread_diff_record_added_rejects_start_address_before():
    with pytest.raises(ValueError, match="added"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                          start_address_before=hex_address(0x1000),
                          start_address_after=hex_address(0x2000))


def test_thread_diff_record_removed_rejects_backing_module_after():
    with pytest.raises(ValueError, match="removed"):
        ThreadDiffRecord(change_type=THREAD_DIFF_REMOVED, tid=1,
                          start_address_before=hex_address(0x1000), start_address_after=None,
                          backing_module_after="a.dll")


def test_memory_diff_record_is_frozen():
    rec = MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address=hex_address(0x1000),
                            size_before=None, size_after=0x1000,
                            protect_before=None, protect_after="PAGE_READWRITE",
                            type_before=None, type_after="MEM_PRIVATE",
                            suspicious_before=None, suspicious_after=False)
    with pytest.raises(Exception):
        rec.base_address = hex_address(0x2000)


def test_memory_diff_record_rejects_invalid_change_type():
    with pytest.raises(ValueError, match="change_type"):
        MemoryDiffRecord(change_type="bogus", base_address=hex_address(0x1000),
                          size_before=None, size_after=None,
                          protect_before=None, protect_after=None,
                          type_before=None, type_after=None,
                          suspicious_before=None, suspicious_after=None)


def test_memory_diff_record_rejects_empty_base_address():
    with pytest.raises(ValueError, match="base_address"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address="",
                          size_before=None, size_after=0x1000,
                          protect_before=None, protect_after="PAGE_READWRITE",
                          type_before=None, type_after="MEM_PRIVATE",
                          suspicious_before=None, suspicious_after=False)


def test_memory_diff_record_added_rejects_a_before_value():
    with pytest.raises(ValueError, match="added"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address=hex_address(0x1000),
                          size_before=0x1000, size_after=0x1000,
                          protect_before="PAGE_READWRITE", protect_after="PAGE_READWRITE",
                          type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
                          suspicious_before=False, suspicious_after=False)


def test_memory_diff_record_removed_rejects_an_after_value():
    with pytest.raises(ValueError, match="removed"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_REMOVED, base_address=hex_address(0x1000),
                          size_before=0x1000, size_after=0x1000,
                          protect_before="PAGE_READWRITE", protect_after="PAGE_READWRITE",
                          type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
                          suspicious_before=False, suspicious_after=False)


def test_memory_diff_record_protection_changed_requires_both_protect_values():
    with pytest.raises(ValueError, match="protection_changed"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address=hex_address(0x1000),
                          size_before=0x1000, size_after=0x1000,
                          protect_before="PAGE_READWRITE", protect_after=None,
                          type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
                          suspicious_before=False, suspicious_after=False)


# ── Diff record field-shape validation (Phase C review round 2) ─────────
# The Python model previously accepted values the v2.1 schema already
# rejected on the wire (a malformed hex address, an unknown module_context
# string, a bool where an int/str/bool field expects the OTHER type) --
# these close that gap directly, mirroring the pattern coverage.py's own
# CoverageLimitation validation already established for the same class of
# bug.

def test_module_diff_record_rejects_malformed_hex_address():
    with pytest.raises(ValueError, match="base_address_after"):
        ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                          full_path_before=None, full_path_after=None,
                          base_address_before=None, base_address_after="not-a-hex-address")


def test_module_diff_record_rejects_variable_width_hex_address():
    with pytest.raises(ValueError, match="base_address_after"):
        ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                          full_path_before=None, full_path_after=None,
                          base_address_before=None, base_address_after="0x1000")


def test_module_diff_record_rebased_rejects_identical_addresses():
    with pytest.raises(ValueError, match="rebased"):
        ModuleDiffRecord(change_type=MODULE_DIFF_REBASED, name="a.dll",
                          full_path_before="x", full_path_after="x",
                          base_address_before=hex_address(0x1000),
                          base_address_after=hex_address(0x1000))


def test_thread_diff_record_rejects_malformed_start_address():
    with pytest.raises(ValueError, match="start_address_after"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                          start_address_before=None, start_address_after="not-a-hex-address")


def test_thread_diff_record_rejects_unknown_module_context():
    with pytest.raises(ValueError, match="backing_module_context"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                          start_address_before=None, start_address_after=hex_address(0x1000),
                          backing_module_after=None, backing_module_context="bogus")


def test_thread_diff_record_added_null_address_rejects_backing_module_context():
    with pytest.raises(ValueError, match="start_address_after=None"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                          start_address_before=None, start_address_after=None,
                          backing_module_after=None, backing_module_context=MODULE_CONTEXT_UNAVAILABLE)


def test_thread_diff_record_added_known_address_requires_module_context():
    with pytest.raises(ValueError, match="requires backing_module_context"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                          start_address_before=None, start_address_after=hex_address(0x1000),
                          backing_module_after=None, backing_module_context=None)


def test_thread_diff_record_resolved_requires_backing_module_after():
    with pytest.raises(ValueError, match="resolved"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                          start_address_before=None, start_address_after=hex_address(0x1000),
                          backing_module_after=None, backing_module_context=MODULE_CONTEXT_RESOLVED)


@pytest.mark.parametrize("context", [MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE])
def test_thread_diff_record_non_resolved_rejects_backing_module_after(context):
    with pytest.raises(ValueError, match="must not carry backing_module_after"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                          start_address_before=None, start_address_after=hex_address(0x1000),
                          backing_module_after="a.dll", backing_module_context=context)


def test_memory_diff_record_rejects_malformed_base_address():
    with pytest.raises(ValueError, match="base_address"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address="not-a-hex-address",
                          size_before=None, size_after=100,
                          protect_before=None, protect_after="PAGE_READWRITE",
                          type_before=None, type_after="MEM_PRIVATE",
                          suspicious_before=None, suspicious_after=False)


def test_memory_diff_record_rejects_bool_size():
    with pytest.raises(ValueError, match="size_after"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address=hex_address(0x1000),
                          size_before=None, size_after=True,
                          protect_before=None, protect_after="PAGE_READWRITE",
                          type_before=None, type_after="MEM_PRIVATE",
                          suspicious_before=None, suspicious_after=False)


def test_memory_diff_record_rejects_non_string_protect():
    with pytest.raises(ValueError, match="protect_after"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address=hex_address(0x1000),
                          size_before=None, size_after=100,
                          protect_before=None, protect_after=123,
                          type_before=None, type_after="MEM_PRIVATE",
                          suspicious_before=None, suspicious_after=False)


def test_memory_diff_record_rejects_non_string_type():
    with pytest.raises(ValueError, match="type_after"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address=hex_address(0x1000),
                          size_before=None, size_after=100,
                          protect_before=None, protect_after="PAGE_READWRITE",
                          type_before=None, type_after=123,
                          suspicious_before=None, suspicious_after=False)


def test_memory_diff_record_rejects_non_bool_suspicious():
    with pytest.raises(ValueError, match="suspicious_after"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address=hex_address(0x1000),
                          size_before=None, size_after=100,
                          protect_before=None, protect_after="PAGE_READWRITE",
                          type_before=None, type_after="MEM_PRIVATE",
                          suspicious_before=None, suspicious_after="yes")


def test_memory_diff_record_protection_changed_rejects_identical_protect():
    with pytest.raises(ValueError, match="protection_changed"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address=hex_address(0x1000),
                          size_before=0x1000, size_after=0x1000,
                          protect_before="PAGE_READWRITE", protect_after="PAGE_READWRITE",
                          type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
                          suspicious_before=False, suspicious_after=True)


def test_memory_diff_record_protection_changed_requires_suspicious_values():
    # Regression: the v2.1 schema already requires suspicious_before/
    # suspicious_after non-null for protection_changed, but the Python
    # model didn't check either -- a document Python happily built and
    # to_dict()'d could never actually pass its own schema.
    with pytest.raises(ValueError, match="suspicious_before"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address=hex_address(0x1000),
                          size_before=None, size_after=None,
                          protect_before="PAGE_READWRITE", protect_after="PAGE_EXECUTE_READWRITE",
                          type_before=None, type_after=None,
                          suspicious_before=None, suspicious_after=None)


def test_module_diff_record_rejects_empty_string_full_path():
    # Regression: the new field-shape validators reject "" for these
    # optional string fields, but the v2.1 schema itself only gained the
    # matching minLength: 1 constraint in this same review round -- both
    # now agree that "" is never a legitimate stand-in for "no value."
    with pytest.raises(ValueError, match="full_path_before"):
        ModuleDiffRecord(change_type=MODULE_DIFF_REBASED, name="a.dll",
                          full_path_before="", full_path_after="x",
                          base_address_before=hex_address(0x1000),
                          base_address_after=hex_address(0x2000))


def test_thread_diff_record_rejects_empty_string_backing_module_after():
    with pytest.raises(ValueError, match="backing_module_after"):
        ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                          start_address_before=None, start_address_after=hex_address(0x1000),
                          backing_module_after="", backing_module_context=MODULE_CONTEXT_RESOLVED)


def test_memory_diff_record_rejects_empty_string_protect():
    with pytest.raises(ValueError, match="protect_after"):
        MemoryDiffRecord(change_type=MEMORY_DIFF_ADDED, base_address=hex_address(0x1000),
                          size_before=None, size_after=100,
                          protect_before=None, protect_after="",
                          type_before=None, type_after="MEM_PRIVATE",
                          suspicious_before=None, suspicious_after=False)


# ── ReportIocString context_hex/context_hit_offset bounds (RevFix2-P2) ────
# The docstring/schema both promise a bounded (<=256 byte) hexdump context
# window with the hit offset falling inside it -- these were previously
# unenforced in Python, so a 257-byte context or an out-of-range offset
# was silently accepted.

def _valid_ioc_kwargs(**overrides):
    kwargs = dict(offset=0, address=hex_address(0x1000), encoding="ASCII", text="x",
                   is_network_pattern=True, context_hex="deadbeef",
                   context_base_address=hex_address(0xf80), context_hit_offset=2)
    kwargs.update(overrides)
    return kwargs


def test_report_ioc_string_valid_network_pattern_accepted():
    rec = ReportIocString(**_valid_ioc_kwargs())
    assert rec.context_hex == "deadbeef"


def test_report_ioc_string_rejects_context_hex_over_256_bytes():
    with pytest.raises(ValueError, match="512 hex chars"):
        ReportIocString(**_valid_ioc_kwargs(context_hex="ab" * 257, context_hit_offset=0))


def test_report_ioc_string_accepts_context_hex_at_exactly_256_bytes():
    rec = ReportIocString(**_valid_ioc_kwargs(context_hex="ab" * 256, context_hit_offset=255))
    assert len(rec.context_hex) == 512


def test_report_ioc_string_rejects_hit_offset_past_context_window():
    with pytest.raises(ValueError, match="context_hit_offset"):
        ReportIocString(**_valid_ioc_kwargs(context_hex="ab" * 10, context_hit_offset=999))


def test_report_ioc_string_rejects_hit_offset_equal_to_context_length():
    # offset must be a valid index INTO the window (strictly less than its
    # byte length) -- landing exactly at the end means zero bytes remain.
    with pytest.raises(ValueError, match="context_hit_offset"):
        ReportIocString(**_valid_ioc_kwargs(context_hex="ab" * 4, context_hit_offset=4))


def test_report_ioc_string_accepts_hit_offset_at_last_valid_index():
    rec = ReportIocString(**_valid_ioc_kwargs(context_hex="ab" * 4, context_hit_offset=3))
    assert rec.context_hit_offset == 3


# ── ReportThreadInfo negative-branch coverage ─────────────────────────────

def _valid_thread_info(**overrides):
    kwargs = dict(tid=1, start_address=hex_address(0x1000), backing_module=None,
                  module_context=None, kernel_time_100ns=None, user_time_100ns=None,
                  backing_module_base=None, backing_module_end=None)
    kwargs.update(overrides)
    return ReportThreadInfo(**kwargs)


def test_report_thread_info_rejects_invalid_module_context():
    with pytest.raises(ValueError, match="module_context"):
        _valid_thread_info(module_context="not-a-real-context")


def test_report_thread_info_rejects_module_context_without_start_address():
    with pytest.raises(ValueError, match="start_address is None"):
        _valid_thread_info(start_address=None, module_context=MODULE_CONTEXT_RESOLVED)


def test_report_thread_info_rejects_mismatched_backing_module_range():
    with pytest.raises(ValueError, match="both be"):
        _valid_thread_info(backing_module_base=hex_address(0x2000), backing_module_end=None)


def test_report_thread_info_rejects_backing_module_range_without_resolved_context():
    with pytest.raises(ValueError, match="resolved"):
        _valid_thread_info(module_context=MODULE_CONTEXT_UNREGISTERED,
                           backing_module_base=hex_address(0x2000),
                           backing_module_end=hex_address(0x3000))


# ── ReportRegionInfo negative-branch coverage ─────────────────────────────

def _valid_region_info(**overrides):
    kwargs = dict(base_address=hex_address(0x1000), size=0x1000, protect="PAGE_READWRITE",
                  type="MEM_PRIVATE", module_owner=None, file_offset=None,
                  is_rwx_private=False, module_context=MODULE_CONTEXT_RESOLVED,
                  mz_header_detected=None, has_injected_pe=None, protection_suspicious=False)
    kwargs.update(overrides)
    return ReportRegionInfo(**kwargs)


def test_report_region_info_rejects_empty_protect():
    with pytest.raises(ValueError, match="protect"):
        _valid_region_info(protect="")


def test_report_region_info_rejects_empty_type():
    with pytest.raises(ValueError, match="type"):
        _valid_region_info(type="")


def test_report_region_info_rejects_invalid_module_context():
    with pytest.raises(ValueError, match="module_context"):
        _valid_region_info(module_context="not-a-real-context")


def test_report_region_info_rwx_private_requires_protection_suspicious():
    with pytest.raises(ValueError, match="protection_suspicious"):
        _valid_region_info(is_rwx_private=True, protection_suspicious=False)


def test_report_region_info_rejects_injected_pe_without_mz_header_detected():
    with pytest.raises(ValueError, match="mz_header_detected is None"):
        _valid_region_info(mz_header_detected=None, has_injected_pe=True)


def test_report_region_info_rejects_injected_pe_true_when_mz_not_detected():
    with pytest.raises(ValueError, match="must be False"):
        _valid_region_info(mz_header_detected=False, has_injected_pe=True)


def test_report_region_info_rejects_injected_pe_false_when_unregistered():
    with pytest.raises(ValueError, match="must be True"):
        _valid_region_info(module_context=MODULE_CONTEXT_UNREGISTERED,
                           mz_header_detected=True, has_injected_pe=False)


def test_report_region_info_rejects_injected_pe_true_when_resolved():
    with pytest.raises(ValueError, match="must be False"):
        _valid_region_info(module_context=MODULE_CONTEXT_RESOLVED,
                           mz_header_detected=True, has_injected_pe=True)


def test_report_region_info_rejects_injected_pe_set_when_unavailable():
    with pytest.raises(ValueError, match="must be None"):
        _valid_region_info(module_context=MODULE_CONTEXT_UNAVAILABLE,
                           mz_header_detected=True, has_injected_pe=True)


# ── ReportIocString negative-branch coverage ──────────────────────────────

def test_report_ioc_string_rejects_invalid_encoding():
    with pytest.raises(ValueError, match="encoding"):
        ReportIocString(**_valid_ioc_kwargs(encoding="not-a-real-encoding"))


def test_report_ioc_string_rejects_non_str_text():
    with pytest.raises(ValueError, match="text"):
        ReportIocString(**_valid_ioc_kwargs(text=123))


def test_report_ioc_string_rejects_context_fields_when_not_network_pattern():
    with pytest.raises(ValueError, match="is_network_pattern is False"):
        ReportIocString(**_valid_ioc_kwargs(is_network_pattern=False))


def test_report_ioc_string_rejects_empty_context_hex_when_network_pattern():
    with pytest.raises(ValueError, match="non-empty hex string"):
        ReportIocString(**_valid_ioc_kwargs(context_hex=None))


def test_report_ioc_string_rejects_non_hex_characters():
    with pytest.raises(ValueError, match="lowercase hex string"):
        ReportIocString(**_valid_ioc_kwargs(context_hex="zzzz"))


# ── ImportEntryRecord (issue #40, §3.5.3) ─────────────────────────────────

def _name_entry(**overrides):
    kwargs = dict(dll="KERNEL32.dll", import_by="name", symbol="CreateFileW", ordinal=None,
                  iat_slot_va=hex_address(0x1000), resolved_target_va=hex_address(0x2000),
                  slot_in_bounds=True)
    kwargs.update(overrides)
    return ImportEntryRecord(**kwargs)


def test_import_entry_record_name_shape():
    entry = _name_entry()
    assert entry.to_dict() == {
        "dll": "KERNEL32.dll", "import_by": "name", "symbol": "CreateFileW", "ordinal": None,
        "iat_slot_va": "0x0000000000001000", "resolved_target_va": "0x0000000000002000",
        "slot_in_bounds": True,
    }


def test_import_entry_record_ordinal_shape():
    entry = _name_entry(import_by="ordinal", symbol=None, ordinal=42)
    assert entry.symbol is None
    assert entry.ordinal == 42


def test_import_entry_record_unavailable_import_by():
    entry = _name_entry(import_by="unavailable", symbol=None, ordinal=None)
    assert entry.to_dict()["import_by"] == "unavailable"


def test_import_entry_record_rejects_unknown_import_by():
    with pytest.raises(ValueError, match="import_by"):
        _name_entry(import_by="bogus")


def test_import_entry_record_rejects_symbol_outside_name_mode():
    with pytest.raises(ValueError, match="symbol must be None"):
        _name_entry(import_by="ordinal", symbol="CreateFileW", ordinal=1)


def test_import_entry_record_rejects_ordinal_outside_ordinal_mode():
    with pytest.raises(ValueError, match="ordinal must be None"):
        _name_entry(import_by="name", ordinal=1)


def test_import_entry_record_requires_ordinal_when_import_by_is_ordinal():
    # Unlike symbol (a separate, fallible read that can legitimately come
    # back null for a captured "name" entry), ordinal is decoded directly
    # from the thunk value already in hand -- there is no "ordinal read
    # failed" case import_by == "ordinal" can report null for.
    with pytest.raises(ValueError, match="ordinal must be set"):
        _name_entry(import_by="ordinal", symbol=None, ordinal=None)


def test_import_entry_record_rejects_non_string_dll():
    with pytest.raises(ValueError, match="dll"):
        _name_entry(dll=123)


def test_import_entry_record_rejects_non_string_symbol():
    with pytest.raises(ValueError, match="symbol"):
        _name_entry(symbol=123)


def test_import_entry_record_rejects_non_hex_addresses():
    with pytest.raises(ValueError):
        _name_entry(iat_slot_va="not-hex")
    with pytest.raises(ValueError):
        _name_entry(resolved_target_va="not-hex")


def test_import_entry_record_rejects_non_bool_slot_in_bounds():
    with pytest.raises(ValueError, match="slot_in_bounds"):
        _name_entry(slot_in_bounds="yes")


def test_import_entry_record_slot_in_bounds_may_be_null():
    entry = _name_entry(slot_in_bounds=None)
    assert entry.slot_in_bounds is None


# ── ProcessDiagnosticRecord (issue #40, §3.4.4/§6.2) ─────────────────────

def _diagnostic(**overrides):
    # "PROCESS_MODULE_BASE_UNMATCHED" (§6.2's #1) is the closed registry's
    # own only single-key code, so its own frozen details shape --
    # {"peb_base": ...} -- is the cheapest well-formed default any
    # override can build on without also needing to override `details`.
    kwargs = dict(code="PROCESS_MODULE_BASE_UNMATCHED", severity="info",
                  message="no module registered at the PEB-reported image base",
                  details={"peb_base": "0x0000000140000000"})
    kwargs.update(overrides)
    return ProcessDiagnosticRecord(**kwargs)


def test_process_diagnostic_record_default_shape():
    d = _diagnostic()
    assert d.to_dict() == {
        "code": "PROCESS_MODULE_BASE_UNMATCHED", "severity": "info",
        "message": "no module registered at the PEB-reported image base",
        "affected_count": None, "details": {"peb_base": "0x0000000140000000"},
    }


def test_process_diagnostic_record_with_details_and_count():
    d = _diagnostic(code="IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS", severity="warning",
                     message="1 IAT slot(s) fall outside the declared IAT directory range",
                     affected_count=1,
                     details={"table_va": "0x1000", "table_size": 8,
                              "first_out_of_bounds_slot_va": "0x2000"})
    assert d.to_dict()["details"] == {"table_va": "0x1000", "table_size": 8,
                                       "first_out_of_bounds_slot_va": "0x2000"}
    assert d.to_dict()["affected_count"] == 1


def test_process_diagnostic_record_rejects_unknown_code():
    with pytest.raises(ValueError, match="code"):
        _diagnostic(code="PEB_TRUSTED", details={"peb_trusted": True})


def test_process_diagnostic_record_rejects_details_key_mismatch_for_its_code():
    # A known code with a details key set that doesn't match the frozen
    # per-code registry -- neither too few nor an unrelated extra key may
    # slip through.
    with pytest.raises(ValueError, match="details"):
        _diagnostic(code="PROCESS_MODULE_BASE_UNMATCHED", details={})
    with pytest.raises(ValueError, match="details"):
        _diagnostic(code="PROCESS_MODULE_BASE_UNMATCHED",
                     details={"peb_base": "0x0000000140000000", "verdict": "malicious"})


def test_process_diagnostic_record_rejects_empty_code():
    with pytest.raises(ValueError, match="code"):
        _diagnostic(code="")


def test_process_diagnostic_record_rejects_unknown_severity():
    with pytest.raises(ValueError, match="severity"):
        _diagnostic(severity="critical")


def test_process_diagnostic_record_rejects_empty_message():
    with pytest.raises(ValueError, match="message"):
        _diagnostic(message="")


def test_process_diagnostic_record_rejects_non_positive_affected_count():
    with pytest.raises(ValueError, match="affected_count"):
        _diagnostic(affected_count=0)
    with pytest.raises(ValueError, match="affected_count"):
        _diagnostic(affected_count=True)


def test_process_diagnostic_record_rejects_non_dict_details():
    with pytest.raises(ValueError, match="details"):
        _diagnostic(details=[("a", 1)])


# ── IatRecord (issue #40, §3.5) ────────────────────────────────────────

def _empty_iat(**overrides):
    kwargs = dict(table_present=None, table_va=None, table_size=None,
                  import_directory_present=None, import_directory_va=None,
                  import_directory_size=None, has_entries=False, dll_count=0, entry_count=0,
                  entries=(), diagnostics=())
    kwargs.update(overrides)
    return IatRecord(**kwargs)


def test_iat_record_empty_shape():
    iat = _empty_iat()
    d = iat.to_dict()
    assert d["table_present"] is None
    assert d["entries"] == []
    assert d["diagnostics"] == []


def test_iat_record_with_one_entry():
    entry = _name_entry()
    iat = _empty_iat(import_directory_present=True, table_present=True,
                      table_va=hex_address(0x3000), table_size=8,
                      import_directory_va=hex_address(0x2000), import_directory_size=20,
                      has_entries=True, dll_count=1, entry_count=1, entries=(entry,))
    d = iat.to_dict()
    assert d["entries"] == [entry.to_dict()]
    assert d["has_entries"] is True


def test_iat_record_rejects_non_bool_table_present():
    with pytest.raises(ValueError, match="table_present"):
        _empty_iat(table_present="yes")


def test_iat_record_rejects_non_bool_import_directory_present():
    with pytest.raises(ValueError, match="import_directory_present"):
        _empty_iat(import_directory_present="yes")


def test_iat_record_rejects_non_bool_has_entries():
    with pytest.raises(ValueError, match="has_entries"):
        IatRecord(table_present=None, table_va=None, table_size=None,
                  import_directory_present=None, import_directory_va=None,
                  import_directory_size=None, has_entries=None, dll_count=0, entry_count=0,
                  entries=(), diagnostics=())


def test_iat_record_rejects_non_import_entry_record_entries():
    with pytest.raises(TypeError, match="ImportEntryRecord"):
        _empty_iat(entries=({"dll": "x"},), entry_count=1, has_entries=True)


def test_iat_record_rejects_non_process_diagnostic_record_diagnostics():
    with pytest.raises(TypeError, match="ProcessDiagnosticRecord"):
        _empty_iat(diagnostics=({"code": "X"},))


def test_iat_record_rejects_negative_table_size():
    with pytest.raises(ValueError, match="table_size"):
        _empty_iat(table_present=True, table_va=hex_address(0x1000), table_size=-1)


def test_iat_record_rejects_negative_import_directory_size():
    with pytest.raises(ValueError, match="import_directory_size"):
        _empty_iat(import_directory_present=True, import_directory_va=hex_address(0x1000),
                    import_directory_size=-1)


def test_iat_record_rejects_table_address_when_table_present_is_false():
    with pytest.raises(ValueError, match="table_va and table_size must both be None"):
        _empty_iat(table_present=False, table_va=hex_address(0x1000), table_size=8)


def test_iat_record_rejects_table_address_when_table_present_is_null():
    with pytest.raises(ValueError, match="table_va and table_size must both be None"):
        _empty_iat(table_present=None, table_va=hex_address(0x1000), table_size=8)


def test_iat_record_rejects_mismatched_table_va_and_size_pairing():
    # table_va and table_size are always set or unset TOGETHER -- never
    # one without the other, regardless of table_present.
    with pytest.raises(ValueError, match="both be None or both set together"):
        _empty_iat(table_present=True, table_va=hex_address(0x1000), table_size=None)
    with pytest.raises(ValueError, match="both be None or both set together"):
        _empty_iat(table_present=True, table_va=None, table_size=8)


def test_iat_record_allows_table_present_true_with_both_null():
    # dumpex.core.pe_utils.parse_iat() can legitimately report
    # table_present=True with table_va/table_size BOTH still None when
    # the range's own address arithmetic overflows a real 64-bit address
    # (bounds_exceeded) -- "the directory is declared" and "its range is
    # a usable address" are different facts. Must NOT raise.
    iat = _empty_iat(table_present=True, table_va=None, table_size=None)
    assert iat.table_va is None and iat.table_size is None


def test_iat_record_rejects_import_directory_address_when_not_present():
    with pytest.raises(ValueError, match="import_directory_va and import_directory_size must "
                                          "both be None"):
        _empty_iat(import_directory_present=False, import_directory_va=hex_address(0x1000),
                    import_directory_size=20)
    with pytest.raises(ValueError, match="import_directory_va and import_directory_size must "
                                          "both be None"):
        _empty_iat(import_directory_present=None, import_directory_va=hex_address(0x1000),
                    import_directory_size=20)


def test_iat_record_allows_import_directory_size_without_va():
    # UNLIKE table_va/table_size, import_directory_va and
    # import_directory_size are NOT required to be paired:
    # parse_iat() records the declared Size unconditionally once
    # import_directory_present is true, independent of whether the RVA's
    # own address arithmetic overflowed -- so import_directory_size can
    # legitimately be set while import_directory_va is None. Must NOT
    # raise.
    iat = _empty_iat(import_directory_present=True, import_directory_va=None,
                      import_directory_size=20)
    assert iat.import_directory_va is None
    assert iat.import_directory_size == 20


def test_iat_record_has_entries_must_match_entry_count():
    with pytest.raises(ValueError, match="has_entries"):
        _empty_iat(has_entries=True, entry_count=0)


def test_iat_record_entries_length_must_match_entry_count():
    with pytest.raises(ValueError, match="entry_count"):
        _empty_iat(entries=(_name_entry(),), entry_count=0, has_entries=True)
    with pytest.raises(ValueError, match="entry_count"):
        _empty_iat(entries=(_name_entry(),), entry_count=2, has_entries=True)


# ── ProcessRecord (issue #40, §3.1) ───────────────────────────────────────

def _process_record(**overrides):
    kwargs = dict(process_name="malware.exe", pid=4242, process_path=r"C:\Samples\malware.exe",
                  command_line=r'"C:\Samples\malware.exe" -k',
                  process_start_utc="2026-08-14 01:15:05 UTC",
                  image_base_address=hex_address(0x00007ff600010000),
                  iat=_empty_iat(), identity_evidence={"diagnostics": []})
    kwargs.update(overrides)
    return ProcessRecord(**kwargs)


def test_process_record_default_shape_has_no_peb_extended_key():
    record = _process_record()
    d = record.to_dict()
    assert "peb_extended" not in d
    assert d["pid"] == 4242
    assert d["iat"] == _empty_iat().to_dict()


def test_process_record_peb_extended_key_present_only_when_set():
    record = _process_record(peb_extended={"peb_address": None, "being_debugged": None,
                                            "window_title": None, "dll_path": None,
                                            "standard_input": None, "standard_output": None,
                                            "standard_error": None})
    d = record.to_dict()
    assert "peb_extended" in d
    assert d["peb_extended"]["being_debugged"] is None


def test_process_record_rejects_non_string_process_name():
    with pytest.raises(ValueError, match="process_name"):
        _process_record(process_name=123)


def test_process_record_rejects_non_int_pid():
    with pytest.raises(ValueError, match="pid"):
        _process_record(pid="4242")
    with pytest.raises(ValueError, match="pid"):
        _process_record(pid=True)


def test_process_record_rejects_non_string_process_path():
    with pytest.raises(ValueError, match="process_path"):
        _process_record(process_path=123)


def test_process_record_rejects_non_string_command_line():
    with pytest.raises(ValueError, match="command_line"):
        _process_record(command_line=123)


def test_process_record_rejects_non_string_process_start_utc():
    with pytest.raises(ValueError, match="process_start_utc"):
        _process_record(process_start_utc=123)


def test_process_record_rejects_bad_image_base_address():
    with pytest.raises(ValueError):
        _process_record(image_base_address="not-hex")


def test_process_record_rejects_non_iat_record_iat():
    with pytest.raises(TypeError, match="IatRecord"):
        _process_record(iat={})


def test_process_record_rejects_non_dict_identity_evidence():
    with pytest.raises(TypeError, match="identity_evidence"):
        _process_record(identity_evidence=[])


def test_process_record_rejects_non_dict_peb_extended():
    with pytest.raises(TypeError, match="peb_extended"):
        _process_record(peb_extended="nope")


# ── HandleRecord (issue #42 / contract §5.2/§5.2.1) ─────────────────────


def _record(**overrides):
    fields = dict(handle="0x0000000000000010", type_name="File", type_name_status="ok",
                   object_name=None, object_name_status="unnamed", attributes=0,
                   granted_access=1, handle_count=1, pointer_count=1)
    fields.update(overrides)
    return HandleRecord(**fields)


def test_handle_record_requires_a_fixed_width_handle():
    with pytest.raises(ValueError, match="handle"):
        _record(handle="0x10")
    with pytest.raises(ValueError, match="handle"):
        _record(handle=0x10)


@pytest.mark.parametrize("status", ["", "OK", "missing", None])
def test_handle_record_rejects_an_unknown_name_status(status):
    with pytest.raises(ValueError, match="type_name_status must be one of"):
        _record(type_name_status=status)


def test_handle_record_rejects_a_status_value_contradiction():
    # "ok" promises a non-null, non-empty value ...
    with pytest.raises(ValueError, match="must be a non-empty string"):
        _record(type_name=None, type_name_status="ok")
    with pytest.raises(ValueError, match="must be a non-empty string"):
        _record(type_name="", type_name_status="ok")
    # ... and every other status promises null.
    with pytest.raises(ValueError, match="must be None"):
        _record(type_name="File", type_name_status="unnamed")
    with pytest.raises(ValueError, match="must be None"):
        _record(object_name="\\Device\\X", object_name_status="unreadable")


def test_handle_record_statuses_are_independent():
    record = _record(type_name=None, type_name_status="unnamed",
                      object_name=None, object_name_status="unreadable")
    assert (record.type_name_status, record.object_name_status) == ("unnamed", "unreadable")


@pytest.mark.parametrize("field", ["attributes", "granted_access", "handle_count", "pointer_count"])
def test_handle_record_rejects_unusable_numeric_fields(field):
    with pytest.raises(ValueError, match=field):
        _record(**{field: -1})
    with pytest.raises(ValueError, match=field):
        _record(**{field: True})
    with pytest.raises(ValueError, match=field):
        _record(**{field: "1"})


def test_handle_record_to_dict_emits_every_field_always():
    assert set(_record().to_dict()) == {
        "handle", "type_name", "type_name_status", "object_name", "object_name_status",
        "attributes", "granted_access", "handle_count", "pointer_count",
    }


def test_handle_name_display_uses_each_fields_own_status():
    # §5.6: a lost name must never print as if the handle were anonymous.
    assert handle_name_display("File", "ok") == "File"
    assert handle_name_display(None, "unnamed") == "(unnamed)"
    assert handle_name_display(None, "unreadable") == "(unreadable)"
    assert handle_name_display(None, "unnamed") != handle_name_display(None, "unreadable")


def test_every_non_ok_status_has_its_own_display_label():
    # The vocabulary's VALUES are pinned against the contract document's
    # own §5.2/§5.2.1 tables in tests/unit/test_recon_contract_doc.py --
    # the artifact an implementer works from, and the one that cannot be
    # edited by the same hand that edits this tuple. What matters here is
    # that the label map stays in step with the vocabulary: a status with
    # no label would raise a KeyError inside handle_name_display(), and a
    # label for a status that no longer exists is a bucket nothing lands
    # in. "ok" is the one status that renders the captured name itself,
    # so it must NOT have a reserved label.
    assert set(HANDLE_NAME_STATUS_LABELS) == set(HANDLE_NAME_STATUSES) - {"ok"}
    assert len(HANDLE_RESERVED_NAME_LABELS) == len(HANDLE_NAME_STATUS_LABELS)


@pytest.mark.parametrize("status", HANDLE_NAME_STATUSES)
def test_handle_name_display_renders_every_status_distinctly(status):
    value = "File" if status == "ok" else None
    rendered = handle_name_display(value, status)
    assert rendered and isinstance(rendered, str)
    others = {handle_name_display("File" if s == "ok" else None, s)
              for s in HANDLE_NAME_STATUSES if s != status}
    assert rendered not in others


@pytest.mark.parametrize("status", HANDLE_NAME_STATUSES)
def test_handle_record_accepts_every_status_in_the_vocabulary(status):
    rec = HandleRecord(
        handle=hex_address(0x1000), type_name="File" if status == "ok" else None,
        type_name_status=status, object_name=None, object_name_status="unnamed",
        attributes=0, granted_access=0x1F0001, handle_count=1, pointer_count=2)
    assert rec.to_dict()["type_name_status"] == status


def test_handle_record_rejects_a_status_outside_the_vocabulary():
    with pytest.raises(ValueError, match="type_name_status"):
        HandleRecord(
            handle=hex_address(0x1000), type_name=None, type_name_status="missing",
            object_name=None, object_name_status="unnamed", attributes=0,
            granted_access=0x1F0001, handle_count=1, pointer_count=2)


# ── TriageCardRecord ────────────────────────────────────────────────────
# --report's own record, and the only one in this module that carries a
# VERDICT. Its __post_init__ is the single place the card's internal
# consistency is enforced against any caller -- dumpex.commands.report is
# the only thing that builds one today, and it always builds a valid one,
# so without the negative tests below every rule here would be caller
# discipline rather than enforcement. Note what these do NOT duplicate:
# tests/integration/test_json_schema_v2.py has same-named checks for the
# string_hit/string_scan rules, but those build plain dicts and validate
# them against the JSON schema -- the schema half of a rule that is
# written twice. These drive the record half.

def _thread_info(**overrides):
    kwargs = dict(tid=4321, start_address=None, backing_module=None, module_context=None,
                   kernel_time_100ns=None, user_time_100ns=None)
    kwargs.update(overrides)
    return ReportThreadInfo(**kwargs)


def _region_info(**overrides):
    kwargs = dict(base_address=hex_address(0x2000), size=0x1000,
                   protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE", module_owner=None,
                   file_offset=None, is_rwx_private=True, module_context="unregistered",
                   mz_header_detected=False, has_injected_pe=False, protection_suspicious=True)
    kwargs.update(overrides)
    return ReportRegionInfo(**kwargs)


def _string_hit(**overrides):
    kwargs = dict(offset=16, address=hex_address(0x1010), encoding="ASCII")
    kwargs.update(overrides)
    return kwargs


def _string_scan(**overrides):
    kwargs = dict(requested_bytes=4096, bytes_read=4096, clamped=False, truncated=False,
                   total=3, ascii_count=2, utf16_count=1)
    kwargs.update(overrides)
    return kwargs


def _card(**overrides):
    # The same minimal shape tests/integration/test_json_schema_v2.py's
    # own _minimal_valid_triage_card_record() spells out as a dict --
    # deliberately, so the two halves of each doubly-written rule are
    # driven from the same starting point.
    kwargs = dict(anchor_tid=None, anchor_address=hex_address(0x1000),
                   anchor_source=TRIAGE_ANCHOR_ADDRESS, thread=None, region=None,
                   string_hit=None, other_threads_in_region=[], notable_strings=[],
                   ioc_strings=[], string_scan=None, string_scan_error=None,
                   thread_region_correlation_excluded=False, findings=[], finding_details={},
                   verdict="CLEAN", artifact_id=None, extract_read_clamped=None,
                   extract_read_truncated=None)
    kwargs.update(overrides)
    return TriageCardRecord(**kwargs)


def test_triage_card_baseline_fixture_is_valid_and_a_populated_card_builds():
    # Guards every negative test below (a fixture that stopped being
    # constructible would make each pytest.raises pass for the wrong
    # reason), and exercises the populated shape the collector really
    # produces -- not just the all-None minimum.
    assert _card().to_dict()["verdict"] == "CLEAN"
    populated = _card(anchor_tid=1234, anchor_source=TRIAGE_ANCHOR_TID,
                       thread=_thread_info(), region=_region_info(),
                       other_threads_in_region=[_thread_info(tid=99)],
                       notable_strings=[StringRecord(offset=0, address=hex_address(0x2000),
                                                      encoding="ASCII", text="hi",
                                                      matched_grep=None)],
                       ioc_strings=[ReportIocString(**_valid_ioc_kwargs())],
                       string_scan=_string_scan(), findings=["rwx_private"],
                       finding_details={"rwx_private": "PAGE_EXECUTE_READWRITE + MEM_PRIVATE"},
                       verdict="SUSPICIOUS")
    assert populated.to_dict()["findings"] == ["rwx_private"]


def test_triage_card_rejects_an_anchor_source_outside_the_vocabulary():
    with pytest.raises(ValueError, match="anchor_source must be one of"):
        _card(anchor_source="grep")


def test_triage_card_thread_and_region_must_be_their_own_report_types():
    # A ThreadRecord/MemoryRegionRecord is a wider, differently-shaped
    # record (see ReportThreadInfo's own docstring) -- accepting one here
    # would emit fields --report's own schema does not declare.
    with pytest.raises(TypeError, match="thread must be None or a ReportThreadInfo"):
        _card(thread="tid 1234")
    with pytest.raises(TypeError, match="region must be None or a ReportRegionInfo"):
        _card(region={"base_address": hex_address(0x2000)})


@pytest.mark.parametrize("string_hit", [
    hex_address(0x1010),                                      # not a dict at all
    {"offset": 16, "address": hex_address(0x1010)},            # a key short
    {"offset": 16, "address": hex_address(0x1010), "encoding": "ASCII", "text": "x"},
])
def test_triage_card_string_hit_must_have_exactly_its_three_keys(string_hit):
    with pytest.raises(ValueError, match="offset.*address.*encoding"):
        _card(anchor_source=TRIAGE_ANCHOR_STRING_HIT, string_hit=string_hit)


def test_triage_card_string_hit_encoding_must_be_in_the_string_vocabulary():
    with pytest.raises(ValueError, match="string_hit..encoding.. must be one of"):
        _card(anchor_source=TRIAGE_ANCHOR_STRING_HIT, string_hit=_string_hit(encoding="UTF8"))


def test_triage_card_string_hit_and_anchor_source_agree_in_both_directions():
    # string-hit mode produces N cards, each anchored at a real hit; any
    # other mode never has one. Either half alone would let a card claim
    # a hit location it never found, or lose the one it did.
    with pytest.raises(ValueError, match="string_hit is required when anchor_source"):
        _card(anchor_source=TRIAGE_ANCHOR_STRING_HIT, string_hit=None)
    with pytest.raises(ValueError, match="string_hit must be None when anchor_source"):
        _card(anchor_source=TRIAGE_ANCHOR_ADDRESS, string_hit=_string_hit())


def test_triage_card_other_threads_must_all_be_report_thread_infos():
    with pytest.raises(TypeError, match="other_threads_in_region must be a list"):
        _card(other_threads_in_region=[_thread_info(), "tid 99"])
    with pytest.raises(TypeError, match="other_threads_in_region must be a list"):
        _card(other_threads_in_region=(_thread_info(),))


def test_triage_card_notable_strings_must_all_be_string_records():
    with pytest.raises(TypeError, match="notable_strings must be a list of StringRecord"):
        _card(notable_strings=[{"text": "hi"}])


def test_triage_card_ioc_strings_reject_a_plain_string_record():
    # ReportIocString is NOT interchangeable with StringRecord: it adds
    # is_network_pattern plus the bounded hexdump context, and --report's
    # own schema declares both. A StringRecord here would silently drop
    # them -- and it is the single most likely wrong type to pass, since
    # notable_strings right above it takes exactly that.
    plain = StringRecord(offset=0, address=hex_address(0x2000), encoding="ASCII",
                          text="http://evil.example", matched_grep=None)
    with pytest.raises(TypeError, match="ioc_strings must be a list of ReportIocString"):
        _card(ioc_strings=[plain])


def test_triage_card_string_scan_must_be_a_dict_with_exactly_its_seven_keys():
    with pytest.raises(TypeError, match="string_scan must be None or a dict"):
        _card(string_scan="4096 bytes")
    short = _string_scan()
    del short["utf16_count"]
    with pytest.raises(ValueError, match="string_scan must have exactly the keys"):
        _card(string_scan=short)


def test_triage_card_string_scan_read_can_come_up_short_never_long():
    with pytest.raises(ValueError, match="must not exceed"):
        _card(string_scan=_string_scan(requested_bytes=4096, bytes_read=8192, truncated=False))


def test_triage_card_string_scan_truncated_must_agree_with_the_byte_counts():
    # The flag is not an independent opinion -- it IS bytes_read <
    # requested_bytes. A card claiming a complete scan over a short read
    # publishes "scanned it all, found nothing" for evidence that was
    # never fully read, which is the one thing this record must not do.
    with pytest.raises(ValueError, match="truncated.. must equal"):
        _card(string_scan=_string_scan(requested_bytes=4096, bytes_read=1024, truncated=False))
    with pytest.raises(ValueError, match="truncated.. must equal"):
        _card(string_scan=_string_scan(requested_bytes=4096, bytes_read=4096, truncated=True))


def test_triage_card_string_scan_and_its_error_are_mutually_exclusive():
    # A scan either produced counts or raised; both at once is a
    # self-contradicting evidence state no real dump can produce.
    with pytest.raises(ValueError, match="mutually exclusive"):
        _card(string_scan=_string_scan(), string_scan_error="read_region failed: boom")


def test_triage_card_extract_read_flags_travel_together():
    # Both None means no --output was attempted for this card at all;
    # once it was, both are real answers. One alone would make "no
    # extract happened" indistinguishable from "the extract was complete".
    with pytest.raises(ValueError, match="must both be"):
        _card(extract_read_clamped=True, extract_read_truncated=None)
    with pytest.raises(ValueError, match="must both be"):
        _card(extract_read_clamped=None, extract_read_truncated=False)


def test_triage_card_findings_are_restricted_to_the_closed_dimension_keys():
    with pytest.raises(ValueError, match="findings entries must all be one of"):
        _card(findings=["looked_weird"], finding_details={"looked_weird": "a hunch"},
               verdict="SUSPICIOUS")


def test_triage_card_findings_may_not_repeat_a_dimension():
    # The dimensions are MECE: counting one twice would inflate the
    # verdict tier below, which is derived from len(findings).
    with pytest.raises(ValueError, match="must not contain duplicate keys"):
        _card(findings=["rwx_private", "rwx_private"],
               finding_details={"rwx_private": "x"}, verdict="LIKELY_MALICIOUS")


def test_triage_card_finding_details_must_be_str_to_str():
    with pytest.raises(TypeError, match="finding_details must be a dict of str"):
        _card(findings=["rwx_private"], finding_details={"rwx_private": 1},
               verdict="SUSPICIOUS")


def test_triage_card_findings_and_finding_details_must_name_the_same_keys():
    # A finding with no detail prints as a bare key with nothing behind
    # it; a detail with no finding is text for a dimension that never
    # fired -- and neither is visible in the JSON without cross-reading.
    with pytest.raises(ValueError, match="must name the same keys"):
        _card(findings=["rwx_private"], finding_details={}, verdict="SUSPICIOUS")
    with pytest.raises(ValueError, match="must name the same keys"):
        _card(findings=[], finding_details={"rwx_private": "x"}, verdict="CLEAN")


def test_triage_card_rejects_a_verdict_outside_the_vocabulary():
    with pytest.raises(ValueError, match="verdict must be one of"):
        _card(verdict="MALICIOUS")


def test_triage_card_verdict_must_match_the_four_tier_rule():
    with pytest.raises(ValueError, match="does not match the four-tier rule"):
        _card(findings=["rwx_private"], finding_details={"rwx_private": "x"}, verdict="CLEAN")
    with pytest.raises(ValueError, match="does not match the four-tier rule"):
        _card(findings=[], finding_details={}, verdict="HIGH_CONFIDENCE_MALICIOUS")


@pytest.mark.parametrize("count", [0, 1, 2, 3, 4])
def test_triage_card_verdict_tiering_agrees_with_core_memory_verdict_for(count):
    """The one rule in this module that is deliberately MIRRORED rather
    than imported: records.py keeps its own _TRIAGE_VERDICTS and its own
    four-tier check so it takes no dependency on dumpex.core.memory,
    while core.memory.verdict_for() is what the console's own colored
    text renders from. The class docstring claims the wire value and the
    console text are provably the same rule -- nothing proved it until
    here. A test can import both sides without creating the dependency
    the records module is avoiding, so this is where the mirror is
    checked, including the len(findings) >= 3 saturation both share.
    """
    from dumpex.core.memory import verdict_for

    findings = list(_TRIAGE_FINDING_KEYS)[:count]
    dims = {key: f"{key} fired" for key in findings}
    expected = verdict_for(dims)
    card = _card(findings=findings, finding_details=dims, verdict=expected)
    assert card.verdict == expected == _TRIAGE_VERDICTS[min(count, 3)]

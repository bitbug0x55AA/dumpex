"""
Unit tests for dumpex.output.records -- the v2 canonical record
dataclasses. Covers to_dict() shapes, the None-not-"" convention, and
hex_address()'s normalization (fixed-width, zero-padded, lowercase).
"""
import pytest

from dumpex.output.records import (
    MemoryRegionRecord, ModuleRecord, ThreadRecord, SysInfoRecord, PidRecord, PebRecord,
    Diagnostic, SEVERITY_WARNING, SEVERITY_ERROR, hex_address, Artifact,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
    ModuleDiffRecord, MODULE_DIFF_ADDED, MODULE_DIFF_REMOVED, MODULE_DIFF_REBASED,
    ThreadDiffRecord, THREAD_DIFF_ADDED, THREAD_DIFF_REMOVED,
    MemoryDiffRecord, MEMORY_DIFF_ADDED, MEMORY_DIFF_REMOVED, MEMORY_DIFF_PROTECTION_CHANGED,
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


def test_module_record_has_no_size_hex_field():
    rec = ModuleRecord(name="a.dll", full_path=None, base_address="0x1000",
                        end_address="0x2000", size=4096, compiled_utc=None,
                        file_version=None, checksum=None)
    assert "size_hex" not in rec.to_dict()
    assert rec.to_dict()["size"] == 4096


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


# ── SysInfoRecord / PidRecord / PebRecord ─────────────────────────────────
# Split from a single shared record type after review -- see the v2
# schema task: three separate, tightly-typed record kinds instead of one
# with dozens of nulled-out fields per command.

def test_sysinfo_record_all_fields_default_to_none():
    rec = SysInfoRecord()
    for key, value in rec.to_dict().items():
        assert value is None, f"{key} should default to None, got {value!r}"


def test_sysinfo_record_partial_population_leaves_rest_none():
    rec = SysInfoRecord(pid=1234, thread_count=3)
    d = rec.to_dict()
    assert d["pid"] == 1234
    assert d["thread_count"] == 3
    assert d["hostname"] is None
    assert d["os"] is None


def test_pid_record_all_fields_default_to_none():
    rec = PidRecord()
    for key, value in rec.to_dict().items():
        assert value is None, f"{key} should default to None, got {value!r}"


def test_pid_record_partial_population():
    rec = PidRecord(pid=1234, source="MINIDUMP_MISC_INFO (ProcessId field)", thread_count=3)
    d = rec.to_dict()
    assert d == {"pid": 1234, "source": "MINIDUMP_MISC_INFO (ProcessId field)",
                 "thread_count": 3, "exc_tid": None}


def test_peb_record_all_fields_default_to_none():
    rec = PebRecord()
    for key, value in rec.to_dict().items():
        assert value is None, f"{key} should default to None, got {value!r}"


def test_peb_record_environment_variables_defensive_copy():
    env = [{"name": "PATH", "value": "C:\\"}]
    rec = PebRecord(environment_variables=env)
    d = rec.to_dict()
    env.append({"name": "MUTATED", "value": "x"})
    assert d["environment_variables"] == [{"name": "PATH", "value": "C:\\"}]


# ── Diagnostic ───────────────────────────────────────────────────────────

def test_diagnostic_to_dict():
    d = Diagnostic(severity=SEVERITY_WARNING, message="something", code="W001").to_dict()
    assert d == {"severity": "warning", "message": "something", "code": "W001"}
    assert SEVERITY_ERROR == "error"


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

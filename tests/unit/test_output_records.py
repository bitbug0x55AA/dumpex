"""
Unit tests for dumpex.output.records -- the v2 canonical record
dataclasses. Covers to_dict() shapes, the None-not-"" convention, and
hex_address()'s normalization (fixed-width, zero-padded, lowercase).
"""
from dumpex.output.records import (
    MemoryRegionRecord, ModuleRecord, ThreadRecord, ProcessInfoRecord,
    Diagnostic, SEVERITY_WARNING, SEVERITY_ERROR, hex_address,
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
    rec = ThreadRecord(tid=4660, start_address=None, backing_module=None,
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
                        create_time=None, exit_time=None, exit_status=None,
                        kernel_time_100ns=None, user_time_100ns=None,
                        suspend_count=None, priority=None, teb=hex_address(0x2000))
    d = rec.to_dict()
    assert d["start_address"] == "0x0000000000001000"
    assert d["teb"] == "0x0000000000002000"


def test_thread_record_flags_defaults_to_empty_list():
    rec = ThreadRecord(tid=1, start_address=None, backing_module=None,
                        create_time=None, exit_time=None, exit_status=None,
                        kernel_time_100ns=None, user_time_100ns=None,
                        suspend_count=None, priority=None, teb=None)
    assert rec.to_dict()["flags"] == []


# ── ProcessInfoRecord ────────────────────────────────────────────────────

def test_process_info_record_all_fields_default_to_none():
    rec = ProcessInfoRecord()
    d = rec.to_dict()
    for key, value in d.items():
        assert value is None, f"{key} should default to None, got {value!r}"


def test_process_info_record_environment_variables_defensive_copy():
    env = [{"name": "PATH", "value": "C:\\"}]
    rec = ProcessInfoRecord(environment_variables=env)
    d = rec.to_dict()
    env.append({"name": "MUTATED", "value": "x"})
    assert d["environment_variables"] == [{"name": "PATH", "value": "C:\\"}]


def test_process_info_record_partial_population_leaves_rest_none():
    rec = ProcessInfoRecord(pid=1234, source="MINIDUMP_MISC_INFO (ProcessId field)",
                             thread_count=3)
    d = rec.to_dict()
    assert d["pid"] == 1234
    assert d["source"] == "MINIDUMP_MISC_INFO (ProcessId field)"
    assert d["thread_count"] == 3
    assert d["hostname"] is None
    assert d["os"] is None


# ── Diagnostic ───────────────────────────────────────────────────────────

def test_diagnostic_to_dict():
    d = Diagnostic(severity=SEVERITY_WARNING, message="something", code="W001").to_dict()
    assert d == {"severity": "warning", "message": "something", "code": "W001"}
    assert SEVERITY_ERROR == "error"


def test_diagnostic_code_defaults_to_none():
    d = Diagnostic(severity=SEVERITY_ERROR, message="boom").to_dict()
    assert d["code"] is None

"""Unit tests for dumpex.core.process_info's shared process-identity
boundary -- issue #37 contract §3.4 (claims/diagnostics),
§3.3.3/§3.3.4 (module resolution and fallback precedence), and §4.4
(environment entry `=`-prefix reconstruction).

These are the tests the P1/P2 review of the first #38 pass asked for:
a builder that combines PEB/MiscInfo/ModuleList source precedence with
typed diagnostics, module resolution that never leaks a raw parser
object past this module's boundary, a UTC-formatted process creation
time (not just its ok/unset/invalid classification), and proof that a
fallback source can never erase a preferred source's own conflicting
claim.
"""
import dataclasses
import json

import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE

from tests.fixtures.fakes import (
    Module, Peb, MiscInfo, FakeStream, Segment, build_pe_header, TEXT_SECTION_RX,
)

from dumpex.core.process_info import (
    format_process_create_time_utc, build_process_identity_snapshot,
    parse_environment_entries, EnvironmentEntry,
    MiscInfoClaim, PebClaim, ModuleClaim, ModuleReference, ProcessDiagnostic,
    ProcessIdentitySnapshot, MainImagePeClaim,
)


class _FakeSegment:
    """Stand-in for MinidumpBufferedMemorySegment -- just enough of
    .remaining_len() for dumpex.core.memory.read_region()'s move()/
    read() pair."""
    def __init__(self, start, data):
        self.start_address = start
        self.data = data
        self.end_address = start + len(data)

    def remaining_len(self, position):
        if not (self.start_address <= position < self.end_address):
            return None
        return self.end_address - position


class _FakeBufferedReader:
    def __init__(self, segments: dict):
        self._segments = [_FakeSegment(start, data) for start, data in segments.items()]
        self.current_segment = None
        self.current_position = None

    def move(self, address):
        for seg in self._segments:
            if seg.start_address <= address < seg.end_address:
                self.current_segment = seg
                self.current_position = address
                return
        raise Exception('Memory address 0x%08x is not in process memory space' % address)

    def read(self, size):
        end = self.current_position + size
        if end > self.current_segment.end_address:
            raise Exception('Would read over segment boundaries!')
        off = self.current_position - self.current_segment.start_address
        data = self.current_segment.data[off:off + size]
        self.current_position = end
        return data


class _FakeReader:
    def __init__(self, buffered):
        self._buffered = buffered

    def get_buffered_reader(self):
        return self._buffered


class _Poison:
    """Stands in for a raw parser sub-object a malformed/mocked `mf`
    might expose -- must never leak into a snapshot's raw_* fields."""
    def __init__(self, label):
        self.label = label

    def __str__(self):
        return f"<Poison {self.label}>"


class _MF:
    def __init__(self, *, misc_info=None, peb=None, modules=None, stream_failures=None, memory=None):
        self.misc_info = misc_info
        self.peb = peb
        # `modules` is a list -- None means "ModuleListStream absent",
        # matching mf.modules being None after open_dump()'s isolation.
        self.modules = FakeStream(modules, "modules") if modules is not None else None
        # Real open_dump() always sets this (possibly {}); a bare test
        # fixture defaults it the same way so stream_failure()'s own
        # "missing attribute means no failures" fallback is exercised
        # only by the tests that explicitly want it.
        self._dumpex_stream_failures = stream_failures or {}
        # dumpex.core.memory.va_range_captured_bytes()/read_region() (used
        # by _build_main_image_pe_claim) read these unconditionally --
        # `memory` is {va: bytes}, one contiguous segment per entry.
        memory = memory or {}
        self.memory_segments_64 = (
            FakeStream([Segment(va, va, len(data)) for va, data in memory.items()], "memory_segments")
            if memory else None)
        self.memory_segments = None
        self._reader = _FakeReader(_FakeBufferedReader(memory))

    def get_reader(self):
        return self._reader


# ── format_process_create_time_utc ────────────────────────────────────────

def test_format_process_create_time_utc_ok_value():
    # 2026-08-14 01:15:05 UTC
    assert format_process_create_time_utc(1786670105) == "2026-08-14 01:15:05 UTC"


def test_format_process_create_time_utc_unset_is_none():
    assert format_process_create_time_utc(0) is None


def test_format_process_create_time_utc_invalid_is_none():
    assert format_process_create_time_utc(0x1_0000_0000) is None
    assert format_process_create_time_utc(-1) is None
    assert format_process_create_time_utc("nope") is None


def test_format_process_create_time_utc_never_depends_on_local_timezone(monkeypatch):
    # Same raw value -> same string, regardless of what TZ the process
    # happens to be running under.
    import time
    a = format_process_create_time_utc(1700000000)
    monkeypatch.setenv("TZ", "America/New_York")
    if hasattr(time, "tzset"):
        time.tzset()
    b = format_process_create_time_utc(1700000000)
    if hasattr(time, "tzset"):
        monkeypatch.delenv("TZ", raising=False)
        time.tzset()
    assert a == b


# ── MiscInfoClaim / PebClaim via build_process_identity_snapshot ─────────

def test_misc_info_claim_all_none_when_misc_info_absent():
    snap = build_process_identity_snapshot(_MF())
    assert snap.misc_info_claim == MiscInfoClaim(
        pid=None, process_create_time_utc=None, raw_pid=None, raw_process_create_time=None,
        source_state="absent", failure_detail=None)


def test_misc_info_claim_populated_for_valid_values():
    mi = MiscInfo(process_id=4242, process_create_time=1786670105)
    snap = build_process_identity_snapshot(_MF(misc_info=mi))
    assert snap.misc_info_claim.pid == 4242
    assert snap.misc_info_claim.process_create_time_utc == "2026-08-14 01:15:05 UTC"
    assert snap.misc_info_claim.raw_pid is None
    assert snap.misc_info_claim.raw_process_create_time is None
    assert snap.pid == 4242
    assert snap.process_start_utc == "2026-08-14 01:15:05 UTC"


def test_misc_info_claim_preserves_raw_pid_when_rejected():
    mi = MiscInfo(process_id=0, process_create_time=1786670105)   # 0 is the library's unset value
    snap = build_process_identity_snapshot(_MF(misc_info=mi))
    assert snap.misc_info_claim.pid is None
    assert snap.misc_info_claim.raw_pid == 0
    assert snap.pid is None


def test_misc_info_claim_preserves_raw_create_time_when_invalid():
    mi = MiscInfo(process_id=4242, process_create_time=0x1_0000_0000)
    snap = build_process_identity_snapshot(_MF(misc_info=mi))
    assert snap.misc_info_claim.process_create_time_utc is None
    assert snap.misc_info_claim.raw_process_create_time == 0x1_0000_0000


def test_peb_claim_all_none_when_peb_absent():
    snap = build_process_identity_snapshot(_MF())
    assert snap.peb_claim == PebClaim(
        image_base_address=None, image_path=None, name=None, command_line=None,
        raw_image_base_address=None, raw_image_path=None, raw_command_line=None,
        source_state="absent")
    assert snap.image_base_address is None
    assert snap.command_line is None


def test_peb_claim_populated_and_name_is_windows_basename():
    peb = Peb(0x00007ff600010000, r"C:\Samples\malware.exe", command_line='"malware.exe" -k')
    snap = build_process_identity_snapshot(_MF(peb=peb))
    assert snap.peb_claim.image_base_address == 0x00007ff600010000
    assert snap.peb_claim.image_path == r"C:\Samples\malware.exe"
    assert snap.peb_claim.name == "malware.exe"
    assert snap.peb_claim.command_line == '"malware.exe" -k'
    assert snap.image_base_address == 0x00007ff600010000


def test_peb_claim_preserves_raw_image_base_when_unaligned():
    peb = Peb(0x00007ff600010abc, r"C:\Samples\malware.exe")   # not 0x1000-aligned
    snap = build_process_identity_snapshot(_MF(peb=peb))
    assert snap.peb_claim.image_base_address is None
    # §3.2: "hex string when the raw value is an int in uint64 range" --
    # unaligned doesn't disqualify it from being renderable as an address.
    assert snap.peb_claim.raw_image_base_address == "0x00007ff600010abc"


def test_peb_claim_never_lowercases_name():
    peb = Peb(0x140000000, r"C:\Samples\Malware.EXE")
    snap = build_process_identity_snapshot(_MF(peb=peb))
    assert snap.peb_claim.name == "Malware.EXE"


# ── ModuleClaim: match_state and module resolution ────────────────────────

def test_module_claim_unavailable_when_peb_absent():
    snap = build_process_identity_snapshot(_MF(modules=[Module(0x140000000, 0x1000, "a.dll")]))
    assert snap.module_claim.match_state == "unavailable"
    assert snap.module_claim.base_address is None


def test_module_claim_unavailable_when_modules_stream_absent():
    peb = Peb(0x140000000, r"C:\a.exe")
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=None))
    assert snap.module_claim.match_state == "unavailable"


def test_module_claim_resolved_returns_module_reference_never_raw_module():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x140000000, 0x2000, r"C:\Samples\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.match_state == "resolved"
    assert snap.module_claim.base_address == 0x140000000
    assert snap.module_claim.name == "malware.exe"
    assert snap.module_claim.path == r"C:\Samples\malware.exe"
    # Never the raw fakes.Module instance -- only scalars survive the boundary.
    assert not isinstance(snap.module_claim.base_address, Module)
    assert type(snap.module_claim) is ModuleClaim


def test_module_claim_unregistered_no_candidate():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x150000000, 0x2000, r"C:\Windows\other.dll")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.match_state == "unregistered"
    assert snap.module_claim.name_matched_candidate is None
    assert snap.module_claim.name_matched_candidate_ambiguous is False


def test_module_claim_unregistered_with_single_name_matched_candidate():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x999000000, 0x2000, r"C:\Windows\Temp\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.match_state == "unregistered"
    candidate = snap.module_claim.name_matched_candidate
    assert candidate == ModuleReference(base_address=0x999000000, name="malware.exe",
                                         path=r"C:\Windows\Temp\malware.exe")
    assert snap.module_claim.name_matched_candidate_ambiguous is False


def test_module_claim_name_matched_candidate_case_insensitive():
    peb = Peb(0x140000000, r"C:\Samples\MALWARE.EXE")
    modules = [Module(0x999000000, 0x2000, r"C:\Windows\Temp\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.name_matched_candidate is not None


def test_module_claim_ambiguous_when_multiple_candidates_keeps_first_in_source_order():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [
        Module(0x999000000, 0x2000, r"C:\Windows\Temp\malware.exe"),
        Module(0x888000000, 0x2000, r"C:\ProgramData\malware.exe"),
    ]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.name_matched_candidate_ambiguous is True
    assert snap.module_claim.name_matched_candidate.base_address == 0x999000000


# ── path/name precedence (§3.3.1) and the fallback ─────────────────────────

def test_selected_path_source_is_peb_when_peb_path_present():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x999000000, 0x2000, r"C:\Windows\Temp\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.selected_path_source == "peb"
    assert snap.selected_process_path == r"C:\Samples\malware.exe"
    assert snap.selected_process_name == "malware.exe"


def test_selected_path_source_falls_back_to_module_when_peb_path_unavailable():
    peb = Peb(0x140000000, "")   # empty PEB path -> normalize_windows_path() -> None
    modules = [Module(0x140000000, 0x2000, r"C:\Samples\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.selected_path_source == "module"
    assert snap.selected_process_path == r"C:\Samples\malware.exe"
    assert snap.selected_process_name == "malware.exe"
    codes = [d.code for d in snap.diagnostics]
    assert "PROCESS_PATH_SOURCE_FALLBACK" in codes


def test_selected_path_source_none_when_neither_source_has_a_path():
    peb = Peb(0x140000000, "")
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=[]))
    assert snap.selected_path_source is None
    assert snap.selected_process_path is None
    assert snap.selected_process_name is None


def test_fallback_never_erases_the_preferred_sources_own_claim():
    # PEB DOES supply a path -- it wins -- but ModuleListStream's own
    # matching-name module sits at a conflicting base. The module fact
    # must still be fully visible (module_claim + its diagnostic), and
    # the PEB's own claim (and the selected path) must be completely
    # unaffected by it.
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x999000000, 0x2000, r"C:\Windows\Temp\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))

    assert snap.selected_path_source == "peb"
    assert snap.selected_process_path == r"C:\Samples\malware.exe"
    assert snap.image_base_address == 0x140000000   # never promoted from module_claim

    assert snap.peb_claim.image_path == r"C:\Samples\malware.exe"
    assert snap.module_claim.match_state == "unregistered"
    assert snap.module_claim.name_matched_candidate.base_address == 0x999000000

    codes = [d.code for d in snap.diagnostics]
    assert "PROCESS_MODULE_BASE_CONFLICT" in codes
    assert "PROCESS_PATH_SOURCE_FALLBACK" not in codes   # the module was never used as the path source


# ── diagnostics (§3.4.4/§6.2) ─────────────────────────────────────────────

def test_diagnostic_base_unmatched_when_no_candidate():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x150000000, 0x2000, r"C:\Windows\other.dll")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert len(snap.diagnostics) == 1
    d = snap.diagnostics[0]
    assert d.code == "PROCESS_MODULE_BASE_UNMATCHED"
    assert d.severity == "info"
    assert d.details["peb_base"] == "0x0000000140000000"


def test_diagnostic_base_conflict_when_candidate_present():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x999000000, 0x2000, r"C:\Windows\Temp\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    d = snap.diagnostics[0]
    assert d.code == "PROCESS_MODULE_BASE_CONFLICT"
    assert d.severity == "warning"
    assert d.details["name"] == "malware.exe"
    assert d.details["module_base"] == "0x0000000999000000"
    assert d.details["peb_base"] == "0x0000000140000000"


def test_diagnostic_name_ambiguous_alongside_base_conflict_in_declared_order():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [
        Module(0x999000000, 0x2000, r"C:\Windows\Temp\malware.exe"),
        Module(0x888000000, 0x2000, r"C:\ProgramData\malware.exe"),
    ]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    codes = [d.code for d in snap.diagnostics]
    assert codes == ["PROCESS_MODULE_BASE_CONFLICT", "PROCESS_MODULE_NAME_AMBIGUOUS"]
    assert snap.diagnostics[1].details["count"] == 2


def test_diagnostic_identity_mismatch_when_resolved_names_disagree():
    peb = Peb(0x140000000, r"C:\Samples\renamed.exe")
    modules = [Module(0x140000000, 0x2000, r"C:\Samples\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.match_state == "resolved"
    codes = [d.code for d in snap.diagnostics]
    assert codes == ["PROCESS_MODULE_IDENTITY_MISMATCH"]
    d = snap.diagnostics[0]
    assert d.severity == "warning"
    assert d.details == {"peb_name": "renamed.exe", "module_name": "malware.exe"}


def test_no_identity_mismatch_when_resolved_names_agree_case_insensitively():
    peb = Peb(0x140000000, r"C:\Samples\MALWARE.exe")
    modules = [Module(0x140000000, 0x2000, r"C:\Windows\malware.EXE")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.match_state == "resolved"
    assert snap.diagnostics == ()


def test_module_claim_unavailable_fires_no_diagnostics():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=None))
    assert snap.module_claim.match_state == "unavailable"
    assert snap.diagnostics == ()


def test_diagnostics_never_change_when_everything_is_clean():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x140000000, 0x2000, r"C:\Samples\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.match_state == "resolved"
    assert snap.diagnostics == ()


# ── immutability ──────────────────────────────────────────────────────────

def test_snapshot_and_claims_are_frozen():
    snap = build_process_identity_snapshot(_MF())
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.selected_path_source = "peb"
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.peb_claim.image_path = "x"
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.misc_info_claim.pid = 1


def test_diagnostic_details_is_immutable_mapping():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x150000000, 0x2000, r"C:\Windows\other.dll")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    with pytest.raises(TypeError):
        snap.diagnostics[0].details["peb_base"] = "tampered"


# ── parse_environment_entries (§4.4) ───────────────────────────────────────

def test_parse_environment_entries_none_or_empty():
    assert parse_environment_entries(None) == ()
    assert parse_environment_entries([]) == ()


def test_parse_environment_entries_simple():
    assert parse_environment_entries(["A=1"]) == (EnvironmentEntry("A", "1"),)


def test_parse_environment_entries_preserves_order_and_duplicates():
    result = parse_environment_entries(["A=1", "B=2", "A=1"])
    assert result == (EnvironmentEntry("A", "1"), EnvironmentEntry("B", "2"), EnvironmentEntry("A", "1"))


def test_parse_environment_entries_empty_value():
    assert parse_environment_entries(["A="]) == (EnvironmentEntry("A", ""),)


def test_parse_environment_entries_no_equals_sign_keeps_whole_string_as_name():
    assert parse_environment_entries(["JUSTNAME"]) == (EnvironmentEntry("JUSTNAME", ""),)


def test_parse_environment_entries_special_drive_working_directory_reconstruction():
    result = parse_environment_entries(["=C:=C:\\Work"])
    assert result == (EnvironmentEntry("=C:", "C:\\Work"),)


def test_parse_environment_entries_multiple_special_entries():
    result = parse_environment_entries(["=C:=C:\\Work", "=D:=D:\\Data", "PATH=C:\\Windows"])
    assert result == (
        EnvironmentEntry("=C:", "C:\\Work"),
        EnvironmentEntry("=D:", "D:\\Data"),
        EnvironmentEntry("PATH", "C:\\Windows"),
    )


# ── parse_environment_entries: dict / tuple-like input shapes ────────────
# The issue explicitly asks for "dictionaries and tuple-like entries" --
# the installed minidump library's OWN PEB.from_minidump() already
# produces peb.environment_variables as a list of {"name":..., "value":...}
# dicts, so a caller consuming that directly (rather than
# walk_environment_block()'s independent re-walk) must normalize through
# the same function.

def test_parse_environment_entries_accepts_name_value_mapping():
    result = parse_environment_entries([{"name": "A", "value": "1"}])
    assert result == (EnvironmentEntry("A", "1"),)


def test_parse_environment_entries_name_value_mapping_defaults_missing_value_to_empty():
    result = parse_environment_entries([{"name": "A"}])
    assert result == (EnvironmentEntry("A", ""),)


def test_parse_environment_entries_accepts_single_key_mapping():
    result = parse_environment_entries([{"A": "1"}])
    assert result == (EnvironmentEntry("A", "1"),)


def test_parse_environment_entries_accepts_tuple_and_list_pairs():
    assert parse_environment_entries([("A", "1")]) == (EnvironmentEntry("A", "1"),)
    assert parse_environment_entries([["B", "2"]]) == (EnvironmentEntry("B", "2"),)


def test_parse_environment_entries_mixed_shapes_in_one_list():
    result = parse_environment_entries(
        ["A=1", {"name": "B", "value": "2"}, ("C", "3"), {"D": "4"}])
    assert result == (
        EnvironmentEntry("A", "1"), EnvironmentEntry("B", "2"),
        EnvironmentEntry("C", "3"), EnvironmentEntry("D", "4"))


def test_parse_environment_entries_coerces_non_string_name_value():
    result = parse_environment_entries([(1, 2)])
    assert result == (EnvironmentEntry("1", "2"),)


def test_parse_environment_entries_mapping_without_name_or_single_key_raises():
    with pytest.raises(TypeError):
        parse_environment_entries([{"A": "1", "B": "2"}])


def test_parse_environment_entries_unsupported_shape_raises():
    with pytest.raises(TypeError):
        parse_environment_entries([123])
    with pytest.raises(TypeError):
        parse_environment_entries([("only", "two", "allowed")])


def test_parse_environment_entries_input_mutation_after_call_does_not_affect_result():
    entry = {"name": "A", "value": "1"}
    entries = [entry]
    result = parse_environment_entries(entries)
    entry["value"] = "MUTATED"
    entries.append({"name": "B", "value": "2"})
    assert result == (EnvironmentEntry("A", "1"),)


# ── absence vs. failure: MiscInfo/ModuleList source_state ────────────────

def test_misc_info_claim_source_state_present_when_populated():
    mi = MiscInfo(process_id=4242, process_create_time=1786670105)
    snap = build_process_identity_snapshot(_MF(misc_info=mi))
    assert snap.misc_info_claim.source_state == "present"
    assert snap.misc_info_claim.failure_detail is None


def test_misc_info_claim_source_state_absent_when_stream_absent():
    snap = build_process_identity_snapshot(_MF())
    assert snap.misc_info_claim.source_state == "absent"
    assert snap.misc_info_claim.failure_detail is None


def test_misc_info_claim_source_state_failed_distinguishable_from_absent():
    snap = build_process_identity_snapshot(_MF(
        stream_failures={MINIDUMP_STREAM_TYPE.MiscInfoStream: "ValueError: corrupt stream"}))
    assert snap.misc_info_claim.source_state == "failed"
    assert snap.misc_info_claim.failure_detail == "ValueError: corrupt stream"
    assert snap.misc_info_claim.pid is None


def test_peb_claim_source_state_present_and_absent():
    absent = build_process_identity_snapshot(_MF())
    present = build_process_identity_snapshot(_MF(peb=Peb(0x140000000, r"C:\a.exe")))
    assert absent.peb_claim.source_state == "absent"
    assert present.peb_claim.source_state == "present"


def test_module_claim_absent_vs_failed_distinguishable_though_match_state_agrees():
    peb = Peb(0x140000000, r"C:\a.exe")
    absent_snap = build_process_identity_snapshot(_MF(peb=peb, modules=None))
    failed_snap = build_process_identity_snapshot(_MF(
        peb=peb, modules=None,
        stream_failures={MINIDUMP_STREAM_TYPE.ModuleListStream: "ValueError: corrupt module list"}))

    assert absent_snap.module_claim.match_state == "unavailable"
    assert failed_snap.module_claim.match_state == "unavailable"
    assert absent_snap.module_claim.modules_source_state == "absent"
    assert absent_snap.module_claim.modules_failure_detail is None
    assert failed_snap.module_claim.modules_source_state == "failed"
    assert failed_snap.module_claim.modules_failure_detail == "ValueError: corrupt module list"


def test_module_claim_source_state_present_when_resolved():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x140000000, 0x2000, r"C:\Samples\malware.exe")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.module_claim.modules_source_state == "present"
    assert snap.module_claim.modules_failure_detail is None


# ── poison-reference / mutation / JSON-serialization ─────────────────────

def test_raw_pid_never_retains_the_original_rejected_object():
    poison = _Poison("pid")
    mi = MiscInfo(process_id=poison)
    snap = build_process_identity_snapshot(_MF(misc_info=mi))
    assert snap.misc_info_claim.pid is None
    assert snap.misc_info_claim.raw_pid == "<Poison pid>"
    assert snap.misc_info_claim.raw_pid is not poison
    assert isinstance(snap.misc_info_claim.raw_pid, str)
    json.dumps(snap.misc_info_claim.raw_pid)   # must not raise


def test_raw_process_create_time_never_retains_the_original_rejected_object():
    poison = _Poison("time")
    mi = MiscInfo(process_id=1, process_create_time=poison)
    snap = build_process_identity_snapshot(_MF(misc_info=mi))
    assert snap.misc_info_claim.process_create_time_utc is None
    assert snap.misc_info_claim.raw_process_create_time == "<Poison time>"
    json.dumps(snap.misc_info_claim.raw_process_create_time)


def test_raw_image_base_never_retains_the_original_rejected_object():
    poison = _Poison("base")
    peb = Peb(poison, r"C:\a.exe")
    snap = build_process_identity_snapshot(_MF(peb=peb))
    assert snap.peb_claim.image_base_address is None
    assert snap.peb_claim.raw_image_base_address == "<Poison base>"
    json.dumps(snap.peb_claim.raw_image_base_address)


def test_raw_image_base_negative_int_becomes_decimal_string_not_hex():
    peb = Peb(-4096, r"C:\a.exe")
    snap = build_process_identity_snapshot(_MF(peb=peb))
    assert snap.peb_claim.raw_image_base_address == "-4096"


def test_raw_image_path_never_retains_a_non_string_object():
    poison = _Poison("path")
    peb = Peb(0x140000000, poison)
    snap = build_process_identity_snapshot(_MF(peb=peb))
    assert snap.peb_claim.image_path is None
    assert snap.peb_claim.raw_image_path == "<Poison path>"
    json.dumps(snap.peb_claim.raw_image_path)


def test_str_conversion_failure_is_caught_not_propagated():
    class _Explodes:
        def __str__(self):
            raise RuntimeError("nope")
    mi = MiscInfo(process_id=_Explodes())
    snap = build_process_identity_snapshot(_MF(misc_info=mi))
    assert snap.misc_info_claim.raw_pid == "<unrepresentable _Explodes>"


def test_mutating_source_object_after_snapshot_does_not_affect_it():
    mi = MiscInfo(process_id=4242)
    snap = build_process_identity_snapshot(_MF(misc_info=mi))
    mi.ProcessId = 9999
    assert snap.misc_info_claim.pid == 4242


def test_snapshot_claims_are_json_serializable_end_to_end():
    poison = _Poison("pid")
    mi = MiscInfo(process_id=poison, process_create_time=0x1_0000_0000)
    peb = Peb(0x00007ff600010abc, "")   # unaligned base, empty path
    snap = build_process_identity_snapshot(_MF(misc_info=mi, peb=peb))
    payload = {
        "misc_info_claim": dataclasses.asdict(snap.misc_info_claim),
        "peb_claim": dataclasses.asdict(snap.peb_claim),
    }
    json.dumps(payload)   # must not raise


# ── ProcessDiagnostic.affected_count (§3.4.4) ─────────────────────────────

def test_process_diagnostic_affected_count_defaults_to_none_for_one_shot_diagnostics():
    peb = Peb(0x140000000, r"C:\Samples\malware.exe")
    modules = [Module(0x150000000, 0x2000, r"C:\Windows\other.dll")]
    snap = build_process_identity_snapshot(_MF(peb=peb, modules=modules))
    assert snap.diagnostics
    assert all(d.affected_count is None for d in snap.diagnostics)


def test_process_diagnostic_accepts_positive_affected_count():
    d = ProcessDiagnostic(code="X", severity="info", message="m", affected_count=3)
    assert d.affected_count == 3


def test_process_diagnostic_rejects_zero_or_negative_affected_count():
    with pytest.raises(ValueError):
        ProcessDiagnostic(code="X", severity="info", message="m", affected_count=0)
    with pytest.raises(ValueError):
        ProcessDiagnostic(code="X", severity="info", message="m", affected_count=-1)


def test_process_diagnostic_rejects_bool_affected_count():
    with pytest.raises(ValueError):
        ProcessDiagnostic(code="X", severity="info", message="m", affected_count=True)


def test_process_diagnostic_rejects_non_int_affected_count():
    with pytest.raises(ValueError):
        ProcessDiagnostic(code="X", severity="info", message="m", affected_count="3")


# ── MainImagePeClaim (§3.4.4) ─────────────────────────────────────────────

def test_main_image_pe_not_checked_when_no_normalized_image_base():
    snap = build_process_identity_snapshot(_MF())
    assert snap.main_image_pe == MainImagePeClaim(checked=False, valid=None, reason=None)


def test_main_image_pe_not_checked_when_nothing_captured_at_image_base():
    peb = Peb(0x140000000, r"C:\a.exe")
    snap = build_process_identity_snapshot(_MF(peb=peb))   # no memory data at all
    assert snap.main_image_pe.checked is False
    assert snap.main_image_pe.valid is None


def test_main_image_pe_valid_for_a_structurally_sound_header():
    base = 0x140000000
    header_bytes = build_pe_header([TEXT_SECTION_RX], image_base=base)
    peb = Peb(base, r"C:\Samples\malware.exe")
    snap = build_process_identity_snapshot(_MF(peb=peb, memory={base: header_bytes}))
    assert snap.main_image_pe.checked is True
    assert snap.main_image_pe.valid is True
    assert snap.main_image_pe.reason is None


def test_main_image_pe_invalid_for_garbage_bytes():
    base = 0x140000000
    peb = Peb(base, r"C:\Samples\malware.exe")
    snap = build_process_identity_snapshot(_MF(peb=peb, memory={base: b"\x00" * 4096}))
    assert snap.main_image_pe.checked is True
    assert snap.main_image_pe.valid is False
    assert snap.main_image_pe.reason


def test_main_image_pe_never_shares_reason_string_object_by_composition():
    # reason is copied verbatim from parse_pe_header()'s own dict, never
    # composed/concatenated here.
    base = 0x140000000
    peb = Peb(base, r"C:\Samples\malware.exe")
    snap = build_process_identity_snapshot(_MF(peb=peb, memory={base: b"NOTMZ" + b"\x00" * 100}))
    assert snap.main_image_pe.checked is True
    assert snap.main_image_pe.valid is False
    assert "MZ" in snap.main_image_pe.reason

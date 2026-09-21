"""Unit tests for dumpex.commands.extract's --extract collect/render split
(Phase E, PR1). collect_extract() returns a dumpex.output.command_result.
CommandResult -- accessed via attributes, never unpacked as a tuple.

--strings (cmd_strings) is migrated separately in Phase E, PR2 -- see
tests/unit/test_strings_cmd.py.

Every success-path test writes through the real write_output_bytes(), so
each uses tmp_path for the output path -- never a bare relative filename,
which would write into whatever the test runner's cwd happens to be.
"""
import hashlib

import pytest

from tests.fixtures.fakes import (
    FakeMF, FakeStream, Module, Region, mem_reader, build_pe_header, TEXT_SECTION_RX,
)

import dumpex.commands.extract as extract_mod
from dumpex.commands.extract import (
    collect_extract, cmd_extract, build_extract_artifact, OutputWriteError,
    render_extract_console,
)
from dumpex.core.memory import RegionReadError
from dumpex.output.coverage import SourceState, CoverageStatus
from dumpex.output.records import ExtractRecord, Artifact, Diagnostic, SEVERITY_WARNING

# Reuse the same fixtures test_report_cmd.py builds: a minimal, structurally
# valid PE32+ header (one executable .text section), and the same header
# with its one section declared read-only (a resource-only PE).
_VALID_PE_BYTES = build_pe_header([TEXT_SECTION_RX])
_RESOURCE_ONLY_PE_BYTES = build_pe_header([{
    "name": b".rsrc", "vaddr": 0x1000, "vsize": 0x2000,
    "rawptr": 0x400, "rawsize": 0x2000, "chars": 0x40000000,  # READ only
}])


def _mk_mf(monkeypatch, data_map, filename="test.dmp"):
    mf = FakeMF()
    mf.filename = filename
    monkeypatch.setattr(extract_mod, "read_region", mem_reader(data_map))
    return mf


def test_collect_extract_happy_path(monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, {0x1000: b"hello world"})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x1000, 11, out_path, auto_size=False, force=True)

    assert result.kind == "extract"
    assert len(result.records) == 1
    rec = result.records[0]
    assert isinstance(rec, ExtractRecord)
    assert rec.requested_address == "0x0000000000001000"
    assert rec.requested_size == 11
    assert rec.auto_sized is False
    assert rec.bytes_read == 11
    assert rec.mz_header_detected is False

    assert len(result.artifacts) == 1
    artifact = result.artifacts[0]
    assert isinstance(artifact, Artifact)
    assert artifact.id == "extract_output"
    assert artifact.kind == "extracted_region"
    assert artifact.path == out_path
    assert artifact.size_bytes == 11
    assert artifact.sha256 == hashlib.sha256(b"hello world").hexdigest()

    assert result.diagnostics == []
    assert result.coverage.status == "complete"
    assert result.coverage.sources["requested_region"].state == SourceState.PRESENT
    assert result.coverage.sources["requested_region"].record_count == 1
    # No output_path in summary -- artifacts[0].path (asserted above) is
    # the one authoritative place the write-side path lives (P1
    # remediation: a second unredacted copy of the path in `summary`
    # would leak it even under --redact-paths).
    assert result.summary == {"count": 1}
    assert (tmp_path / "out.bin").read_bytes() == b"hello world"


def test_collect_extract_default_output_filename(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    mf = _mk_mf(monkeypatch, {0x2000: b"x" * 10})
    result = collect_extract(mf, 0x2000, 10, None, auto_size=False, force=True)
    assert result.artifacts[0].path == "region_0x2000.bin"
    assert "output_path" not in result.summary
    assert (tmp_path / "region_0x2000.bin").read_bytes() == b"x" * 10


def test_collect_extract_auto_sized_flag_reflected_on_record(monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, {0x3000: b"y" * 20})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x3000, 20, out_path, auto_size=True, force=True)
    assert result.records[0].auto_sized is True


def test_collect_extract_mz_header_detected_adds_diagnostic(monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, {0x4000: b"MZ" + b"\x90" * 62})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4000, 64, out_path, auto_size=False, force=True)
    assert result.records[0].mz_header_detected is True
    assert len(result.diagnostics) == 1
    diag = result.diagnostics[0]
    assert isinstance(diag, Diagnostic)
    assert diag.severity == SEVERITY_WARNING
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "MZ header detected" in diag.message


# ── domain correction: extraction, like Report, requires more than a bare
# ── MZ prefix before claiming "injected PE" -- module registration, memory
# ── type, and structural validity are independent facts (issue #216) ─────

def test_collect_extract_mz_only_in_unregistered_private_memory_is_not_confirmed_injected(
        monkeypatch, tmp_path):
    # e_lfanew doesn't even point at a real "PE\0\0" signature -- a bare
    # MZ-shaped coincidence, not a structurally valid PE. Even though the
    # region IS MEM_PRIVATE and confirmed unregistered, this must stay the
    # weaker, honest claim.
    mf = _mk_mf(monkeypatch, {0x4100: b"MZ" + b"\x90" * 62})
    mf.modules = FakeStream([], "modules")   # present but empty -> confirmed unregistered
    mf.memory_info = FakeStream(
        [Region(0x4100, 0x4100, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4100, 64, out_path, auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "not independently confirmed as an injected PE" in diag.message
    assert "failed structural PE validation" in diag.message
    assert result.records[0].pe_header_state == "pe_invalid"
    assert result.coverage.status == CoverageStatus.COMPLETE   # both streams present
    render_extract_console(result.records, result.artifacts, result.diagnostics, result.coverage)


def test_collect_extract_valid_resource_pe_in_mapped_memory_is_not_confirmed_injected(
        monkeypatch, tmp_path):
    # A structurally valid, read-only PE header with no executable
    # section, in a confirmed-unregistered MEM_MAPPED region -- a
    # resource-only file view (e.g. via MapViewOfFile) legitimately has no
    # module-list entry and is not, by itself, evidence of injection.
    mf = _mk_mf(monkeypatch, {0x4200: _RESOURCE_ONLY_PE_BYTES})
    mf.modules = FakeStream([], "modules")
    mf.memory_info = FakeStream(
        [Region(0x4200, 0x4200, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")], "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4200, len(_RESOURCE_ONLY_PE_BYTES), out_path,
                             auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "not independently confirmed as an injected PE" in diag.message
    assert "neither MEM_PRIVATE nor executable" in diag.message
    assert result.records[0].pe_header_state == "ok"
    assert result.coverage.status == CoverageStatus.COMPLETE   # both streams present


def test_collect_extract_valid_pe_in_unregistered_private_memory_is_confirmed_injected(
        monkeypatch, tmp_path):
    # A structurally valid, executable PE header, confirmed unregistered,
    # in MEM_PRIVATE memory -- the one case worth the stronger claim.
    mf = _mk_mf(monkeypatch, {0x4300: _VALID_PE_BYTES})
    mf.modules = FakeStream([Module(0x9000, 0x1000, r"C:\Windows\System32\ntdll.dll")], "modules")
    mf.memory_info = FakeStream(
        [Region(0x4300, 0x4300, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4300, len(_VALID_PE_BYTES), out_path,
                             auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_INJECTED_PE_DETECTED"
    assert "possible injected PE" in diag.message
    assert "MEM_PRIVATE" in diag.message
    assert result.records[0].pe_header_state == "ok"
    assert result.coverage.status == CoverageStatus.COMPLETE
    render_extract_console(result.records, result.artifacts, result.diagnostics, result.coverage)


# ── the same scenario with ModuleListStream / MemoryInfoListStream
# ── missing: the injected-PE claim's own evidence dependency must be
# ── visible in coverage.status, not just silently degrade the diagnostic ──

def test_collect_extract_injected_pe_evidence_lowers_coverage_without_modules(
        monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, {0x4310: _VALID_PE_BYTES})
    # mf.modules left at its FakeMF default (None) -- ModuleListStream
    # entirely absent, so registration itself could never be checked.
    mf.memory_info = FakeStream(
        [Region(0x4310, 0x4310, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4310, len(_VALID_PE_BYTES), out_path,
                             auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "ModuleListStream absent" in diag.message
    assert result.coverage.status != CoverageStatus.COMPLETE
    assert any("ModuleListStream" in r for r in result.coverage.reasons)


def test_collect_extract_injected_pe_evidence_lowers_coverage_without_memory_info(
        monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, {0x4320: _VALID_PE_BYTES})
    mf.modules = FakeStream([Module(0x9000, 0x1000, r"C:\Windows\System32\ntdll.dll")], "modules")
    # mf.memory_info left at its FakeMF default (None) -- MemoryInfoListStream
    # entirely absent, so memory type/protection could never be confirmed.
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4320, len(_VALID_PE_BYTES), out_path,
                             auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "MemoryInfoListStream absent" in diag.message
    assert result.coverage.status != CoverageStatus.COMPLETE
    assert any("MemoryInfoListStream" in r for r in result.coverage.reasons)


def test_collect_extract_known_module_owns_address_stays_complete_without_memory_info(
        monkeypatch, tmp_path):
    # A known module already confirms this address is NOT an unregistered
    # injected PE, regardless of the containing region's memory type --
    # MemoryInfoListStream is never even consulted for that decision, so a
    # dump missing it entirely must not lower coverage.status. Requiring
    # it unconditionally once an MZ header is seen would penalize a
    # perfectly resolved, sufficiently-evidenced extraction for evidence
    # its own conclusion never depended on.
    mf = _mk_mf(monkeypatch, {0x4500: _VALID_PE_BYTES})
    mf.modules = FakeStream([Module(0x4500, 0x1000, r"C:\Windows\System32\known.dll")], "modules")
    # mf.memory_info left at its FakeMF default (None) -- entirely absent.
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4500, len(_VALID_PE_BYTES), out_path,
                             auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "a known module owns this address" in diag.message
    assert result.records[0].pe_header_state is None
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert result.coverage.limitations == []
    assert "memory_info" not in result.coverage.sources


def test_collect_extract_known_module_owns_address_stays_complete_with_memory_info_present(
        monkeypatch, tmp_path):
    # Same known-module resolution, but MemoryInfoListStream also happens
    # to be present this time -- an unrelated source's presence or absence
    # must not change the result either way once module ownership alone
    # already settles the question.
    mf = _mk_mf(monkeypatch, {0x4510: _VALID_PE_BYTES})
    mf.modules = FakeStream([Module(0x4510, 0x1000, r"C:\Windows\System32\known.dll")], "modules")
    mf.memory_info = FakeStream(
        [Region(0x4510, 0x4510, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")], "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4510, len(_VALID_PE_BYTES), out_path,
                             auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "a known module owns this address" in diag.message
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert result.coverage.limitations == []


def test_collect_extract_region_not_found_is_diagnostic_only_matches_report(
        monkeypatch, tmp_path):
    # MemoryInfoListStream IS present -- unlike the sibling test above --
    # but has no descriptor covering the extracted address. The diagnostic
    # names this clearly, but it must NOT move coverage.status: this is
    # the same dump condition dumpex.commands.report's own
    # REPORT_REGION_NOT_FOUND handles as diagnostic-only ("no committed
    # region found" is loud on the console but never itself a coverage
    # gap there), and the two commands must agree on whether the same
    # condition is a coverage gap.
    mf = _mk_mf(monkeypatch, {0x4325: _VALID_PE_BYTES})
    mf.modules = FakeStream([Module(0x9000, 0x1000, r"C:\Windows\System32\ntdll.dll")], "modules")
    mf.memory_info = FakeStream(
        [Region(0x9000, 0x9000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")], "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4325, len(_VALID_PE_BYTES), out_path,
                             auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "no MemoryInfo region covers this address" in diag.message
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert result.coverage.limitations == []


def test_collect_extract_names_both_deficits_when_modules_absent_and_region_not_found(
        monkeypatch, tmp_path):
    # Two INDEPENDENT axes fail at once here: ModuleListStream is entirely
    # absent (module ownership unconfirmable) AND MemoryInfoListStream,
    # while present, has no descriptor covering the address (memory type/
    # protection also unconfirmable). Both must be named -- an analyst
    # reading only the module-list reason would wrongly conclude that
    # re-collecting just the module list would settle the question.
    mf = _mk_mf(monkeypatch, {0x4326: _VALID_PE_BYTES})
    # mf.modules left at its FakeMF default (None) -- ModuleListStream absent.
    mf.memory_info = FakeStream(
        [Region(0x9000, 0x9000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")], "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4326, len(_VALID_PE_BYTES), out_path,
                             auto_size=False, force=True)
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "ModuleListStream absent" in diag.message
    assert "no MemoryInfo region covers this address" in diag.message
    # coverage.status still moves to partial, but solely via the
    # ModuleListStream axis (EXTRACT_MODULE_CONTEXT_UNAVAILABLE) -- the
    # region-not-found fact stays diagnostic-only, per the test above.
    assert result.coverage.status != CoverageStatus.COMPLETE
    codes = {lim.code.value for lim in result.coverage.limitations}
    assert codes == {"EXTRACT_MODULE_CONTEXT_UNAVAILABLE"}


def test_report_and_extract_agree_region_not_found_is_diagnostic_only(monkeypatch):
    # --report and --extract must answer "is this a coverage gap" the same
    # way for the identical dump condition: a present MemoryInfoListStream
    # with no descriptor covering the target address. --report's own
    # REPORT_REGION_NOT_FOUND has always stayed diagnostic-only; the two
    # sibling tests above establish --extract's analogous fact now matches
    # it rather than lowering coverage.status on its own -- this test pins
    # the agreement directly, on the same fixture shape, rather than
    # relying on separately-verified pieces staying in sync by accident.
    import dumpex.commands.report as report_mod
    import dumpex.core.memory as core_memory_mod
    from dumpex.commands.report import collect_report

    mf = FakeMF()
    mf.filename = "test.dmp"
    mf.modules = FakeStream([Module(0x9000, 0x1000, r"C:\Windows\System32\ntdll.dll")], "modules")
    mf.memory_info = FakeStream(
        [Region(0x9000, 0x9000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")], "infos")
    mf.thread_info = FakeStream([], "infos")
    monkeypatch.setattr(report_mod, "read_region", mem_reader({}))
    monkeypatch.setattr(core_memory_mod, "read_region", mem_reader({}))

    result = collect_report(mf, report_addr="0x4327")
    codes = [d.code for d in result.diagnostics]
    assert "REPORT_REGION_NOT_FOUND" in codes
    assert result.coverage.status == CoverageStatus.COMPLETE


def test_collect_extract_mz_only_no_context_needed_stays_complete(monkeypatch, tmp_path):
    # No MZ header at all -- module/region context is never even consulted,
    # so missing streams must not lower coverage for an ordinary extract.
    mf = _mk_mf(monkeypatch, {0x4330: b"not a PE header." + b"\x00" * 48})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4330, 64, out_path, auto_size=False, force=True)
    assert result.records[0].mz_header_detected is False
    assert result.diagnostics == []
    assert result.coverage.status == CoverageStatus.COMPLETE


def test_collect_extract_pe_invalid_header_is_not_confirmed_injected(monkeypatch, tmp_path):
    # A full, deterministic structural rejection (not a capture-length
    # gap): distinct from the short_read case below, and the console
    # message must name the specific reason, not both at once.
    mf = _mk_mf(monkeypatch, {0x4340: b"MZ" + b"\x90" * 62})
    mf.modules = FakeStream([], "modules")
    mf.memory_info = FakeStream(
        [Region(0x4340, 0x4340, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4340, 64, out_path, auto_size=False, force=True)
    assert result.records[0].pe_header_state == "pe_invalid"
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "failed structural PE validation" in diag.message
    assert result.coverage.status == CoverageStatus.COMPLETE


def test_collect_extract_partial_pe_header_is_not_confirmed_injected(monkeypatch, tmp_path):
    # Fewer bytes requested than a full header needs -- parse_pe_header()
    # cannot structurally validate (a genuine capture-length gap, distinct
    # from test_collect_extract_pe_invalid_header_is_not_confirmed_injected's
    # deterministic rejection above), so this must not be promoted to a
    # confirmed injected-PE claim either.
    mf = _mk_mf(monkeypatch, {0x4400: _VALID_PE_BYTES[:48]})
    mf.modules = FakeStream([], "modules")
    mf.memory_info = FakeStream(
        [Region(0x4400, 0x4400, 64, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4400, 48, out_path, auto_size=False, force=True)
    assert result.records[0].pe_header_state == "short_read"
    diag = result.diagnostics[0]
    assert diag.code == "EXTRACT_MZ_HEADER_DETECTED"
    assert "too little of the header was captured" in diag.message
    assert "failed structural PE validation" not in diag.message
    # The raw read itself came up FULL (48 of 48 requested bytes) -- only
    # the structural parse was left short -- so REGION_READ_TRUNCATED must
    # NOT fire, but the unresolved structural question is still a real
    # coverage gap: --report's own REPORT_PE_HEADER_VALIDATION_INCOMPLETE
    # marks the identical fact partial rather than complete, and --extract
    # must not answer "is this a coverage gap" differently for the same
    # dump condition.
    assert result.coverage.status == CoverageStatus.PARTIAL
    codes = {lim.code.value for lim in result.coverage.limitations}
    assert codes == {"EXTRACT_PE_HEADER_VALIDATION_INCOMPLETE"}


def test_collect_extract_short_raw_read_also_leaving_header_short_names_both_gaps(
        monkeypatch, tmp_path):
    # The raw read AND the structural parse are both short at once: fewer
    # bytes came back than requested (read_region() itself came up short --
    # the dump does not back the rest), and what little arrived is not even
    # enough to reach e_lfanew. REGION_READ_TRUNCATED and
    # EXTRACT_PE_HEADER_VALIDATION_INCOMPLETE are independent facts and
    # must both fire; neither's fixed text may claim the other's cause
    # (e.g. neither may assert the read was "in full").
    mf = _mk_mf(monkeypatch, {0x4410: _VALID_PE_BYTES[:48]})
    mf.modules = FakeStream([], "modules")
    mf.memory_info = FakeStream(
        [Region(0x4410, 0x4410, 64, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x4410, 64, out_path, auto_size=False, force=True)
    assert result.records[0].bytes_read == 48
    assert result.records[0].pe_header_state == "short_read"
    assert result.coverage.status == CoverageStatus.PARTIAL
    codes = {lim.code.value for lim in result.coverage.limitations}
    assert codes == {"REGION_READ_TRUNCATED", "EXTRACT_PE_HEADER_VALIDATION_INCOMPLETE"}


def test_collect_extract_short_read_marks_coverage_partial(monkeypatch, tmp_path):
    # P1-4 remediation: read_region() returning fewer bytes than requested
    # (the region extends past what's actually backed in the dump) must
    # not be silently reported as a full, complete read.
    mf = _mk_mf(monkeypatch, {0x6000: b"only nine"})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x6000, 64, out_path, auto_size=False, force=True)
    assert result.records[0].requested_size == 64
    assert result.records[0].bytes_read == 9
    assert result.coverage.status == "partial"
    assert result.coverage.sources["requested_region"].state == SourceState.PRESENT
    codes = {lim.code for lim in result.coverage.limitations}
    assert "REGION_READ_TRUNCATED" in codes


def test_collect_extract_full_read_stays_complete(monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, {0x7000: b"exactly ten"})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x7000, 11, out_path, auto_size=False, force=True)
    assert result.records[0].bytes_read == 11
    assert result.coverage.status == "complete"
    assert result.coverage.limitations == []


def test_collect_extract_no_mz_header_no_diagnostic(monkeypatch, tmp_path):
    mf = _mk_mf(monkeypatch, {0x5000: b"not a pe header"})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x5000, 15, out_path, auto_size=False, force=True)
    assert result.records[0].mz_header_detected is False
    assert result.diagnostics == []


def test_collect_extract_read_failure_wrapped_as_region_read_error(monkeypatch):
    # P2-2 remediation: collect_extract() wraps a read_region() failure
    # into RegionReadError specifically (not left as whatever raw
    # exception type read_region() happened to raise) -- a bad
    # address/size is a usage error, not a coverage fact (see Phase E's
    # plan for why this stays a hard failure rather than becoming
    # SourceState.FAILED/coverage), and cmd_extract's own try/except
    # relies on this specific type to distinguish a read failure from an
    # unrelated write failure or construction bug (see tests below).
    def _boom(mf, addr, size):
        raise RuntimeError("bad address")
    monkeypatch.setattr(extract_mod, "read_region", _boom)
    mf = FakeMF()
    with pytest.raises(RegionReadError, match="bad address"):
        collect_extract(mf, 0x9999, 16, "out.bin")


def test_collect_extract_write_failure_wrapped_as_output_write_error(monkeypatch, tmp_path):
    # A write failure (e.g. PermissionError) must be distinguishable from
    # a read failure -- before this fix, cmd_extract's blanket
    # `except Exception` mislabeled this as "Read failed".
    mf = _mk_mf(monkeypatch, {0x1000: b"hello world"})

    def _boom_write(*args, **kwargs):
        raise PermissionError("access denied")
    monkeypatch.setattr(extract_mod, "write_output_bytes", _boom_write)

    with pytest.raises(OutputWriteError, match="access denied"):
        collect_extract(mf, 0x1000, 11, str(tmp_path / "out.bin"), force=True)


def test_collect_extract_non_io_construction_bug_propagates_as_itself(monkeypatch, tmp_path):
    # A programming/schema-construction bug (here simulated as a bogus
    # Artifact kwarg) must propagate as ITSELF -- neither "Read failed"
    # nor "Write failed" is an honest description of what went wrong, and
    # silently mislabeling it would hide a real bug behind a misleading
    # user-facing message.
    mf = _mk_mf(monkeypatch, {0x1000: b"hello world"})

    def _boom_artifact(*args, **kwargs):
        raise TypeError("Artifact() got an unexpected keyword argument 'bogus'")
    monkeypatch.setattr(extract_mod, "build_extract_artifact", _boom_artifact)

    with pytest.raises(TypeError, match="bogus"):
        collect_extract(mf, 0x1000, 11, str(tmp_path / "out.bin"), force=True)


def test_build_extract_artifact_computes_size_and_hash():
    data = b"payload bytes"
    artifact = build_extract_artifact("id1", "some_kind", "some/path.bin", data,
                                       description="a description")
    assert artifact.size_bytes == len(data)
    assert artifact.sha256 == hashlib.sha256(data).hexdigest()
    assert artifact.description == "a description"


def test_cmd_extract_read_failure_exits_1(monkeypatch, capsys):
    def _boom(mf, addr, size):
        raise RuntimeError("bad address")
    monkeypatch.setattr(extract_mod, "read_region", _boom)
    mf = FakeMF()
    mf.filename = "test.dmp"
    with pytest.raises(SystemExit) as exc:
        cmd_extract(mf, 0x9999, 16, "out.bin")
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "[*] Reading 0x10 bytes from 0x9999 ..." in out
    assert "[!] Read failed: bad address" in out


def test_cmd_extract_write_failure_exits_1_with_write_failed_message(monkeypatch, capsys, tmp_path):
    # P2-2 remediation: a write failure must print "Write failed", not
    # "Read failed" -- the read itself succeeded.
    mf = _mk_mf(monkeypatch, {0x1000: b"hello world"})

    def _boom_write(*args, **kwargs):
        raise PermissionError("access denied")
    monkeypatch.setattr(extract_mod, "write_output_bytes", _boom_write)

    with pytest.raises(SystemExit) as exc:
        cmd_extract(mf, 0x1000, 11, str(tmp_path / "out.bin"), force=True)
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "[!] Write failed: access denied" in out
    assert "Read failed" not in out


def test_cmd_extract_returns_command_result_on_success(monkeypatch, capsys, tmp_path):
    mf = _mk_mf(monkeypatch, {0x1000: b"hello world"})
    out_path = str(tmp_path / "out.bin")
    result = cmd_extract(mf, 0x1000, 11, out_path, auto_size=False, force=True)
    assert result.kind == "extract"
    out = capsys.readouterr().out
    assert "[*] Reading 0xb bytes from 0x1000 ..." in out
    assert "[+] Saved" in out
    assert "[~]" not in out   # a full read must print no coverage-reason line at all


def test_cmd_extract_short_read_prints_partial_notice_and_still_saves(monkeypatch, tmp_path, capsys):
    # P2 remediation: a short read must be visible on the console, not
    # just in the JSON exit code -- an analyst running --extract without
    # --json would otherwise see a normal-looking "[+] Saved" line
    # with no indication the read was truncated.
    mf = _mk_mf(monkeypatch, {0x6000: b"only nine"})
    out_path = str(tmp_path / "out.bin")
    result = cmd_extract(mf, 0x6000, 64, out_path, auto_size=False, force=True)
    assert result.coverage.status == "partial"
    out = capsys.readouterr().out
    assert "[~] Requested memory region was only partially read" in out
    assert "[+] Saved" in out   # the (truncated) output is still saved and reported

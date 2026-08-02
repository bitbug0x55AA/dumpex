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

from tests.fixtures.fakes import FakeMF, mem_reader

import dumpex.commands.extract as extract_mod
from dumpex.commands.extract import (
    collect_extract, cmd_extract, build_extract_artifact, OutputWriteError,
)
from dumpex.core.memory import RegionReadError
from dumpex.output.coverage import SourceState
from dumpex.output.records import ExtractRecord, Artifact, Diagnostic, SEVERITY_WARNING


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
    assert result.summary == {"count": 1, "output_path": out_path}
    assert (tmp_path / "out.bin").read_bytes() == b"hello world"


def test_collect_extract_default_output_filename(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    mf = _mk_mf(monkeypatch, {0x2000: b"x" * 10})
    result = collect_extract(mf, 0x2000, 10, None, auto_size=False, force=True)
    assert result.artifacts[0].path == "region_0x2000.bin"
    assert result.summary["output_path"] == "region_0x2000.bin"
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

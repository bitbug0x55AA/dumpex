"""Unit tests for dumpex.commands.extract's --strings collect/render split
(Phase E, PR2). collect_strings() returns a dumpex.output.command_result.
CommandResult -- accessed via attributes, never unpacked as a tuple.
"""
import re

import pytest

from tests.fixtures.fakes import FakeMF, mem_reader

import dumpex.commands.extract as extract_mod
from dumpex.commands.extract import collect_strings, cmd_strings, render_strings_console
from dumpex.core.memory import RegionReadError
from dumpex.output.coverage import SourceState
from dumpex.output.records import StringRecord


def _mk_mf(monkeypatch, data_map, filename="test.dmp"):
    mf = FakeMF()
    mf.filename = filename
    monkeypatch.setattr(extract_mod, "read_region", mem_reader(data_map))
    return mf


def test_collect_strings_happy_path(monkeypatch):
    data = b"hello world!\x00\x00" + b"another string here" + b"\x00" * 10
    mf = _mk_mf(monkeypatch, {0x1000: data})
    result = collect_strings(mf, 0x1000, len(data), 6, None, "both")

    assert result.kind == "strings"
    assert len(result.records) == 2
    rec = result.records[0]
    assert isinstance(rec, StringRecord)
    assert rec.offset == 0
    assert rec.address == "0x0000000000001000"
    assert rec.encoding == "ASCII"
    assert rec.text == "hello world!"
    assert rec.matched_grep is None

    assert result.coverage.status == "complete"
    assert result.coverage.sources["requested_region"].state == SourceState.PRESENT
    assert result.coverage.sources["requested_region"].record_count == 2
    assert result.summary == {"count": 2, "shown": 2, "requested_address": "0x0000000000001000",
                               "requested_size": len(data), "bytes_read": len(data),
                               "auto_sized": False}


def test_collect_strings_no_strings_found_is_present_empty(monkeypatch):
    mf = _mk_mf(monkeypatch, {0x4000: b"\x01\x02\x03" * 5})
    result = collect_strings(mf, 0x4000, 15, 6, None, "both")

    assert result.records == []
    assert result.coverage.sources["requested_region"].state == SourceState.PRESENT_EMPTY
    assert result.coverage.sources["requested_region"].record_count == 0
    assert result.coverage.status == "complete"
    # P2 remediation: a zero-result scan is exactly the case where
    # summary.requested_address matters most -- the structured records
    # list is empty, so requested_address is the ONLY way a consumer can
    # tell where the (empty) scan even started.
    assert result.summary == {"count": 0, "shown": 0, "requested_address": "0x0000000000004000",
                               "requested_size": 15, "bytes_read": 15, "auto_sized": False}


def test_collect_strings_requested_address_reflects_auto_sized_flag(monkeypatch):
    # requested_address is independent of auto_size -- it's always
    # hex_address(addr) regardless of how the size argument was resolved.
    mf = _mk_mf(monkeypatch, {0x9000: b"a string long enough"})
    result = collect_strings(mf, 0x9000, 21, 6, None, "ascii", auto_size=True)
    assert result.summary["requested_address"] == "0x0000000000009000"
    assert result.summary["auto_sized"] is True


def test_collect_strings_short_read_marks_coverage_partial(monkeypatch):
    # P1-4 remediation: same short-read gap as collect_extract -- a
    # truncated read must not be silently reported as complete just
    # because at least one string happened to be found in what WAS read.
    mf = _mk_mf(monkeypatch, {0x6000: b"only a short string here"})
    result = collect_strings(mf, 0x6000, 200, 6, None, "ascii")
    assert result.summary["requested_size"] == 200
    assert result.summary["bytes_read"] == 24
    assert result.coverage.status == "partial"
    assert result.coverage.sources["requested_region"].state == SourceState.PRESENT
    codes = {lim.code for lim in result.coverage.limitations}
    assert "REGION_READ_TRUNCATED" in codes


def test_collect_strings_full_read_stays_complete(monkeypatch):
    data = b"exactly this many bytes"
    mf = _mk_mf(monkeypatch, {0x7000: data})
    result = collect_strings(mf, 0x7000, len(data), 6, None, "ascii")
    assert result.summary["bytes_read"] == len(data)
    assert result.coverage.status == "complete"
    assert result.coverage.limitations == []


def test_collect_strings_matched_grep_true_false_when_grep_given(monkeypatch):
    data = b"apple pie recipe" + b"\x00" * 5 + b"cherry tart notes"
    mf = _mk_mf(monkeypatch, {0x3000: data})
    result = collect_strings(mf, 0x3000, len(data), 6, "recipe", "ascii")

    assert len(result.records) == 2
    assert result.records[0].matched_grep is True
    assert result.records[1].matched_grep is False
    # matched_grep is a flag, not a filter -- both records are always present.
    assert result.summary["count"] == 2
    assert result.summary["shown"] == 1


def test_grep_console_shows_fewer_lines_than_structured_records(monkeypatch, capsys):
    # Docs remediation: the structured records list (JSON/CSV) and the
    # console rendering deliberately show DIFFERENT amounts of data for a
    # --grep run -- records always includes every extracted string
    # (matched_grep is a flag, never a filter), but the console SKIPS any
    # record with matched_grep is False, only ever highlighting matches.
    # This test locks in that contrast directly, rather than trusting a
    # prose description of it.
    data = b"apple pie recipe" + b"\x00" * 5 + b"cherry tart notes"
    mf = _mk_mf(monkeypatch, {0x3000: data})
    result = collect_strings(mf, 0x3000, len(data), 6, "recipe", "ascii")

    assert len(result.records) == 2   # structured: both the match AND the non-match

    render_strings_console(result.records, result.coverage)
    console = capsys.readouterr().out
    assert "apple pie recipe" in console
    assert "cherry tart notes" not in console   # console: the non-match is skipped entirely
    assert "[+] 1 string(s) shown." in console


def test_collect_strings_matched_grep_none_when_no_grep(monkeypatch):
    data = b"apple pie recipe here"
    mf = _mk_mf(monkeypatch, {0x3000: data})
    result = collect_strings(mf, 0x3000, len(data), 6, None, "ascii")

    assert result.records[0].matched_grep is None
    assert result.summary["shown"] == 1


def test_collect_strings_encoding_ascii_excludes_utf16(monkeypatch):
    utf16_str = "wide string here".encode("utf-16-le")
    data = b"short" + b"\x00" + utf16_str + b"\x00\x00" + b"ascii text too here"
    mf = _mk_mf(monkeypatch, {0x2000: data})
    result = collect_strings(mf, 0x2000, len(data), 6, None, "ascii")

    assert all(r.encoding == "ASCII" for r in result.records)


def test_collect_strings_encoding_unicode_excludes_ascii(monkeypatch):
    utf16_str = "wide string here".encode("utf-16-le")
    data = b"short" + b"\x00" + utf16_str + b"\x00\x00" + b"ascii text too here"
    mf = _mk_mf(monkeypatch, {0x2000: data})
    result = collect_strings(mf, 0x2000, len(data), 6, None, "unicode")

    assert all(r.encoding == "UTF16" for r in result.records)


def test_collect_strings_read_failure_wrapped_as_region_read_error(monkeypatch):
    # P2-2 remediation: same RegionReadError wrapping as collect_extract
    # -- see test_extract_cmd.py's equivalent test and Phase E's plan for
    # why this stays a hard failure rather than becoming
    # SourceState.FAILED/coverage.
    def _boom(mf, addr, size):
        raise RuntimeError("bad address")
    monkeypatch.setattr(extract_mod, "read_region", _boom)
    mf = FakeMF()
    with pytest.raises(RegionReadError, match="bad address"):
        collect_strings(mf, 0x9999, 16, 6, None, "both")


def test_collect_strings_bad_grep_regex_propagates_as_re_error(monkeypatch):
    # A malformed --grep pattern must propagate as re.error, not get
    # relabeled as a read failure just because it's raised inside the
    # same function, after a successful read.
    mf = _mk_mf(monkeypatch, {0x1000: b"hello world!" + b"\x00" * 10})
    with pytest.raises(re.error):
        collect_strings(mf, 0x1000, 22, 6, "(unclosed", "ascii")


def test_cmd_strings_read_failure_exits_1(monkeypatch, capsys):
    def _boom(mf, addr, size):
        raise RuntimeError("bad address")
    monkeypatch.setattr(extract_mod, "read_region", _boom)
    mf = FakeMF()
    mf.filename = "test.dmp"
    with pytest.raises(SystemExit) as exc:
        cmd_strings(mf, 0x9999, 16, 6, None, "both")
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "[*] Extracting strings from 0x9999" in out
    assert "[!] Read failed: bad address" in out


def test_cmd_strings_bad_grep_regex_exits_1_with_invalid_regex_message(monkeypatch, capsys):
    mf = _mk_mf(monkeypatch, {0x1000: b"hello world!" + b"\x00" * 10})
    with pytest.raises(SystemExit) as exc:
        cmd_strings(mf, 0x1000, 22, 6, "(unclosed", "ascii")
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "[!] Invalid --grep regex:" in out
    assert "Read failed" not in out


def test_cmd_strings_returns_command_result_on_success(monkeypatch, capsys):
    data = b"hello world!\x00\x00"
    mf = _mk_mf(monkeypatch, {0x1000: data})
    result = cmd_strings(mf, 0x1000, len(data), 6, None, "both")
    assert result.kind == "strings"
    out = capsys.readouterr().out
    assert "[*] Extracting strings from 0x1000" in out
    assert "string(s) shown" in out
    assert "[~]" not in out   # a full read must print no coverage-reason line at all


def test_cmd_strings_short_read_prints_partial_notice(monkeypatch, capsys):
    # P2 remediation: same console visibility gap as cmd_extract -- a
    # short read must not look identical to a complete one just because
    # at least one string was found in what WAS read.
    mf = _mk_mf(monkeypatch, {0x6000: b"only a short string here"})
    result = cmd_strings(mf, 0x6000, 200, 6, None, "ascii")
    assert result.coverage.status == "partial"
    out = capsys.readouterr().out
    assert "[~] Requested memory region was only partially read" in out

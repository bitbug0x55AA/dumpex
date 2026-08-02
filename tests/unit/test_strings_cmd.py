"""Unit tests for dumpex.commands.extract's --strings collect/render split
(Phase E, PR2). collect_strings() returns a dumpex.output.command_result.
CommandResult -- accessed via attributes, never unpacked as a tuple.
"""
import re

import pytest

from tests.fixtures.fakes import FakeMF, mem_reader

import dumpex.commands.extract as extract_mod
from dumpex.commands.extract import collect_strings, cmd_strings
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
    assert result.summary == {"count": 2, "shown": 2}


def test_collect_strings_no_strings_found_is_present_empty(monkeypatch):
    mf = _mk_mf(monkeypatch, {0x4000: b"\x01\x02\x03" * 5})
    result = collect_strings(mf, 0x4000, 15, 6, None, "both")

    assert result.records == []
    assert result.coverage.sources["requested_region"].state == SourceState.PRESENT_EMPTY
    assert result.coverage.sources["requested_region"].record_count == 0
    assert result.coverage.status == "complete"
    assert result.summary == {"count": 0, "shown": 0}


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


def test_collect_strings_read_failure_propagates_unwrapped(monkeypatch):
    # Same reasoning as collect_extract -- see test_extract_cmd.py's
    # equivalent test and Phase E's plan for why this stays a hard
    # failure rather than becoming SourceState.FAILED/coverage.
    def _boom(mf, addr, size):
        raise RuntimeError("bad address")
    monkeypatch.setattr(extract_mod, "read_region", _boom)
    mf = FakeMF()
    with pytest.raises(RuntimeError, match="bad address"):
        collect_strings(mf, 0x9999, 16, 6, None, "both")


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


def test_cmd_strings_returns_command_result_on_success(monkeypatch, capsys):
    data = b"hello world!\x00\x00"
    mf = _mk_mf(monkeypatch, {0x1000: data})
    result = cmd_strings(mf, 0x1000, len(data), 6, None, "both")
    assert result.kind == "strings"
    out = capsys.readouterr().out
    assert "[*] Extracting strings from 0x1000" in out
    assert "string(s) shown" in out

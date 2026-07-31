"""
Integration tests for --csv through the real CLI, driven by each of the
six v2-routed recon commands' actual collect_*() output (via FakeMF), not
synthetic hand-built records. This was the single largest gap identified
in the Phase A compatibility-freeze audit: --csv was previously only
exercised in tests/unit/test_output_csv_and_collector.py against records
constructed directly (bypassing the real collectors), always at
status="complete", and never through the --csv CLI flag itself.

Each command gets one "real source data present" test (asserting the CSV
records table reflects genuine field values) and one "source(s) absent /
degraded" test (asserting the CSV summary table reflects the resulting
non-complete coverage_status and the process exit code matches).
"""
import csv
import io
import os
import re
import sys
import tempfile

import pytest

import dumpex.cli as cli
from tests.fixtures.fakes import (
    FakeMF, Region, Module, Thread, ThreadInfo, Ctx, FakeStream, Peb, MiscInfo, SysInfo,
)


def _run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["dumpex"] + argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def _make_dump_file() -> str:
    fd, path = tempfile.mkstemp(suffix=".dmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"synthetic dump content")
    return path


def _table(text: str, header: str) -> list:
    # Cuts the named table's block out from between its own "## kind /
    # name" header and either the next such header or end of file --
    # a single-file --csv export concatenates every table into one
    # document, so a naive split on the header alone would let
    # csv.DictReader run past this table's rows into the next table's
    # header/rows.
    pattern = re.compile(rf"## {re.escape(header)}\n(.*?)(?=\n## |\Z)", re.S)
    match = pattern.search(text)
    assert match, f"table {header!r} not found in:\n{text}"
    return list(csv.DictReader(io.StringIO(match.group(1))))


# ── --list ────────────────────────────────────────────────────────────

def test_list_csv_present_reflects_real_records(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.memory_info = FakeStream(
            [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
            "infos")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--list", "--csv", out_csv])
        cli.main()   # complete -- no SystemExit

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "memory_regions / records")
        assert len(rows) == 1
        assert rows[0]["base_address"] == "0x0000000000001000"
        assert rows[0]["suspicious"] == "True"
    finally:
        os.remove(dump_path)


def test_list_csv_absent_stream_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # MemoryInfoListStream absent entirely
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        code = _run(monkeypatch, [dump_path, "--list", "--csv", out_csv])
        assert code == cli.EXIT_NOT_EVALUATED == 4

        text = open(out_csv, encoding="utf-8").read()
        assert "## memory_regions / records" not in text   # zero records -- table omitted
        rows = _table(text, "memory_regions / summary")
        assert rows[0]["coverage_status"] == "not_evaluated"
        assert rows[0]["count"] == "0"
    finally:
        os.remove(dump_path)


# ── --modules ─────────────────────────────────────────────────────────

def test_modules_csv_present_reflects_real_records(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.modules = FakeStream(
            [Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")], "modules")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--modules", "--csv", out_csv])
        cli.main()

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "modules / records")
        assert len(rows) == 1
        assert rows[0]["name"] == "ntdll.dll"
    finally:
        os.remove(dump_path)


def test_modules_csv_absent_stream_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # ModuleListStream absent entirely
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        code = _run(monkeypatch, [dump_path, "--modules", "--csv", out_csv])
        assert code == cli.EXIT_NOT_EVALUATED == 4

        text = open(out_csv, encoding="utf-8").read()
        assert "## modules / records" not in text
        rows = _table(text, "modules / summary")
        assert rows[0]["coverage_status"] == "not_evaluated"
    finally:
        os.remove(dump_path)


# ── --threads ─────────────────────────────────────────────────────────

def test_threads_csv_present_reflects_real_records(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
        mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
        mf.modules = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads", "--csv", out_csv])
        cli.main()   # thread_info + modules both present and matching -- fully complete

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "threads / records")
        assert len(rows) == 1
        assert rows[0]["tid"] == "1"
        summary = _table(text, "threads / summary")
        assert summary[0]["coverage_status"] == "complete"
    finally:
        os.remove(dump_path)


def test_threads_csv_degraded_missing_thread_info_is_partial(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")   # no thread_info/modules
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        code = _run(monkeypatch, [dump_path, "--threads", "--csv", out_csv])
        assert code == cli.EXIT_PARTIAL == 3

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "threads / records")
        assert rows[0]["tid"] == "1"
        summary = _table(text, "threads / summary")
        assert summary[0]["coverage_status"] == "partial"
    finally:
        os.remove(dump_path)


def test_threads_csv_all_absent_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # threads/thread_info both absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        code = _run(monkeypatch, [dump_path, "--threads", "--csv", out_csv])
        assert code == cli.EXIT_NOT_EVALUATED == 4

        text = open(out_csv, encoding="utf-8").read()
        summary = _table(text, "threads / summary")
        assert summary[0]["coverage_status"] == "not_evaluated"
    finally:
        os.remove(dump_path)


# ── --peb ─────────────────────────────────────────────────────────────

def test_peb_csv_present_reflects_real_records(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.peb = Peb(0x140000000, r"C:\test.exe")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--peb", "--csv", out_csv])
        cli.main()

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "peb / records")
        assert rows[0]["image_path"] == r"C:\test.exe"
    finally:
        os.remove(dump_path)


def test_peb_csv_absent_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # no peb at all
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        code = _run(monkeypatch, [dump_path, "--peb", "--csv", out_csv])
        assert code == cli.EXIT_NOT_EVALUATED == 4

        text = open(out_csv, encoding="utf-8").read()
        summary = _table(text, "peb / summary")
        assert summary[0]["coverage_status"] == "not_evaluated"
    finally:
        os.remove(dump_path)


# ── --pid ─────────────────────────────────────────────────────────────

def test_pid_csv_present_via_misc_info_reflects_real_records(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.misc_info = MiscInfo(process_id=4321)
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--pid", "--csv", out_csv])
        cli.main()   # complete -- no SystemExit

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "pid / records")
        assert rows[0]["pid"] == "4321"
        assert rows[0]["source"] == "MINIDUMP_MISC_INFO (ProcessId field)"
        summary = _table(text, "pid / summary")
        assert summary[0]["coverage_status"] == "complete"
    finally:
        os.remove(dump_path)


def test_pid_csv_all_absent_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # misc_info/threads/exception all absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        code = _run(monkeypatch, [dump_path, "--pid", "--csv", out_csv])
        assert code == cli.EXIT_NOT_EVALUATED == 4

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "pid / records")
        assert rows[0]["pid"] == ""
        summary = _table(text, "pid / summary")
        assert summary[0]["coverage_status"] == "not_evaluated"
    finally:
        os.remove(dump_path)


# ── --sysinfo ─────────────────────────────────────────────────────────

def test_sysinfo_csv_present_reflects_real_records(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.sysinfo = SysInfo()
        mf.misc_info = MiscInfo(process_id=1234)
        mf.peb = Peb(0x140000000, r"C:\test.exe")
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
        mf.modules = FakeStream([Module(0, 0, "a")], "modules")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--sysinfo", "--csv", out_csv])
        cli.main()   # complete -- no SystemExit

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "sysinfo / records")
        assert rows[0]["pid"] == "1234"
        assert rows[0]["thread_count"] == "1"
        summary = _table(text, "sysinfo / summary")
        assert summary[0]["coverage_status"] == "complete"
    finally:
        os.remove(dump_path)


def test_sysinfo_csv_all_sources_missing_is_partial(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # sysinfo/misc_info/peb/threads/modules all absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        out_csv = str(tmp_path / "out.csv")
        code = _run(monkeypatch, [dump_path, "--sysinfo", "--csv", out_csv])
        assert code == cli.EXIT_PARTIAL == 3   # dump_file is always real -- never not_evaluated

        text = open(out_csv, encoding="utf-8").read()
        rows = _table(text, "sysinfo / records")
        assert rows[0]["pid"] == ""
        assert rows[0]["thread_count"] == ""
        summary = _table(text, "sysinfo / summary")
        assert summary[0]["coverage_status"] == "partial"
    finally:
        os.remove(dump_path)

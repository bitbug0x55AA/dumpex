"""
Integration tests for cli.py's v2 routing: the pre-flight rejection of
--json/--csv on not-yet-migrated commands (before the dump is even
opened), the six recon commands actually writing a v2-shaped document,
--hunt continuing to write the unchanged v1.1-shaped document, and the
new exit-code contract (0 complete / 3 partial) for the six v2 commands.
"""
import json
import os
import sys
import tempfile

import pytest

import dumpex.cli as cli
from tests.fixtures.fakes import FakeMF, Module, Thread, Ctx, FakeStream


def _run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["dumpex"] + argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


# ── pre-flight rejection: before open_dump(), not after a full run ───────

def _forbid_open_dump(monkeypatch):
    def _boom(path):
        raise AssertionError("open_dump must not be called for a rejected mode")
    monkeypatch.setattr(cli, "open_dump", _boom)


@pytest.mark.parametrize("mode_args", [
    ["--diff", "/nonexistent2.dmp"],
    ["--report", "--report-tid", "1"],
    ["--extract", "0x1000"],
    ["--strings", "0x1000"],
])
def test_json_on_unsupported_mode_rejected_before_open_dump(monkeypatch, capsys, mode_args):
    _forbid_open_dump(monkeypatch)

    code = _run(monkeypatch, ["/nonexistent.dmp", *mode_args, "--json", "out.json"])

    assert code == 2
    err = capsys.readouterr().err
    assert "is not supported for" in err


def test_csv_on_unsupported_mode_rejected_before_open_dump(monkeypatch, capsys):
    _forbid_open_dump(monkeypatch)
    code = _run(monkeypatch, ["/nonexistent.dmp", "--diff", "/other.dmp", "--csv", "out.csv"])
    assert code == 2
    assert "--csv" in capsys.readouterr().err


def test_json_on_v2_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # A v2-supported mode must proceed past the pre-flight check and reach
    # open_dump()'s own (different) failure mode for a nonexistent file.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_hunt_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--hunt", "injection", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


# ── v2 vs v1.1 routing + exit codes, via a real (fake-backed) run ────────

def _make_dump_file() -> str:
    fd, path = tempfile.mkstemp(suffix=".dmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"synthetic dump content")
    return path


def test_modules_json_produces_v2_shaped_document(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.modules = FakeStream([Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")],
                                 "modules")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--modules", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "2.0"
        assert isinstance(doc["meta"]["evidence"], list)
        assert doc["result"]["kind"] == "modules"
        assert doc["result"]["data"]["records"][0]["name"] == "ntdll.dll"
        assert "hunt" not in doc
    finally:
        os.remove(dump_path)


def test_hunt_json_still_produces_v1_1_shaped_document(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--hunt", "injection", "--json", out_json])
        cli.main()

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "1.1"
        assert "hunt" in doc
        assert "result" not in doc
    finally:
        os.remove(dump_path)


def test_threads_degraded_exits_with_partial_code_even_without_json(monkeypatch):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")   # no thread_info -> degraded
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3
    finally:
        os.remove(dump_path)


def test_modules_complete_coverage_exits_zero(monkeypatch):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--modules"])
        cli.main()   # must NOT raise SystemExit at all (falsy EXIT_OK)
    finally:
        os.remove(dump_path)

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
from tests.fixtures.fakes import (
    FakeMF, Module, Region, Thread, ThreadInfo, Ctx, FakeStream, Peb, MiscInfo,
    ExceptionStream, SysInfo,
)


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
        assert doc["meta"]["schema_version"] == "2.1"
        assert isinstance(doc["meta"]["evidence"], list)
        assert doc["result"]["kind"] == "modules"
        assert doc["result"]["data"]["records"][0]["name"] == "ntdll.dll"
        assert "hunt" not in doc
    finally:
        os.remove(dump_path)


def test_list_json_produces_v2_shaped_document(monkeypatch, tmp_path):
    # --list had zero CLI-integration-level coverage before this test --
    # only collect_regions()/cmd_list() were exercised directly in
    # tests/unit/test_list_cmd.py.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.memory_info = FakeStream(
            [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
            "infos")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--list", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "memory_regions"
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["data"]["records"][0]["base_address"] == "0x0000000000001000"
    finally:
        os.remove(dump_path)


def test_list_missing_stream_json_is_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # MemoryInfoListStream absent entirely
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--list", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["data"]["records"] == []
    finally:
        os.remove(dump_path)


def test_threads_complete_json_exits_zero(monkeypatch, tmp_path):
    # Fills the missing "threads, fully complete" exit-code combo -- the
    # existing threads tests here only cover the degraded/partial case.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads     = FakeStream([Thread(1, Ctx(0))], "threads")
        mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
        mf.modules     = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["data"]["records"][0]["tid"] == 1
    finally:
        os.remove(dump_path)


def test_threads_neither_stream_present_json_is_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # neither ThreadListStream nor ThreadInfoListStream present
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["coverage"]["reasons"] == [
            "Neither ThreadListStream nor ThreadInfoListStream present in this dump"]
    finally:
        os.remove(dump_path)


def test_pid_complete_via_misc_info_json_exits_zero(monkeypatch, tmp_path):
    # Fills the missing "pid, complete via MiscInfo" exit-code combo --
    # the existing pid tests here only cover the fallback/not_evaluated
    # cases.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.misc_info = MiscInfo(process_id=100)
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--pid", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["data"]["records"][0]["pid"] == 100
    finally:
        os.remove(dump_path)


def test_threads_json_produces_v2_shaped_document_via_command_result_adapter(monkeypatch, tmp_path):
    # threads.py is migrated onto CommandResult (unlike this file's other
    # v2 commands at the time this test was added) -- this proves the
    # real CLI path (cli.main -> _apply_command_result ->
    # V2Output.set_command_result, not the older set_result adapter)
    # actually gets exercised end to end, not just collect_threads()
    # called directly in a unit test.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3   # degraded: no thread_info stream

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "2.1"
        assert doc["result"]["kind"] == "threads"
        assert doc["result"]["execution_status"] == "completed"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert doc["result"]["coverage"]["reasons"] == [
            "ThreadInfoListStream not present; StartAddress/CreateTime/ExitTime/KernelTime/"
            "UserTime unavailable (TID/SuspendCount/Priority/TEB only)",
            "ModuleListStream not present; thread backing-module classification unavailable "
            "(cannot confirm whether a start address is backed by a known module)",
        ]
        assert doc["result"]["data"]["records"][0]["tid"] == 1
        assert doc["artifacts"] == []
        assert doc["diagnostics"] == {"warnings": [], "errors": []}
    finally:
        os.remove(dump_path)


def test_peb_missing_json_produces_v2_shaped_document_via_command_result_adapter(monkeypatch, tmp_path):
    # peb.py is migrated onto CommandResult -- proves the real CLI path
    # (cli.main -> _apply_command_result -> V2Output.set_command_result)
    # for the not_evaluated / dedicated-code (PEB_UNAVAILABLE) case.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # no mf.peb at all
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--peb", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "2.1"
        assert doc["result"]["kind"] == "peb"
        assert doc["result"]["execution_status"] == "completed"
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["coverage"]["reasons"] == [
            "PEB could not be parsed (missing sysinfo or thread list in dump)"]
        assert doc["result"]["data"]["records"][0]["peb_address"] is None
    finally:
        os.remove(dump_path)


def test_peb_present_json_produces_complete_status(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.peb = Peb(0x140000000, r"C:\test.exe")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--peb", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "peb"
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["coverage"]["reasons"] == []
    finally:
        os.remove(dump_path)


def test_pid_fallback_json_produces_v2_shaped_document_via_command_result_adapter(monkeypatch, tmp_path):
    # sysinfo.py's collect_pid is migrated onto CommandResult -- proves the
    # real CLI path (cli.main -> _apply_command_result ->
    # V2Output.set_command_result) for the thread-list/exception-stream
    # fallback (structured PID_THREAD_LIST_FALLBACK/PID_EXCEPTION_TID_FALLBACK
    # limitations) case.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads = FakeStream([Thread(9, Ctx(0))], "threads")
        mf.exception = ExceptionStream(9)
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--pid", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "pid"
        assert doc["result"]["execution_status"] == "completed"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert doc["result"]["coverage"]["reasons"] == [
            "MiscInfo stream absent — PID not directly recoverable from thread list.\n"
            "    1 thread(s) found: 0x9",
            "Exception stream present: faulting TID = 0x9 (this is a Thread ID, not a Process ID)",
        ]
        assert doc["result"]["data"]["records"][0]["exc_tid"] == 9
    finally:
        os.remove(dump_path)


def test_pid_all_absent_json_is_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # misc_info/threads/exception all absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--pid", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["coverage"]["reasons"] == [
            "MiscInfo, thread list, and exception stream are all absent from this "
            "dump; PID could not be evaluated"]
    finally:
        os.remove(dump_path)


def test_sysinfo_missing_streams_json_produces_v2_shaped_document_via_command_result_adapter(
        monkeypatch, tmp_path):
    # sysinfo.py's collect_sysinfo is migrated onto CommandResult -- the
    # last of the six original recon commands to migrate. Proves the real
    # CLI path (cli.main -> _apply_command_result ->
    # V2Output.set_command_result) for the "all five sources missing"
    # case, whose five dedicated codes never render as not_evaluated
    # (dump_file is always real).
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # sysinfo/misc_info/peb/threads/modules all absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--sysinfo", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "sysinfo"
        assert doc["result"]["execution_status"] == "completed"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert doc["result"]["coverage"]["reasons"] == [
            "SystemInfoStream not present",
            "MiscInfo stream not present",
            "PEB not available (requires sysinfo + thread list)",
            "ThreadListStream not present (thread_count unavailable)",
            "ModuleListStream not present (module_count unavailable)",
        ]
        assert doc["result"]["data"]["records"][0]["dump_file"] is not None
    finally:
        os.remove(dump_path)


def test_sysinfo_normal_json_produces_complete_status(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.sysinfo = SysInfo()
        mf.misc_info = MiscInfo(process_id=1234)
        mf.peb = Peb(0x140000000, r"C:\test.exe")
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
        mf.modules = FakeStream([Module(0, 0, "a")], "modules")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--sysinfo", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "sysinfo"
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["coverage"]["reasons"] == []
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
        mf.modules = FakeStream([], "modules")   # stream present (not missing) -> "complete"
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--modules"])
        cli.main()   # must NOT raise SystemExit at all (falsy EXIT_OK)
    finally:
        os.remove(dump_path)


def test_modules_stream_missing_exits_not_evaluated(monkeypatch):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # ModuleListStream entirely absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--modules"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4
    finally:
        os.remove(dump_path)

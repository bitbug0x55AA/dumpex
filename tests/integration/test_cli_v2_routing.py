"""
Integration tests for cli.py's v2 routing: the pre-flight rejection of
--json/--csv on not-yet-migrated commands (before the dump is even
opened), the six recon commands actually writing a v2-shaped document,
--hunt now also writing a v2.4-shaped document (PR4 -- see
dumpex.hunt.cmd_hunt()'s own collect_records= docstring), and the
exit-code contract (0 complete / 3 partial / 4 not_evaluated) for the
v2-routed commands.
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


# ── pre-flight: every mode reaches open_dump(), none are rejected ────────
# _UNSUPPORTED_STRUCTURED_MODES is permanently empty as of Phase E, PR3
# (--report was the last command still on it) -- there is no longer any
# mode a --json/--csv pre-flight check can reject before open_dump().

def test_json_on_v2_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # A v2-supported mode must proceed past the pre-flight check and reach
    # open_dump()'s own (different) failure mode for a nonexistent file.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_extract_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # --extract is v2-supported too (Phase E, PR1) -- must proceed past
    # the pre-flight check and reach open_dump()'s own failure mode.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--extract", "0x1000", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_strings_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # --strings is v2-supported too (Phase E, PR2) -- must proceed past
    # the pre-flight check and reach open_dump()'s own failure mode.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--strings", "0x1000", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_report_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # --report is v2-supported too (Phase E, PR3) -- must proceed past
    # the pre-flight check and reach open_dump()'s own failure mode.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--report", "--report-tid", "1",
                              "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_diff_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # --diff is v2-supported too -- must proceed past the pre-flight check
    # and reach open_dump()'s failure mode for the (nonexistent) PRIMARY
    # dump, same as any other v2 mode. main() opens args.dumpfile before
    # args.diff, so a bad primary path's error surfaces first (deliberate,
    # not a gap -- see cli.py's own comment at the mf_reference= line).
    code = _run(monkeypatch, ["/nonexistent.dmp", "--diff", "/other.dmp", "--json", "out.json"])
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
        assert doc["meta"]["schema_version"] == "2.4"
        assert isinstance(doc["meta"]["evidence"], list)
        assert doc["result"]["kind"] == "modules"
        assert doc["result"]["data"]["records"][0]["name"] == "ntdll.dll"
        assert "hunt" not in doc
    finally:
        os.remove(dump_path)


def test_extract_json_produces_v2_shaped_document_with_artifact(monkeypatch, tmp_path):
    # --extract (Phase E, PR1) is the first v2-routed command to populate
    # result.artifacts/diagnostics for real -- both were plumbed end to
    # end (CommandResult -> V2Output.set_command_result()) since Phase B
    # but had no real producer until now.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        import dumpex.commands.extract as extract_mod
        from tests.fixtures.fakes import mem_reader
        monkeypatch.setattr(extract_mod, "read_region",
                             mem_reader({0x1000: b"MZ" + b"\x90" * 62}))
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        extract_out = str(tmp_path / "extracted.bin")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--extract", "0x1000", "--size", "0x40",
                              "--output", extract_out, "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "2.4"
        assert doc["result"]["kind"] == "extract"
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["data"]["records"][0]["mz_header_detected"] is True
        assert doc["artifacts"][0]["path"] == extract_out
        assert doc["artifacts"][0]["size_bytes"] == 64
        assert doc["diagnostics"]["warnings"][0]["code"] == "EXTRACT_MZ_HEADER_DETECTED"
        assert os.path.exists(extract_out)
    finally:
        os.remove(dump_path)


def test_strings_json_produces_v2_shaped_document(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        import dumpex.commands.extract as extract_mod
        from tests.fixtures.fakes import mem_reader
        data = b"hello world!\x00\x00" + b"another string here" + b"\x00" * 10
        monkeypatch.setattr(extract_mod, "read_region", mem_reader({0x1000: data}))
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--strings", "0x1000",
                              "--size", str(hex(len(data))), "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "2.4"
        assert doc["result"]["kind"] == "strings"
        assert doc["result"]["coverage"]["status"] == "complete"
        records = doc["result"]["data"]["records"]
        assert len(records) == 2
        assert records[0]["text"] == "hello world!"
        assert records[0]["matched_grep"] is None
        assert "hunt" not in doc
        assert doc["result"]["summary"]["requested_address"] == "0x0000000000001000"
    finally:
        os.remove(dump_path)


def test_report_json_produces_v2_shaped_document_with_triage_card(monkeypatch, tmp_path):
    # --report (Phase E, PR3) -- the last of the three Phase E commands to
    # populate result.records for real, one TriageCardRecord per card.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        mf.modules = FakeStream([], "modules")
        mf.thread_info = FakeStream([], "infos")
        mf.memory_info = FakeStream(
            [Region(0x6000, 0x6000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
            "infos")
        import dumpex.commands.report as report_mod
        import dumpex.core.memory as core_memory_mod
        from tests.fixtures.fakes import mem_reader
        reader = mem_reader({0x6000: b"boring data here nothing to see".ljust(0x1000, b"\x00")})
        monkeypatch.setattr(report_mod, "read_region", reader)
        monkeypatch.setattr(core_memory_mod, "read_region", reader)
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--report", "--report-addr", "0x6000",
                              "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "2.4"
        assert doc["result"]["kind"] == "report"
        assert doc["result"]["coverage"]["status"] == "complete"
        records = doc["result"]["data"]["records"]
        assert len(records) == 1
        assert records[0]["verdict"] == "SUSPICIOUS"
        assert records[0]["findings"] == ["rwx_private"]
        assert doc["result"]["summary"]["mode"] == "addr"
        assert "hunt" not in doc
    finally:
        os.remove(dump_path)


def test_extract_short_read_exits_partial_and_json_shows_truncation(monkeypatch, tmp_path, capsys):
    # P1-4 remediation: a short read (read_region() returned fewer bytes
    # than requested) must surface as exit code 3 (EXIT_PARTIAL), not the
    # 0 a full "complete" read gets -- a SOC script checking `$?` on a
    # bare `dumpex --extract ...` (no --json/--csv) must be able to detect
    # this without parsing JSON at all. P2 remediation: it must ALSO be
    # visible on the console itself, not just the exit code/JSON.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        import dumpex.commands.extract as extract_mod
        from tests.fixtures.fakes import mem_reader
        monkeypatch.setattr(extract_mod, "read_region", mem_reader({0x1000: b"only 5by"}))
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        extract_out = str(tmp_path / "extracted.bin")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--extract", "0x1000", "--size", "0x40",
                              "--output", extract_out, "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 3
        assert "[~] Requested memory region was only partially read" in capsys.readouterr().out

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "partial"
        codes = {lim["code"] for lim in doc["result"]["coverage"]["limitations"]}
        assert "REGION_READ_TRUNCATED" in codes
        assert doc["result"]["data"]["records"][0]["bytes_read"] == 8
    finally:
        os.remove(dump_path)


def test_strings_short_read_exits_partial_and_console_shows_truncation(monkeypatch, tmp_path, capsys):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        import dumpex.commands.extract as extract_mod
        from tests.fixtures.fakes import mem_reader
        monkeypatch.setattr(extract_mod, "read_region",
                             mem_reader({0x1000: b"only a short string here"}))
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--strings", "0x1000", "--size", "0xc8",
                              "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 3
        assert "[~] Requested memory region was only partially read" in capsys.readouterr().out

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "partial"
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
        assert doc["meta"]["schema_version"] == "2.4"
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
        assert doc["meta"]["schema_version"] == "2.4"
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


def test_diff_json_produces_comparison_document_with_two_evidence_entries(monkeypatch, tmp_path):
    # diff.py's cmd_diff is migrated onto CommandResult via
    # V2Output.from_evidence() -- the multi-dump counterpart to every
    # other test in this file, which all use the single dump_path
    # constructor. open_dump must be PATH-AWARE here (unlike every other
    # test's path-ignoring lambda) since --diff opens two distinct dumps.
    baseline_path = _make_dump_file()
    target_path = _make_dump_file()
    try:
        mf_baseline = FakeMF()
        mf_baseline.modules = FakeStream(
            [Module(0x1000, 0x1000, r"C:\a.dll")], "modules")
        mf_baseline.filename = baseline_path
        mf_target = FakeMF()
        mf_target.modules = FakeStream(
            [Module(0x1000, 0x1000, r"C:\a.dll"), Module(0x2000, 0x1000, r"C:\b.dll")],
            "modules")
        mf_target.filename = target_path
        mfs = {baseline_path: mf_baseline, target_path: mf_target}
        monkeypatch.setattr(cli, "open_dump", lambda path: mfs[path])

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", target_path, "--diff", baseline_path,
                              "--diff-mode", "modules", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "2.4"
        assert [e["id"] for e in doc["meta"]["evidence"]] == ["baseline", "target"]
        assert [e["role"] for e in doc["meta"]["evidence"]] == ["baseline", "target"]
        assert [e["file_name"] for e in doc["meta"]["evidence"]] == [
            os.path.basename(baseline_path), os.path.basename(target_path)]
        assert doc["result"]["kind"] == "comparison"
        assert doc["result"]["coverage"]["status"] == "complete"
        added = [r for r in doc["result"]["data"]["records"] if r["change_type"] == "added"]
        assert len(added) == 1
        assert added[0]["entity_type"] == "module"
        assert added[0]["name"] == "b.dll"
    finally:
        os.remove(baseline_path)
        os.remove(target_path)


def test_diff_json_partial_when_one_entity_not_evaluated_among_others_complete(
        monkeypatch, tmp_path):
    # A single not_evaluated entity (ModuleListStream absent on BOTH sides)
    # among otherwise-complete entities (threads/memory) must roll the
    # OVERALL coverage into "partial", not "not_evaluated" outright, and
    # exit code 3 -- combine_coverage_reports' unanimous-not_evaluated-
    # required rule (see dumpex.output.coverage) exercised end to end
    # through the real CLI path (mode="all") for the first time; the
    # collect_comparison()-level version of this rule is already covered
    # directly in tests/unit/test_comparison_cmd.py.
    baseline_path = _make_dump_file()
    target_path = _make_dump_file()
    try:
        mf_baseline = FakeMF()   # ModuleListStream absent
        mf_baseline.thread_info = FakeStream([], "infos")
        mf_baseline.memory_info = FakeStream([], "infos")
        mf_baseline.filename = baseline_path
        mf_target = FakeMF()   # ModuleListStream absent
        mf_target.thread_info = FakeStream([], "infos")
        mf_target.memory_info = FakeStream([], "infos")
        mf_target.filename = target_path
        mfs = {baseline_path: mf_baseline, target_path: mf_target}
        monkeypatch.setattr(cli, "open_dump", lambda path: mfs[path])

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", target_path, "--diff", baseline_path,
                              "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "comparison"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert doc["result"]["data"]["records"] == []
    finally:
        os.remove(baseline_path)
        os.remove(target_path)


def test_diff_csv_directory_mode_writes_module_diffs_table(monkeypatch, tmp_path):
    # csv_export.build_tables()' comparison-specific module_diffs/
    # thread_diffs/memory_diffs table split (Phase C) is already proven
    # directly against V2Output in tests/unit/test_output_csv_and_collector.py
    # -- this proves it survives a real cli.main() --diff --csv DIR\ call,
    # the one command shape that couldn't be exercised before --diff was
    # wired onto V2Output.
    baseline_path = _make_dump_file()
    target_path = _make_dump_file()
    try:
        mf_baseline = FakeMF()
        mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, r"C:\a.dll")], "modules")
        mf_baseline.filename = baseline_path
        mf_target = FakeMF()
        mf_target.modules = FakeStream(
            [Module(0x1000, 0x1000, r"C:\a.dll"), Module(0x2000, 0x1000, r"C:\b.dll")],
            "modules")
        mf_target.filename = target_path
        mfs = {baseline_path: mf_baseline, target_path: mf_target}
        monkeypatch.setattr(cli, "open_dump", lambda path: mfs[path])

        csv_dir = tmp_path / "csvout"
        csv_dir.mkdir()
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", target_path, "--diff", baseline_path,
                              "--diff-mode", "modules", "--csv", str(csv_dir) + os.sep])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        names = os.listdir(csv_dir)
        module_diff_files = [n for n in names if "module_diffs" in n]
        assert len(module_diff_files) == 1
        assert not any("records.csv" in n for n in names)
        contents = (csv_dir / module_diff_files[0]).read_text(encoding="utf-8")
        assert "b.dll" in contents
    finally:
        os.remove(baseline_path)
        os.remove(target_path)


def test_hunt_json_now_produces_v2_4_shaped_document(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--hunt", "injection", "--json", out_json])
        # A bare FakeMF() has no memory/thread streams at all -> injection
        # is NOT_EVALUATED -> exit_code_for("not_evaluated") == 4, same
        # coverage-based exit code the other v2-routed commands already
        # use (see EXIT_NOT_EVALUATED) -- --hunt no longer always exits 0
        # regardless of coverage now that it's v2-routed too.
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == "2.4"
        assert "hunt" not in doc
        assert doc["result"]["kind"] == "hunt"
        assert [r["hunter"] for r in doc["result"]["data"]["records"]] == ["injection"]
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

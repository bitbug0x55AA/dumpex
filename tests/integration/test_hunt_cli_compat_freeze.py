"""
CLI-layer compatibility freeze for `--hunt` (v2.4 output migration, PR4 --
the CLI's atomic switch onto the v2.4 `--hunt` contract) -- runs the real
`cli.main()` end to end against a synthetic `FakeMF`, the same discipline
tests/integration/test_report_compat_freeze.py established for the prior
(`--report`) migration: monkeypatch `cli.open_dump()` to return the fake
(no real .dmp file is parsed), freeze `datetime.datetime.now()` so
`meta.execution.started_at/finished_at/duration_seconds` are reproducible,
and assert exit code + full JSON `HunterRecord` + full CSV text + full
console body for all 7 hunters individually AND for `--hunt all` (all 7 at
once, NOT_EVALUATED). Every module-attribute override (`read_region`/
`get_thread_contexts`) goes through pytest's `monkeypatch` fixture, never a
bare module-attribute assignment -- nothing here can leak into a later,
unrelated test regardless of execution order.

tests/fixtures/hunt_cases.py + tests/integration/test_hunt_compat_freeze.py
freeze each hunter's OWN `_hunt_*()`/`cmd_hunt()` v1.1-shaped dict return
value in isolation (no CLI, no `meta`) -- that contract is UNCHANGED by
PR4 (see cmd_hunt()'s own docstring: its console output and bare `results`
dict return value are byte-identical to before; only the CLI's own
`--json`/`--csv` output and process exit code moved onto the v2.4
envelope). This file freezes what that approach cannot: what
`dumpex.output.V2Output` actually writes to `--json`/`--csv` for `--hunt`
now, and the real process exit code -- now coverage-based via
`exit_code_for()`, the same convention the ten other v2-routed commands
already used, rather than always 0 regardless of coverage.

Expected values live in tests/fixtures/hunt_cli_golden/<ttp>_{hunt_dict.json,
csv.txt,console.txt} -- one synthetic golden snapshot per hunter, generated
once by a capture script (kept in the PR's own history, not committed here,
since it's a one-shot tool, not something the suite imports) and reviewable/
diffable like any other checked-in fixture. These are NOT real-dump output
(see tests/fixtures/hunt_cases.py's own docstring for why that would be a
privacy violation) -- every one of them was produced by exactly the FakeMF
construction each test function below builds, so re-running the generator
against the same construction reproduces them byte-for-byte. `console.txt`
is unchanged from the pre-PR4 (v1.1) fixtures -- confirmed byte-identical
when this suite was migrated, since `cmd_hunt()`'s console rendering was
never touched by this switch, only what wraps its return value for
`--json`/`--csv`.

Like test_report_compat_freeze.py, this does NOT compare the full JSON
document as one string -- `meta.evidence.path` embeds `tmp_path` (different
every test run) and `meta.tool.version` embeds this checkout's git-describe
string, neither of which a frozen fixture can pin. Only
`doc["result"]["data"]["records"][0]` (the single `HunterRecord` dict for
a single-TTP run -- the part with no such dynamic content) is compared, in
full; `test_hunt_all_all_not_evaluated` compares the full 7-element
`records` list the same way.

`test_hunt_all_all_not_evaluated`, like every other scenario here, freezes
the FULL JSON `records` list (all 7 hunters at once)/CSV/console body -- it
does NOT rely on the default packaged YARA rules directory (which would
print its own absolute host path, an un-freezable dynamic segment): it
passes `--yara-dir <tmp_path>/empty_rules` (a synthetic, always-empty
directory), same as the per-hunter `yara` scenario below passes its own
`tmp_path`-derived rules dir. Both have that one dynamic path segment
replaced with the literal placeholder `<RULES_DIR>` before comparison.
Requires no optional yara-python dependency either way: an empty rules
directory hits yara_hunt's "no .yar/.yara files found" branch before ever
importing it (see `test_hunt_yara_detected_cli`'s own `importorskip` for
the one scenario that actually needs a compiled rule and does need it).

Global rules-loader state (`dumpex.rules_pkg.loader._RULES_CACHE`/
`_EXPLICIT_RULES_PATH`/`_LAST_SOURCE_INFO`, `dumpex.hunt.yara_hunt.
_LAST_YARA_PROVENANCE`) is reset via `monkeypatch.setattr()`, not a bare
`configure_rules_source(None)` call -- pytest restores the ORIGINAL values
automatically once the test ends, so no scenario here can leak a
loaded/cached rules state into a later, unrelated test regardless of
execution order.
"""
import contextlib
import datetime
import io
import json
import pathlib
import re
import sys

import pytest

import dumpex.cli as cli
import dumpex.ui.structured as structured_mod
import dumpex.rules_pkg.loader as rules_loader
import dumpex.hunt.yara_hunt as yara_hunt_mod

_GOLDEN = pathlib.Path(__file__).parent.parent / "fixtures" / "hunt_cli_golden"

_OBJ_ADDR_RE = re.compile(r"(<[\w.]+ object at )0x[0-9A-Fa-f]+(>)")


def _normalize_object_addresses(obj):
    """Replace `<module.Class object at 0x...>` -- the live interpreter
    heap address `_json_safe()`'s `str(obj)` fallback embeds for any raw
    fake/real object it doesn't know how to convert (see
    docs/hunt_migration_field_matrix.md's cross-cutting finding #1;
    confirmed present in injection's rwx/threads/rip_hits and pipe's
    private_pipes/handle_pipes/c2_context/unbacked_in_rgn) -- with a fixed
    placeholder, matching the same normalization the golden fixtures
    themselves were generated with. Without this, comparing either
    hunter's full `doc["hunt"][ttp]` against a golden snapshot would be
    flaky by construction: the address is different on every single run,
    identical input or not."""
    if isinstance(obj, str):
        return _OBJ_ADDR_RE.sub(r"\g<1>0xNORMALIZED\g<2>", obj)
    if isinstance(obj, list):
        return [_normalize_object_addresses(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _normalize_object_addresses(v) for k, v in obj.items()}
    return obj


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, tzinfo=tz)


_real_timezone = datetime.timezone
_real_timedelta = datetime.timedelta


class _FrozenDateTimeModule:
    datetime = _FixedDateTime
    timezone = _real_timezone
    timedelta = _real_timedelta


def _run(monkeypatch, tmp_path, argv_extra, mf):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(structured_mod, "datetime", _FrozenDateTimeModule)
    # Reset via monkeypatch (auto-restored), not configure_rules_source(None)
    # (a bare global mutation with no restoration) -- see module docstring.
    monkeypatch.setattr(rules_loader, "_RULES_CACHE", None)
    monkeypatch.setattr(rules_loader, "_EXPLICIT_RULES_PATH", None)
    monkeypatch.setattr(rules_loader, "_LAST_SOURCE_INFO", None)
    monkeypatch.setattr(yara_hunt_mod, "_LAST_YARA_PROVENANCE", None)

    dump_path = str(tmp_path / "test.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf.filename = dump_path
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)

    out_json = str(tmp_path / "out.json")
    out_csv = str(tmp_path / "out.csv")
    argv = ["dumpex", dump_path, *argv_extra, "--json", out_json, "--csv", out_csv, "--force"]
    monkeypatch.setattr(sys, "argv", argv)

    buf = io.StringIO()
    exit_code = 0
    with contextlib.redirect_stdout(buf):
        try:
            cli.main()
        except SystemExit as exc:
            exit_code = exc.code
    doc = json.loads(open(out_json, encoding="utf-8").read())
    csv_text = open(out_csv, encoding="utf-8").read()
    return exit_code, doc, csv_text, buf.getvalue()


def _split_console_body(console_text: str) -> str:
    write_start = console_text.find("  [\u00b7] JSON written")
    assert write_start != -1, "missing JSON write confirmation line"
    return console_text[:write_start]


def _load_golden(ttp):
    hunt_dict = json.loads((_GOLDEN / f"{ttp}_hunt_dict.json").read_text(encoding="utf-8"))
    csv_text = (_GOLDEN / f"{ttp}_csv.txt").read_text(encoding="utf-8")
    console = (_GOLDEN / f"{ttp}_console.txt").read_text(encoding="utf-8")
    return hunt_dict, csv_text, console


def _assert_frozen(ttp, doc, csv_text, console, *, tmp_path=None, rules_dir_placeholder=None):
    expected_record, expected_csv, expected_console = _load_golden(ttp)
    records = doc["result"]["data"]["records"]
    assert len(records) == 1, f"expected exactly 1 record for a single-TTP run, got {len(records)}"
    assert _normalize_object_addresses(records[0]) == expected_record
    assert csv_text == expected_csv
    body = _split_console_body(console)
    if rules_dir_placeholder is not None:
        body = body.replace(str(rules_dir_placeholder), "<RULES_DIR>")
    assert body == expected_console


def _mf_injection(monkeypatch):
    from tests.fixtures.fakes import (FakeMF, FakeStream, Region, Module, ThreadInfo, Ctx, Thread,
        build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)
    import dumpex.hunt.injection as injection
    alloc_base = 0x7ff700000000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000, "rawptr": 0x400,
          "rawsize": 0x1000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, alloc_base + 0x2000)]
    thread_list = [Thread(0x1, Ctx(alloc_base + 0x2000))]
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream(mods, "modules")
    mf.thread_info = FakeStream(thread_infos, "infos")
    mf.threads = FakeStream(thread_list, "threads")
    monkeypatch.setattr(injection, "read_region", mem_reader({alloc_base + 0x2000: pe_bytes}))
    return mf


def test_hunt_injection_detected_full_correlation_cli(monkeypatch, tmp_path):
    exit_code, doc, csv_text, console = _run(
        monkeypatch, tmp_path, ["--hunt", "injection"], _mf_injection(monkeypatch))
    # One of this scenario's two memory-info regions is a short read while
    # checking for hidden PE headers, so status is DETECTED (score 3/3) but
    # coverage.status is "partial" -- status and coverage.status are
    # independent dimensions, and this document-level exit code must reflect
    # coverage, not overall detection outcome: EXIT_PARTIAL (3), not 0.
    assert exit_code == cli.EXIT_PARTIAL == 3
    assert doc["meta"]["schema_version"] == "2.5"
    assert doc["meta"]["execution"]["command"] == "hunt_injection"
    assert doc["meta"]["execution"]["started_at"] == "2024-01-01T00:00:00Z"
    assert doc["result"]["kind"] == "hunt"
    assert doc["result"]["data"]["records"][0]["status"] == "DETECTED"
    assert doc["result"]["coverage"]["status"] == "partial"
    assert [r["hunter"] for r in doc["result"]["data"]["records"]] == ["injection"]
    _assert_frozen("injection", doc, csv_text, console)


def test_hunt_hollowing_detected_cli(monkeypatch, tmp_path):
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Module, Peb, mem_reader
    import dumpex.hunt.hollowing as hollowing
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    mf = FakeMF()
    mf.peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
    mf.modules = FakeStream([module], "modules")
    mf.memory_info = FakeStream(regions, "infos")
    monkeypatch.setattr(hollowing, "read_region", mem_reader({image_base: b"MZ" + b"\x90" * 62}))

    exit_code, doc, csv_text, console = _run(monkeypatch, tmp_path, ["--hunt", "hollowing"], mf)
    assert exit_code == 0
    _assert_frozen("hollowing", doc, csv_text, console)


def test_hunt_stomping_detected_cli(monkeypatch, tmp_path):
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Module, mem_reader, matching_module_and_ref
    import dumpex.hunt.stomping as stomping
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    tampered_text = bytes(b ^ 0xFF for b in mem_text)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream(mods, "modules")
    monkeypatch.setattr(stomping, "read_region", mem_reader(
        {module_base: header, module_base + section["vaddr"]: tampered_text}))
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    (ref_dir / "legit.dll").write_bytes(ref_file)

    exit_code, doc, csv_text, console = _run(
        monkeypatch, tmp_path, ["--hunt", "stomping", "--ref-dir", str(ref_dir)], mf)
    assert exit_code == 0
    _assert_frozen("stomping", doc, csv_text, console)


def test_hunt_pipe_detected_cli(monkeypatch, tmp_path):
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Handle, ThreadInfo, mem_reader
    import dumpex.hunt.pipe as pipemod
    region_base = 0x1230000
    pipe_name = b"\\\\.\\pipe\\msagent_1337"
    pipe_off = 0x100
    data = (b"A" * pipe_off + pipe_name + b"\x00"
            + b"http://198.51.100.7:8080/submit.php" + b"B" * 0x200)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_PRIVATE")]
    handle_list = [Handle(0x88, "File", r"\Device\NamedPipe\msagent_1337")]
    thread_infos = [ThreadInfo(0x999, region_base + 0x10)]
    pipe_va = region_base + pipe_off
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream([], "modules")
    mf.thread_info = FakeStream(thread_infos, "infos")
    mf.handles = FakeStream(handle_list, "handles")
    monkeypatch.setattr(pipemod, "read_region", mem_reader({region_base: data}))
    monkeypatch.setattr(pipemod, "get_thread_contexts", lambda mf: [
        {"ThreadId": 0x999, "ip": pipe_va + 5, "ip_reg": "RIP", "is_wow64": False}])

    exit_code, doc, csv_text, console = _run(monkeypatch, tmp_path, ["--hunt", "pipe"], mf)
    # This FakeMF's memory-string scan hits a short read (see the golden
    # fixture's own coverage.reasons), so status is DETECTED (full
    # corroboration, score 3/3) but coverage.status is "partial" -- status
    # and coverage.status are independent dimensions, and this
    # document-level exit code must reflect coverage: EXIT_PARTIAL (3).
    assert exit_code == cli.EXIT_PARTIAL == 3
    assert doc["result"]["data"]["records"][0]["status"] == "DETECTED"
    assert doc["result"]["coverage"]["status"] == "partial"
    _assert_frozen("pipe", doc, csv_text, console)


def test_hunt_cs_beacon_detected_cli(monkeypatch, tmp_path):
    from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment, FakeReader, cs_beacon_config_bytes
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = b"\x00" * 0x100 + config + b"\x00" * 0x100
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    mf = FakeMF()
    mf.memory_segments_64 = FakeStream([seg], "memory_segments")
    mf.memory_info = FakeStream(regions, "infos")
    mf._reader = FakeReader({seg_va: data})

    exit_code, doc, csv_text, console = _run(monkeypatch, tmp_path, ["--hunt", "cs-beacon"], mf)
    assert exit_code == 0
    _assert_frozen("cs-beacon", doc, csv_text, console)


def test_hunt_yara_detected_cli(monkeypatch, tmp_path):
    pytest.importorskip("yara")   # scoped to this test only -- every other
                                    # hunter's CLI test must still run in an
                                    # environment without the optional
                                    # yara-python ("full") extra installed.
    from tests.fixtures.fakes import FakeMF, FakeStream, Segment, FakeReader
    seg_va, seg_fo = 0x50000, 0x5000
    data = b"A" * 0x100 + b"FINDME_MARKER" + b"B" * 0x100
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "hit.yar").write_text('rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
    seg = Segment(seg_va, seg_fo, len(data))
    mf = FakeMF()
    mf.memory_segments_64 = FakeStream([seg], "memory_segments")
    mf._reader = FakeReader({seg_va: data})

    exit_code, doc, csv_text, console = _run(
        monkeypatch, tmp_path, ["--hunt", "yara", "--yara-dir", str(rules_dir)], mf)
    assert exit_code == 0
    _assert_frozen("yara", doc, csv_text, console, rules_dir_placeholder=rules_dir)


def test_hunt_obfuscation_detected_cli(monkeypatch, tmp_path):
    import base64
    from tests.fixtures.fakes import (FakeMF, FakeStream, Region, build_pe_header,
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader)
    import dumpex.hunt.encoding as encoding
    region_base = 0x300000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    mf.modules = FakeStream([], "modules")
    monkeypatch.setattr(encoding, "read_region", mem_reader({region_base: b64_pe.ljust(0x1000, b"\x00")}))

    exit_code, doc, csv_text, console = _run(monkeypatch, tmp_path, ["--hunt", "obfuscation"], mf)
    assert exit_code == 0
    _assert_frozen("obfuscation", doc, csv_text, console)


def test_hunt_all_all_not_evaluated(monkeypatch, tmp_path):
    """A fully empty FakeMF -> all 7 hunters NOT_EVALUATED -> summary.
    overall_status == "NOT_EVALUATED" -> coverage.status ==
    "not_evaluated" -> exit_code_for() now returns EXIT_NOT_EVALUATED (4),
    not 0 -- the coverage-based exit code PR4 brings `--hunt` onto, same
    as the ten other v2-routed commands already had. `--yara-dir` is
    pointed at a synthetic EMPTY tmp_path directory instead of the
    default packaged rules dir -- the packaged dir's own absolute host
    path would otherwise appear in the printed "Loaded N rule file(s)
    from <path>" line, making full console/JSON/CSV freezing impossible
    across machines/CI runners (same reasoning as
    test_hunt_yara_detected_cli's rules_dir_placeholder). An empty
    directory still reaches yara_hunt's "no .yar/.yara files found" branch
    without ever importing yara-python, so this needs no optional
    dependency either."""
    from tests.fixtures.fakes import FakeMF
    mf = FakeMF()
    rules_dir = tmp_path / "empty_rules"
    rules_dir.mkdir()

    exit_code, doc, csv_text, console = _run(
        monkeypatch, tmp_path, ["--hunt", "all", "--yara-dir", str(rules_dir)], mf)

    assert exit_code == cli.EXIT_NOT_EVALUATED == 4
    assert doc["meta"]["execution"]["command"] == "hunt_all"
    assert doc["result"]["kind"] == "hunt"
    records = doc["result"]["data"]["records"]
    assert [r["hunter"] for r in records] == [
        "injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation"]
    assert all(r["status"] == "NOT_EVALUATED" for r in records)
    assert doc["result"]["summary"]["overall_status"] == "NOT_EVALUATED"
    assert doc["result"]["coverage"]["status"] == "not_evaluated"

    expected_records = json.loads((_GOLDEN / "all_hunt_dict.json").read_text(encoding="utf-8"))
    expected_csv = (_GOLDEN / "all_csv.txt").read_text(encoding="utf-8")
    expected_console = (_GOLDEN / "all_console.txt").read_text(encoding="utf-8")
    assert _normalize_object_addresses(records) == expected_records
    assert csv_text == expected_csv
    body = _split_console_body(console).replace(str(rules_dir), "<RULES_DIR>")
    assert body == expected_console

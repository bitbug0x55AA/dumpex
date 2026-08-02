"""
Compatibility-freeze suite for `--extract` (Phase E, PR1) and `--strings`
(Phase E, PR2) -- both share the same read-region/no-baseline-target-
duality shape, unlike `--diff`'s own two-dump suite
(test_diff_compat_freeze.py).

Every scenario runs the real `cli.main()` end to end against a FakeMF and
asserts exit code, the full console text, and the JSON document's
kind/coverage/artifact shape -- same discipline as test_diff_compat_freeze.py.
Expected console text was captured by actually running the ORIGINAL
(pre-migration) `cmd_extract`/`cmd_strings` (see the scratchpad capture
scripts referenced in Phase E's plan) before extract.py was rewritten, not
hand-guessed -- there is no pre-existing test suite for either command to
fall back on if a guess were wrong (zero tests existed for either before
this phase).

Every scenario here passes an explicit `--size`, so `_resolve_size()`'s
own auto-detection-from-region logic (unchanged by this migration, lives
in dumpex.core.memory) is never exercised by this suite -- the
`auto_sized=True` cosmetic rendering path (the "(auto from region)" note)
is covered directly against collect_extract()/collect_strings() and their
own render_*_console() in tests/unit/test_extract_cmd.py and
tests/unit/test_strings_cmd.py instead, decoupled from _resolve_size's own
region-lookup behavior.
"""
import datetime
import hashlib
import json
import os
import sys

import pytest

import dumpex.cli as cli
import dumpex.output.collector as collector_mod
import dumpex.commands.extract as extract_mod
from tests.fixtures.fakes import FakeMF, mem_reader


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, tzinfo=tz)


_real_timezone = datetime.timezone
_real_timedelta = datetime.timedelta


class _FrozenDateTimeModule:
    """See test_compat_freeze.py's identical helper for why the whole
    `datetime` module is replaced rather than patching `.now` in place --
    both cli.py and collector.py `import datetime` (the module)."""
    datetime = _FixedDateTime
    timezone = _real_timezone
    timedelta = _real_timedelta


def _run(monkeypatch, tmp_path, extract_addr, size_hex, output_arg, data_map, force=True):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    dump_path = str(tmp_path / "sample.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    monkeypatch.setattr(extract_mod, "read_region", mem_reader(data_map))

    out_json = str(tmp_path / "out.json")
    out_csv = str(tmp_path / "out.csv")
    argv = ["dumpex", dump_path, "--extract", extract_addr, "--size", size_hex]
    if output_arg is not None:
        argv += ["--output", output_arg]
    argv += ["--json", out_json, "--csv", out_csv]
    if force:
        argv += ["--force"]
    monkeypatch.setattr(sys, "argv", argv)

    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    doc = json.loads(open(out_json, encoding="utf-8").read())
    csv_text = open(out_csv, encoding="utf-8").read()
    console = os.path.basename(dump_path)
    return exit_code, doc, csv_text, console


def _split_console_body(console_text: str) -> str:
    write_start = console_text.find("  [·] JSON written")
    assert write_start != -1, "missing JSON write confirmation line"
    return console_text[:write_start]


# ── TRUE_FREEZE scenarios: console text captured from the original
# cmd_extract before Phase E's rewrite ──────────────────────────────────
# (name, extract_addr, size_hex, output_rel_path, data, exit_code, console_body)

TRUE_FREEZE = [
    (
        "normal_explicit_output",
        "0x1000", "0x10", "out.bin",
        b"hello world" + b"\x00" * 100,
        0,
        "[*] Reading 0x10 bytes from 0x1000 ...\n",
    ),
    (
        "mz_header_detected",
        "0x3000", "0x40", "out.bin",
        b"MZ" + b"\x90" * 62,
        0,
        "[*] Reading 0x40 bytes from 0x3000 ...\n"
        "[!] MZ header detected — this looks like an injected PE!\n",
    ),
]


@pytest.mark.parametrize(
    "name,extract_addr,size_hex,output_rel,data,exit_code,console_prefix",
    TRUE_FREEZE, ids=[s[0] for s in TRUE_FREEZE],
)
def test_extract_compat_freeze(monkeypatch, tmp_path, capsys, name, extract_addr, size_hex,
                                output_rel, data, exit_code, console_prefix):
    output_path = str(tmp_path / output_rel)
    actual_exit, doc, csv_text, dump_label = _run(
        monkeypatch, tmp_path, extract_addr, size_hex, output_path, {int(extract_addr, 16): data})
    console = capsys.readouterr().out
    body = _split_console_body(console)

    size = int(size_hex, 16)
    written = data[:size]
    sha256 = hashlib.sha256(written).hexdigest()
    expected_body = (console_prefix +
                      f"[+] Saved → {output_path}  ({size} bytes  sha256={sha256})\n")

    assert actual_exit == exit_code, f"{name}: exit code drifted"
    assert body == expected_body, f"{name}: console drifted"

    assert doc["meta"]["schema_version"] == "2.2"
    assert doc["result"]["kind"] == "extract"
    assert doc["result"]["coverage"]["status"] == "complete"
    rec = doc["result"]["data"]["records"][0]
    assert rec["requested_size"] == size
    assert rec["bytes_read"] == size
    assert doc["artifacts"][0]["path"] == output_path
    assert doc["artifacts"][0]["size_bytes"] == size
    assert doc["artifacts"][0]["sha256"] == sha256

    assert (tmp_path / output_rel).read_bytes() == written

    assert "## extract / summary" in csv_text or "## extract / records" in csv_text


def test_extract_default_output_filename_writes_into_cwd(monkeypatch, tmp_path, capsys):
    # No --output given -- cmd_extract falls back to f"region_0x{addr:x}.bin"
    # in the current working directory, exactly as before this migration.
    monkeypatch.chdir(tmp_path)
    data = b"default name test" + b"\x00" * 50
    exit_code, doc, csv_text, _ = _run(
        monkeypatch, tmp_path, "0x4000", "0x14", None, {0x4000: data})
    console = capsys.readouterr().out
    body = _split_console_body(console)

    size = 0x14
    written = data[:size]
    sha256 = hashlib.sha256(written).hexdigest()
    expected_body = (
        "[*] Reading 0x14 bytes from 0x4000 ...\n"
        f"[+] Saved → region_0x4000.bin  ({size} bytes  sha256={sha256})\n"
    )

    assert exit_code == 0
    assert body == expected_body
    assert doc["artifacts"][0]["path"] == "region_0x4000.bin"
    assert (tmp_path / "region_0x4000.bin").read_bytes() == written


def test_extract_read_failure_exits_1_before_any_structured_output(monkeypatch, tmp_path, capsys):
    dump_path = str(tmp_path / "sample.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)

    def _boom(mf, addr, size):
        raise RuntimeError("bad address")
    monkeypatch.setattr(extract_mod, "read_region", _boom)

    out_json = str(tmp_path / "out.json")
    monkeypatch.setattr(sys, "argv",
                         ["dumpex", dump_path, "--extract", "0x9999", "--size", "0x10",
                          "--json", out_json])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    console = capsys.readouterr().out
    assert "[*] Reading 0x10 bytes from 0x9999 ...\n" in console
    assert "[!] Read failed: bad address" in console
    assert not os.path.exists(out_json), "a failed read must not leave a partial JSON file"


# ── --strings (Phase E, PR2) ───────────────────────────────────────────────

def _run_strings(monkeypatch, tmp_path, addr, size_hex, min_len, grep, encoding, data_map):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    dump_path = str(tmp_path / "sample.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    monkeypatch.setattr(extract_mod, "read_region", mem_reader(data_map))

    out_json = str(tmp_path / "out.json")
    out_csv = str(tmp_path / "out.csv")
    argv = ["dumpex", dump_path, "--strings", addr, "--size", size_hex,
            "--min-len", str(min_len), "--encoding", encoding]
    if grep is not None:
        argv += ["--grep", grep]
    argv += ["--json", out_json, "--csv", out_csv]
    monkeypatch.setattr(sys, "argv", argv)

    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    doc = json.loads(open(out_json, encoding="utf-8").read())
    csv_text = open(out_csv, encoding="utf-8").read()
    return exit_code, doc, csv_text


# ── TRUE_FREEZE_STRINGS scenarios: console text captured from the original
# cmd_strings before Phase E, PR2's rewrite (see the scratchpad capture
# script capture_old_strings_output.py referenced in Phase E's plan) ─────
# (name, addr, size_hex, min_len, grep, encoding, data, expected_console)

_DASH_LINE = "─" * 70   # matches render_strings_console's own "─" * 70

TRUE_FREEZE_STRINGS = [
    (
        "ascii_only_both_encoding",
        "0x1000", None, 6, None, "both",
        b"hello world!\x00\x00" + b"another string here" + b"\x00" * 10,
        "\nOffset         Enc     String\n"
        f"{_DASH_LINE}\n"
        "0x1000         ASCII   hello world!\n"
        "0x100e         ASCII   another string here\n"
        "\n[+] 2 string(s) shown.\n",
    ),
    (
        "grep_filter_matches_some",
        "0x3000", None, 6, "recipe", "ascii",
        b"apple pie recipe" + b"\x00" * 5 + b"banana bread recipe" + b"\x00" * 5 + b"cherry tart",
        "\nOffset         Enc     String\n"
        f"{_DASH_LINE}\n"
        "0x3000         ASCII   apple pie recipe\n"
        "0x3015         ASCII   banana bread recipe\n"
        "\n[+] 2 string(s) shown.\n",
    ),
    (
        "no_strings_found",
        "0x4000", 15, 6, None, "both",
        b"\x01\x02\x03" * 5,
        "\nOffset         Enc     String\n"
        f"{_DASH_LINE}\n"
        "\n[+] 0 string(s) shown.\n",
    ),
    (
        "min_len_boundary_exact_match",
        "0x6000", 16, 6, None, "ascii",
        b"abcdef" + b"\x00" * 10,
        "\nOffset         Enc     String\n"
        f"{_DASH_LINE}\n"
        "0x6000         ASCII   abcdef\n"
        "\n[+] 1 string(s) shown.\n",
    ),
]


@pytest.mark.parametrize(
    "name,addr,size_hex_override,min_len,grep,encoding,data,expected_body",
    TRUE_FREEZE_STRINGS, ids=[s[0] for s in TRUE_FREEZE_STRINGS],
)
def test_strings_compat_freeze(monkeypatch, tmp_path, capsys, name, addr, size_hex_override,
                                min_len, grep, encoding, data, expected_body):
    size = size_hex_override if size_hex_override is not None else len(data)
    size_hex = hex(size)
    exit_code, doc, csv_text = _run_strings(
        monkeypatch, tmp_path, addr, size_hex, min_len, grep, encoding, {int(addr, 16): data})
    console = capsys.readouterr().out
    body = _split_console_body(console)

    auto_note = ""
    expected_header = (f"[*] Extracting strings from {addr} (size={size_hex}{auto_note}, "
                        f"min={min_len}, enc={encoding})\n")

    assert exit_code == 0, f"{name}: exit code drifted"
    assert body == expected_header + expected_body, f"{name}: console drifted"

    assert doc["meta"]["schema_version"] == "2.2"
    assert doc["result"]["kind"] == "strings"
    assert doc["result"]["coverage"]["status"] == "complete"
    assert "## strings / summary" in csv_text or "## strings / records" in csv_text


def test_strings_read_failure_exits_1_before_any_structured_output(monkeypatch, tmp_path, capsys):
    dump_path = str(tmp_path / "sample.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)

    def _boom(mf, addr, size):
        raise RuntimeError("bad address")
    monkeypatch.setattr(extract_mod, "read_region", _boom)

    out_json = str(tmp_path / "out.json")
    monkeypatch.setattr(sys, "argv",
                         ["dumpex", dump_path, "--strings", "0x9999", "--size", "0x10",
                          "--json", out_json])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    console = capsys.readouterr().out
    assert "[*] Extracting strings from 0x9999" in console
    assert "[!] Read failed: bad address" in console
    assert not os.path.exists(out_json), "a failed read must not leave a partial JSON file"

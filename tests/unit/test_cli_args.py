"""
Unit tests for dumpex.cli.main()'s argument parsing and pre-open_dump
validation — the mutually-exclusive mode group, --ref-dir existence
check, and the output-path-vs-dump-path safety refusal (--json/--csv/
--txt/--output). All of these paths run and can be fully exercised
BEFORE main() ever calls open_dump()/MinidumpFile.parse(), so no real
or synthetic .dmp file is needed — a nonexistent path is enough to prove
which check fired first.

This module previously had 0% coverage despite being the very first
thing every invocation goes through, including the safety checks that
protect the evidence file from being overwritten.
"""
import sys
import tempfile

import pytest

import dumpex.cli as cli


def _run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["dumpex"] + argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


# ── argparse-level validation (no dumpfile access at all) ─────────────────

def test_no_arguments_at_all_exits_2(monkeypatch, capsys):
    code = _run(monkeypatch, [])
    assert code == 2
    assert "required: dumpfile" in capsys.readouterr().err


def test_missing_mode_flag_exits_2(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp"])
    assert code == 2
    assert "one of the arguments" in capsys.readouterr().err or \
           "required" in capsys.readouterr().err


def test_conflicting_mode_flags_exits_2(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules", "--peb"])
    assert code == 2
    assert "not allowed with argument" in capsys.readouterr().err


# ── --ref-dir existence check (parser.error, before open_dump) ────────────

def test_ref_dir_nonexistent_directory_rejected(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules",
                              "--ref-dir", "/definitely_not_a_real_dir_xyz123"])
    assert code == 2
    assert "is not an existing directory" in capsys.readouterr().err


def test_ref_dir_existing_directory_passes_validation(monkeypatch, capsys):
    # A valid --ref-dir must let execution proceed PAST the ref-dir check
    # and reach open_dump()'s own "File not found" refusal (exit 1, not
    # the ref-dir parser.error's exit 2) -- proving the ref-dir check
    # itself did not fire.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules",
                              "--ref-dir", tempfile.gettempdir()])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


# ── output-path-vs-dump-path refusal (check_not_dump_path, before open_dump) ─

def test_json_path_same_as_dumpfile_refused(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules",
                              "--json", "/nonexistent.dmp"])
    assert code == 1
    out = capsys.readouterr().out
    assert "same path as the input dump" in out
    assert "--json" in out


def test_csv_path_same_as_dumpfile_refused(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules",
                              "--csv", "/nonexistent.dmp"])
    assert code == 1
    out = capsys.readouterr().out
    assert "same path as the input dump" in out
    assert "--csv" in out


def test_txt_path_same_as_dumpfile_refused(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules",
                              "--txt", "/nonexistent.dmp"])
    assert code == 1
    out = capsys.readouterr().out
    assert "same path as the input dump" in out
    assert "--txt" in out


def test_output_path_same_as_dumpfile_refused(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--extract", "0x1000",
                              "--output", "/nonexistent.dmp"])
    assert code == 1
    out = capsys.readouterr().out
    assert "same path as the input dump" in out
    assert "--output" in out


def test_json_path_different_from_dumpfile_reaches_open_dump(monkeypatch, capsys):
    # A --json path that is NOT the dump file must not be refused --
    # execution proceeds to open_dump()'s own (different) failure mode.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules",
                              "--json", "/tmp/some_other_output.json"])
    assert code == 1
    out = capsys.readouterr().out
    assert "same path as the input dump" not in out
    assert "File not found" in out

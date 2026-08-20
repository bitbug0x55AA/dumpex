"""
Unit tests for dumpex.cli.main()'s argument parsing and pre-open_dump
validation — the mutually-exclusive mode group, --ref-dir existence
check, and the output-path-vs-dump-path safety refusal
(--json/--txt/--output). All of these paths run and can be fully exercised
BEFORE main() ever calls open_dump()/MinidumpFile.parse(), so no real
or synthetic .dmp file is needed — a nonexistent path is enough to prove
which check fired first.

This module previously had 0% coverage despite being the very first
thing every invocation goes through, including the safety checks that
protect the evidence file from being overwritten.
"""
import argparse
import re
import sys
import tempfile
from pathlib import Path

import pytest

import dumpex.cli as cli

_CLI_SOURCE = Path(cli.__file__).read_text(encoding="utf-8")


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
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules", "--process"])
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


def test_csv_option_is_rejected(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules",
                              "--csv", "out.csv"])
    assert code == 2
    assert "unrecognized arguments: --csv out.csv" in capsys.readouterr().err

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


def test_json_path_same_as_diff_target_refused(monkeypatch, capsys):
    # --diff's SECOND dump is just as much real evidence as the primary
    # --dumpfile -- check_not_dump_path must guard against overwriting
    # EITHER one, not just args.dumpfile (see cli.py's dump_paths list).
    code = _run(monkeypatch, ["/nonexistent.dmp", "--diff", "/other.dmp",
                              "--json", "/other.dmp"])
    assert code == 1
    out = capsys.readouterr().out
    assert "same path as the input dump" in out
    assert "--json" in out


def test_json_path_different_from_dumpfile_reaches_open_dump(monkeypatch, capsys):
    # A --json path that is NOT the dump file must not be refused --
    # execution proceeds to open_dump()'s own (different) failure mode.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules",
                              "--json", "/tmp/some_other_output.json"])
    assert code == 1
    out = capsys.readouterr().out
    assert "same path as the input dump" not in out
    assert "File not found" in out


# ── output-target-vs-output-target collision (check_no_output_collisions,
# before open_dump) -- P1-1 remediation: --output/--json/--txt must
# not be allowed to collide with EACH OTHER, not just with the dump ──────

def test_output_and_json_same_path_refused(monkeypatch, tmp_path, capsys):
    same = str(tmp_path / "same.out")
    code = _run(monkeypatch, [str(tmp_path / "sample.dmp"), "--extract", "0x1000",
                              "--output", same, "--json", same])
    assert code == 1
    out = capsys.readouterr().out
    assert "would both write to the same file" in out
    assert "--output" in out and "--json" in out


def test_output_and_json_same_path_refused_even_with_force(monkeypatch, tmp_path, capsys):
    # The exact scenario from the bug report: --force must NOT lift this
    # refusal -- it exists precisely because --force otherwise lets the
    # later --json write silently clobber the just-written extract
    # output, leaving the JSON's own artifact entry describing bytes that
    # no longer exist at that path.
    same = str(tmp_path / "same.out")
    code = _run(monkeypatch, [str(tmp_path / "sample.dmp"), "--extract", "0x1000",
                              "--output", same, "--json", same, "--force"])
    assert code == 1
    out = capsys.readouterr().out
    assert "would both write to the same file" in out
    assert not (tmp_path / "same.out").exists(), "no output file may be created after refusal"


def test_output_and_txt_same_path_refused(monkeypatch, tmp_path, capsys):
    same = str(tmp_path / "same.out")
    code = _run(monkeypatch, [str(tmp_path / "sample.dmp"), "--extract", "0x1000",
                              "--output", same, "--txt", same])
    assert code == 1
    out = capsys.readouterr().out
    assert "would both write to the same file" in out
    assert "--txt" in out


def test_extract_default_output_path_collides_with_json_refused(monkeypatch, tmp_path, capsys):
    # No --output given -- --extract's own auto-generated default filename
    # (region_0x1000.bin, relative to cwd) must still be checked against
    # --json/--txt, not just an explicit --output.
    monkeypatch.chdir(tmp_path)
    code = _run(monkeypatch, [str(tmp_path / "sample.dmp"), "--extract", "0x1000",
                              "--json", "region_0x1000.bin"])
    assert code == 1
    out = capsys.readouterr().out
    assert "would both write to the same file" in out
    assert "--extract's default output filename" in out
    assert not (tmp_path / "region_0x1000.bin").exists()


# ── _selected_run_mode() <-> _V2_STRUCTURED_MODES <-> the mode group ─────
# _selected_run_mode()'s return value for a new mode flag is otherwise
# unobservable: its only real call site (main()) only ever compares the
# result to == "diff", so a flag added to the mutually-exclusive group
# without a matching branch here (or spelled wrong, e.g. "proccess")
# would not fail a single existing test -- out.set_command_result() would
# just never be called for that mode, silently writing a --json document
# with no result. This pins the three-way agreement that class of bug
# would break: every flag argparse's mode group actually offers, every
# value _selected_run_mode() can actually return, and the set cli.py
# itself claims those values live in.

def _mode_group_flags() -> tuple:
    # Parsed straight out of cli.py's own source rather than hand-listed
    # here a second time -- a flag added to (or removed from) the real
    # `mode.add_argument(...)` mutex group changes what THIS function
    # returns too, so the three-way comparison below can't quietly drift
    # from the actual argparse definition the same way a hand-copied list
    # could.
    calls = re.findall(r'mode\.add_argument\("--([a-z-]+)"', _CLI_SOURCE)
    return tuple(name.replace("-", "_") for name in calls)


_MODE_FLAGS = _mode_group_flags()


def _namespace_selecting(flag: str) -> argparse.Namespace:
    # extract/strings/diff/hunt are metavar-valued (a string), the rest
    # are store_true booleans -- either way, "truthy" is what
    # _selected_run_mode()'s own `if args.X:` checks test.
    values = {name: (name if name in ("extract", "strings", "diff", "hunt") else True)
              if name == flag else (None if name in ("extract", "strings", "diff", "hunt") else False)
              for name in _MODE_FLAGS}
    return argparse.Namespace(**values)


def test_mode_group_flags_are_actually_parsed_from_cli_py():
    # Guards the guard: a regex that stopped matching would make every
    # test below vacuously pass an empty-set comparison instead of
    # catching real drift.
    assert len(_MODE_FLAGS) >= 10
    assert "process" in _MODE_FLAGS and "handles" in _MODE_FLAGS and "profile" in _MODE_FLAGS
    assert "pid" not in _MODE_FLAGS and "peb" not in _MODE_FLAGS


@pytest.mark.parametrize("flag", _MODE_FLAGS)
def test_selected_run_mode_returns_the_one_flag_selected(flag):
    assert cli._selected_run_mode(_namespace_selecting(flag)) == flag


def test_mode_flags_selected_run_mode_values_and_v2_structured_modes_all_agree():
    possible_returns = {cli._selected_run_mode(_namespace_selecting(flag)) for flag in _MODE_FLAGS}
    assert possible_returns == set(_MODE_FLAGS)
    assert cli._V2_STRUCTURED_MODES == set(_MODE_FLAGS)

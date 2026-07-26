"""
Unit tests for dumpex.core.memory.open_dump() -- corrupted/malformed dump
handling.

A missing file already exited cleanly with a "File not found" message.
A file that EXISTS but isn't a valid minidump (corrupted, truncated,
or just not a .dmp at all) previously propagated whatever internal
exception the minidump library happened to raise as a raw, unhandled
traceback all the way up through cli.main() -- an analyst feeding
dumpex bad evidence deserves the same clean refusal as the missing-file
case, not an implementation-detail stack trace.
"""
import pytest

from dumpex.core.memory import open_dump


def test_missing_file_exits_1_with_clean_message(capsys):
    with pytest.raises(SystemExit) as exc:
        open_dump("/definitely_does_not_exist_dumpex_test.dmp")
    assert exc.value.code == 1
    assert "File not found" in capsys.readouterr().out


def test_corrupted_file_exits_cleanly_instead_of_raw_traceback(tmp_path, capsys):
    bogus = tmp_path / "garbage.dmp"
    bogus.write_bytes(b"NOT A REAL MINIDUMP FILE" * 100)

    with pytest.raises(SystemExit) as exc:
        open_dump(str(bogus))

    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Could not parse" in out
    assert str(bogus) in out


def test_empty_file_exits_cleanly(tmp_path, capsys):
    empty = tmp_path / "empty.dmp"
    empty.write_bytes(b"")

    with pytest.raises(SystemExit) as exc:
        open_dump(str(empty))

    assert exc.value.code == 1
    assert "Could not parse" in capsys.readouterr().out

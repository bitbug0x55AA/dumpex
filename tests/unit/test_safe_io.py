"""
Unit tests for dumpex.core.safe_io — the output-file safety primitives
every --json/--csv/--txt/--extract writer funnels through: no-clobber by
default, atomic commit (never a half-written or empty placeholder left
behind), and an unconditional refusal to write onto the input dump path.

This module had almost no test coverage despite being where a bug would
have the worst possible consequence for a DFIR tool: silently corrupting
or truncating the evidence file being analyzed.
"""
import hashlib
import re

import pytest

from dumpex.core import safe_io


# ── check_not_dump_path ─────────────────────────────────────────────────

def test_check_not_dump_path_allows_different_path(tmp_path):
    dump = tmp_path / "evidence.dmp"
    dump.write_bytes(b"x")
    out = tmp_path / "out.json"
    safe_io.check_not_dump_path(out, str(dump), "test output")   # must not raise


def test_check_not_dump_path_refuses_same_path(tmp_path, capsys):
    dump = tmp_path / "evidence.dmp"
    dump.write_bytes(b"x")
    with pytest.raises(SystemExit) as exc:
        safe_io.check_not_dump_path(dump, str(dump), "test output")
    assert exc.value.code == 1
    assert "same path as the input dump" in capsys.readouterr().out
    assert dump.read_bytes() == b"x"   # evidence untouched


def test_check_not_dump_path_accepts_path_description_tuple(tmp_path, capsys):
    # Used by V2Output to protect an already-written artifact path (not
    # the input dump) -- the printed message must name the actual thing
    # being protected, not always claim it's the input dump.
    artifact_path = tmp_path / "extracted.bin"
    artifact_path.write_bytes(b"x")
    with pytest.raises(SystemExit) as exc:
        safe_io.check_not_dump_path(
            artifact_path, [(str(artifact_path), "the 'extracted_region' artifact")],
            "test output")
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "same path as the 'extracted_region' artifact" in out
    assert "same path as the input dump" not in out
    assert artifact_path.read_bytes() == b"x"   # untouched


def test_check_not_dump_path_mixed_bare_string_and_tuple_entries(tmp_path):
    dump = tmp_path / "evidence.dmp"
    dump.write_bytes(b"x")
    out = tmp_path / "out.json"
    # A bare string entry alongside a tuple entry, neither colliding --
    # must not raise.
    safe_io.check_not_dump_path(out, [str(dump), (str(tmp_path / "other.bin"), "other")],
                                 "test output")


# ── check_no_output_collisions ──────────────────────────────────────────

def test_check_no_output_collisions_allows_distinct_paths(tmp_path):
    safe_io.check_no_output_collisions([
        (str(tmp_path / "a.json"), "--json"),
        (str(tmp_path / "b.csv"), "--csv"),
        (None, "--txt"),
    ])   # must not raise


def test_check_no_output_collisions_refuses_same_path(tmp_path, capsys):
    same = str(tmp_path / "same.out")
    with pytest.raises(SystemExit) as exc:
        safe_io.check_no_output_collisions([(same, "--output"), (same, "--json")])
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "would both write to the same file" in out
    assert "--output" in out and "--json" in out


def test_check_no_output_collisions_skips_directory_mode_targets(tmp_path):
    # A directory-mode target (existing dir, or trailing slash) writes
    # auto-named files INTO it -- never at the literal path itself -- so
    # it must not be compared for equality against another target that
    # happens to share that literal string.
    safe_io.check_no_output_collisions([
        (str(tmp_path), "--csv"),
        (str(tmp_path), "--txt"),
    ])   # must not raise: both are directory-mode, skipped entirely


def test_check_no_output_collisions_skips_none_entries(tmp_path):
    safe_io.check_no_output_collisions([(None, "--output"), (None, "--json")])   # must not raise


# ── summarize_bytes / summarize_file / compute_bytes_summary ────────────

def test_summarize_bytes_and_file_agree(tmp_path):
    data = b"hello world"
    summary = safe_io.summarize_bytes(data)
    assert str(len(data)) in summary
    assert hashlib.sha256(data).hexdigest() in summary

    f = tmp_path / "x.bin"
    f.write_bytes(data)
    assert safe_io.summarize_file(f) == summary


def test_compute_bytes_summary_matches_summarize_bytes():
    # compute_bytes_summary() is the raw (size, sha256) pair a caller
    # building a structured record/Artifact needs directly, without
    # parsing them back out of summarize_bytes()'s own display string --
    # both must derive from the identical computation.
    data = b"hello world"
    size, digest = safe_io.compute_bytes_summary(data)
    assert size == len(data)
    assert digest == hashlib.sha256(data).hexdigest()
    assert safe_io.summarize_bytes(data) == f"{size} bytes  sha256={digest}"


def test_compute_bytes_summary_empty_bytes():
    size, digest = safe_io.compute_bytes_summary(b"")
    assert size == 0
    assert digest == hashlib.sha256(b"").hexdigest()


# ── write_output_bytes / write_output_text ──────────────────────────────

def test_write_output_bytes_creates_new_file(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "result.json"
    summary = safe_io.write_output_bytes(out, b'{"a":1}', str(dump), False, "test output")
    assert out.read_bytes() == b'{"a":1}'
    assert "sha256=" in summary


def test_write_output_bytes_refuses_existing_without_force(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "result.json"
    out.write_bytes(b"old")
    with pytest.raises(SystemExit):
        safe_io.write_output_bytes(out, b"new", str(dump), False, "test output")
    assert out.read_bytes() == b"old"   # untouched


def test_write_output_bytes_overwrites_with_force(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "result.json"
    out.write_bytes(b"old")
    safe_io.write_output_bytes(out, b"new", str(dump), True, "test output")
    assert out.read_bytes() == b"new"


def test_write_output_bytes_refuses_dump_path_even_with_force(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    with pytest.raises(SystemExit):
        safe_io.write_output_bytes(dump, b"malicious", str(dump), True, "test output")
    assert dump.read_bytes() == b"d"   # evidence untouched even under --force


def test_write_output_bytes_no_leftover_temp_file_on_refusal(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "result.json"
    out.write_bytes(b"old")
    with pytest.raises(SystemExit):
        safe_io.write_output_bytes(out, b"new", str(dump), False, "test output")
    leftovers = [p.name for p in tmp_path.iterdir() if p.name not in ("e.dmp", "result.json")]
    assert leftovers == []


def test_write_output_text_encodes_and_writes(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "r.txt"
    safe_io.write_output_text(out, "hello", str(dump), False, "test output")
    assert out.read_text() == "hello"


# ── commit_to_directory ──────────────────────────────────────────────────

def test_commit_to_directory_auto_retries_on_collision(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    d = tmp_path / "outdir"

    tmp1 = tmp_path / "scratch1.tmp"
    tmp1.write_bytes(b"1")
    p1 = safe_io.commit_to_directory(str(tmp1), d, "dumpex_report", ".csv", str(dump), False)
    assert p1.name == "dumpex_report.csv"

    tmp2 = tmp_path / "scratch2.tmp"
    tmp2.write_bytes(b"2")
    p2 = safe_io.commit_to_directory(str(tmp2), d, "dumpex_report", ".csv", str(dump), False)
    assert p2.name == "dumpex_report_001.csv"

    assert p1.read_bytes() == b"1"
    assert p2.read_bytes() == b"2"


def test_commit_to_directory_force_overwrites_first_name(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    d = tmp_path / "outdir"

    tmp1 = tmp_path / "scratch1.tmp"
    tmp1.write_bytes(b"1")
    p1 = safe_io.commit_to_directory(str(tmp1), d, "report", ".csv", str(dump), False)

    tmp2 = tmp_path / "scratch2.tmp"
    tmp2.write_bytes(b"2")
    p2 = safe_io.commit_to_directory(str(tmp2), d, "report", ".csv", str(dump), True)

    assert p1 == p2
    assert p2.read_bytes() == b"2"


def test_commit_to_directory_refuses_dump_path_collision(tmp_path):
    d = tmp_path
    dump = d / "dumpex_report.csv"
    dump.write_bytes(b"evidence")
    tmp1 = tmp_path / "scratch.tmp"
    tmp1.write_bytes(b"data")
    with pytest.raises(SystemExit):
        safe_io.commit_to_directory(str(tmp1), d, "dumpex_report", ".csv", str(dump), False)
    assert dump.read_bytes() == b"evidence"


# ── commit_output ─────────────────────────────────────────────────────────

def test_commit_output_dir_target_auto_names(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    outdir = tmp_path / "outdir"
    tmp1 = tmp_path / "scratch.tmp"
    tmp1.write_bytes(b"content")
    final = safe_io.commit_output(str(tmp1), str(outdir) + "/", ".json", "hunt", str(dump), False)
    assert final.parent == outdir
    assert final.name.startswith("dumpex_") and final.name.endswith("_hunt.json")
    assert final.read_bytes() == b"content"


def test_commit_output_file_target(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "result.json"
    tmp1 = tmp_path / "scratch.tmp"
    tmp1.write_bytes(b"content")
    final = safe_io.commit_output(str(tmp1), str(out), ".json", "hunt", str(dump), False)
    assert final == out
    assert out.read_bytes() == b"content"


# ── write_text_to_target / write_text_to_directory ──────────────────────

def test_write_text_to_target_full_pipeline(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "result.json"
    final = safe_io.write_text_to_target(str(out), '{"x":1}', ".json", "modules", str(dump), False)
    assert final == out
    assert out.read_text() == '{"x":1}'


def test_write_text_to_directory_uses_stem(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    d = tmp_path / "outdir"
    final = safe_io.write_text_to_directory(d, "a,b\n1,2\n", "dumpex_hunt_summary", ".csv",
                                             str(dump), False)
    assert final.name == "dumpex_hunt_summary.csv"
    assert final.read_text() == "a,b\n1,2\n"


# ── AtomicTextTee ─────────────────────────────────────────────────────────

class _FakeStdout:
    def __init__(self):
        self.buf = []

    def write(self, s):
        self.buf.append(s)

    def flush(self):
        pass


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def test_atomic_text_tee_writes_stripped_ansi_and_finalizes(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "report.txt"
    fake = _FakeStdout()

    tee = safe_io.AtomicTextTee(str(out), "modules", str(dump), False, fake, _ANSI_RE)
    tee.write("\x1b[31mHello\x1b[0m World\n")
    tee.flush()
    final_path, summary = tee.finalize()

    assert final_path == out
    assert out.read_text() == "Hello World\n"          # ANSI stripped in the file
    assert "".join(fake.buf) == "\x1b[31mHello\x1b[0m World\n"   # NOT stripped on the console
    assert "sha256=" in summary


def test_atomic_text_tee_abandon_leaves_no_final_file(tmp_path):
    dump = tmp_path / "e.dmp"
    dump.write_bytes(b"d")
    out = tmp_path / "report.txt"

    tee = safe_io.AtomicTextTee(str(out), "modules", str(dump), False, _FakeStdout(), _ANSI_RE)
    tee.write("partial output that should never be committed")
    tee.abandon()

    assert not out.exists()
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "e.dmp"]
    assert leftovers == []

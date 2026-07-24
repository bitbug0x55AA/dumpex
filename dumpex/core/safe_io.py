"""
Output-file safety helpers: no-clobber by default, atomic writes, and a
hard refusal when an output path would collide with the input dump.

A DFIR tool's output paths need to be provably safe:
  - never truncate/overwrite the evidence file being analyzed
  - never silently clobber an existing output the analyst didn't expect
    to lose (unless they explicitly opted in with --force)
  - never leave a half-written file behind if the write is interrupted
    (crash, disk full, Ctrl-C) — a truncated JSON/CSV/txt report that
    LOOKS complete is worse than no report at all
"""
import os
import sys
import hashlib
import tempfile
from pathlib import Path

from dumpex.ui.colors import RED, DIM, GREEN


def resolve_or_none(path) -> Path | None:
    """Path.resolve(), tolerating a path that doesn't exist yet."""
    try:
        return Path(path).resolve()
    except Exception:
        return None


def check_not_dump_path(out_path, dump_path, label: str):
    """
    Refuse if out_path resolves to the same file as dump_path.

    This must be checked regardless of write timing (before or after the
    dump is parsed): MinidumpFile reads are lazy/on-demand against the
    still-open file handle for the life of the process, not a one-time
    upfront slurp — so even writing "after the initial parse" doesn't
    make it safe to replace the underlying file mid-run.
    """
    out_resolved  = resolve_or_none(out_path)
    dump_resolved = resolve_or_none(dump_path)
    if out_resolved is not None and out_resolved == dump_resolved:
        print(RED(f"[!] Refusing to write {label} to the same path as the input dump: {out_path}"))
        print(DIM(f"    This would destroy the evidence file. Choose a different output path."))
        sys.exit(1)


def check_overwrite(out_path, force: bool, label: str):
    """Refuse to clobber an existing file unless --force was passed."""
    p = Path(out_path)
    if p.exists() and not force:
        print(RED(f"[!] {label} already exists: {out_path}"))
        print(DIM(f"    Pass --force to overwrite."))
        sys.exit(1)


def atomic_write_bytes(out_path, data: bytes) -> str:
    """
    Write data to out_path atomically: write to a temp file in the same
    directory, then os.replace() into place. A crash, Ctrl-C, or full disk
    mid-write leaves the temp file orphaned and the target path untouched
    (either the old version, if any, or nothing) — never a truncated
    half-write masquerading as a complete file.

    Returns a "N bytes  sha256=..." summary string for chain-of-custody
    logging.
    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, p)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return summarize_bytes(data)


def atomic_write_text(out_path, text: str, encoding: str = "utf-8") -> str:
    return atomic_write_bytes(out_path, text.encode(encoding))


def summarize_bytes(data: bytes) -> str:
    return f"{len(data)} bytes  sha256={hashlib.sha256(data).hexdigest()}"


def summarize_file(path) -> str:
    return summarize_bytes(Path(path).read_bytes())


class AtomicTextTee:
    """
    Streaming tee-to-file that stays atomic: writes accumulate in a temp
    file in the target's directory throughout the run, and are only
    renamed onto the final path in finalize(). If the process dies mid-run
    (crash, Ctrl-C, disk full), the target path is left exactly as it was
    before — never a partial capture masquerading as the full run's output.
    """

    def __init__(self, final_path, original_stdout, ansi_re):
        self._final_path = Path(final_path)
        self._original   = original_stdout
        self._ansi_re     = ansi_re
        self._final_path.parent.mkdir(parents=True, exist_ok=True)
        fd, self._tmp_path = tempfile.mkstemp(
            dir=str(self._final_path.parent),
            prefix=f".{self._final_path.name}.", suffix=".tmp")
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def write(self, text: str) -> int:
        self._original.write(text)
        self._fh.write(self._ansi_re.sub('', text))
        return len(text)

    def flush(self):
        self._original.flush()
        self._fh.flush()

    def __getattr__(self, name):
        return getattr(self._original, name)

    def finalize(self) -> str:
        """Close the temp file and atomically rename it onto the final path."""
        self._fh.close()
        os.replace(self._tmp_path, self._final_path)
        return summarize_file(self._final_path)

    def abandon(self):
        """Discard the temp file without touching the final path (on error paths)."""
        try:
            self._fh.close()
        except Exception:
            pass
        try:
            os.unlink(self._tmp_path)
        except OSError:
            pass

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
import datetime
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


def _reserve_exclusive(path: Path) -> bool:
    """
    Atomically claim `path` iff nothing exists there yet (O_CREAT|O_EXCL).

    A plain `Path.exists()` check followed by a later write has a TOCTOU
    window: two concurrent dumpex runs (or two runs racing on the same
    output path) can both observe "free" and then both write, one silently
    clobbering the other. Creating the file here — even though its content
    is only filled in later via atomic_write_* — closes that window for the
    lifetime of the reservation.
    """
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    os.close(fd)
    return True


def check_overwrite(out_path, force: bool, label: str):
    """
    Refuse to clobber an existing file unless --force was passed.

    When not forcing, this reserves out_path via O_CREAT|O_EXCL rather than
    just checking existence (see _reserve_exclusive) — the empty file this
    leaves behind is safe for the caller's subsequent atomic_write_* to
    replace via os.replace().
    """
    p = Path(out_path)
    if force:
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    if not _reserve_exclusive(p):
        print(RED(f"[!] {label} already exists: {out_path}"))
        print(DIM(f"    Pass --force to overwrite."))
        sys.exit(1)


def reserve_unique_path(directory, stem: str, suffix: str, force: bool = False,
                         max_attempts: int = 1000) -> Path:
    """
    Reserve a unique filename `{stem}{suffix}` (or `{stem}_NNN{suffix}` on
    collision) inside `directory`, for auto-generated output targets
    (directory mode for --txt/--json/--csv).

    A fixed-timestamp stem is not guaranteed unique — two runs within the
    same wall-clock second, or two hunts against the same dump, would
    otherwise produce the identical filename and one write would silently
    clobber the other. Instead of trusting `Path.exists()` (itself a TOCTOU
    race), each candidate is claimed with O_CREAT|O_EXCL and the first one
    that succeeds is returned already reserved.

    force=True skips the collision search entirely and returns the bare
    `{stem}{suffix}` path unreserved — the caller intends to overwrite
    whatever (if anything) is already there.
    """
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    if force:
        return d / f"{stem}{suffix}"

    candidate = d / f"{stem}{suffix}"
    if _reserve_exclusive(candidate):
        return candidate
    for i in range(1, max_attempts):
        candidate = d / f"{stem}_{i:03d}{suffix}"
        if _reserve_exclusive(candidate):
            return candidate
    raise RuntimeError(
        f"could not reserve a unique output filename under {d} "
        f"(tried {max_attempts} names starting with '{stem}{suffix}')")


def resolve_output_target(requested_path, suffix: str, cmd_label: str,
                           dump_path, force: bool) -> Path:
    """
    Single entry point for resolving a --txt/--json/--csv(single-file)
    output argument into a concrete, safely-claimed path. Every caller that
    accepts a directory-or-file output argument must go through this
    (or reserve_unique_path directly, for the multi-file --csv directory
    case where table names aren't known until after the scan) rather than
    hand-rolling its own exists()/mkdir()/timestamp logic — see the P1
    "directory-mode output can silently overwrite files" finding.

    Behaviour:
      1. Refuse if the resolved target is the input dump file itself.
         Unconditional — --force does not lift this.
      2. Directory target (path ends in a separator, or already exists as
         a directory): auto-generate `dumpex_<utc-timestamp>_<cmd_label>`
         and reserve a collision-free name for it (reserve_unique_path).
      3. File target: reserve the exact path unless --force (check_overwrite).

    Returns the resolved Path; exits the process on any refusal, consistent
    with check_overwrite/check_not_dump_path.
    """
    p = Path(requested_path)
    is_dir_target = str(requested_path).endswith(('/', '\\')) or p.is_dir()
    if is_dir_target:
        check_not_dump_path(p, dump_path, f"output directory ({suffix})")
        ts    = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        label = f"_{cmd_label}" if cmd_label else ""
        return reserve_unique_path(p, f"dumpex_{ts}{label}", suffix, force=force)

    check_not_dump_path(p, dump_path, f"{suffix} output")
    check_overwrite(p, force, f"{suffix} output")
    return p


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

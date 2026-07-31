"""
Output-file safety helpers: no-clobber by default, atomic writes, and a
hard refusal when an output path would collide with the input dump.

A DFIR tool's output paths need to be provably safe:
  - never truncate/overwrite the evidence file being analyzed — checked
    against the LITERAL final path, unconditionally, right before the
    commit step; --force never lifts this specific check
  - never silently clobber an existing output the analyst didn't expect
    to lose (unless they explicitly opted in with --force)
  - never leave a half-written file — or an empty placeholder — behind if
    the write is interrupted (crash, disk full, Ctrl-C, an existing-file
    refusal) — nothing is ever created at (or near) the final path until
    the content is complete and ready to commit in one atomic step

Everything funnels through commit_output() / commit_to_directory(): the
final filename is generated, dump-path-checked, and committed together, at
the moment the content is ready — never earlier. There is deliberately no
"reserve an empty file now, fill it in later" step anywhere in this module.
"""
import os
import sys
import hashlib
import tempfile
import datetime
import contextlib
from pathlib import Path

from dumpex.ui.colors import RED, DIM


@contextlib.contextmanager
def _unlink_temp_on_error(temp_path):
    """
    Guarantees temp_path never survives a refusal (check_not_dump_path's
    sys.exit) or any other exception raised while committing it — a
    caller-created temp file that outlives the commit attempt because the
    refusal path forgot to clean it up is exactly the kind of leftover
    file this module exists to prevent, even though it's a scratch temp
    file rather than something at the final path.
    """
    try:
        yield
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def resolve_or_none(path) -> Path | None:
    """Path.resolve(), tolerating a path that doesn't exist yet."""
    try:
        return Path(path).resolve()
    except Exception:
        return None


def check_not_dump_path(out_path, dump_path, label: str):
    """
    Refuse if out_path resolves to the same file as ANY of dump_path.

    dump_path is either a single path (str/Path -- the original, still
    most common case: one command, one input dump) or an iterable of
    paths (a comparison command with a baseline AND a target dump, each
    equally real evidence that must never be overwritten). A bare string
    is deliberately NOT treated as "an iterable of characters" here --
    isinstance(dump_path, (str, Path)) is checked explicitly first, since
    Python strings are iterable and would otherwise silently explode into
    single-character "paths" that can never collide with anything,
    defeating the whole check.

    Callers must invoke this against the LITERAL path about to be written,
    at commit time — never against a directory or pattern that merely
    produced that path, and never skip it for --force. MinidumpFile reads
    are lazy/on-demand against the still-open file handle for the life of
    the process (not a one-time upfront slurp), so there is no point in
    program execution where overwriting any protected input path becomes
    safe -- force must never be able to lift this specific check.
    """
    out_resolved = resolve_or_none(out_path)
    if out_resolved is None:
        return
    dump_paths = [dump_path] if isinstance(dump_path, (str, Path)) else list(dump_path)
    for dp in dump_paths:
        if out_resolved == resolve_or_none(dp):
            print(RED(f"[!] Refusing to write {label} to the same path as the input dump: {out_path}"))
            print(DIM(f"    This would destroy the evidence file. Choose a different output path."))
            sys.exit(1)


def summarize_bytes(data: bytes) -> str:
    return f"{len(data)} bytes  sha256={hashlib.sha256(data).hexdigest()}"


def summarize_file(path) -> str:
    return summarize_bytes(Path(path).read_bytes())


# ── Commit primitives ────────────────────────────────────────────────────
# A completed temp file becomes real output content ONLY through these.

def _commit_no_clobber(temp_path, final_path: Path, force: bool, label: str) -> None:
    """
    Commit temp_path onto final_path with no TOCTOU window and, in
    non-force mode, no way to silently discard an existing file: a hard
    link is atomic AND exclusive — it fails immediately (temp_path
    untouched by the failure) if final_path already exists, unlike a
    Path.exists() check followed by a separate write. force=True skips
    straight to os.replace() — overwriting is the explicit intent.

    temp_path is always consumed here: unlinked on the two "expected"
    paths (success, and the existing-file refusal), AND on any other
    exception os.link()/os.replace() can raise — a PermissionError, a
    filesystem that doesn't support hard links (ENOTSUP), a cross-device
    link (EXDEV) — via the _unlink_temp_on_error wrapper. This function is
    the single choke point every caller commits through (write_output_bytes,
    commit_output, commit_to_directory), so making IT self-contained here
    means no caller can forget to wrap its own call and leak a temp file
    on an unexpected failure mode.
    """
    final_path = Path(final_path)
    with _unlink_temp_on_error(temp_path):
        if force:
            os.replace(temp_path, final_path)
            return
        try:
            os.link(temp_path, final_path)
        except FileExistsError:
            os.unlink(temp_path)
            print(RED(f"[!] {label} already exists: {final_path}"))
            print(DIM(f"    Pass --force to overwrite."))
            sys.exit(1)
        else:
            os.unlink(temp_path)


def write_output_bytes(final_path, data: bytes, dump_path, force: bool, label: str) -> str:
    """
    Write `data` as a new output file at an EXACT, caller-chosen path
    (--extract, --output, --json/--csv single-file targets). Not for a
    directory target — see commit_to_directory for the auto-named case.

    check_not_dump_path runs against the literal final_path, unconditionally
    (force never lifts it). The write goes to a temp file in the same
    directory first; final_path itself is only ever touched by the single
    atomic commit step (_commit_no_clobber) once that temp file is
    complete — never before, so a crash or refusal never leaves an empty
    placeholder there.
    """
    p = Path(final_path)
    check_not_dump_path(p, dump_path, label)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    _commit_no_clobber(tmp_path, p, force, label)
    return summarize_bytes(data)


def write_output_text(final_path, text: str, dump_path, force: bool, label: str,
                       encoding: str = "utf-8") -> str:
    return write_output_bytes(final_path, text.encode(encoding), dump_path, force, label)


def commit_to_directory(temp_path, directory, stem: str, suffix: str,
                         dump_path, force: bool, label: str = "",
                         max_attempts: int = 1000) -> Path:
    """
    Commit an already-written temp_path into `directory` as
    `{stem}{suffix}`, retrying with `{stem}_001{suffix}`, `_002`, ... on
    collision instead of refusing outright: the stem here is always
    machine-generated (a timestamp, a CSV table name) rather than
    something the user chose to protect, so a collision means "pick a
    fresher name," not "you're about to lose something."

    check_not_dump_path runs against every literal candidate BEFORE it is
    attempted — including under force=True, which here only skips the
    collision-retry search (single attempt, overwrite-tolerant) rather
    than also skipping the evidence-file check. This is what closes the
    force+directory-mode gap: a directory target whose auto-generated name
    happens to collide with the input dump is refused regardless of
    --force, at the exact final path, not the directory that produced it.
    """
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)

    with _unlink_temp_on_error(temp_path):
        if force:
            final_path = d / f"{stem}{suffix}"
            check_not_dump_path(final_path, dump_path, label or f"output ({suffix})")
            os.replace(temp_path, final_path)
            return final_path

        for i in range(max_attempts):
            final_path = d / (f"{stem}{suffix}" if i == 0 else f"{stem}_{i:03d}{suffix}")
            check_not_dump_path(final_path, dump_path, label or f"output ({suffix})")
            try:
                os.link(temp_path, final_path)
            except FileExistsError:
                continue
            os.unlink(temp_path)
            return final_path

        os.unlink(temp_path)
        raise RuntimeError(
            f"could not commit a unique output filename under {d} "
            f"(tried {max_attempts} names starting with '{stem}{suffix}')")


def commit_output(temp_path, requested_path, suffix: str, cmd_label: str,
                   dump_path, force: bool, label: str = "") -> Path:
    """
    Single entry point for turning a completed temp file into a real
    --json/--csv/--txt output, whether `requested_path` names a directory
    (auto-generated `dumpex_<utc-ts>_<cmd_label>{suffix}` filename, via
    commit_to_directory) or an exact file (write_output_bytes's
    _commit_no_clobber). Every --json/--csv/--txt writer must go through
    this (or commit_to_directory directly, for CSV's per-table directory
    case where the stem isn't a timestamp) rather than hand-rolling its
    own exists()/mkdir()/timestamp logic.
    """
    p = Path(requested_path)
    is_dir_target = str(requested_path).endswith(('/', '\\')) or p.is_dir()
    if is_dir_target:
        ts    = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        tag   = f"_{cmd_label}" if cmd_label else ""
        return commit_to_directory(temp_path, p, f"dumpex_{ts}{tag}", suffix,
                                    dump_path, force, label)

    final_path = p
    with _unlink_temp_on_error(temp_path):
        check_not_dump_path(final_path, dump_path, label or f"{suffix} output")
        final_path.parent.mkdir(parents=True, exist_ok=True)
        _commit_no_clobber(temp_path, final_path, force, label or f"{suffix} output")
        return final_path


# ── Write-then-commit convenience wrappers ───────────────────────────────

def _mkstemp_text(directory: Path, encoding: str = "utf-8",
                  newline: "str | None" = None):
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(directory), prefix=".dumpex-", suffix=".tmp")
    return os.fdopen(fd, "w", encoding=encoding, newline=newline), tmp_path


def write_text_to_target(requested_path, text: str, suffix: str, cmd_label: str,
                          dump_path, force: bool, label: str = "",
                          encoding: str = "utf-8",
                          newline: "str | None" = None) -> Path:
    """
    Full pipeline for a --json/--csv/--txt single-generated-name output:
    write `text` to a scratch temp file (in whatever directory the final
    output will end up in), then commit_output() it onto requested_path.
    Nothing is ever created at/near the final path until the content is
    complete and ready to commit in one atomic step.

    `newline` is forwarded to the text stream. CSV callers pass "" so
    their explicitly selected line terminator reaches disk unchanged on
    every platform.
    """
    p = Path(requested_path)
    is_dir_target = str(requested_path).endswith(('/', '\\')) or p.is_dir()
    directory = p if is_dir_target else (p.parent if str(p.parent) else Path("."))
    fh, tmp_path = _mkstemp_text(directory, encoding, newline)
    try:
        fh.write(text)
        fh.close()
    except BaseException:
        try:
            fh.close()
        except Exception:
            pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return commit_output(tmp_path, requested_path, suffix, cmd_label, dump_path, force, label)


def write_text_to_directory(directory, text: str, stem: str, suffix: str,
                             dump_path, force: bool, label: str = "",
                             encoding: str = "utf-8",
                             newline: "str | None" = None) -> Path:
    """Like write_text_to_target, but for CSV's per-table directory case
    where the stem is a table name, not a timestamp — see commit_to_directory.
    `newline` has the same pass-through semantics as write_text_to_target."""
    d = Path(directory)
    fh, tmp_path = _mkstemp_text(d, encoding, newline)
    try:
        fh.write(text)
        fh.close()
    except BaseException:
        try:
            fh.close()
        except Exception:
            pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return commit_to_directory(tmp_path, d, stem, suffix, dump_path, force, label)


class AtomicTextTee:
    """
    Streaming tee-to-file that stays atomic AND doesn't touch the final
    output path — or its containing directory's namespace — until the run
    actually completes: writes accumulate in a scratch temp file for the
    whole run, and the final filename is generated + committed only in
    finalize(), via commit_output(). A crash, Ctrl-C, or abandon() call
    only ever touches the temp file — no empty placeholder is ever created
    at or near the final path.
    """

    def __init__(self, requested_path, cmd_label: str, dump_path, force: bool,
                 original_stdout, ansi_re):
        self._requested  = requested_path
        self._cmd_label  = cmd_label
        self._dump_path  = dump_path
        self._force      = force
        self._original   = original_stdout
        self._ansi_re    = ansi_re

        p = Path(requested_path)
        is_dir_target = str(requested_path).endswith(('/', '\\')) or p.is_dir()
        scratch_dir = p if is_dir_target else (p.parent if str(p.parent) else Path("."))
        scratch_dir.mkdir(parents=True, exist_ok=True)
        fd, self._tmp_path = tempfile.mkstemp(dir=str(scratch_dir), prefix=".dumpex-txt-", suffix=".tmp")
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

    def finalize(self):
        """Close the temp file, resolve + commit the final path now. Returns
        (final_path, summary)."""
        self._fh.close()
        final_path = commit_output(self._tmp_path, self._requested, ".txt",
                                    self._cmd_label, self._dump_path, self._force,
                                    "--txt output")
        return final_path, summarize_file(final_path)

    def abandon(self):
        """Discard the temp file without touching the final path (on error
        paths) — the final path was never created in the first place."""
        try:
            self._fh.close()
        except Exception:
            pass
        try:
            os.unlink(self._tmp_path)
        except OSError:
            pass

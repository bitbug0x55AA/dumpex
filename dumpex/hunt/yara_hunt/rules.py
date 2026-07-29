"""Packaged YARA rules directory resolution, per-file compilation, and
reproducible content provenance -- see RuleBundle in models.py.

Never imports the facade (dumpex.hunt.yara_hunt) -- see
dumpex/hunt/yara_hunt/__init__.py's docstring for why: __init__.py's own
`_load_yara_rules` wrapper is what stays monkeypatchable and syncs the
compatibility `_LAST_YARA_PROVENANCE` global; this module just does the
real work and hands back a RuleBundle.
"""
import os
import atexit
import hashlib
import contextlib
import importlib.resources
from dumpex.ui.colors import YELLOW
from dumpex.hunt.yara_hunt.models import RuleBundle

_packaged_yara_ctx_stack = None   # lazily-created; closed at process exit via atexit


def packaged_yara_rules_dir() -> "str | None":
    """
    Return the on-disk directory path of the packaged YARA rules
    (dumpex/rules_pkg/data/yara — the single copy shipped in the wheel, see
    pyproject.toml package-data), or None if not present.

    Resolved via importlib.resources rather than a __file__-relative path,
    so this is what actually keeps YARA scanning working for a `pip
    install dumpex` wheel with no rules/ directory anywhere near the
    invoking script, and for a PyInstaller EXE built with `--collect-data
    dumpex.rules_pkg`. importlib.resources.as_file() is a zero-cost
    passthrough when the package is already unpacked on disk, which is the
    case for both of those install forms. It is NOT relied on here for a
    zipapp/zip-safe install: as_file() extracting a whole directory out of
    a zip archive isn't reliably supported until Python 3.12, and this
    project's floor is 3.10 (see pyproject.toml's requires-python) — dumpex
    does not ship or test a zipapp build, so no claim is made about that
    path working.
    """
    global _packaged_yara_ctx_stack
    try:
        traversable = importlib.resources.files("dumpex.rules_pkg").joinpath("data", "yara")
    except (ModuleNotFoundError, FileNotFoundError, NotADirectoryError):
        return None
    try:
        if not traversable.is_dir():
            return None
    except Exception:
        return None
    if _packaged_yara_ctx_stack is None:
        _packaged_yara_ctx_stack = contextlib.ExitStack()
        atexit.register(_packaged_yara_ctx_stack.close)
    path = _packaged_yara_ctx_stack.enter_context(importlib.resources.as_file(traversable))
    return str(path)


def load_and_compile(rules_dir: str) -> RuleBundle:
    """
    Compile every .yar / .yara file in rules_dir independently.

    Returns a RuleBundle(rule_files, compile_failed, provenance):
      rule_files     — list of (filename, compiled_rules)
      compile_failed — count of files that could not be compiled at all
      provenance     — {"rules_dir": str, "files": [{"name", "sha256",
                        "compiled", "error"}, ...] sorted by name,
                        "aggregate_sha256": str, "compiled_ok": int,
                        "compile_failed": int}

    Compiling per-file means a syntax error in one file doesn't prevent the
    rest from running — but a file that never compiled also never
    contributed any rule to the scan, so it must count against scan
    coverage rather than just print a warning and vanish: a dump that would
    have matched that broken rule file's signatures must not come back
    NOT_DETECTED_IN_SCANNED_SCOPE as if the file's rules had actually run.

    Provenance is recorded for every candidate file (compiled or not),
    keyed by sorted filename so the recorded order is deterministic
    regardless of filesystem iteration order — see
    dumpex/hunt/yara_hunt/__init__.py's get_yara_provenance().
    """
    import yara, glob
    from dumpex.core.evidence import sha256_file

    loaded = []
    compile_failed = 0
    file_provenance = []
    patterns = [
        os.path.join(rules_dir, "*.yar"),
        os.path.join(rules_dir, "*.yara"),
    ]
    for pat in patterns:
        for path in sorted(glob.glob(pat)):
            fname = os.path.basename(path)
            try:
                file_sha256 = sha256_file(path)
            except OSError:
                file_sha256 = None
            try:
                compiled = yara.compile(filepath=path)
                loaded.append((fname, compiled))
                file_provenance.append({"name": fname, "sha256": file_sha256,
                                         "compiled": True, "error": None})
            except yara.SyntaxError as e:
                print(YELLOW(f"  [~] YARA syntax error in {fname}: {e}"))
                compile_failed += 1
                file_provenance.append({"name": fname, "sha256": file_sha256,
                                         "compiled": False, "error": str(e)})
            except Exception as e:
                print(YELLOW(f"  [~] Could not load {fname}: {e}"))
                compile_failed += 1
                file_provenance.append({"name": fname, "sha256": file_sha256,
                                         "compiled": False, "error": str(e)})

    file_provenance.sort(key=lambda f: f["name"])
    aggregate = hashlib.sha256()
    for f in file_provenance:
        aggregate.update(f["name"].encode("utf-8"))
        aggregate.update((f["sha256"] or "").encode("utf-8"))
    provenance = {
        "rules_dir":        rules_dir,
        "files":            file_provenance,
        "aggregate_sha256": aggregate.hexdigest(),
        "compiled_ok":      len(loaded),
        "compile_failed":   compile_failed,
    }
    return RuleBundle(rule_files=loaded, compile_failed=compile_failed, provenance=provenance)

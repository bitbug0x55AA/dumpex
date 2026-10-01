"""Release gate: a built dumpex executable must carry every dumpex module.

PyInstaller collects the modules it can reach by following imports from
the entry script. A module that nothing imports statically -- an owner
module the records package or `dumpex.core.memory` stopped importing, a
new package reached only through `importlib` -- is silently left out, and
the executable fails on the first command that needs it. This gate reads
the executable's own archive and requires every module of the source
`dumpex` package to be in it, except the ones `NOT_FROZEN` names.

It reads the archive; it does not run the executable. The decoder smoke
(`frozen_disasm_smoke.py`) is what proves the executable starts.

Deliberately NOT a pytest test: it tests a built artifact. It needs
PyInstaller installed (the release environment that built the artifact
has it) and the source checkout the artifact was built from.

Usage:
    python frozen_layout_smoke.py <path-to-dumpex-executable> [<dumpex-package-dir>]

The package directory defaults to the `dumpex` directory of the checkout
this script lives in.
"""
import os
import sys

# Modules of the source package that the executable does not carry, each
# with the reason it has no place in it. Every entry must name a module
# the source package really has.
NOT_FROZEN = {
    "dumpex.__main__": "the `python -m dumpex` entry point; the executable's entry "
                       "script is dumpex.py",
    "dumpex.schemas": "the output-contract schemas ship beside the executable as "
                      "release assets; no runtime code imports the package",
}

_DEFAULT_PACKAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir,
                                    "dumpex")


def _fail(message: str) -> None:
    print(f"FAIL: {message}")
    sys.exit(1)


def source_modules(package_dir: str) -> "set[str]":
    """Every module of the package rooted at `package_dir`, by dotted
    name: one per `.py` file, a package named by its directory. Byte-code
    caches are not modules."""
    package_dir = os.path.abspath(package_dir)
    root_name = os.path.basename(package_dir)
    modules = set()
    for directory, subdirs, files in os.walk(package_dir):
        subdirs[:] = sorted(d for d in subdirs if d != "__pycache__")
        relative = os.path.relpath(directory, package_dir)
        parts = [root_name] + ([] if relative == os.curdir else relative.split(os.sep))
        for name in files:
            if not name.endswith(".py"):
                continue
            stem = name[:-len(".py")]
            modules.add(".".join(parts if stem == "__init__" else parts + [stem]))
    return modules


def layout_problems(archived: "set[str]", modules: "set[str]") -> "list[str]":
    """What keeps an archive holding `archived` from carrying the package
    whose modules are `modules`: a module left out, or a `NOT_FROZEN`
    entry naming a module the package does not have."""
    problems = [f"{name} is not in the executable's archive"
                for name in sorted(modules - archived - set(NOT_FROZEN))]
    problems += [f"NOT_FROZEN names {name}, which the source package does not have"
                 for name in sorted(set(NOT_FROZEN) - modules)]
    return problems


def archived_names(executable: str) -> "set[str]":
    """Every entry of the executable's archive, the embedded module
    archive's module names included."""
    from PyInstaller.archive.readers import pkg_archive_contents

    return set(pkg_archive_contents(executable, recursive=True))


def main() -> None:
    if len(sys.argv) not in (2, 3):
        _fail("usage: frozen_layout_smoke.py <path-to-dumpex-executable> [<dumpex-package-dir>]")
    executable = sys.argv[1]
    package_dir = sys.argv[2] if len(sys.argv) == 3 else _DEFAULT_PACKAGE_DIR

    modules = source_modules(package_dir)
    if not modules:
        _fail(f"{package_dir} holds no Python modules")
    try:
        archived = archived_names(executable)
    except ImportError:
        _fail("PyInstaller is not installed; the archive cannot be read")
    except Exception as exc:  # any unreadable archive fails the gate
        _fail(f"could not read the archive of {executable}: {type(exc).__name__}: {exc}")

    problems = layout_problems(archived, modules)
    if problems:
        _fail(f"{executable} does not carry the dumpex package layout:\n  "
              + "\n  ".join(problems))
    carried = len(modules) - len(NOT_FROZEN)
    print(f"OK: {executable} carries all {carried} dumpex modules "
          f"(not frozen by design: {', '.join(sorted(NOT_FROZEN))})")


if __name__ == "__main__":
    main()

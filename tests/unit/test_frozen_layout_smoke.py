"""The release gate that the Windows executable carries the dumpex package
layout: every module of the source package is in the built artifact's
archive, except the modules the gate names as not frozen by design."""
import ast
import importlib.util
import pkgutil
from pathlib import Path

import pytest

import dumpex

_REPO_ROOT = Path(__file__).parents[2]
_BUILD_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "build.yml"
_PACKAGE_DIR = _REPO_ROOT / "dumpex"


def _load_smoke():
    """Import the gate by path. The release scripts are standalone by
    design and are never on sys.path."""
    path = _REPO_ROOT / "scripts" / "frozen_layout_smoke.py"
    spec = importlib.util.spec_from_file_location("frozen_layout_smoke", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def smoke():
    return _load_smoke()


@pytest.fixture(scope="module")
def modules(smoke):
    return smoke.source_modules(str(_PACKAGE_DIR))


def _run_main(smoke, monkeypatch, archived):
    monkeypatch.setattr(smoke, "archived_names", lambda executable: set(archived))
    monkeypatch.setattr(smoke.sys, "argv", ["frozen_layout_smoke.py", "dumpex.exe",
                                            str(_PACKAGE_DIR)])
    try:
        smoke.main()
    except SystemExit as exit_info:
        return exit_info.code
    return 0


# ── the release runs the gate against the built artifact ───────────────

def test_the_release_checks_the_built_executable_layout():
    workflow = _BUILD_WORKFLOW.read_text(encoding="utf-8")
    run = "python scripts/frozen_layout_smoke.py dist/dumpex.exe"
    assert run in workflow
    assert workflow.index("pyinstaller --onefile") < workflow.index(run)
    assert workflow.index(run) < workflow.index("Compress-Archive")


# ── what the source package holds ──────────────────────────────────────

def test_source_modules_are_the_modules_the_import_system_finds(modules):
    found = {"dumpex"}
    found.update(info.name for info in pkgutil.walk_packages(dumpex.__path__, "dumpex."))
    assert modules == found


def test_source_modules_include_every_records_and_memory_owner(modules):
    for package in ("dumpex.output.records", "dumpex.core.dumpfile", "dumpex.core.dumpquery"):
        owners = {name for name in modules if name.startswith(package + ".")}
        assert len(owners) > 1, package
    assert {"dumpex.core.memory", "dumpex.core.verdict", "dumpex.ui.memory_presentation",
            "dumpex.output.coverage"} <= modules


def test_source_modules_skip_byte_code_caches_and_non_python_files(smoke, tmp_path):
    package = tmp_path / "pkg"
    (package / "sub" / "__pycache__").mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "sub" / "__init__.py").write_text("")
    (package / "sub" / "owner.py").write_text("")
    (package / "sub" / "__pycache__" / "owner.py").write_text("")
    (package / "sub" / "data.json").write_text("{}")
    assert smoke.source_modules(str(package)) == {"pkg", "pkg.sub", "pkg.sub.owner"}


# ── the comparison ─────────────────────────────────────────────────────

def test_an_archive_holding_every_frozen_module_passes(smoke, modules):
    assert smoke.layout_problems(modules - set(smoke.NOT_FROZEN), modules) == []


@pytest.mark.parametrize("left_out", [
    "dumpex.output.records.hunt_scope",
    "dumpex.core.dumpfile.segments",
    "dumpex.core.dumpquery.threads",
    "dumpex.ui.memory_presentation",
])
def test_an_owner_module_left_out_of_the_archive_is_reported(smoke, modules, left_out):
    archived = modules - set(smoke.NOT_FROZEN) - {left_out}
    assert smoke.layout_problems(archived, modules) == [
        f"{left_out} is not in the executable's archive"]


def test_an_exclusion_naming_no_source_module_is_reported(smoke, modules, monkeypatch):
    monkeypatch.setitem(smoke.NOT_FROZEN, "dumpex.gone", "renamed")
    assert smoke.layout_problems(modules, modules) == [
        "NOT_FROZEN names dumpex.gone, which the source package does not have"]


def test_the_gate_exits_0_for_a_complete_archive(smoke, modules, monkeypatch, capsys):
    assert _run_main(smoke, monkeypatch, modules - set(smoke.NOT_FROZEN)) == 0
    assert capsys.readouterr().out.startswith("OK: dumpex.exe carries all ")


def test_the_gate_exits_1_for_an_archive_missing_an_owner(smoke, modules, monkeypatch, capsys):
    archived = modules - set(smoke.NOT_FROZEN) - {"dumpex.output.records.profile"}
    assert _run_main(smoke, monkeypatch, archived) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL: dumpex.exe does not carry the dumpex package layout")
    assert "dumpex.output.records.profile is not in the executable's archive" in out


# ── the exclusions hold for the reasons they state ─────────────────────

def _imported_modules(path: Path, package: str) -> "set[str]":
    """Every module `path` imports by absolute name, and every name an
    import-from binds, with relative imports resolved against `package`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = package.split(".")[:len(package.split(".")) - node.level + 1] \
                if node.level else []
            module = ".".join(base + ([node.module] if node.module else []))
            names.add(module)
            names.update(f"{module}.{alias.name}" for alias in node.names)
    return names


def test_no_runtime_module_imports_a_module_that_is_not_frozen(smoke, modules):
    # The executable's entry script and every module it can load.
    sources = {"Dumpex": _REPO_ROOT / "Dumpex.py"}
    for name in modules:
        relative = name.split(".")[1:]
        package_path = _PACKAGE_DIR.joinpath(*relative, "__init__.py")
        sources[name] = package_path if package_path.exists() \
            else _PACKAGE_DIR.joinpath(*relative).with_suffix(".py")
    importers = {}
    for name, path in sorted(sources.items()):
        package = name if path.name == "__init__.py" else name.rpartition(".")[0]
        for excluded in set(smoke.NOT_FROZEN) & _imported_modules(path, package):
            if excluded != name:
                importers.setdefault(excluded, []).append(name)
    assert importers == {}

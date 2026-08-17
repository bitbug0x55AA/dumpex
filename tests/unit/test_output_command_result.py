"""Unit tests for dumpex.output.command_result.CommandResult -- the
generic per-command return type replacing the ad hoc positional tuple
every recon command used to return."""
import ast
import pathlib

import pytest

import dumpex.output.command_result as command_result_mod
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import (
    CoverageReport, COVERAGE_COMPLETE, EXECUTION_COMPLETED, ExecutionStatus,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


_BANNED_LAYERS = ("dumpex.output.envelope", "dumpex.hunt")


def _is_banned(module: str) -> bool:
    return any(module == banned or module.startswith(banned + ".")
               for banned in _BANNED_LAYERS)


def _module_path(module: str) -> "pathlib.Path | None":
    """Source file for a first-party `dumpex.*` module, or None if the
    name is a package or an imported symbol rather than a module."""
    path = _REPO_ROOT.joinpath(*module.split(".")).with_suffix(".py")
    return path if path.is_file() else None


def _imports_of(module: str) -> "set[str]":
    """Every `dumpex.*` name `module` imports, read off the parsed AST.

    Taken from the AST rather than from lines that start with `import`/
    `from`, so an import nested in a function body, a `try:` block or a
    conditional counts exactly like a top-level one -- deferring an
    import does not undo the dependency. `importlib.import_module()` and
    `__import__()` string literals count too.
    """
    path = _module_path(module)
    if path is None:
        return set()
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            name = node.module or ""
            if node.level:                       # `from .coverage import X`
                package = module.rsplit(".", node.level)[0]
                name = f"{package}.{name}" if name else package
            if name:
                found.add(name)
                # `from dumpex.output import envelope` -- the submodule is
                # named by the alias, not by the module part.
                found.update(f"{name}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call):
            func = node.func
            called = getattr(func, "attr", None) or getattr(func, "id", None)
            if called in ("import_module", "__import__"):
                found.update(arg.value for arg in node.args
                             if isinstance(arg, ast.Constant) and isinstance(arg.value, str))
    return {name for name in found if name.startswith("dumpex")}


def test_command_result_module_does_not_import_envelope_or_hunt():
    # Regression guard for the P2 layering fix: this is a command/domain
    # model and must not depend on the wire-format layer (envelope.py) or
    # detection logic (dumpex.hunt.*) -- only on dumpex.output.coverage.
    # Read from the AST, not the source text, so the module's own
    # docstring naming envelope.py in prose is not a false positive and a
    # deferred/importlib import is not a false negative.
    offenders = sorted(name for name in _imports_of(command_result_mod.__name__)
                       if _is_banned(name))
    assert offenders == [], f"command_result.py imports the banned layer(s): {offenders}"


def test_command_result_does_not_reach_envelope_or_hunt_transitively():
    """The direct-import guard sees only this module's own text, so it
    stays green if command_result keeps importing records.py and
    records.py starts importing envelope.py -- the layering is just as
    broken, one hop further out. This walks the whole first-party import
    closure instead.

    Deliberately static rather than a `sys.modules` check after import:
    dumpex/output/__init__.py re-exports collector.V2Output, so importing
    ANY dumpex.output submodule loads envelope at runtime. That package
    re-export is not this module's dependency, and a runtime check could
    not tell the two apart.
    """
    start = command_result_mod.__name__
    seen, pending, via = {start}, [start], {}
    crossings = []
    while pending:
        current = pending.pop()
        for name in sorted(_imports_of(current)):
            via.setdefault(name, current)
            if _is_banned(name):
                # Record the boundary crossing but do NOT descend: what a
                # banned module imports in turn is its own business, and
                # walking it would bury the one real edge under its whole
                # downstream closure.
                crossings.append(name)
            elif name not in seen and _module_path(name) is not None:
                seen.add(name)
                pending.append(name)

    def _path_to(name: str) -> str:
        chain, node = [name], via.get(name)
        while node is not None and node != start:
            chain.append(node)
            node = via.get(node)
        chain.append(start)
        return " -> ".join(reversed(chain))

    assert crossings == [], ("command_result reaches a banned layer:\n  "
                            + "\n  ".join(_path_to(name) for name in sorted(set(crossings))))


def test_command_result_defaults():
    result = CommandResult(kind="modules", records=[],
                            coverage=CoverageReport(status=COVERAGE_COMPLETE))
    assert result.kind == "modules"
    assert result.records == []
    assert result.execution_status == EXECUTION_COMPLETED
    assert result.summary == {}
    assert result.diagnostics == []
    assert result.artifacts == []


def test_command_result_holds_arbitrary_record_type():
    class FakeRecord:
        pass

    records = [FakeRecord(), FakeRecord()]
    result = CommandResult(kind="modules", records=records,
                            coverage=CoverageReport(status=COVERAGE_COMPLETE),
                            summary={"count": 2})
    assert result.records is records
    assert result.summary == {"count": 2}


def test_command_result_mutable_defaults_are_not_shared_between_instances():
    r1 = CommandResult(kind="a", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE))
    r2 = CommandResult(kind="b", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE))
    r1.diagnostics.append("x")
    assert r2.diagnostics == []


def test_command_result_rejects_invalid_execution_status():
    with pytest.raises(ValueError, match="unknown execution status"):
        CommandResult(kind="modules", records=[],
                      coverage=CoverageReport(status=COVERAGE_COMPLETE),
                      execution_status="bogus")


def test_command_result_normalizes_bare_string_execution_status():
    result = CommandResult(kind="modules", records=[],
                            coverage=CoverageReport(status=COVERAGE_COMPLETE),
                            execution_status="partial")
    assert result.execution_status == ExecutionStatus.PARTIAL
    assert isinstance(result.execution_status, ExecutionStatus)

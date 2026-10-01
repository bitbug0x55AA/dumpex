"""
Layout of the `dumpex.output.records` package.

The package is a compatibility facade over owner modules, one per evidence
domain. The facade binds every supported name by an explicit import from
the module that defines it, and defines nothing itself. Owner modules
import only the lower-level owners they need -- never the facade, never a
hunter or command -- so the import graph between them is acyclic and every
owner is reachable by static import following (the frozen build collects
exactly what the facade imports).

The symbol-level contract (exports, fields, validation, serialization) is
held by the decomposition baseline; these tests hold the shape of the
package itself.
"""
import ast
import builtins
import dis
import enum
import importlib
import inspect
import pickle
import pkgutil
import subprocess
import sys
import types

import pytest

import dumpex.output.records as records

PACKAGE = "dumpex.output.records"
OWNERS = tuple(sorted(info.name for info in pkgutil.iter_modules(records.__path__, PACKAGE + ".")))

# The only dumpex modules outside the package an owner may import.
ALLOWED_EXTERNAL = {"dumpex.core.pe_utils", "dumpex.output.coverage"}

# Owners the records of more than one command build on. Every other owner
# belongs to one command domain (see _domain) and imports only these and
# owners of its own domain.
SHARED = {f"{PACKAGE}.{name}" for name in (
    "common", "diagnostics", "base", "extraction", "pe_observation", "stream_state")}


def _domain(module_name: str) -> str:
    short = module_name.rpartition(".")[2]
    if short.startswith("report_"):
        return "report"
    if short.startswith("hunt_"):
        return "hunt"
    if short in ("process", "process_pe"):
        return "process"
    if short in ("profile", "capabilities"):
        return "profile"
    return short


def _tree(module_name: str) -> ast.Module:
    return ast.parse(inspect.getsource(importlib.import_module(module_name)))


def _assigned_names(target) -> list:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _assigned_names(elt)]
    return []


def _definitions(source: str) -> set:
    """Every name `source` binds at top level by its own def, class or
    assignment -- imports excluded."""
    out = set()
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            out.update(n for t in node.targets for n in _assigned_names(t))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            out.update(_assigned_names(node.target))
    return out


def _defined(module_name: str) -> set:
    return _definitions(inspect.getsource(importlib.import_module(module_name)))


def _multiply_defined(sources: dict) -> list:
    """"name: [modules]" for every top-level name more than one of
    `sources` ({module: source text}) defines itself."""
    where = {}
    for module, source in sources.items():
        for name in _definitions(source):
            where.setdefault(name, []).append(module)
    return sorted(f"{name}: {sorted(mods)}" for name, mods in where.items() if len(mods) > 1)


def _package_sources() -> dict:
    return {m: inspect.getsource(importlib.import_module(m)) for m in (PACKAGE, *OWNERS)}


def _dumpex_imports(module_name: str) -> list:
    """(imported module, [names]) for every dumpex import anywhere in the
    module's source, function-level imports included."""
    out = []
    for node in ast.walk(_tree(module_name)):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"{module_name}: relative import"
            if node.module.split(".")[0] == "dumpex":
                out.append((node.module, [a.name for a in node.names]))
        elif isinstance(node, ast.Import):
            out += [(a.name, []) for a in node.names if a.name.split(".")[0] == "dumpex"]
    return out


def test_the_package_has_owner_modules():
    assert records.__path__ and len(OWNERS) > 1


# ── Facade ───────────────────────────────────────────────────────────────


def test_facade_binds_only_explicit_imports_from_owner_modules():
    body = _tree(PACKAGE).body
    assert isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
    for node in body[1:]:
        assert isinstance(node, ast.ImportFrom), ast.dump(node)[:80]
        assert node.level == 0 and node.module in OWNERS, node.module
        for alias in node.names:
            assert alias.name != "*", f"star import from {node.module}"
            assert alias.asname is None, f"{node.module}.{alias.name} rebound as {alias.asname}"


def test_facade_imports_every_owner_module():
    """Static import following from the facade reaches every owner, so a
    frozen build that follows imports carries the whole package."""
    imported = {node.module for node in _tree(PACKAGE).body if isinstance(node, ast.ImportFrom)}
    assert imported == set(OWNERS)


def test_every_facade_name_is_its_defining_owners_object():
    for node in _tree(PACKAGE).body[1:]:
        owner = importlib.import_module(node.module)
        defined = _defined(node.module)
        for alias in node.names:
            assert alias.name in defined, (
                f"{PACKAGE} imports {alias.name} from {node.module}, which does not define it")
            assert getattr(records, alias.name) is getattr(owner, alias.name)


def test_facade_names_resolve_through_every_supported_access_path():
    """`from dumpex.output.records import X`, `records.X` and the owner
    module's own attribute are one object; a class or function names the
    owner that defines it."""
    namespace = {}
    for node in _tree(PACKAGE).body[1:]:
        for alias in node.names:
            exec(f"from {PACKAGE} import {alias.name}", namespace)
            obj = namespace[alias.name]
            assert obj is getattr(records, alias.name)
            assert obj is getattr(importlib.import_module(node.module), alias.name)
            if inspect.isclass(obj) or inspect.isfunction(obj):
                assert obj.__module__ == node.module


# ── Owner modules ────────────────────────────────────────────────────────


def test_every_top_level_name_has_exactly_one_defining_module():
    """Owner definitions are pairwise disjoint and the facade defines
    nothing. Read from the source text, so a scalar budget or cap copied
    into a second owner as a local literal -- which object identity cannot
    tell from an import -- is reported with both owners."""
    sources = _package_sources()
    assert _definitions(sources[PACKAGE]) == set()
    assert _multiply_defined(sources) == []


def test_a_cap_redefined_as_a_local_literal_is_reported():
    sources = _package_sources()
    context = f"{PACKAGE}.report_context"
    assert "    ENRICHMENT_TEXT_CAP,\n" in sources[context]
    sources[context] = (sources[context].replace("    ENRICHMENT_TEXT_CAP,\n", "", 1)
                        + "\n\nENRICHMENT_TEXT_CAP = 200\n")
    assert _multiply_defined(sources) == [
        f"ENRICHMENT_TEXT_CAP: ['{PACKAGE}.common', '{context}']"]


def test_owner_modules_import_only_concrete_lower_level_owners():
    for owner in OWNERS:
        for module, names in _dumpex_imports(owner):
            assert module != PACKAGE, f"{owner} imports the facade"
            assert not module.startswith(("dumpex.hunt", "dumpex.commands")), (
                f"{owner} imports {module}")
            if module.startswith(PACKAGE + "."):
                assert module != owner
                defined = _defined(module)
                assert all(n in defined for n in names), (
                    f"{owner} imports {sorted(set(names) - defined)} from {module}, "
                    f"which does not define them")
            else:
                assert module in ALLOWED_EXTERNAL, f"{owner} imports {module}"


def test_owner_import_graph_is_acyclic():
    graph = {owner: {m for m, _ in _dumpex_imports(owner) if m in OWNERS} for owner in OWNERS}
    done, order = set(), []

    def visit(node, path):
        assert node not in path, "import cycle: " + " -> ".join([*path, node])
        if node in done:
            return
        for dep in sorted(graph[node]):
            visit(dep, (*path, node))
        done.add(node)
        order.append(node)

    for owner in OWNERS:
        visit(owner, ())
    assert len(order) == len(OWNERS)


def test_command_domains_import_only_the_shared_layer_and_themselves():
    """A --report record never pulls in --profile's or --process's owners,
    nor the reverse: what several commands build on lives in SHARED, and
    SHARED itself imports nothing outside SHARED."""
    crossings = []
    for owner in OWNERS:
        for module, _ in _dumpex_imports(owner):
            if module not in OWNERS or module in SHARED:
                continue
            if owner in SHARED or _domain(module) != _domain(owner):
                crossings.append(f"{owner} -> {module}")
    assert crossings == []


def _functions(module):
    for obj in vars(module).values():
        if inspect.isfunction(obj) and obj.__module__ == module.__name__:
            yield obj.__qualname__, obj
        elif inspect.isclass(obj) and obj.__module__ == module.__name__:
            for name, raw in vars(obj).items():
                if isinstance(raw, (staticmethod, classmethod)):
                    raw = raw.__func__
                elif isinstance(raw, property):
                    raw = raw.fget
                if inspect.isfunction(raw) and raw.__module__ == module.__name__:
                    yield f"{obj.__qualname__}.{name}", raw


def _global_loads(code: types.CodeType, into: set) -> None:
    for ins in dis.get_instructions(code):
        if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME"):
            into.add(ins.argval)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            _global_loads(const, into)


@pytest.mark.parametrize("owner", OWNERS)
def test_every_global_an_owner_function_loads_is_bound_in_that_owner(owner):
    """A name a moved function reads at call time must be bound in the
    module it now resolves globals in -- a missing import is otherwise
    only a NameError on the first call that reaches it."""
    module = importlib.import_module(owner)
    unbound = []
    for qualname, fn in _functions(module):
        loads = set()
        _global_loads(fn.__code__, loads)
        unbound += [f"{qualname}: {n}" for n in sorted(loads)
                    if n not in fn.__globals__ and not hasattr(builtins, n)]
    assert unbound == []


def _owner_closure(owner: str) -> list:
    """`owner` and every owner it imports, transitively."""
    seen, pending = set(), [owner]
    while pending:
        current = pending.pop()
        if current not in seen:
            seen.add(current)
            pending += [m for m, _ in _dumpex_imports(current) if m in OWNERS]
    return sorted(seen)


# Run in a fresh interpreter with a JSON argument {"package": ..., "stubs":
# {package: __path__}, "forbidden": [module prefixes], "cases": {owner:
# [expected owners]}}. For each owner: drop every dumpex module, install
# the stub packages (plain modules with the real __path__ and no __init__
# code), import the owner with builtins.open recording every call, and
# report which owners its import chain loaded, any loaded module under a
# forbidden prefix, and any file it opened.
_ISOLATED_IMPORT_SCRIPT = """
import builtins, importlib, io, json, sys, types
spec = json.loads(sys.argv[1])
failures = []
real_open = builtins.open
for owner, expected in spec["cases"].items():
    for key in [k for k in sys.modules if k == "dumpex" or k.startswith("dumpex.")]:
        del sys.modules[key]
    stubs = {}
    for name, path in spec["stubs"].items():
        stubs[name] = sys.modules[name] = types.ModuleType(name)
        stubs[name].__path__ = path
    opened = []
    def recording_open(*args, **kwargs):
        opened.append(str(args[0]) if args else "?")
        return real_open(*args, **kwargs)
    builtins.open = io.open = recording_open
    try:
        importlib.import_module(owner)
    except Exception as exc:
        failures.append(f"{owner}: {type(exc).__name__}: {exc}")
        continue
    finally:
        builtins.open = io.open = real_open
    if opened:
        failures.append(f"{owner}: importing it opened {opened}")
    if any(sys.modules.get(name) is not stub for name, stub in stubs.items()):
        failures.append(f"{owner}: a stubbed package __init__ ran")
    prefix = spec["package"] + "."
    loaded = sorted(k for k in sys.modules if k.startswith(prefix))
    if loaded != expected:
        failures.append(f"{owner}: loaded {loaded}, declares {expected}")
    reached = sorted(k for k in sys.modules for p in spec["forbidden"]
                     if k == p or k.startswith(p + "."))
    if reached:
        failures.append(f"{owner}: its import chain loads {reached}")
print(json.dumps(failures))
"""


# Module prefixes no owner's import chain may load, directly or through
# an allowed external module.
FORBIDDEN_TRANSITIVE = ("dumpex.hunt", "dumpex.commands")


def _import_owners_alone(owners, forbidden) -> list:
    import json
    import dumpex.output
    spec = {"package": PACKAGE,
            "stubs": {"dumpex.output": list(dumpex.output.__path__),
                      PACKAGE: list(records.__path__)},
            "forbidden": list(forbidden),
            "cases": {owner: _owner_closure(owner) for owner in owners}}
    result = subprocess.run([sys.executable, "-c", _ISOLATED_IMPORT_SCRIPT, json.dumps(spec)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_each_owner_module_imports_alone_with_only_its_own_dependencies():
    """Importing a submodule normally runs the package __init__ first, and
    the facade imports every owner. Here the facade and dumpex.output are
    empty stand-in packages, so each owner is imported through its own
    import chain alone: it must succeed, load exactly the owners it
    declares, transitively, load no hunter or command module -- through
    dumpex.core.pe_utils or dumpex.output.coverage as much as directly --
    and open no file."""
    assert _import_owners_alone(OWNERS, FORBIDDEN_TRANSITIVE) == []


def test_a_forbidden_module_reached_through_an_allowed_import_is_reported():
    """report_thread reaches dumpex.core.pe_utils only through its allowed
    external import; forbidding that prefix proves the transitive check
    sees modules an owner never names itself."""
    assert _import_owners_alone([f"{PACKAGE}.report_thread"], ("dumpex.core.pe_utils",)) == [
        f"{PACKAGE}.report_thread: its import chain loads ['dumpex.core.pe_utils']"]


# Run in a fresh interpreter with the module to import as its argument:
# import it with builtins.open and os.open recording every call, and print
# the files opened and every dumpex module then loaded.
_ENTRY_IMPORT_SCRIPT = """
import builtins, importlib, io, json, os, sys
real_open, real_os_open, opened = builtins.open, os.open, []
def recording_open(*args, **kwargs):
    opened.append(str(args[0]) if args else "?")
    return real_open(*args, **kwargs)
def recording_os_open(path, *args, **kwargs):
    opened.append(str(path))
    return real_os_open(path, *args, **kwargs)
builtins.open = io.open = recording_open
os.open = recording_os_open
try:
    importlib.import_module(sys.argv[1])
finally:
    builtins.open, io.open, os.open = real_open, real_open, real_os_open
print(json.dumps({"opened": opened,
                  "loaded": sorted(k for k in sys.modules if k.split(".")[0] == "dumpex")}))
"""


def test_importing_the_facade_opens_no_file_and_loads_no_hunter_or_command():
    import json
    result = subprocess.run([sys.executable, "-c", _ENTRY_IMPORT_SCRIPT, PACKAGE],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout)
    assert outcome["opened"] == []
    assert set(OWNERS) <= set(outcome["loaded"])
    assert [m for m in outcome["loaded"] if m.startswith(FORBIDDEN_TRANSITIVE)] == []


# ── Module-qualified lookup ──────────────────────────────────────────────


def test_pickles_naming_the_legacy_path_load_the_canonical_objects():
    """A pickle stream that names a class, enum or function by its
    `dumpex.output.records.<Name>` path loads the owner's object."""
    legacy_class = b"cdumpex.output.records\nThreadRecord\n."
    assert pickle.loads(legacy_class) is records.ThreadRecord
    legacy_member = b"cdumpex.output.records\nStreamParserState\n(Vparsed\ntR."
    assert pickle.loads(legacy_member) is records.StreamParserState.PARSED
    legacy_function = b"cdumpex.output.records\nhex_address\n."
    assert pickle.loads(legacy_function) is records.hex_address


def test_record_instances_round_trip_through_pickle():
    section = records.EnrichmentSection(
        name="environment", scope=records.ENRICHMENT_SCOPE_PROCESS,
        status=records.ENRICHMENT_COMPLETE, total=0, included=0, cap=8, truncated=False)
    for value in (section, records.CapabilityStatus.LIMITED,
                  records.Diagnostic(severity=records.SEVERITY_WARNING, message="m")):
        loaded = pickle.loads(pickle.dumps(value))
        assert loaded == value and type(loaded) is type(value)
        if isinstance(value, enum.Enum):
            assert loaded is value


# ── Packaging ────────────────────────────────────────────────────────────


def test_setuptools_discovers_the_records_package():
    """pyproject.toml's `packages.find` (include = ["dumpex*"]) ships the
    package and so every owner module in it."""
    setuptools = pytest.importorskip("setuptools")
    from tests.fixtures.decomposition_baseline import REPO_ROOT
    assert PACKAGE in setuptools.find_packages(REPO_ROOT, include=["dumpex*"])


def test_the_package_smoke_accepts_the_records_layout(capsys):
    from scripts import package_smoke
    package_smoke.validate_records_package()
    assert f"{len(OWNERS)} owner modules" in capsys.readouterr().out

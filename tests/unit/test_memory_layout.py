"""
Layout of `dumpex.core.memory` and the owner modules in
`dumpex.core.dumpfile` that hold its loader, stream parsers,
stream-state observation and captured-range access.

`dumpex.core.memory` stays the legacy import path. Every owner-defined
name it supports is bound there by an explicit import of the owner's own
object. Where a test replaces a name on the legacy path (a parser class,
cap, cache or reader), the consumer that must observe the replacement is
a small delegating entry point defined in `dumpex.core.memory`, which
passes that name to the owner at call time; no owner function reads such
a name as a global of its own. Owner modules never import the legacy
module, a hunter, a command, the records package or the console layer,
their import graph is acyclic, and importing one opens no file and
creates no mutable module state.

The symbol-level contract and the patch-seam checks are held by the
decomposition baseline; these tests hold the shape of the layout itself.
"""
import ast
import builtins
import dis
import importlib
import inspect
import json
import pkgutil
import subprocess
import sys
import types

import pytest
from minidump.constants import MINIDUMP_STREAM_TYPE

import dumpex.core.dumpfile as dumpfile
import dumpex.core.memory as memory
from tests.fixtures.decomposition_baseline import MEMORY, capture
from tests.fixtures.decomposition_baseline.consumers import scan_legacy_rebinds
from tests.fixtures.decomposition_baseline.stable import load_golden
from tests.fixtures.minidump_bytes import (
    HANDLE_DATA, DumpSpec, ModuleSpec, RawStreamSpec, write_minidump)

PACKAGE = "dumpex.core.dumpfile"
OWNERS = tuple(sorted(info.name for info in pkgutil.iter_modules(dumpfile.__path__, PACKAGE + ".")))

# The only dumpex module outside the package an owner may import.
ALLOWED_EXTERNAL = {"dumpex.output.coverage"}

# Module prefixes no owner's import chain may load, directly or through an
# allowed external module.
FORBIDDEN_TRANSITIVE = ("dumpex.core.memory", "dumpex.hunt", "dumpex.commands", "dumpex.ui",
                        "dumpex.output.records")


def _tree(module_name: str) -> ast.Module:
    return ast.parse(inspect.getsource(importlib.import_module(module_name)))


def _assigned_names(target) -> list:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _assigned_names(elt)]
    return []


def _definitions(module_name: str) -> set:
    """Every name the module's source binds at top level by its own def,
    class or assignment -- imports excluded."""
    out = set()
    for node in _tree(module_name).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            out.update(n for t in node.targets for n in _assigned_names(t))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            out.update(_assigned_names(node.target))
    return out


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


def test_the_package_has_owner_modules():
    assert len(OWNERS) > 1


def test_the_package_init_binds_nothing():
    """Importing one owner runs the package __init__ first; it binds
    nothing, so an owner loads only what it declares."""
    body = _tree(PACKAGE).body
    assert len(body) == 1
    assert isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)


# ── The legacy entry point ───────────────────────────────────────────────


def _facade_owner_imports() -> list:
    return [node for node in _tree(MEMORY).body
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(PACKAGE + ".")]


def test_the_legacy_module_imports_every_owner_module():
    """Static import following from the legacy path reaches every owner,
    so a frozen build that follows imports carries all of them."""
    assert {node.module for node in _facade_owner_imports()} == set(OWNERS)


def test_every_owner_name_the_legacy_module_binds_is_the_owners_object():
    for node in _facade_owner_imports():
        owner = importlib.import_module(node.module)
        defined = _definitions(node.module)
        for alias in node.names:
            assert alias.name != "*", f"star import from {node.module}"
            assert alias.asname is None, f"{node.module}.{alias.name} rebound as {alias.asname}"
            assert alias.name in defined, (
                f"{MEMORY} imports {alias.name} from {node.module}, which does not define it")
            assert getattr(memory, alias.name) is getattr(owner, alias.name)


def test_every_top_level_name_has_exactly_one_defining_module():
    """Read from the source text, so a cap or budget copied into a second
    module as an equal literal -- which object identity cannot tell from
    an import -- is reported with both modules."""
    where = {}
    for module in (MEMORY, *OWNERS):
        for name in _definitions(module):
            where.setdefault(name, []).append(module)
    assert sorted(f"{n}: {m}" for n, m in where.items() if len(m) > 1) == []


def test_stream_dispatch_parses_through_the_legacy_entry_points():
    """open_dump() hands the dispatch table to the loader, so the two
    dumpex-owned parsers it runs are the legacy module's entry points --
    the ones that read this module's caps and layout cache."""
    dispatch = memory._STREAM_DISPATCH
    assert dispatch[MINIDUMP_STREAM_TYPE.HandleDataStream] == ("handles", memory.parse_handle_stream)
    assert dispatch[MINIDUMP_STREAM_TYPE.ThreadInfoListStream] == (
        "thread_info", memory.parse_thread_info_stream)


# ── Owner modules ────────────────────────────────────────────────────────


def test_owner_modules_import_only_lower_level_owners_and_coverage():
    for owner in OWNERS:
        for module, names in _dumpex_imports(owner):
            assert module != MEMORY, f"{owner} imports the legacy module"
            if module.startswith(PACKAGE + "."):
                assert module != owner
                defined = _definitions(module)
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


def _legacy_replaced_names() -> set:
    """Every name tests replace on the legacy module: the committed seam
    inventory and the live scan of the test files."""
    committed = load_golden(capture.SEAMS)["legacy_patch_targets"].get(MEMORY, [])
    return set(committed) | set(scan_legacy_rebinds().get(MEMORY, {}))


@pytest.mark.parametrize("owner", OWNERS)
def test_no_owner_function_reads_a_name_tests_replace_on_the_legacy_module(owner):
    """A replacement on `dumpex.core.memory` reaches only code that reads
    the name there. An owner function that read such a name as its own
    global would silently bypass it; the legacy entry point passes the
    name in instead."""
    replaced = _legacy_replaced_names()
    module = importlib.import_module(owner)
    bypassing = []
    for qualname, fn in _functions(module):
        loads = set()
        _global_loads(fn.__code__, loads)
        bypassing += [f"{qualname}: {n}" for n in sorted(loads & replaced) if n in fn.__globals__]
    assert bypassing == []


def test_a_legacy_replaced_name_read_by_an_owner_is_reported():
    """The guard above sees a replaced name an owner function loads."""
    replaced = _legacy_replaced_names()
    assert "MAX_HANDLE_DESCRIPTORS" in replaced
    namespace = {"MAX_HANDLE_DESCRIPTORS": 1}
    exec("def cap():\n    return MAX_HANDLE_DESCRIPTORS\n", namespace)
    loads = set()
    _global_loads(namespace["cap"].__code__, loads)
    assert loads & replaced == {"MAX_HANDLE_DESCRIPTORS"}


@pytest.mark.parametrize("owner", OWNERS)
def test_every_global_an_owner_function_loads_is_bound_in_that_owner(owner):
    module = importlib.import_module(owner)
    unbound = []
    for qualname, fn in _functions(module):
        loads = set()
        _global_loads(fn.__code__, loads)
        unbound += [f"{qualname}: {n}" for n in sorted(loads)
                    if n not in fn.__globals__ and not hasattr(builtins, n)]
    assert unbound == []


_IMMUTABLE = (type(None), bool, int, float, str, bytes, frozenset)


def _immutable(value) -> bool:
    if isinstance(value, tuple):
        return all(_immutable(v) for v in value)
    return isinstance(value, _IMMUTABLE)


@pytest.mark.parametrize("owner", OWNERS)
def test_owner_modules_hold_no_mutable_module_state(owner):
    """Caches and other process-lifetime state stay where the baseline
    keeps them (the handle-descriptor layout cache is
    dumpex.core.memory._HANDLE_DESCRIPTOR_LAYOUT_CACHE; the segment index
    is memoized on each dump object): every value an owner module binds
    at top level is immutable."""
    module = importlib.import_module(owner)
    mutable = [name for name in _definitions(owner)
               if not (inspect.isclass(getattr(module, name)) or inspect.isfunction(getattr(module, name)))
               and not _immutable(getattr(module, name))]
    assert mutable == []


# Run in a fresh interpreter with a JSON argument {"package": ...,
# "stubs": {package: __path__}, "forbidden": [module prefixes], "cases":
# {owner: [expected owners]}}. For each owner: drop every dumpex module,
# install the stub packages (plain modules with the real __path__ and no
# __init__ code), import the owner with builtins.open recording every
# call, and report which owners its import chain loaded, any loaded module
# under a forbidden prefix, and any file it opened.
_ISOLATED_IMPORT_SCRIPT = """
import builtins, importlib, io, json, sys, types
import minidump.minidumpfile
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
    if opened:
        failures.append(f"{owner}: importing it opened {opened}")
print(json.dumps(failures))
"""


def _owner_closure(owner: str) -> list:
    seen, pending = set(), [owner]
    while pending:
        current = pending.pop()
        if current not in seen:
            seen.add(current)
            pending += [m for m, _ in _dumpex_imports(current) if m in OWNERS]
    return sorted(seen)


def _import_owners_alone(owners, forbidden) -> list:
    import dumpex.core
    import dumpex.output
    spec = {"package": PACKAGE,
            "stubs": {"dumpex.core": list(dumpex.core.__path__),
                      "dumpex.output": list(dumpex.output.__path__),
                      PACKAGE: list(dumpfile.__path__)},
            "forbidden": list(forbidden),
            "cases": {owner: _owner_closure(owner) for owner in owners}}
    result = subprocess.run([sys.executable, "-c", _ISOLATED_IMPORT_SCRIPT, json.dumps(spec)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_each_owner_module_imports_alone_with_only_its_own_dependencies():
    """Each owner is imported through its own import chain alone, with
    dumpex.core, dumpex.output and the owner package as empty stand-ins:
    it must succeed, load exactly the owners it declares, transitively,
    load no legacy, hunter, command, records or console module -- through
    dumpex.output.coverage as much as directly -- and open no file."""
    assert _import_owners_alone(OWNERS, FORBIDDEN_TRANSITIVE) == []


def test_a_forbidden_module_reached_through_an_allowed_import_is_reported():
    """stream_state reaches dumpex.output.coverage only through its
    allowed import; forbidding that prefix proves the transitive check
    sees modules an owner never names itself."""
    owner = f"{PACKAGE}.stream_state"
    assert _import_owners_alone([owner], ("dumpex.output.coverage",)) == [
        f"{owner}: its import chain loads ['dumpex.output.coverage']"]


# ── Behaviour the delegation preserves ───────────────────────────────────


def _handle_stream_body(count: int) -> bytes:
    import struct
    return struct.pack("<IIII", 16, 32, count, 0) + b"\x00" * (32 * count)


def test_a_legacy_handle_cap_reaches_the_loader_path(tmp_path, monkeypatch):
    """The cap a test sets on the legacy module bounds the handle stream
    open_dump() parses, and the shortfall is reported, not dropped."""
    monkeypatch.setattr(memory, "MAX_HANDLE_DESCRIPTORS", 2)
    path = write_minidump(tmp_path / "handles.dmp", DumpSpec(
        modules=(ModuleSpec(0x400000, 0x1000, "a.exe"),),
        raw_streams=(RawStreamSpec(HANDLE_DATA, _handle_stream_body(3)),)))
    mf = memory.open_dump(path)
    try:
        assert memory.stream_failure(mf, MINIDUMP_STREAM_TYPE.HandleDataStream) is None
        assert len(memory.get_handles(mf)) == 2
        assert memory.declared_descriptor_count(mf.handles) == 3
        assert memory.truncated_descriptor_count(mf.handles) == 1
    finally:
        mf.file_handle.close()


class _Directory:
    def __init__(self, data_size):
        self.Location = types.SimpleNamespace(Rva=0, DataSize=data_size)


def test_handle_layout_is_derived_only_after_the_stream_framing_is_checked(monkeypatch):
    """A stream too small for its own header fails on its framing even
    when the descriptor layout cannot be derived."""
    import io
    monkeypatch.setattr(memory, "_HANDLE_DESCRIPTOR_LAYOUT_CACHE", None)
    monkeypatch.setattr(memory, "_descriptor_class_size", lambda cls: 32)
    with pytest.raises(memory.HandleStreamFramingError):
        memory.parse_handle_stream(_Directory(8), io.BytesIO(b"\x00" * 8))
    assert memory._HANDLE_DESCRIPTOR_LAYOUT_CACHE is None


def test_the_handle_layout_cache_lives_on_the_legacy_module(monkeypatch):
    """Derived once, on first use, into dumpex.core.memory's own cache; a
    failed derivation caches nothing."""
    import io
    monkeypatch.setattr(memory, "_HANDLE_DESCRIPTOR_LAYOUT_CACHE", None)
    body = _handle_stream_body(1)
    parsed = memory.parse_handle_stream(_Directory(len(body)), io.BytesIO(body))
    assert len(parsed.handles) == 1
    assert memory._HANDLE_DESCRIPTOR_LAYOUT_CACHE == (32, 40)
    monkeypatch.setattr(memory, "_HANDLE_DESCRIPTOR_LAYOUT_CACHE", None)
    monkeypatch.setattr(memory, "_descriptor_class_size", lambda cls: 32)
    with pytest.raises(memory.HandleDescriptorLayoutError):
        memory._handle_descriptor_layout()
    assert memory._HANDLE_DESCRIPTOR_LAYOUT_CACHE is None


def _refusing_segment_table(mf):
    raise AssertionError("the segment table was consulted")


@pytest.mark.parametrize("va, size", [(0, 0x10), (0x1000, 0), (0x1000, -1)])
def test_empty_address_ranges_never_consult_the_segment_table(monkeypatch, va, size):
    monkeypatch.setattr(memory, "_memory_segments", _refusing_segment_table)
    mf = types.SimpleNamespace()
    assert memory.va_range_captured_bytes(mf, va, size) == 0
    if not va:
        assert memory.va_to_file_offset(mf, va) is None


def test_a_missing_dump_is_reported_by_the_legacy_entry_point(tmp_path, capsys):
    from dumpex.core.dumpfile.loader import DumpFileNotFoundError, load_minidump
    path = str(tmp_path / "absent.dmp")
    with pytest.raises(DumpFileNotFoundError) as raised:
        load_minidump(path, stream_dispatch={}, context=None, wow64_context=None, peb=None)
    assert raised.value.path == path
    with pytest.raises(SystemExit) as exited:
        memory.open_dump(path)
    assert exited.value.code == 1
    assert f"[!] File not found: {path}" in capsys.readouterr().out


def test_an_unreadable_header_carries_its_cause(tmp_path, capsys):
    from dumpex.core.dumpfile.loader import DumpFormatError, load_minidump
    path = tmp_path / "not_a_dump.dmp"
    path.write_bytes(b"MZ" + b"\x00" * 64)
    with pytest.raises(DumpFormatError) as raised:
        load_minidump(str(path), stream_dispatch={}, context=None, wow64_context=None, peb=None)
    cause = raised.value.cause
    assert raised.value.__cause__ is cause and raised.value.path == str(path)
    with pytest.raises(SystemExit) as exited:
        memory.open_dump(str(path))
    assert exited.value.code == 1
    out = capsys.readouterr().out
    assert f"as a minidump file: {type(cause).__name__}: {cause}" in out
    assert "The file may be corrupted, truncated, or not a Windows minidump (.dmp) at all." in out


# ── Packaging ────────────────────────────────────────────────────────────


def test_setuptools_discovers_the_owner_package():
    setuptools = pytest.importorskip("setuptools")
    from tests.fixtures.decomposition_baseline import REPO_ROOT
    assert PACKAGE in setuptools.find_packages(REPO_ROOT, include=["dumpex*"])


def test_the_package_smoke_accepts_the_memory_layout(capsys):
    from scripts import package_smoke
    package_smoke.validate_memory_owner_modules()
    assert f"{len(OWNERS)} owner modules" in capsys.readouterr().out

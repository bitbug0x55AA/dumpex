"""
Layout of `dumpex.core.memory` and the owner modules that hold its
implementation: `dumpex.core.dumpfile` (loader, stream parsers,
stream-state observation, captured-range access), `dumpex.core.dumpquery`
(thread interpretation, lookups, string search), `dumpex.core.verdict`
(verdict tiers) and `dumpex.ui.memory_presentation` (console text).

`dumpex.core.memory` stays the legacy import path. Every owner-defined
name it supports is bound there by an explicit import of the owner's own
object. Where a test replaces a name on the legacy path (a parser class,
cap, cache, reader or thread interpretation), the consumer that must
observe the replacement is a small delegating entry point defined in
`dumpex.core.memory`, which passes that name to the owner at call time; no
owner function reads such a name as a global of its own. Owner modules
never import the legacy module, a hunter, a command or the records
package; only the presentation owner imports the console layer; each
owner imports only owners of its own layer or a lower one, their import
graph is acyclic, and importing one opens no file and creates no mutable
module state.

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

import dumpex.core.memory as memory
from tests.fixtures.decomposition_baseline import MEMORY, capture
from tests.fixtures.decomposition_baseline.consumers import scan_legacy_rebinds
from tests.fixtures.decomposition_baseline.stable import load_golden
from tests.fixtures.minidump_bytes import (
    HANDLE_DATA, DumpSpec, ModuleSpec, RawStreamSpec, write_minidump)

DUMPFILE = "dumpex.core.dumpfile"
DUMPQUERY = "dumpex.core.dumpquery"
PACKAGES = (DUMPFILE, DUMPQUERY)
VERDICT = "dumpex.core.verdict"
PRESENTATION = "dumpex.ui.memory_presentation"


def _package_owners(package: str) -> tuple:
    path = importlib.import_module(package).__path__
    return tuple(sorted(info.name for info in pkgutil.iter_modules(path, package + ".")))


DUMPFILE_OWNERS = _package_owners(DUMPFILE)
DUMPQUERY_OWNERS = _package_owners(DUMPQUERY)
OWNERS = tuple(sorted((*DUMPFILE_OWNERS, *DUMPQUERY_OWNERS, VERDICT, PRESENTATION)))

# The dumpex modules each owner may import: owners of its own layer or a
# lower one, and the named modules outside the family. File access is the
# lowest layer, interpretation of a loaded dump sits on it, verdict policy
# stands alone, and presentation formats verdicts with the console colors.
ALLOWED_IMPORTS = {
    **{owner: {*DUMPFILE_OWNERS, "dumpex.output.coverage"} for owner in DUMPFILE_OWNERS},
    **{owner: {*DUMPFILE_OWNERS, *DUMPQUERY_OWNERS} for owner in DUMPQUERY_OWNERS},
    VERDICT: set(),
    PRESENTATION: {VERDICT, "dumpex.ui.colors"},
}

# Module prefixes no owner's import chain may load, directly or through an
# allowed import.
_NEVER = ("dumpex.core.memory", "dumpex.hunt", "dumpex.commands", "dumpex.output.records")
FORBIDDEN_TRANSITIVE = {
    **{owner: (*_NEVER, "dumpex.ui", DUMPQUERY, VERDICT) for owner in DUMPFILE_OWNERS},
    **{owner: (*_NEVER, "dumpex.ui", VERDICT) for owner in DUMPQUERY_OWNERS},
    VERDICT: (*_NEVER, "dumpex.ui", DUMPFILE, DUMPQUERY),
    PRESENTATION: (*_NEVER, DUMPFILE, DUMPQUERY),
}

# Tables whose baseline type is a dict. They are read-only vocabularies no
# code writes to; every other value an owner binds is immutable.
_CONSTANT_DICTS = {(f"{DUMPQUERY}.strings", "IOC_STRING_ENCODING_WIDTHS"),
                   (VERDICT, "INDICATOR_DIMS")}


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


def test_every_owner_has_import_rules():
    assert set(ALLOWED_IMPORTS) == set(FORBIDDEN_TRANSITIVE) == set(OWNERS)


@pytest.mark.parametrize("package", PACKAGES)
def test_the_package_has_owner_modules(package):
    assert len(_package_owners(package)) > 1


@pytest.mark.parametrize("package", PACKAGES)
def test_the_package_init_binds_nothing(package):
    """Importing one owner runs the package __init__ first; it binds
    nothing, so an owner loads only what it declares."""
    body = _tree(package).body
    assert len(body) == 1
    assert isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)


# ── The legacy entry point ───────────────────────────────────────────────


def _facade_owner_imports() -> list:
    return [node for node in _tree(MEMORY).body
            if isinstance(node, ast.ImportFrom) and node.module in OWNERS]


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


@pytest.mark.parametrize("owner", OWNERS)
def test_owner_modules_import_only_their_own_or_lower_layers(owner):
    for module, names in _dumpex_imports(owner):
        assert module != MEMORY, f"{owner} imports the legacy module"
        assert module != owner
        assert module in ALLOWED_IMPORTS[owner], f"{owner} imports {module}"
        if module in OWNERS:
            defined = _definitions(module)
            assert all(n in defined for n in names), (
                f"{owner} imports {sorted(set(names) - defined)} from {module}, "
                f"which does not define them")


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
    at top level is immutable, except the read-only vocabulary tables the
    baseline contract fixes as dicts."""
    module = importlib.import_module(owner)
    mutable = [name for name in _definitions(owner)
               if not (inspect.isclass(getattr(module, name)) or inspect.isfunction(getattr(module, name)))
               and not _immutable(getattr(module, name))
               and (owner, name) not in _CONSTANT_DICTS]
    assert mutable == []


def test_the_constant_dicts_are_owner_values():
    for owner, name in _CONSTANT_DICTS:
        assert name in _definitions(owner)
        assert isinstance(getattr(importlib.import_module(owner), name), dict)


_DICT_MUTATORS = {"__setitem__", "__delitem__", "__ior__", "update", "pop", "popitem",
                  "setdefault", "clear"}


def _names(node, names) -> bool:
    return ((isinstance(node, ast.Name) and node.id in names)
            or (isinstance(node, ast.Attribute) and node.attr in names))


def _constant_dict_writes(tree: ast.AST, names) -> list:
    """(line, name) for every statement that writes to one of `names` in
    place, reached by its own name or as a module attribute: an item
    store or delete, an augmented assignment, a mutating method call, or
    a rebinding of the module attribute. A write through an alias bound to
    another name is out of reach of a source scan."""
    found = []
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, (ast.Assign, ast.Delete)):
            targets = node.targets
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Subscript) and _names(target.value, names):
                found.append((node.lineno, _written(target.value)))
            elif isinstance(target, ast.Attribute) and _names(target, names):
                found.append((node.lineno, target.attr))
            elif isinstance(node, ast.AugAssign) and _names(target, names):
                found.append((node.lineno, _written(target)))
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _DICT_MUTATORS and _names(node.func.value, names)):
            found.append((node.lineno, _written(node.func.value)))
    return found


def _written(node) -> str:
    return node.id if isinstance(node, ast.Name) else node.attr


def test_no_shipped_code_writes_to_a_constant_dict():
    """The two vocabulary tables stay dicts for the baseline contract; no
    production or script file writes to them, so every console and JSON
    rendering reads the values their owner defines."""
    from tests.fixtures.decomposition_baseline import REPO_ROOT
    from tests.fixtures.decomposition_baseline.consumers import category, python_files
    names = {name for _, name in _CONSTANT_DICTS}
    writes = []
    for relpath in python_files():
        if category(relpath) == "tests":
            continue
        with open(f"{REPO_ROOT}/{relpath}", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        writes += [f"{relpath}:{line}: {name}" for line, name in _constant_dict_writes(tree, names)]
    assert writes == []


def test_a_write_to_a_constant_dict_is_reported():
    sample = ast.parse(
        "from dumpex.core.memory import INDICATOR_DIMS\n"
        "import dumpex.core.memory as memory\n"
        "INDICATOR_DIMS['x'] = 'y'\n"
        "del memory.INDICATOR_DIMS['rwx_private']\n"
        "INDICATOR_DIMS |= {'z': 'w'}\n"
        "memory.IOC_STRING_ENCODING_WIDTHS.update(UTF32=4)\n"
        "memory.INDICATOR_DIMS = {}\n"
        "dims = dict(INDICATOR_DIMS)\n"
        "dims['x'] = 'y'\n")
    names = {name for _, name in _CONSTANT_DICTS}
    assert sorted(_constant_dict_writes(sample, names)) == [
        (3, "INDICATOR_DIMS"), (4, "INDICATOR_DIMS"), (5, "INDICATOR_DIMS"),
        (6, "IOC_STRING_ENCODING_WIDTHS"), (7, "INDICATOR_DIMS")]


# Run in a fresh interpreter with a JSON argument {"owners": [every
# owner], "stubs": {package: __path__}, "cases": {owner: {"expected":
# [expected owners], "forbidden": [module prefixes]}}}. For each owner:
# drop every dumpex module,
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
for owner, case in spec["cases"].items():
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
    loaded = sorted(k for k in sys.modules if k in spec["owners"])
    if loaded != case["expected"]:
        failures.append(f"{owner}: loaded {loaded}, declares {case['expected']}")
    reached = sorted(k for k in sys.modules for p in case["forbidden"]
                     if k not in stubs and (k == p or k.startswith(p + ".")))
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


def _import_owners_alone(forbidden: dict) -> list:
    """`forbidden` maps each owner to import to its forbidden prefixes."""
    stubs = {name: list(importlib.import_module(name).__path__)
             for name in ("dumpex.core", "dumpex.output", "dumpex.ui", *PACKAGES)}
    spec = {"owners": list(OWNERS), "stubs": stubs,
            "cases": {owner: {"expected": _owner_closure(owner), "forbidden": list(prefixes)}
                      for owner, prefixes in forbidden.items()}}
    result = subprocess.run([sys.executable, "-c", _ISOLATED_IMPORT_SCRIPT, json.dumps(spec)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_each_owner_module_imports_alone_with_only_its_own_dependencies():
    """Each owner is imported through its own import chain alone, with
    dumpex.core, dumpex.output, dumpex.ui and the owner packages as empty
    stand-ins: it must succeed, load exactly the owners it declares,
    transitively, load no module its layer forbids -- the legacy module, a
    hunter, a command, the records package, a higher layer, and the
    console layer everywhere but in presentation -- through an allowed
    import as much as directly, and open no file."""
    assert _import_owners_alone(FORBIDDEN_TRANSITIVE) == []


def test_a_forbidden_module_reached_through_an_allowed_import_is_reported():
    """stream_state reaches dumpex.output.coverage only through its
    allowed import; forbidding that prefix proves the transitive check
    sees modules an owner never names itself."""
    owner = f"{DUMPFILE}.stream_state"
    assert _import_owners_alone({owner: ("dumpex.output.coverage",)}) == [
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


def _tripwire(name):
    def refuse(*args, **kwargs):
        raise AssertionError(f"{name} was consulted")
    return refuse


@pytest.mark.parametrize("record", [None, memory.RawThreadInfo(7)], ids=["none", "placeholder"])
def test_a_missing_thread_record_never_reads_dump_flags(monkeypatch, record):
    """The record-presence test comes first; a missing record has no
    DumpFlags to read."""
    monkeypatch.setattr(memory, "dump_flags_value", _tripwire("dump_flags_value"))
    assert memory.dump_flags_state(record) == memory.DUMP_FLAGS_ABSENT
    assert memory.recorded_start_address(record) == (None, memory.START_ADDRESS_ABSENT)
    assert memory.ip_context_conflict_for(0x401000, record) is None


def test_a_thread_without_a_captured_ip_consults_nothing(monkeypatch):
    monkeypatch.setattr(memory, "_is_real_thread_info", _tripwire("_is_real_thread_info"))
    monkeypatch.setattr(memory, "dump_flags_value", _tripwire("dump_flags_value"))
    assert memory.ip_context_conflict_for(None, object()) is False


def test_the_thread_join_reads_records_before_contexts(monkeypatch):
    calls = []

    def infos(mf):
        calls.append("get_thread_infos")
        return []

    def contexts(mf):
        calls.append("get_thread_contexts")
        return [{"ThreadId": 7, "ip": 0x10, "ip_reg": "RIP", "is_wow64": False}]

    def start(record):
        calls.append("recorded_start_address")
        return None, memory.START_ADDRESS_ABSENT

    def conflict(ip, record):
        calls.append("ip_context_conflict_for")
        return None

    monkeypatch.setattr(memory, "get_thread_infos", infos)
    monkeypatch.setattr(memory, "get_thread_contexts", contexts)
    monkeypatch.setattr(memory, "recorded_start_address", start)
    monkeypatch.setattr(memory, "ip_context_conflict_for", conflict)
    joined = memory.enriched_thread_contexts(types.SimpleNamespace())
    assert calls == ["get_thread_infos", "get_thread_contexts",
                     "recorded_start_address", "ip_context_conflict_for"]
    assert joined == [{"ThreadId": 7, "ip": 0x10, "ip_reg": "RIP", "is_wow64": False,
                       "start_address": None, "start_address_state": memory.START_ADDRESS_ABSENT,
                       "ip_context_conflict": None}]


class _NoMemoryInfo:
    @property
    def memory_info(self):
        raise AssertionError("the memory-info stream was consulted")


def test_an_explicit_read_size_never_consults_the_memory_info_stream():
    assert memory._resolve_size(_NoMemoryInfo(), 0x1000, 0x20) == 0x20
    assert memory._resolve_size(_NoMemoryInfo(), 0x1000, 0) == 0


def _reordered_entry_points(monkeypatch):
    """Replace the thread entry points with versions that consult the
    legacy names out of order, then behave like the real ones."""
    real = {name: getattr(memory, name) for name in (
        "dump_flags_state", "recorded_start_address", "ip_context_conflict_for",
        "enriched_thread_contexts")}

    def eager_state(thread_info):
        memory.dump_flags_value(thread_info)
        return real["dump_flags_state"](thread_info)

    def eager_start(thread_info):
        memory.dump_flags_value(thread_info)
        return real["recorded_start_address"](thread_info)

    def eager_conflict(ip, thread_info):
        memory._is_real_thread_info(thread_info)
        memory.dump_flags_value(thread_info)
        return real["ip_context_conflict_for"](ip, thread_info)

    def contexts_first(mf):
        memory.get_thread_contexts(mf)
        return real["enriched_thread_contexts"](mf)

    monkeypatch.setattr(memory, "dump_flags_state", eager_state)
    monkeypatch.setattr(memory, "recorded_start_address", eager_start)
    monkeypatch.setattr(memory, "ip_context_conflict_for", eager_conflict)
    monkeypatch.setattr(memory, "enriched_thread_contexts", contexts_first)


@pytest.mark.parametrize("test, params", [
    (test_a_missing_thread_record_never_reads_dump_flags, {"record": None}),
    (test_a_thread_without_a_captured_ip_consults_nothing, {}),
    (test_the_thread_join_reads_records_before_contexts, {}),
], ids=lambda v: getattr(v, "__name__", ""))
def test_a_reordered_thread_interpretation_is_reported(monkeypatch, test, params):
    """Each ordering check fails against entry points that read DumpFlags
    for a missing record, consult the predicates without a captured IP, or
    read contexts before records."""
    _reordered_entry_points(monkeypatch)
    inner = pytest.MonkeyPatch()
    try:
        with pytest.raises(AssertionError):
            test(inner, **params)
    finally:
        inner.undo()


def test_a_read_size_resolution_that_consults_the_stream_first_is_reported(monkeypatch):
    real = memory._resolve_size

    def eager(mf, addr, requested_size):
        memory.get_memory_regions(mf)
        return real(mf, addr, requested_size)

    monkeypatch.setattr(memory, "_resolve_size", eager)
    with pytest.raises(AssertionError, match="memory-info stream"):
        test_an_explicit_read_size_never_consults_the_memory_info_stream()


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


@pytest.mark.parametrize("package", PACKAGES)
def test_setuptools_discovers_the_owner_package(package):
    setuptools = pytest.importorskip("setuptools")
    from tests.fixtures.decomposition_baseline import REPO_ROOT
    assert package in setuptools.find_packages(REPO_ROOT, include=["dumpex*"])


def test_the_package_smoke_accepts_the_memory_layout(capsys):
    from scripts import package_smoke
    package_smoke.validate_memory_owner_modules()
    assert f"{len(OWNERS)} owner modules" in capsys.readouterr().out

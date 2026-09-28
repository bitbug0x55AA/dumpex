"""
Symbol surface of the decomposed modules.

A module's surface has two parts, captured separately:

* `capture_contract()` -- the supported observable surface a relocation
  must keep exactly. For every export (every public name, and every
  private name some shipped file imports, reads or patches) its kind,
  signature, dataclass fields (order, types, defaults, flags), enum
  members and order, class members, or value, plus which exports are the
  very same object where identity is observable (mutable values, classes,
  functions, enum members). For every other module-level value binding --
  private and unused constants, vocabularies and tables included -- its
  value: those contents are behaviour too.

* `capture_structure()` -- metadata a relocation is EXPECTED to change and
  must update deliberately: which module owns each baseline definition
  now, the legacy module's import provenance, and the module globals each
  function resolves at call time. It is the old-to-new ownership map.

The name lists are sticky: the committed baseline fixes them, so a module
that becomes a re-exporting facade keeps being measured against every name
it promised. Each entry is read from the runtime object alone -- found on
the legacy module, or on the owner module that defines it now (see
`Locator`) -- so an object defined in place and the same object
re-exported from a new owner have the identical contract.
"""
import ast
import dataclasses
import dis
import enum
import importlib
import importlib.util
import inspect
import pkgutil
import types

from tests.fixtures.decomposition_baseline.stable import annotation_text, signature, stable

_SCALARS = (type(None), bool, int, float, str)
# A dataclass field's flags are recorded only where they differ from these.
_FIELD_FLAG_DEFAULTS = {"init": True, "repr": True, "compare": True, "hash": None, "kw_only": False}


def _walk_top_level(body):
    """Top-level statements, descending into module-level if/try blocks."""
    for node in body:
        if isinstance(node, ast.If):
            yield from _walk_top_level(node.body)
            yield from _walk_top_level(node.orelse)
        elif isinstance(node, ast.Try):
            yield from _walk_top_level(node.body)
            for handler in node.handlers:
                yield from _walk_top_level(handler.body)
            yield from _walk_top_level(node.orelse)
            yield from _walk_top_level(node.finalbody)
        else:
            yield node


def _bound_names(target):
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _bound_names(elt)


def source_bindings(module) -> dict:
    """How `module`'s own source binds each top-level name:
    {"defined": [(name, "def"|"class"|"value"), ...] in source order,
     "imports": {name: "source.module:attribute"},
     "class_members": {class_name: [member names in source order]},
     "initializers": {name: source text of its first top-level assignment}}."""
    tree = ast.parse(inspect.getsource(module))
    defined, seen, imports, members, initializers = [], set(), {}, {}, {}

    def define(name, how):
        if name not in seen:
            seen.add(name)
            defined.append((name, how))

    for node in _walk_top_level(tree.body):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            define(node.name, "def")
        elif isinstance(node, ast.ClassDef):
            define(node.name, "class")
            names = []
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.append(item.name)
                elif isinstance(item, ast.Assign):
                    for target in item.targets:
                        names.extend(_bound_names(target))
                elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    names.append(item.target.id)
            members[node.name] = names
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _bound_names(target):
                    define(name, "value")
                    initializers.setdefault(name, ast.unparse(node.value))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name):
            define(node.target.id, "value")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                imports[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom):
            source = "." * node.level + (node.module or "")
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{source}:{alias.name}"
    for name, _ in defined:
        imports.pop(name, None)
    return {"defined": defined, "imports": imports, "class_members": members,
            "initializers": initializers}


# ── Contract ──────────────────────────────────────────────────────────────


def _dataclass_contract(cls) -> dict:
    params = cls.__dataclass_params__
    fields = []
    for f in dataclasses.fields(cls):
        entry = {"name": f.name, "type": annotation_text(f.type)}
        flags = {"init": f.init, "repr": f.repr, "compare": f.compare, "hash": f.hash,
                 "kw_only": getattr(f, "kw_only", False) is True}
        entry.update({k: v for k, v in flags.items() if v != _FIELD_FLAG_DEFAULTS[k]})
        if f.default is not dataclasses.MISSING:
            entry["default"] = stable(f.default)
        if f.default_factory is not dataclasses.MISSING:
            entry["default_factory"] = stable(f.default_factory)
        fields.append(entry)
    return {"frozen": params.frozen, "eq": params.eq, "order": params.order,
            "unsafe_hash": params.unsafe_hash, "init": params.init, "repr": params.repr,
            "fields": fields}


def _member_contract(cls, name):
    raw = cls.__dict__.get(name, None)
    if raw is None:
        return {"kind": "absent"}
    if isinstance(raw, property):
        return {"kind": "property", "signature": signature(raw.fget)}
    if isinstance(raw, staticmethod):
        return {"kind": "staticmethod", "signature": signature(raw.__func__)}
    if isinstance(raw, classmethod):
        return {"kind": "classmethod", "signature": signature(raw.__func__)}
    if inspect.isfunction(raw):
        return {"kind": "method", "signature": signature(raw)}
    return {"kind": "attribute", "value": stable(raw)}


def class_contract(cls, member_names) -> dict:
    out = {"bases": [b.__qualname__ for b in cls.__bases__]}
    if issubclass(cls, enum.Enum):
        out["kind"] = "enum"
        out["members"] = [[name, stable(member.value)] for name, member in cls.__members__.items()]
        skip = set(cls.__members__)
    elif dataclasses.is_dataclass(cls):
        out["kind"] = "dataclass"
        out["dataclass"] = _dataclass_contract(cls)
        skip = {f.name for f in dataclasses.fields(cls)}
    elif issubclass(cls, tuple) and hasattr(cls, "_fields"):
        out["kind"] = "namedtuple"
        out["fields"] = list(cls._fields)
        out["defaults"] = stable(cls._field_defaults)
        skip = set(cls._fields)
    elif issubclass(cls, BaseException):
        out["kind"] = "exception"
        skip = set()
    else:
        out["kind"] = "class"
        skip = set()
    out["class_members"] = {name: _member_contract(cls, name)
                            for name in member_names if name not in skip}
    return out


# Values whose full content a dedicated corpus already captures in a more
# readable form; the surface records only where to find it.
CAPTURED_ELSEWHERE = {
    ("dumpex.output.coverage", "_CODE_SPECS"): "coverage_corpus.json#code_specs",
}

# Module globals that are process-lifetime state rather than constants: their
# current value depends on what already ran, so the contract records only
# that the name exists; its source initializer is structural metadata.
RUNTIME_STATE = {
    ("dumpex.core.memory", "_HANDLE_DESCRIPTOR_LAYOUT_CACHE"),
}


_MISSING = object()


def _is_dumpex(obj) -> bool:
    return (getattr(obj, "__module__", None) or "").split(".")[0] == "dumpex"


# ── Locating baseline names after a move ──────────────────────────────────


class Locator:
    """Finds where a name the baseline recorded for a legacy module lives
    now.

    The search starts from the legacy module, the owner modules of the
    dumpex classes and functions it exports, and -- when the legacy module
    has become a package -- every submodule of it. From each of those it
    follows `from X import name` provenance, module by module, to the one
    whose own source defines the name; every module reached that way joins
    the family searched. A name no chain reaches is looked for among the
    definitions of the whole family. Other target modules are never
    entered: their names belong to their own baseline.

    A name the legacy module still exposes resolves to that object (the
    compatibility path). Otherwise a name defined as different objects in
    several places is ambiguous: a duplicate definition."""

    def __init__(self, target: str, exports, names=(), module_name: "str | None" = None):
        from tests.fixtures.decomposition_baseline import TARGET_MODULES
        self.target = target
        self.legacy = importlib.import_module(module_name or target)
        self._foreign = set(TARGET_MODULES) - {target}
        self._bindings = {}
        self._reached = {}
        owners = set()
        for name in exports:
            obj = getattr(self.legacy, name, None)
            module = getattr(obj, "__module__", None) if (
                inspect.isclass(obj) or inspect.isfunction(obj)) else None
            if (module and _is_dumpex(obj) and module != self.legacy.__name__
                    and module not in self._foreign):
                owners.add(module)
        self.owners = [importlib.import_module(m) for m in sorted(owners)]
        self._submodules = self._package_modules()
        for name in {*exports, *names}:
            for module in self._starts():
                self._chase(module, name)

    # -- module sets -------------------------------------------------------

    def _package_modules(self) -> list:
        path = getattr(self.legacy, "__path__", None)
        if not path:
            return []
        out = []
        for info in pkgutil.walk_packages(path, self.legacy.__name__ + "."):
            try:
                out.append(importlib.import_module(info.name))
            except ImportError:
                continue
        return out

    def _starts(self) -> list:
        return _unique([self.legacy, *self.owners, *self._submodules])

    def family(self) -> list:
        """The legacy module, its owners, its submodules and every module
        reached through import provenance -- where its definitions live."""
        return _unique([*self._starts(), *self._reached.values()])

    def bindings(self, module) -> dict:
        if module.__name__ not in self._bindings:
            try:
                self._bindings[module.__name__] = source_bindings(module)
            except (OSError, TypeError):
                self._bindings[module.__name__] = {
                    "defined": [], "imports": {}, "class_members": {}, "initializers": {}}
        return self._bindings[module.__name__]

    def defined_in(self, module) -> dict:
        return dict(self.bindings(module)["defined"])

    # -- provenance --------------------------------------------------------

    def _import_source(self, module, spec: str):
        module_name, _, attribute = spec.partition(":")
        if not attribute:
            return None, None
        if module_name.startswith("."):
            package = (module.__name__ if hasattr(module, "__path__")
                       else module.__name__.rpartition(".")[0])
            module_name = importlib.util.resolve_name(module_name, package)
        if module_name.split(".")[0] != "dumpex" or module_name in self._foreign:
            return None, None
        try:
            return importlib.import_module(module_name), attribute
        except ImportError:
            return None, None

    def _chase(self, module, name, depth: int = 0):
        """(defining module, object) for `name` as `module` binds it,
        following import provenance; None when the chain leaves the family
        or ends without a definition."""
        if depth > 32:
            return None
        bindings = self.bindings(module)
        if name in dict(bindings["defined"]):
            return module, getattr(module, name, _MISSING)
        spec = bindings["imports"].get(name)
        if spec is None:
            return None
        source, attribute = self._import_source(module, spec)
        if source is None:
            return None
        self._reached.setdefault(source.__name__, source)
        return self._chase(source, attribute, depth + 1)

    def definers(self, name) -> list:
        """Every (module, object) whose own source defines `name`, found by
        provenance from the start modules and then across the family."""
        found = {}
        for module in self._starts():
            hit = self._chase(module, name)
            if hit is not None and hit[1] is not _MISSING:
                found.setdefault(hit[0].__name__, hit)
        for module in self.family():
            if module.__name__ not in found and name in self.defined_in(module) \
                    and hasattr(module, name):
                found[module.__name__] = (module, getattr(module, name))
        return [found[m] for m in sorted(found)]

    def find(self, name):
        """(module, object) for `name`. The object is _MISSING when nothing
        has it, and a list of (module, object) pairs when several modules
        define it as different objects."""
        if hasattr(self.legacy, name):
            return self.legacy, getattr(self.legacy, name)
        found = self.definers(name)
        if not found:
            return None, _MISSING
        if len({id(obj) for _, obj in found}) > 1:
            return None, found
        return found[0]

    def resolve(self, name):
        """The object `name` stands for now; raises LookupError when it is
        missing or ambiguous."""
        _, obj = self.find(name)
        if obj is _MISSING or isinstance(obj, list):
            raise LookupError(f"{self.target}.{name} is "
                              f"{'missing' if obj is _MISSING else 'ambiguous'}")
        return obj

    def owner_of(self, name, obj) -> "str | None":
        if (inspect.isclass(obj) or inspect.isfunction(obj)) and getattr(obj, "__module__", None):
            return obj.__module__
        for module, candidate in self.definers(name):
            if candidate is obj:
                return module.__name__
        return self.legacy.__name__ if name in self.defined_in(self.legacy) else None


def _unique(modules) -> list:
    seen, out = set(), []
    for module in modules:
        if module.__name__ not in seen:
            seen.add(module.__name__)
            out.append(module)
    return out


_LOCATORS = {}


def baseline_locator(target: str) -> Locator:
    """A Locator for `target` over the committed baseline name lists,
    rebuilt whenever the module installed under the legacy name changes."""
    import sys
    from tests.fixtures.decomposition_baseline import stable as stable_module
    committed_golden = stable_module.committed_golden
    key = (target, id(sys.modules.get(target)), stable_module.GOLDEN_DIR)
    if key not in _LOCATORS:
        contract = (committed_golden("surface_contract.json") or {}).get(target, {})
        exports = contract.get("exports") or sorted(
            n for n in vars(importlib.import_module(target)) if not n.startswith("__"))
        _LOCATORS[key] = Locator(target, exports, names=contract.get("private_values", {}))
    return _LOCATORS[key]


def baseline_object(target: str, name: str):
    """The object the baseline name `target.name` stands for now: the legacy
    module's own attribute when it still exposes one, otherwise the
    definition Locator finds."""
    return baseline_locator(target).resolve(name)


# ── Contract ──────────────────────────────────────────────────────────────


def _owner_class_members(locator: Locator, cls) -> tuple:
    if cls.__qualname__ != cls.__name__:
        return ()
    owner = importlib.import_module(cls.__module__)
    return tuple(locator.bindings(owner)["class_members"].get(cls.__name__, ()))


def _entry(key, obj, locator: Locator):
    """The contract of one object, decided by the object itself -- never by
    how the exporting module binds it, so the same object exported by
    definition or by re-export has the same contract. A dumpex class's
    members are read from its owning module's source."""
    if obj is _MISSING:
        return {"kind": "missing"}
    if isinstance(obj, list):
        return {"kind": "ambiguous", "owners": sorted(m.__name__ for m, _ in obj)}
    if key in RUNTIME_STATE:
        return {"kind": "runtime_state"}
    elsewhere = CAPTURED_ELSEWHERE.get(key)
    if elsewhere is not None:
        return {"kind": "value", "type": type(obj).__qualname__, "captured_in": elsewhere}
    if inspect.ismodule(obj):
        return {"kind": "module", "name": obj.__name__}
    if inspect.isclass(obj):
        if not _is_dumpex(obj):
            return {"kind": "external_class", "object": stable(obj)}
        return class_contract(obj, _owner_class_members(locator, obj))
    if inspect.isfunction(obj) or inspect.isbuiltin(obj):
        if not _is_dumpex(obj):
            return {"kind": "external_callable", "object": stable(obj)}
        return {"kind": "function", "signature": signature(obj)}
    return {"kind": "value", "type": type(obj).__qualname__, "value": stable(obj)}


def _immutable_value(obj) -> bool:
    """True for a scalar, or a tuple/frozenset built only of them: a value
    whose identity no consumer can rely on -- equal literals may or may not
    be one object depending on how the compiler folded constants."""
    if isinstance(obj, enum.Enum):
        return False
    if isinstance(obj, _SCALARS):
        return True
    return isinstance(obj, (tuple, frozenset)) and all(_immutable_value(v) for v in obj)


def _identity_groups(module, names) -> list:
    """Exports that are the very same object, among those whose identity is
    observable: mutable values, classes, functions and enum members."""
    by_id = {}
    for name in names:
        obj = getattr(module, name, _MISSING)
        if obj is _MISSING or _immutable_value(obj):
            continue
        by_id.setdefault(id(obj), []).append(name)
    return sorted(sorted(group) for group in by_id.values() if len(group) > 1)


def derived_exports(module_name: str, externally_used: "set[str]") -> list:
    """Names the module's current source commits it to exposing: every
    public name it defines, and every name another shipped file imports,
    reads or patches through it."""
    module = importlib.import_module(module_name)
    bindings = source_bindings(module)
    how = dict(bindings["defined"])
    for name in bindings["imports"]:
        how.setdefault(name, "imported")
    return sorted(
        name for name in how
        if hasattr(module, name) and (
            (how[name] != "imported" and not name.startswith("_")) or name in externally_used))


def derived_private_values(module_name: str) -> list:
    """Every module-level value binding the module's current source makes
    (constants, vocabularies, tables), private and unused ones included:
    their contents are behaviour even when no other file names them."""
    module = importlib.import_module(module_name)
    return sorted(name for name, how in source_bindings(module)["defined"] if how == "value")


def capture_contract(target: str, exports, private_values,
                     module_name: "str | None" = None) -> dict:
    """The contract of `exports` and `private_values` for the legacy module
    `target`, read at runtime from `module_name` (default: `target`) and,
    for a private value it does not expose, from wherever it is defined
    now (see Locator)."""
    exports = sorted(exports)
    values = sorted(set(private_values) - set(exports))
    locator = Locator(target, exports, names=values, module_name=module_name)
    module = locator.legacy
    return {
        "exports": exports,
        "entries": {name: _entry((target, name), getattr(module, name, _MISSING), locator)
                    for name in exports},
        "identity_groups": _identity_groups(module, exports),
        "private_values": {name: _entry((target, name), locator.find(name)[1], locator)
                           for name in values},
    }


def duplicate_definitions(target: str, names, exports, module_name: "str | None" = None) -> list:
    """Non-scalar `names` bound to more than one distinct object across the
    legacy module and every module of its family that defines them -- a
    copy where one canonical definition is required."""
    locator = Locator(target, exports, names=names, module_name=module_name)
    out = []
    for name in sorted(names):
        holders = [(m, obj) for m, obj in locator.definers(name)]
        if hasattr(locator.legacy, name):
            holders.append((locator.legacy, getattr(locator.legacy, name)))
        holders = [(m, o) for m, o in holders
                   if not (isinstance(o, _SCALARS) and not isinstance(o, enum.Enum))]
        if len({id(o) for _, o in holders}) > 1:
            out.append(f"{name}: {sorted({m.__name__ for m, _ in holders})}")
    return out


# ── Structure ─────────────────────────────────────────────────────────────


def capture_structure(target: str, exports, baseline_definitions,
                      module_name: "str | None" = None) -> dict:
    """Where every baseline definition lives now, and the module globals
    each of its functions resolves at call time. `baseline_definitions` is
    the [name, kind] list the legacy module's source made at the baseline
    commit, so the map keeps following a definition after it moves."""
    locator = Locator(target, exports, names=[n for n, _ in baseline_definitions],
                      module_name=module_name)
    legacy_bindings = locator.bindings(locator.legacy)
    owners, resolution, initializers = {}, {}, {}
    for name, kind in baseline_definitions:
        _, obj = locator.find(name)
        if obj is _MISSING:
            owners[name] = None
            continue
        if isinstance(obj, list):
            owners[name] = sorted(m.__name__ for m, _ in obj)
            continue
        owners[name] = locator.owner_of(name, obj)
        if (target, name) in RUNTIME_STATE and owners[name]:
            source_owner = importlib.import_module(owners[name])
            initializers[name] = locator.bindings(source_owner)["initializers"].get(name)
        if kind == "def" and inspect.isfunction(obj):
            resolution[name] = _resolution(obj)
        elif kind == "class" and inspect.isclass(obj) and _is_dumpex(obj):
            for member in _owner_class_members(locator, obj):
                raw = obj.__dict__.get(member)
                if isinstance(raw, (staticmethod, classmethod)):
                    raw = raw.__func__
                elif isinstance(raw, property):
                    raw = raw.fget
                if inspect.isfunction(raw):
                    resolution[f"{name}.{member}"] = _resolution(raw)
    return {
        "baseline_definitions": [list(d) for d in baseline_definitions],
        "owners": owners,
        "legacy_imports": legacy_bindings["imports"],
        "legacy_defines": [name for name, _ in legacy_bindings["defined"]],
        "private_unexported": sorted(name for name, _ in baseline_definitions
                                     if name not in set(exports)),
        "runtime_state_initializers": initializers,
        "global_resolution": resolution,
    }


# ── Global resolution ─────────────────────────────────────────────────────


def _global_loads(code, into: set) -> None:
    for ins in dis.get_instructions(code):
        if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME", "STORE_GLOBAL", "DELETE_GLOBAL"):
            into.add(ins.argval)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            _global_loads(const, into)


def _resolution(fn) -> dict:
    """The module whose namespace `fn` resolves globals in -- read from
    `fn.__globals__` itself, not from the `__module__` it reports -- and the
    names of that namespace it loads at call time. A function moved to
    another module resolves these names in ITS new module, so a patch
    applied to the legacy module stops reaching it unless the move delegates
    explicitly; this is the inventory that makes that visible. A function
    whose `__module__` names a different module than the one it resolves in
    records that too, as `declared_module`."""
    names = set()
    _global_loads(fn.__code__, names)
    out = {"module": fn.__globals__.get("__name__"),
           "globals": sorted(n for n in names if n in fn.__globals__)}
    if fn.__module__ != out["module"]:
        out["declared_module"] = fn.__module__
    return out

"""
Simulated relocations of a target module, for the baseline's own controls.

`split_relocation()` turns a target module into the layout a real split
produces, without touching the source tree:

* ``_split_classes``  -- owns (defines, in its source) every exported class;
* ``_split_functions`` -- owns every exported function and exported value;
* ``_split_internals`` -- owns everything else: the imports, every private
  value, vocabulary and table, every private helper function and private
  class that is not exported. It owns no exported class or function.
* the legacy name -- a facade whose source imports exactly the committed
  exports from those modules and binds nothing else.

Each top-level statement of the legacy source runs, in source order, inside
the namespace of the part that owns it, after every name the other parts
have bound so far is bound there too -- exactly what `from <part> import
name` would give it. A function or class therefore belongs to its part in
every respect: its `__module__`, and the globals it resolves at call time,
are that part's. Each part's source file holds the statements it owns
behind imports of every name the other parts own. Every module is
installed through the caller's `monkeypatch`, so the real modules are back
in place when the test ends.

Nothing here delegates a legacy-module patch to the part that now resolves
the name: a patch applied to the facade reaches no moved function, which is
what the seam checks must report for a split that does not delegate.
"""
import ast
import copy as _copy
import importlib
import importlib.util
import sys
import types

from tests.fixtures.decomposition_baseline.stable import load_golden

CLASSES, FUNCTIONS, INTERNALS = "_split_classes", "_split_functions", "_split_internals"
PARTS = (INTERNALS, CLASSES, FUNCTIONS)
_UNSET = object()


def _bound(node) -> list:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        out = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                out.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                out += [e.id for e in target.elts if isinstance(e, ast.Name)]
        return out
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _part_of(node, exports: set) -> str:
    names = _bound(node)
    if isinstance(node, ast.ClassDef) and node.name in exports:
        return CLASSES
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in exports:
        return FUNCTIONS
    if isinstance(node, (ast.Assign, ast.AnnAssign)) and names and all(n in exports for n in names):
        return FUNCTIONS
    return INTERNALS


def _segment(lines, node) -> str:
    start = min([node.lineno, *[d.lineno for d in getattr(node, "decorator_list", [])]])
    return "".join(lines[start - 1:node.end_lineno])


def split_relocation(target: str, monkeypatch, tmp_path, copied_into_functions=(),
                     extra_internals: str = "") -> dict:
    """Install the split layout for `target` (see the module docstring) and
    return {part name: module}. `copied_into_functions` names internals the
    functions owner additionally binds to a copy -- a duplicate definition.
    `extra_internals` is source appended to the internals module."""
    exports = set(load_golden("surface_contract.json")[target]["exports"])
    package = target.rpartition(".")[0]
    source_path = importlib.import_module(target).__file__
    source = open(source_path, encoding="utf-8").read()
    lines = source.splitlines(keepends=True)
    tree = ast.parse(source)

    names = {part: f"{package}.{part}" for part in PARTS}
    modules = {}
    for part in PARTS:
        module = types.ModuleType(names[part])
        module.__file__ = str(tmp_path / f"{part}.py")
        monkeypatch.setitem(sys.modules, names[part], module)
        modules[part] = module

    owner_of, texts = {}, {part: [] for part in PARTS}

    def share():
        # What `from <owner> import name` gives every other part: the same
        # binding, as it stands when the next statement runs.
        for name, part in owner_of.items():
            value = modules[part].__dict__.get(name, _UNSET)
            if value is _UNSET:
                continue
            for other in PARTS:
                if other != part:
                    modules[other].__dict__[name] = value

    def run(part, code):
        share()
        namespace = modules[part].__dict__
        before = {k: id(v) for k, v in namespace.items()}
        exec(code, namespace)
        for key, value in namespace.items():
            if not key.startswith("__") and before.get(key) != id(value):
                owner_of[key] = part

    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant):
            continue   # the module docstring
        part = _part_of(node, exports)
        texts[part].append(_segment(lines, node))
        run(part, compile(ast.Module(body=[node], type_ignores=[]), source_path, "exec"))
    if extra_internals:
        texts[INTERNALS].append(extra_internals)
        run(INTERNALS, compile(extra_internals, modules[INTERNALS].__file__, "exec"))
    share()

    for name in copied_into_functions:
        modules[FUNCTIONS].__dict__[name] = _copy.copy(modules[owner_of[name]].__dict__[name])
        texts[FUNCTIONS].append(f"{name} = copy.copy({name})\n")

    for part in PARTS:
        header = "".join(
            f"from {names[other]} import (\n"
            + "".join(f"    {n},\n" for n in sorted(n for n, p in owner_of.items() if p == other))
            + ")\n"
            for other in PARTS if other != part)
        with open(modules[part].__file__, "w", encoding="utf-8") as fh:
            fh.write(header + "\n\n" + "\n\n".join(texts[part]))

    facade_lines = []
    for part in PARTS:
        mine = sorted(n for n in exports if owner_of.get(n) == part)
        if mine:
            facade_lines.append(f"from {names[part]} import (\n"
                                + "".join(f"    {n},\n" for n in mine) + ")\n")
    facade_path = tmp_path / "facade.py"
    facade_path.write_text("".join(facade_lines), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(target, facade_path)
    facade = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, target, facade)
    spec.loader.exec_module(facade)
    modules["facade"] = facade
    return modules

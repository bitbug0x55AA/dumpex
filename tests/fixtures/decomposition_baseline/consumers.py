"""
Who uses which name of the decomposed modules, and how.

`scan_consumers()` reads every Python file of the repository with `ast`
and records, per legacy module path, each name that is

* ``from``   -- imported by name (`from dumpex.core.memory import X`,
                including package-relative imports inside `dumpex`);
* ``attr``   -- read module-qualified (`memory.X`, `dumpex.core.memory.X`),
                which resolves against the legacy module's own namespace
                at call time;
* ``patch``  -- replaced through a patching call that undoes itself or is
                scoped (`monkeypatch.setattr(memory, "X", ...)`,
                `monkeypatch.setattr("dumpex.core.memory.X", ...)`,
                `mock.patch("dumpex.core.memory.X")`, `setitem` on a module
                attribute);
* ``assign`` -- replaced by a plain assignment (`memory.X = ...`), which
                nothing undoes.

`scan_reader_seams()` records the same two replacement kinds for
attributes of every OTHER dumpex module that hold one of the target
modules' objects by name -- the consumer-side seams tests replace.

Files that ARE the decomposed modules (the "family") are recorded
separately: their mutual imports are expected to change when the modules
are split into owner modules. Production and script files form the
consumer inventory, family files the structural record of how the
decomposed modules use one another; test files only feed the seam
inventory.
"""
import ast
import importlib
import os

from tests.fixtures.decomposition_baseline import REPO_ROOT, TARGET_MODULES

_SKIP_DIRS = {"__pycache__", ".git", ".venv", "build", "dist", "tmp", "dumpex.egg-info",
              ".pytest_cache"}
_SCAN_ROOTS = ("dumpex", "scripts", "tests")
_ROOT_FILES = ("Dumpex.py", "setup.py")
_PATCH_CALLS = {"setattr", "delattr", "patch", "object", "setitem", "delitem"}

FAMILY_FILES = frozenset({
    "dumpex/output/records.py", "dumpex/core/memory.py", "dumpex/output/coverage.py"})
FAMILY_PREFIXES = ("dumpex/output/records/", "dumpex/core/memory/", "dumpex/output/coverage/")
SHIPPED_CATEGORIES = ("production", "scripts", "family")
EXTERNAL_CATEGORIES = ("production", "scripts")


def category(relpath: str) -> str:
    if relpath in FAMILY_FILES or relpath.startswith(FAMILY_PREFIXES):
        return "family"
    if relpath.startswith("tests/"):
        return "tests"
    if relpath.startswith("scripts/"):
        return "scripts"
    return "production"


def python_files(root: str = REPO_ROOT):
    for name in _ROOT_FILES:
        if os.path.isfile(os.path.join(root, name)):
            yield name
    for top in _SCAN_ROOTS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(root, top)):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            for filename in sorted(filenames):
                if filename.endswith(".py"):
                    full = os.path.join(dirpath, filename)
                    yield os.path.relpath(full, root).replace(os.sep, "/")


def _module_of(relpath: str) -> str:
    parts = relpath[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_relative(relpath: str, level: int, module: "str | None") -> str:
    package = _module_of(relpath)
    if not relpath.endswith("__init__.py"):
        package = package.rpartition(".")[0]
    for _ in range(level - 1):
        package = package.rpartition(".")[0]
    return f"{package}.{module}" if module else package


def _dotted(node) -> "str | None":
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _split_dotted(dotted: str, modules) -> "tuple[str, str] | None":
    """(module, attribute) when `dotted` names an attribute of one of
    `modules` (the longest matching module wins)."""
    for module in sorted(modules, key=len, reverse=True):
        prefix = module + "."
        if dotted.startswith(prefix) and "." not in dotted[len(prefix):]:
            return module, dotted[len(prefix):]
    return None


def _is_dumpex_module_path(dotted: str) -> bool:
    return dotted == "dumpex" or dotted.startswith("dumpex.")


class _FileScanner(ast.NodeVisitor):
    def __init__(self, relpath):
        self.relpath = relpath
        self.aliases = {}              # local name -> target module
        self.module_aliases = {}       # local name -> any dumpex module
        self.uses = set()              # (target, name, kind)
        self.foreign = set()           # (other dumpex module, attribute, kind)

    # -- aliases --------------------------------------------------------

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in TARGET_MODULES and alias.asname:
                self.aliases[alias.asname] = alias.name
            if _is_dumpex_module_path(alias.name) and alias.asname:
                self.module_aliases[alias.asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        source = (_resolve_relative(self.relpath, node.level, node.module)
                  if node.level else node.module)
        for alias in node.names:
            if source in TARGET_MODULES:
                self.uses.add((source, alias.name, "from"))
            elif source and f"{source}.{alias.name}" in TARGET_MODULES:
                self.aliases[alias.asname or alias.name] = f"{source}.{alias.name}"
            if source and _is_dumpex_module_path(source):
                self.module_aliases[alias.asname or alias.name] = f"{source}.{alias.name}"
        self.generic_visit(node)

    def _target_of(self, node) -> "str | None":
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        dotted = _dotted(node)
        return dotted if dotted in TARGET_MODULES else None

    def _dumpex_module_of(self, node) -> "str | None":
        if isinstance(node, ast.Name):
            return self.module_aliases.get(node.id)
        dotted = _dotted(node)
        return dotted if dotted and _is_dumpex_module_path(dotted) else None

    # -- replacement ------------------------------------------------------

    def _replaced(self, module_node, attribute: str, kind: str) -> None:
        target = self._target_of(module_node)
        if target is not None:
            self.uses.add((target, attribute, kind))
            return
        module = self._dumpex_module_of(module_node)
        if module is not None:
            self.foreign.add((module, attribute, kind))

    def _assigned(self, target) -> None:
        if isinstance(target, ast.Attribute):
            self._replaced(target.value, target.attr, "assign")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assigned(elt)

    def visit_Assign(self, node):
        for target in node.targets:
            self._assigned(target)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self._assigned(node.target)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._assigned(node.target)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        target = self._target_of(node.value)
        if target is not None and isinstance(node.ctx, ast.Load):
            self.uses.add((target, node.attr, "attr"))
        self.generic_visit(node)

    def visit_Call(self, node):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name in _PATCH_CALLS and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                split = _split_dotted(first.value, TARGET_MODULES)
                if split:
                    self.uses.add((split[0], split[1], "patch"))
                elif _is_dumpex_module_path(first.value) and "." in first.value:
                    module, _, attribute = first.value.rpartition(".")
                    self.foreign.add((module, attribute, "patch"))
            elif isinstance(first, ast.Attribute) and self._target_of(first.value) is not None:
                # Patching through a module attribute: setattr(memory.PEB, ...),
                # setitem(memory._STREAM_DISPATCH, ...).
                self.uses.add((self._target_of(first.value), first.attr, "patch"))
            elif len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                    and isinstance(node.args[1].value, str):
                self._replaced(first, node.args[1].value, "patch")
        self.generic_visit(node)


def _scan(relpath: str, root: str) -> _FileScanner:
    with open(os.path.join(root, relpath), encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=relpath)
    scanner = _FileScanner(relpath)
    scanner.visit(tree)
    return scanner


def scan_consumers(root: str = REPO_ROOT) -> dict:
    """{target module: {name: {relpath: [kinds]}}}, every level sorted."""
    out = {target: {} for target in TARGET_MODULES}
    for relpath in python_files(root):
        scanner = _scan(relpath, root)
        for target, name, kind in scanner.uses:
            if target == _module_of(relpath):
                continue
            out[target].setdefault(name, {}).setdefault(relpath, set()).add(kind)
    return {target: {name: {path: sorted(kinds) for path, kinds in sorted(files.items())}
                     for name, files in sorted(names.items())}
            for target, names in out.items()}


def scan_legacy_patches(root: str = REPO_ROOT) -> dict:
    """{target module: [names]} every test file replaces on a legacy path."""
    inventory = by_categories(scan_consumers(root), ("tests",))
    return {target: sorted(name for name, files in names.items()
                           if any({"patch", "assign"} & set(k) for k in files.values()))
            for target, names in inventory.items()}


def plain_assignments_to_targets(root: str = REPO_ROOT, exclude=("tests/conftest.py",)) -> list:
    """"relpath: target.name" for every test file that replaces a target
    module attribute by plain assignment -- a replacement nothing undoes."""
    out = []
    for relpath in python_files(root):
        if category(relpath) != "tests" or relpath in exclude:
            continue
        for target, name, kind in _scan(relpath, root).uses:
            if kind == "assign":
                out.append(f"{relpath}: {target}.{name}")
    return sorted(out)


def scan_reader_seams(root: str = REPO_ROOT) -> dict:
    """{consumer module: {name: {"kinds": [...], "same_object_as": {target:
    bool}}}} for every attribute of another dumpex module that a test
    replaces and that shares its name with a definition of a target module
    -- a hunter's own `enriched_thread_contexts`, a command's own
    `read_region`. `same_object_as` records whether that attribute is the
    target module's very object, so a relocation that rebinds a consumer to
    a different object is visible."""
    replaced = {}
    for relpath in python_files(root):
        if category(relpath) != "tests":
            continue
        for module, attribute, kind in _scan(relpath, root).foreign:
            replaced.setdefault((module, attribute), set()).add(kind)
    targets = {t: importlib.import_module(t) for t in TARGET_MODULES}
    out = {}
    for (module_name, attribute), kinds in sorted(replaced.items()):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        if not hasattr(module, attribute):
            continue
        shared = {t: getattr(module, attribute) is vars(m)[attribute]
                  for t, m in targets.items() if attribute in vars(m)}
        if shared:
            out.setdefault(module_name, {})[attribute] = {
                "kinds": sorted(kinds), "same_object_as": shared}
    return out


def unreset_seams(seams: dict, reset: set) -> list:
    """(module, name) pairs among `seams` that `reset` does not restore."""
    return sorted({(m, n) for m, names in seams.items() for n in names} - set(reset))


def by_categories(inventory: dict, wanted) -> dict:
    """The part of `inventory` whose consumer files fall in `wanted`."""
    out = {}
    for target, names in inventory.items():
        kept = {}
        for name, files in names.items():
            files = {p: k for p, k in files.items() if category(p) in wanted}
            if files:
                kept[name] = files
        out[target] = kept
    return out


def externally_used(inventory: dict, target: str) -> set:
    """Every name of `target` some file other than the module itself uses."""
    return set(inventory.get(target, {}))

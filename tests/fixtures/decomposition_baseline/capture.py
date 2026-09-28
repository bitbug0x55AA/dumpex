"""
The single definition of what each golden file contains -- shared by
`scripts/update_decomposition_baseline.py` (which writes them) and
`tests/integration/test_decomposition_baseline.py` (which compares them),
so producing and checking a golden can never drift apart.

Name lists are sticky. The export list, the private value list and the
baseline definition list of each target module are the committed lists
united with whatever the current source derives; a name leaves a list only
when the generator is told to drop it explicitly. A module that becomes a
re-exporting facade therefore keeps being measured against every name the
baseline recorded, and regenerating after a pure relocation reproduces the
contract byte for byte.

Only shipped files (dumpex, scripts, and the decomposed modules
themselves) feed the export derivation, so a change that merely adds a test
never changes a contract golden. The consumer inventory holds the modules
outside the decomposed family; how the family's own modules import one
another is structure, recorded with the ownership map.
"""
import importlib

from tests.fixtures.decomposition_baseline import TARGET_MODULES
from tests.fixtures.decomposition_baseline.consumers import (
    EXTERNAL_CATEGORIES, SHIPPED_CATEGORIES, by_categories, externally_used, scan_consumers, scan_legacy_patches,
    scan_reader_seams)
from tests.fixtures.decomposition_baseline.coverage_corpus import capture_coverage_corpus
from tests.fixtures.decomposition_baseline.record_corpus import capture_record_corpus
from tests.fixtures.decomposition_baseline.stable import committed_golden
from tests.fixtures.decomposition_baseline.surface import (
    capture_contract, capture_structure, derived_exports, derived_private_values,
    source_bindings)

SURFACE_CONTRACT = "surface_contract.json"
SURFACE_STRUCTURE = "surface_structure.json"
CONSUMERS = "consumers.json"
SEAMS = "seams.json"
COVERAGE_CORPUS = "coverage_corpus.json"
RECORD_CORPUS = "record_corpus.json"

# Goldens derived from test files: an inventory, not a contract. The
# generator only ever adds to them, and a check reports additions without
# failing (see scripts/update_decomposition_baseline.py).
INVENTORY_GOLDENS = (SEAMS,)


def committed(name: str):
    return committed_golden(name)


def _merge(committed_names, derived_names, drops=()) -> list:
    return sorted((set(committed_names or ()) | set(derived_names)) - set(drops))


def _ordered_union(committed_pairs, derived_pairs) -> list:
    out = [list(p) for p in committed_pairs or ()]
    seen = {name for name, _ in out}
    out += [list(p) for p in derived_pairs if p[0] not in seen]
    return out


def name_lists(consumers: dict, drops: "dict | None" = None, derive: bool = True) -> dict:
    """{target: (exports, private_values, baseline_definitions)}: the
    committed lists, united with the current source's derivation when
    `derive` is set, minus `drops[target]`."""
    contract, structure = committed(SURFACE_CONTRACT) or {}, committed(SURFACE_STRUCTURE) or {}
    out = {}
    for target in TARGET_MODULES:
        dropped = set((drops or {}).get(target, ()))
        c, s = contract.get(target, {}), structure.get(target, {})
        exports = _merge(c.get("exports"), derived_exports(
            target, externally_used(consumers, target)) if derive else (), dropped)
        values = _merge(c.get("private_values", {}).keys(),
                        derived_private_values(target) if derive else (), dropped)
        values = [v for v in values if v not in set(exports)]
        definitions = _ordered_union(
            s.get("baseline_definitions"),
            source_bindings(importlib.import_module(target))["defined"] if derive else ())
        definitions = [d for d in definitions if d[0] not in dropped]
        out[target] = (exports, values, definitions)
    return out


def capture_surfaces(lists: dict) -> "tuple[dict, dict]":
    """(contract, structure) for `lists` (see name_lists). The structure
    also carries how the decomposed modules import one another -- the
    `family` consumers, which a relocation rewires by design."""
    family = by_categories(scan_consumers(), ("family",))
    contract, structure = {}, {}
    for target, (exports, values, definitions) in lists.items():
        contract[target] = capture_contract(target, exports, values)
        structure[target] = capture_structure(target, exports, definitions)
        structure[target]["family_consumers"] = family.get(target, {})
    return contract, structure


def committed_surfaces() -> "tuple[dict, dict]":
    """(contract, structure) over exactly the committed name lists -- what
    every comparison uses."""
    return capture_surfaces(name_lists({}, derive=False))


def committed_names(target: str) -> set:
    """Every name a --drop may remove from `target`'s sticky lists."""
    contract = (committed(SURFACE_CONTRACT) or {}).get(target, {})
    structure = (committed(SURFACE_STRUCTURE) or {}).get(target, {})
    return ({*contract.get("exports", ()), *contract.get("private_values", {})}
            | {name for name, _ in structure.get("baseline_definitions", ())})


def committed_seams() -> set:
    """Every (module, name) a --drop-seam may remove: legacy patch targets
    and consumer seams."""
    seams = committed(SEAMS) or {}
    out = {(t, n) for t, names in seams.get("legacy_patch_targets", {}).items() for n in names}
    out |= {(m, n) for m, names in seams.get("consumer_seams", {}).items() for n in names}
    return out


def stale_seams() -> list:
    """Committed seam entries that do not resolve: a consumer module that
    cannot be imported, or an attribute its module does not have.
    Remove them with --drop-seam."""
    out = []
    for module_name, name in sorted(committed_seams()):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            out.append(f"{module_name}:{name} (module cannot be imported)")
            continue
        if not hasattr(module, name):
            out.append(f"{module_name}:{name} (no such attribute)")
    return out


def capture_seams(drops=()) -> dict:
    """The live test-derived seam inventory united with the committed one,
    minus the (module, name) pairs in `drops` -- a consumer that was renamed
    or removed, which the live scan does not find."""
    drops = set(drops)
    old = committed(SEAMS) or {}
    live_targets, live_seams = scan_legacy_patches(), scan_reader_seams()
    targets = {}
    for target in TARGET_MODULES:
        names = (set(old.get("legacy_patch_targets", {}).get(target, ()))
                 | set(live_targets.get(target, ())))
        targets[target] = sorted(n for n in names if (target, n) not in drops)
    seams = {}
    for source in (old.get("consumer_seams", {}), live_seams):
        for module, names in source.items():
            for name, entry in names.items():
                if (module, name) in drops:
                    continue
                slot = seams.setdefault(module, {}).setdefault(
                    name, {"kinds": [], "same_object_as": {}})
                slot["kinds"] = sorted(set(slot["kinds"]) | set(entry["kinds"]))
                for target, same in entry["same_object_as"].items():
                    slot["same_object_as"].setdefault(target, same)
    return {
        "legacy_patch_targets": targets,
        "consumer_seams": {m: dict(sorted(ns.items())) for m, ns in sorted(seams.items())},
    }


def capture_static_goldens(drops: "dict | None" = None, seam_drops=(), sections=None) -> dict:
    """{golden file name: data} for the non-CLI sections named in
    `sections` (default: all)."""
    sections = set(sections or ("contract", "structure", "consumers", "seams",
                                "coverage", "records"))
    shipped = by_categories(scan_consumers(), SHIPPED_CATEGORIES)
    out = {}
    if sections & {"contract", "structure"}:
        contract, structure = capture_surfaces(name_lists(shipped, drops))
        if "contract" in sections:
            out[SURFACE_CONTRACT] = contract
        if "structure" in sections:
            out[SURFACE_STRUCTURE] = structure
    if "consumers" in sections:
        out[CONSUMERS] = by_categories(shipped, EXTERNAL_CATEGORIES)
    if "seams" in sections:
        out[SEAMS] = capture_seams(seam_drops)
    if "coverage" in sections:
        out[COVERAGE_CORPUS] = capture_coverage_corpus()
    if "records" in sections:
        out[RECORD_CORPUS] = capture_record_corpus()
    return out

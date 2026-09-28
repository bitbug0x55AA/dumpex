"""
Regenerate (or, with --check, verify) the records/memory decomposition
baseline in tests/fixtures/decomposition_baseline/golden/.

The goldens describe observable behaviour at a declared comparison commit
(see tests/fixtures/decomposition_baseline/__init__.py and
docs/developer/decomposition_baseline.md). This script is the only writer;
tests/integration/test_decomposition_baseline.py only compares. Both call
the same capture functions, so what is written and what is checked cannot
drift apart.

Usage:
    python scripts/update_decomposition_baseline.py             # write every section
    python scripts/update_decomposition_baseline.py --check     # compare, never write
    python scripts/update_decomposition_baseline.py structure   # only these sections:
                                                                # contract, structure,
                                                                # consumers, seams,
                                                                # coverage, records, cli
    python scripts/update_decomposition_baseline.py \\
        --drop dumpex.core.memory:_NAME                         # remove a name from the
                                                                # sticky lists; always
                                                                # regenerates contract
                                                                # and structure together
    python scripts/update_decomposition_baseline.py \\
        --drop-seam dumpex.hunt.gone:read_region                # remove a seam whose
                                                                # consumer does not exist

A --drop or --drop-seam naming something the committed goldens do not hold
is refused, so a typo never silently does nothing.

--check exits 1 when a contract, structure or consumer golden would change,
and when a CLI scenario could not run here (yara-python missing) unless
--allow-skip is given. New entries in an inventory golden (seams.json,
derived from test files) are reported but do not fail the check: that
inventory only grows, and recording the additions is a routine update. A
committed seam entry that does not resolve (its consumer module was
renamed or removed) fails the check until --drop-seam removes it.

Export, private value and baseline definition lists are sticky (see
tests/fixtures/decomposition_baseline/capture.py): regenerating never
drops a name the committed contract promised unless --drop names it, so a
relocation regenerates `structure` -- the ownership map -- and leaves
`contract` byte-identical.

Every file is written as bytes: sorted-key JSON, ASCII escapes, LF line
endings, one trailing newline (see stable.dumps). The golden directory is
pinned to `text eol=lf` in .gitattributes, and the byte comparison here
catches a CRLF checkout even without that pin.

A regenerated golden is a proposed expectation, not an accepted one:
review the diff, and keep an approved behaviour change in its own commit
with the reason stated.
"""
import argparse
import json
import pathlib
import sys
import tempfile

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import pytest  # noqa: E402

from tests.fixtures.decomposition_baseline import TARGET_MODULES  # noqa: E402
from tests.fixtures.decomposition_baseline import capture  # noqa: E402
from tests.fixtures.decomposition_baseline import cli_matrix  # noqa: E402
from tests.fixtures.decomposition_baseline import stable  # noqa: E402
from tests.fixtures.decomposition_baseline.stable import dumps  # noqa: E402

_SECTIONS = {
    "contract": (capture.SURFACE_CONTRACT,),
    "structure": (capture.SURFACE_STRUCTURE,),
    "consumers": (capture.CONSUMERS,),
    "seams": (capture.SEAMS,),
    "coverage": (capture.COVERAGE_CORPUS,),
    "records": (capture.RECORD_CORPUS,),
}


def _cli_goldens() -> "tuple[dict, list]":
    out, skipped = {}, []
    for scenario in cli_matrix.SCENARIOS:
        if scenario.needs_yara and not cli_matrix.yara_available():
            skipped.append(f"cli/{scenario.name} (yara-python not installed)")
            continue
        mp = pytest.MonkeyPatch()
        try:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                out[cli_matrix.golden_name(scenario)] = cli_matrix.run_scenario(scenario, mp, tmp)
        finally:
            mp.undo()
    return out, skipped


def _drops(parser, values) -> dict:
    out = {}
    for value in values:
        module, _, name = value.partition(":")
        if module not in TARGET_MODULES or not name:
            parser.error(f"--drop expects <target module>:<name>, got {value!r}")
        if name not in capture.committed_names(module):
            parser.error(f"--drop {value}: the committed baseline holds no such name")
        out.setdefault(module, set()).add(name)
    return out


def _seam_drops(parser, values) -> set:
    known = capture.committed_seams()
    out = set()
    for value in values:
        module, _, name = value.partition(":")
        if (module, name) not in known:
            parser.error(f"--drop-seam {value}: the committed seam inventory holds no such entry")
        out.add((module, name))
    return out


def _only_additions(old: bytes, new: bytes) -> bool:
    """True when `new` is `old` with entries added and none removed or
    changed (dict keys and list members, recursively)."""
    def covers(a, b):
        if isinstance(a, dict) and isinstance(b, dict):
            return all(k in b and covers(v, b[k]) for k, v in a.items())
        if isinstance(a, list) and isinstance(b, list):
            return all(x in b for x in a)
        return a == b
    return covers(json.loads(old), json.loads(new))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--check", action="store_true",
                        help="compare against the committed goldens; never write")
    parser.add_argument("--allow-skip", action="store_true",
                        help="with --check: do not fail when a scenario cannot run here")
    parser.add_argument("--drop", action="append", default=[], metavar="MODULE:NAME",
                        help="remove a name from the sticky export/value/definition lists")
    parser.add_argument("--drop-seam", action="append", default=[], metavar="MODULE:NAME",
                        help="remove an entry from the seam inventory")
    parser.add_argument("sections", nargs="*",
                        help=f"sections to process: {', '.join([*_SECTIONS, 'cli'])} "
                             f"(default: all)")
    args = parser.parse_args(argv)
    unknown = sorted(set(args.sections) - {*_SECTIONS, "cli"})
    if unknown:
        parser.error(f"unknown section(s): {', '.join(unknown)}")
    sections = list(args.sections or [*_SECTIONS, "cli"])
    drops, seam_drops = _drops(parser, args.drop), _seam_drops(parser, args.drop_seam)
    if drops:
        sections += [s for s in ("contract", "structure") if s not in sections]
    if seam_drops and "seams" not in sections:
        sections.append("seams")

    results, skipped = {}, []
    static = [s for s in sections if s in _SECTIONS]
    if static:
        results.update(capture.capture_static_goldens(
            drops=drops, seam_drops=seam_drops, sections=static))
    if "cli" in sections:
        cli_results, skipped = _cli_goldens()
        results.update(cli_results)

    golden = pathlib.Path(stable.GOLDEN_DIR)
    changed, additions = [], []
    for name, data in sorted(results.items()):
        path = golden / name
        expected = dumps(data)
        existing = path.read_bytes() if path.exists() else None
        if existing == expected:
            continue
        if (name in capture.INVENTORY_GOLDENS and existing is not None and not seam_drops
                and _only_additions(existing, expected)):
            additions.append(name)
        else:
            changed.append(name)
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)

    if "cli" in sections:
        known = {cli_matrix.golden_name(s) for s in cli_matrix.SCENARIOS}
        for stale in sorted((golden / "cli").glob("*.json")):
            name = f"cli/{stale.name}"
            if name not in known:
                changed.append(f"{name} (no such scenario)")
                if not args.check:
                    stale.unlink()

    verb = "would change" if args.check else "updated"
    for name in changed:
        print(f"  {verb}: {name}")
    for name in additions:
        print(f"  {'would record' if args.check else 'recorded'} new inventory entries: {name}")
    for name in skipped:
        print(f"  skipped: {name}")
    stale = capture.stale_seams() if "seams" in sections else []
    for entry in stale:
        print(f"  stale seam inventory entry: {entry} -- remove it with --drop-seam")
    if not (changed or additions or skipped or stale):
        print("  decomposition baseline is up to date")
    if not args.check:
        return 0
    return 1 if (changed or stale or (skipped and not args.allow_skip)) else 0


if __name__ == "__main__":
    sys.exit(main())

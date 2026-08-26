"""
Regenerate (or, with --check, verify) the `--hunt` CLI golden fixtures in
tests/fixtures/hunt_cli_golden/ that tests/integration/test_hunt_cli_compat_
freeze.py diffs against.

This is the single committed generator for those fixtures. It shares
tests/fixtures/hunt_cli_scenarios.py's `SCENARIOS` table (the same
FakeMF constructions the tests themselves parametrize over) and tests/
fixtures/hunt_cli_harness.py's `run_cli()`/`split_console_body()` (the same
CLI-invocation harness, including the frozen datetime and rules-loader
reset) with test_hunt_cli_compat_freeze.py -- so "what produces a golden"
and "what checks against it" can never independently drift.

Usage:
    python scripts/update_hunt_cli_goldens.py            # regenerate all, write to disk
    python scripts/update_hunt_cli_goldens.py --check     # regenerate in memory, diff
                                                           # against what's on disk, exit
                                                           # nonzero (and print which
                                                           # files differ) if anything
                                                           # would change -- CI-friendly,
                                                           # never writes
    python scripts/update_hunt_cli_goldens.py injection stomping_ioc_hit
                                                           # only these scenario names
                                                           # (+ "all" for the NOT_EVALUATED
                                                           # --hunt-all fixture)

Every scenario in tests/fixtures/hunt_cli_scenarios.py's `SCENARIOS` is
regenerated normal AND --verbose (writing/checking <name>_hunt_dict.json,
<name>_console.txt, <name>_verbose_console.txt), plus the "all"
NOT_EVALUATED scenario (all_hunt_dict.json/all_console.txt, no --verbose
variant -- test_hunt_all_all_not_evaluated
doesn't have one either, see its own docstring). yara-needing scenarios
are skipped with a warning (not an error) if yara-python isn't installed,
matching pytest.importorskip's behavior in the test suite itself.

Path/newline/encoding policy (must match exactly, or every scenario's
CI job would show a spurious diff on the other OS in the test matrix):
  - Every file is UTF-8, LF-only, compared and written as BYTES (not
    `str`/`open(..., "r")`/`.read_text()`) -- text-mode reads apply
    universal-newline translation, which would silently accept a CRLF file
    on disk as "matching" an LF string in memory and defeat the entire
    point of an exact-format check. tests/fixtures/hunt_cli_golden/ is
    additionally pinned to `text eol=lf` in .gitattributes so a Windows
    `git checkout` can't reintroduce CRLF into a fixture this script wrote
    as LF -- the byte-level check here catches it even if that pin were
    ever missing or wrong.
  - hunt_dict.json is `json.dumps(..., indent=2, sort_keys=True)` (default
    `ensure_ascii=True`, so non-ASCII text like em-dashes round-trips as a
    backslash-u escape sequence) + a trailing newline, matching every
    existing fixture's own formatting.
  - The one live-heap-address / dynamic-rules-directory-path segment each
    fixture can contain is normalized exactly the way the test-side
    assertions normalize it before comparing (see
    tests.fixtures.hunt_cli_harness.normalize_object_addresses and
    BuiltScenario.rules_dir's "<RULES_DIR>" substitution below) -- this
    script and the tests must apply the IDENTICAL normalization or a
    passing `--check` here would not guarantee a passing pytest run.

Every scenario's `tmp_path` is a `tempfile.TemporaryDirectory()` --
cleaned up (dump file, --ref-dir/--yara-dir contents, --json output)
before this script moves on to the next scenario, not left behind the way
a bare `tempfile.mkdtemp()` would be for every one of the ~19 normal/
--verbose runs a full regen does.
"""
import argparse
import json
import pathlib
import sys
import tempfile

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from tests.fixtures.hunt_cli_harness import run_cli, split_console_body, normalize_object_addresses
from tests.fixtures.hunt_cli_scenarios import SCENARIOS

GOLDEN = _REPO_ROOT / "tests" / "fixtures" / "hunt_cli_golden"


def _write_text(results: dict, path: pathlib.Path, text: str) -> None:
    """Buffers into `results` (for --check) or writes to disk with the
    fixed LF/UTF-8/byte-level policy this module's own docstring
    specifies -- `text` is encoded to bytes here, at buffer time, so
    `_flush()`'s comparison and write are byte-for-byte from a single
    source of truth."""
    results[path] = text.encode("utf-8")


def _flush(results: dict, check_only: bool) -> list:
    """Returns the list of paths whose on-disk content (if any) differs
    from `results`, comparing raw bytes (never a text-mode read, which
    would silently normalize CRLF to LF and defeat this check -- see this
    module's own docstring). Writes every entry to disk first unless
    `check_only`."""
    changed = []
    for path, expected_bytes in results.items():
        existing_bytes = path.read_bytes() if path.exists() else None
        if existing_bytes != expected_bytes:
            changed.append(path)
        if not check_only:
            path.write_bytes(expected_bytes)
    return changed


def _generate_scenario(name: str, results: dict) -> None:
    scenario = SCENARIOS[name]
    if scenario.needs_yara:
        try:
            import yara  # noqa: F401
        except ImportError:
            print(f"  [skip] {name}: yara-python not installed")
            return

    json_path = GOLDEN / f"{scenario.name}_hunt_dict.json"
    record_for_diff = None
    for verbose in (False, True):
        mp = pytest.MonkeyPatch()
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = pathlib.Path(tmp_dir)
                built = scenario.build(mp, tmp_path)
                argv = ["--hunt", scenario.ttp, *built.extra_argv]
                if verbose:
                    argv.append("--verbose")
                exit_code, doc, console = run_cli(mp, tmp_path, argv, built.mf)

                assert exit_code == scenario.expected_exit_code, (
                    f"{name} ({'verbose' if verbose else 'normal'}): expected exit code "
                    f"{scenario.expected_exit_code}, got {exit_code}")

                record = normalize_object_addresses(doc["result"]["data"]["records"][0])
                body = split_console_body(console)
                if built.rules_dir is not None:
                    body = body.replace(str(built.rules_dir), "<RULES_DIR>")

                if scenario.extra_checks is not None:
                    scenario.extra_checks(exit_code, doc, body)
        finally:
            mp.undo()

        if verbose:
            # --verbose must never change the JSON record --
            # enforced here (not just asserted in the test suite) so a
            # divergence is caught at generation time, not discovered as a
            # pytest failure after the goldens were already (wrongly)
            # regenerated to match it.
            assert record == record_for_diff, (
                f"{name}: --verbose changed the JSON record -- Finding.print()'s "
                f"verbose/facts_mode parameters must never affect to_dict()")
        else:
            record_for_diff = record
            _write_text(results, json_path,
                        json.dumps(record, indent=2, sort_keys=True) + "\n")

        console_variant = "verbose_console" if verbose else "console"
        _write_text(results, GOLDEN / f"{scenario.name}_{console_variant}.txt", body)

    print(f"  [ok]   {name}")


def _generate_all_not_evaluated(results: dict) -> None:
    from tests.fixtures.fakes import FakeMF
    mp = pytest.MonkeyPatch()
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = pathlib.Path(tmp_dir)
            mf = FakeMF()
            rules_dir = tmp_path / "empty_rules"
            rules_dir.mkdir()
            exit_code, doc, console = run_cli(
                mp, tmp_path, ["--hunt", "all", "--yara-dir", str(rules_dir)], mf)

            assert exit_code == 4, f"all: expected EXIT_NOT_EVALUATED (4), got {exit_code}"
            records = normalize_object_addresses(doc["result"]["data"]["records"])
            body = split_console_body(console).replace(str(rules_dir), "<RULES_DIR>")
    finally:
        mp.undo()

    _write_text(results, GOLDEN / "all_hunt_dict.json",
                json.dumps(records, indent=2, sort_keys=True) + "\n")
    _write_text(results, GOLDEN / "all_console.txt", body)
    print("  [ok]   all")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*",
                         help="Scenario names to regenerate (default: every SCENARIOS "
                              "entry + 'all'). Scenario names are tests/fixtures/"
                              "hunt_cli_scenarios.py's SCENARIOS keys.")
    parser.add_argument("--check", action="store_true",
                         help="Don't write -- exit nonzero and list any fixture that "
                              "would change.")
    args = parser.parse_args()

    all_names = list(SCENARIOS) + ["all"]
    names = args.names or all_names
    unknown = [n for n in names if n not in all_names]
    if unknown:
        parser.error(f"unknown scenario name(s): {', '.join(unknown)} -- known: {', '.join(all_names)}")

    print(f"{'Checking' if args.check else 'Regenerating'} {len(names)} scenario(s)...")
    results = {}
    for name in names:
        if name == "all":
            _generate_all_not_evaluated(results)
        else:
            _generate_scenario(name, results)

    changed = _flush(results, args.check)
    if args.check:
        if changed:
            print(f"\n{len(changed)} fixture(s) are stale:")
            for path in changed:
                print(f"  {path.relative_to(_REPO_ROOT)}")
            print("\nRun `python scripts/update_hunt_cli_goldens.py` to refresh them.")
            return 1
        print("\nAll golden fixtures are up to date.")
        return 0

    if changed:
        print(f"\nWrote {len(changed)} changed fixture(s):")
        for path in changed:
            print(f"  {path.relative_to(_REPO_ROOT)}")
    else:
        print("\nNo fixtures changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

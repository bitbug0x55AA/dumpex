"""Consistency checks between pyproject.toml's `minidump` version pin and
the .github/workflows/tests.yml `minidump-version-range` CI job (issue
#86 review, P2-B): the CI job's version matrix is a hand-written literal
list, not derived from pyproject.toml, so nothing previously stopped
someone from widening the pyproject.toml range without updating the CI
matrix to match -- the job would keep installing only the OLD pinned
version and reporting green, "proving" a range that was never actually
installed. This file is the PR-time tripwire for that drift: it fails
red the moment the two files disagree, without requiring a network call
or a dynamically-computed CI matrix.

Deliberately checks a SUBSET relationship (floor must be covered, every
matrix entry must be in-range), not exact equality against a computed
"floor and ceiling" pair: an earlier version of this test asserted
`matrix == {floor, highest_allowed}`, which (a) made adding MORE matrix
coverage (e.g. a mid-range version) itself a failure, and (b) computed
"highest_allowed" as floor/ceiling arithmetic on version NUMBERS, not a
release that necessarily exists on PyPI -- its own failure message could
tell a maintainer to add a matrix entry for a version `pip install`
can't find. Which actual released version(s) besides the floor belong in
the matrix is a maintainer judgment call (see the comment on the
minidump-version-range job in tests.yml), not something this test
derives or enforces.
"""
import re
from pathlib import Path

import yaml
from packaging.specifiers import SpecifierSet

REPO_ROOT = Path(__file__).resolve().parents[2]


def _minidump_specifier() -> SpecifierSet:
    """Parse pyproject.toml's `dependencies` list for the `minidump`
    entry's version specifier and return it as a packaging.specifiers.
    SpecifierSet, so all range/containment logic is delegated to
    `packaging` (already a `dev` extras dependency -- packaging>=24.0 in
    pyproject.toml) rather than hand-rolled version-tuple arithmetic. A
    plain regex locates the raw `"minidump..."` string (rather than a
    full TOML parser) because dumpex supports Python 3.10, which has no
    stdlib `tomllib` (3.11+) -- but everything AFTER extracting that
    string is standard PEP 440 parsing via `packaging`, not hand-rolled."""
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'"minidump([^"]*)"', pyproject_text)
    assert match, (
        'pyproject.toml has no "minidump..." dependency entry -- update '
        "the regex in tests/unit/test_minidump_version_pin.py if the "
        "dependency's declaration shape changed")
    return SpecifierSet(match.group(1))


def _specifier_floor(spec: SpecifierSet) -> str:
    """The version string from `spec`'s lower-bound clause (`>=`, `>`,
    `==`, or `~=`), e.g. "0.0.24" from ">=0.0.24,<0.0.25". Asserts
    exactly one such clause exists -- dumpex's minidump pin is expected
    to declare an explicit floor per issue #86; a specifier with zero or
    multiple lower-bound clauses would make the "floor must be in the CI
    matrix" check below either meaningless or ambiguous."""
    floors = [str(s.version) for s in spec if s.operator in (">=", ">", "==", "~=")]
    assert len(floors) == 1, (
        f"expected exactly one lower-bound clause in the minidump "
        f"specifier {spec}, found {floors} -- update _specifier_floor() "
        f"in tests/unit/test_minidump_version_pin.py if the specifier "
        f"shape changed")
    return floors[0]


def _ci_matrix_minidump_versions() -> list:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["minidump-version-range"]
    return job["strategy"]["matrix"]["minidump-version"]


def test_ci_matrix_covers_the_declared_floor_and_stays_within_the_specifier():
    spec = _minidump_specifier()
    floor = _specifier_floor(spec)
    matrix = _ci_matrix_minidump_versions()

    assert floor in matrix, (
        f"pyproject.toml's minidump specifier is {spec}, but its floor "
        f"({floor}) is not in the minidump-version-range CI job's matrix "
        f"{matrix} -- add it in .github/workflows/tests.yml.")

    out_of_range = [v for v in matrix if not spec.contains(v)]
    assert not out_of_range, (
        f"the minidump-version-range CI job's matrix {matrix} contains "
        f"version(s) {out_of_range} that pyproject.toml's minidump "
        f"specifier {spec} does not allow -- either the CI matrix or the "
        f"pyproject.toml specifier is stale; reconcile them.")


def test_pyproject_floor_is_the_version_memory_py_documents_as_validated_against():
    # dumpex/core/memory.py:47-63 documents the three reasons for the
    # parallel HandleDataStream parser as facts about "the installed
    # library" -- the floor pin is the only place that claim is anchored
    # to a concrete version. Guards against the floor silently drifting
    # away from 0.0.24 (e.g. a careless `>=0.0.25,<0.1` edit) without
    # anyone re-reading memory.py's own reasoning against the new floor.
    floor = _specifier_floor(_minidump_specifier())
    assert floor == "0.0.24", (
        f"minidump floor changed to {floor} -- re-validate the three "
        f"reasons documented at dumpex/core/memory.py:47-63 against this "
        f"version before updating this test's expected value")

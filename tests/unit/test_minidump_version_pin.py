"""Consistency checks between pyproject.toml's `minidump` version pin and
the .github/workflows/tests.yml `minidump-version-range` CI job (issue
#86 review, P2-B), plus direct checks that the pin itself actually
excludes the next unreviewed upstream release (issue #86 review rounds
4-5): a prior version of this file's regex happened to require a
`,<A.B.C` clause to even parse the specifier, which incidentally
enforced an upper bound as a side effect of matching a fixed shape.
Generalizing that regex to accept any PEP 440 specifier (round 3)
silently dropped that enforcement -- `"minidump>=0.0.24"` or
`"minidump~=0.0.24"` would both have passed every check in this file
while re-opening issue #86 Part A's original defect (no upper bound,
`pip install --upgrade` can pull in anything). Round 4 added
_specifier_has_upper_bound() to catch that.

Round 5 found _specifier_has_upper_bound() itself checks a PROXY for the
real requirement, not the requirement: it only asks "does a bounding
clause exist", which a deliberately WIDE one (`<1.0`, `<=0.0.99`,
`<9999`) still satisfies while admitting every unreviewed release
between the floor and that ceiling -- the same failure as no bound at
all, just with extra steps, and `<1.0` in particular is the first
instinct most people reach for when "widening the range." The real
requirement is test_specifier_excludes_the_next_unreviewed_release()
below: the version immediately above the floor must be excluded, checked
directly via SpecifierSet.contains() rather than inferred from clause
shape. _specifier_has_upper_bound() is kept as an earlier, friendlier
pre-check (its failure message is easier to act on than "0.0.25 is
admitted"), but it is no longer the sole guarantee.

The "next unreviewed release" probe computed here (_next_patch_above())
is NOT the same kind of computation as the "highest allowed version"
arithmetic removed in round 3: that one had to be a version that
actually exists on PyPI and is `pip install`-able, because its failure
message told a maintainer to add it to the CI matrix. This probe is
never installed and never added to any matrix -- it exists only to be
handed to `SpecifierSet.contains()`, so it doesn't matter whether a
release with that exact number ever ships.

The CI-matrix check (test_ci_matrix_covers_the_declared_floor_and_stays_
within_the_specifier) deliberately checks a SUBSET relationship (floor
must be covered, every matrix entry must be in-range), not exact
equality against a computed "floor and ceiling" pair -- see that
function's own history for why exact equality was wrong. Which actual
released version(s) besides the floor belong in the matrix is a
maintainer judgment call (see the comment on the minidump-version-range
job in tests.yml), not something this test derives or enforces.
"""
import re
from pathlib import Path

import pytest
import yaml
from packaging.specifiers import SpecifierSet
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[2]


def _dependencies_block_text() -> str:
    """The raw text of pyproject.toml's `dependencies = [...]` array
    (the project's required dependencies -- NOT optional-dependencies or
    dev extras), so `_minidump_specifier()` can only ever match a
    `"minidump..."` string that appears INSIDE that array, not e.g. a
    comment, an unrelated table, or some future optional-dependencies
    entry elsewhere in the file that happens to also mention minidump.
    Anchored to a line starting with `dependencies =` (not merely
    containing the substring "dependencies", which would also match a
    hypothetical `test-dependencies = [...]` key) and reads up to the
    array's own closing `]` -- safe because this array holds only flat
    version-string literals, never a nested list."""
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^dependencies\s*=\s*\[', pyproject_text, re.MULTILINE)
    assert match, (
        "pyproject.toml has no `dependencies = [...]` array at the start "
        "of a line -- update the regex in "
        "tests/unit/test_minidump_version_pin.py if pyproject.toml's "
        "structure changed")
    start = match.end()
    end = pyproject_text.index("]", start)
    return pyproject_text[start:end]


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
    match = re.search(r'"minidump([^"]*)"', _dependencies_block_text())
    assert match, (
        'no "minidump..." entry inside pyproject.toml\'s '
        "`dependencies = [...]` array -- update the regex in "
        "tests/unit/test_minidump_version_pin.py if the dependency moved "
        "or its declaration shape changed")
    return SpecifierSet(match.group(1))


def _specifier_floor(spec: SpecifierSet) -> str:
    """The version string from `spec`'s single REAL inclusive lower
    bound -- only `>=` and `==` count. Deliberately excludes two operators
    that superficially "bound below" but don't behave like a floor for
    this file's purposes:
      - `>` (open lower bound): its own version is not itself an allowed
        value, so it cannot correctly be asserted "must be in the CI
        matrix" the way an inclusive floor can.
      - `~=` (compatible release): does not pin a floor independently of
        the upper bound it also implies -- see
        _specifier_has_upper_bound()'s docstring for why `~=` doesn't
        count as a real upper bound either. Lumping it in here would let
        a specifier with ONLY a `~=` clause pass both this function and
        the upper-bound check by satisfying two DIFFERENT semantic
        claims from the SAME clause, which is exactly the kind of
        contradiction-by-construction this function exists to avoid.
    Asserts exactly one such clause exists -- dumpex's minidump pin is
    expected to declare an explicit floor per issue #86; zero or
    multiple such clauses would make the "floor must be in the CI
    matrix" check either meaningless or ambiguous."""
    floors = [str(s.version) for s in spec if s.operator in (">=", "==")]
    assert len(floors) == 1, (
        f"expected exactly one inclusive lower-bound (>=/==) clause in "
        f"the minidump specifier {spec}, found {floors} -- update "
        f"_specifier_floor() in tests/unit/test_minidump_version_pin.py "
        f"if the specifier shape changed (note: `>` and `~=` are "
        f"deliberately not treated as a floor here -- see the "
        f"docstring)")
    return floors[0]


def _specifier_has_upper_bound(spec: SpecifierSet) -> bool:
    """Whether `spec` declares an upper bound that actually constrains
    what version can be installed: `<`, `<=`, or `==` (an exact pin is
    trivially its own ceiling too). `~=X.Y.Z` is deliberately NOT treated
    as an upper bound here: for minidump's 0.0.x-only release history,
    `~=0.0.24` means ">=0.0.24, ==0.0.*" -- it still allows 0.0.25,
    0.0.99, etc. That's "no real protection" for exactly the failure
    issue #86 exists to prevent (an unreviewed upstream release becoming
    installed), even though `~=` superficially looks like a bound."""
    return any(s.operator in ("<", "<=", "==") for s in spec)


def _next_patch_above(version_str: str) -> str:
    """The next patch release above `version_str`, assuming X.Y.Z
    versioning -- true for every minidump release to date -- e.g.
    "0.0.25" from "0.0.24". Used purely as a probe for "the next, as yet
    unreviewed, upstream release": handed to SpecifierSet.contains(),
    never installed and never added to any CI matrix, so unlike the
    "highest allowed version" arithmetic removed in round 3 there is no
    risk of pointing a maintainer at a version that doesn't exist on
    PyPI -- see this module's docstring."""
    v = Version(version_str)
    return f"{v.major}.{v.minor}.{v.micro + 1}"


def _ci_matrix_minidump_versions() -> list:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["minidump-version-range"]
    return job["strategy"]["matrix"]["minidump-version"]


def test_specifier_declares_an_explicit_upper_bound():
    # An early, friendlier pre-check -- "there is no bound at all" gets a
    # clearer failure message here than from
    # test_specifier_excludes_the_next_unreviewed_release() below, which
    # is what actually enforces the real requirement (a wide-but-present
    # bound like `<1.0` passes THIS check while still failing that one;
    # see this module's docstring).
    spec = _minidump_specifier()
    assert _specifier_has_upper_bound(spec), (
        f"pyproject.toml's minidump specifier {spec} has no upper bound "
        f"(a `~=` clause alone does not count -- see "
        f"_specifier_has_upper_bound()'s docstring) -- issue #86 requires "
        f"one so an unreviewed upstream release cannot silently become "
        f"the installed version")


def test_specifier_excludes_the_next_unreviewed_release():
    # The actual requirement, not a proxy for it (see this module's
    # docstring for how _specifier_has_upper_bound() alone is a proxy
    # that a deliberately wide ceiling like `<1.0` still satisfies):
    # the version immediately above the floor must be excluded.
    spec = _minidump_specifier()
    probe = _next_patch_above(_specifier_floor(spec))
    assert not spec.contains(probe), (
        f"minidump specifier {spec} still admits {probe} -- issue #86 "
        f"requires the ceiling to exclude the next unreviewed upstream "
        f"release, not merely to exist. Widening the floor requires "
        f"re-validating dumpex/core/memory.py:47-63 against the new "
        f"floor version -- update "
        f"test_pyproject_floor_is_the_version_memory_py_documents_as_"
        f"validated_against in the same change.")


@pytest.mark.parametrize("specifier_str", [
    ">=0.0.24,<1.0",      # the "first instinct" wide ceiling flagged in review
    ">=0.0.24,<=0.0.99",
    ">=0.0.24,<9999",
    ">=0.0.24",           # no ceiling at all
])
def test_specifier_excludes_the_next_unreviewed_release_meta(specifier_str):
    # Meta-test: proves test_specifier_excludes_the_next_unreviewed_
    # release() is able to fail against a specifier that HAS an upper
    # bound (so _specifier_has_upper_bound() alone would wrongly call it
    # safe) but still admits the very next release.
    spec = SpecifierSet(specifier_str)
    probe = _next_patch_above(_specifier_floor(spec))
    assert spec.contains(probe), (
        f"expected {specifier_str} to (wrongly) admit the next "
        f"unreviewed release {probe} for this meta-test to be "
        f"meaningful -- if it doesn't, this fixture no longer "
        f"demonstrates the intended failure mode")


@pytest.mark.parametrize("version_str,expected_next", [
    ("0.0.24", "0.0.25"),
    ("1.2.9", "1.2.10"),
])
def test_next_patch_above(version_str, expected_next):
    assert _next_patch_above(version_str) == expected_next


@pytest.mark.parametrize("specifier_str,expected_floor", [
    (">=0.0.24,<0.0.25", "0.0.24"),
    ("==0.0.24", "0.0.24"),
])
def test_specifier_floor_accepts_real_inclusive_lower_bounds(specifier_str, expected_floor):
    assert _specifier_floor(SpecifierSet(specifier_str)) == expected_floor


@pytest.mark.parametrize("specifier_str", [
    ">0.0.24,<0.0.26",   # open lower bound -- 0.0.24 itself isn't installable
    "~=0.0.24",          # compatible-release only, no >=/== clause
    "",                  # the original, all-unconstrained #86 bug shape
])
def test_specifier_floor_rejects_non_inclusive_or_missing_lower_bound(specifier_str):
    # Meta-test for _specifier_floor() itself: it must be ABLE to fail,
    # not merely happen to succeed on today's real pyproject.toml value.
    with pytest.raises(AssertionError):
        _specifier_floor(SpecifierSet(specifier_str))


@pytest.mark.parametrize("specifier_str,expected", [
    (">=0.0.24,<0.0.25", True),
    ("==0.0.24", True),
    (">=0.0.24,<=0.0.30", True),
    (">=0.0.24", False),   # the exact regression this check exists to catch
    ("~=0.0.24", False),   # looks bounded, isn't -- see docstring
    ("", False),
])
def test_specifier_has_upper_bound_table(specifier_str, expected):
    # Meta-test for _specifier_has_upper_bound(): proves it can say both
    # True and False, and specifically that `~=` alone is correctly
    # rejected rather than mistaken for real protection.
    assert _specifier_has_upper_bound(SpecifierSet(specifier_str)) == expected


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

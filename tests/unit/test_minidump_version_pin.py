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
"""
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def _minidump_specifier_bounds() -> tuple:
    """Parse pyproject.toml's `dependencies` list for the `minidump`
    entry and return ((floor_major, floor_minor, floor_patch),
    (ceiling_major, ceiling_minor, ceiling_patch)) from a
    `minidump>=X.Y.Z,<A.B.C` specifier. A plain regex over the raw text
    (rather than a full TOML parser) is deliberate: dumpex supports
    Python 3.10, which has no stdlib `tomllib` (3.11+), and pulling in a
    TOML dependency just for this one test isn't worth it."""
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(
        r'"minidump>=(\d+\.\d+\.\d+),<(\d+\.\d+\.\d+)"', pyproject_text)
    assert match, (
        "pyproject.toml's minidump dependency no longer matches the "
        "'minidump>=X.Y.Z,<A.B.C' shape this test parses -- update the "
        "regex in tests/unit/test_minidump_version_pin.py to match "
        "whatever the new specifier looks like")
    floor = tuple(int(p) for p in match.group(1).split("."))
    ceiling = tuple(int(p) for p in match.group(2).split("."))
    return floor, ceiling


def _highest_version_below_ceiling(ceiling: tuple) -> tuple:
    """The highest X.Y.Z release that would satisfy `< ceiling`, assuming
    -- as documented on the pyproject.toml dependency line and matching
    minidump's actual release history (every release to date is 0.0.x,
    incrementing the last component by exactly 1) -- that the next
    version below any given one differs only by decrementing the last
    component. This is a heuristic specific to minidump's own versioning
    scheme, not a general PEP 440 "previous version" computation."""
    assert ceiling[-1] > 0, (
        f"cannot derive a version below {'.'.join(map(str, ceiling))} by "
        f"decrementing its last component -- update this heuristic if "
        f"minidump's versioning scheme changes")
    return ceiling[:-1] + (ceiling[-1] - 1,)


def _ci_matrix_minidump_versions() -> list:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["minidump-version-range"]
    return job["strategy"]["matrix"]["minidump-version"]


def test_ci_matrix_installs_both_the_declared_floor_and_the_highest_allowed_version():
    floor, ceiling = _minidump_specifier_bounds()
    highest_allowed = _highest_version_below_ceiling(ceiling)

    expected = sorted({
        ".".join(map(str, floor)),
        ".".join(map(str, highest_allowed)),
    })
    actual = sorted(_ci_matrix_minidump_versions())

    assert actual == expected, (
        f"pyproject.toml declares minidump>={'.'.join(map(str, floor))},"
        f"<{'.'.join(map(str, ceiling))}, so the minidump-version-range CI "
        f"job's matrix should install {expected}, but currently installs "
        f"{actual}. Update the `minidump-version` matrix in "
        f".github/workflows/tests.yml's minidump-version-range job to "
        f"match -- widening the pyproject.toml range does not "
        f"automatically widen what CI actually installs.")


def test_pyproject_floor_is_the_version_memory_py_documents_as_validated_against():
    # dumpex/core/memory.py:47-63 documents the three reasons for the
    # parallel HandleDataStream parser as facts about "the installed
    # library" -- the floor pin is the only place that claim is anchored
    # to a concrete version. Guards against the floor silently drifting
    # away from 0.0.24 (e.g. a careless `>=0.0.25,<0.1` edit) without
    # anyone re-reading memory.py's own reasoning against the new floor.
    floor, _ceiling = _minidump_specifier_bounds()
    assert floor == (0, 0, 24), (
        f"minidump floor changed to {'.'.join(map(str, floor))} -- "
        f"re-validate the three reasons documented at "
        f"dumpex/core/memory.py:47-63 against this version before "
        f"updating this test's expected value")

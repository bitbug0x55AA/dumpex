"""
Every `coverage report --include="<path>"` line in the CI workflow's
"Coverage gate" step must name a file that still exists in the repo --
`coverage report --include=<missing path>` prints "No data to report."
and exits 1 under the workflow's own `shell: bash` fail-fast semantics
(see .github/workflows/tests.yml's own comment: "Use the same fail-fast
native-command semantics on every runner"), taking down the whole job.

This is exactly the class of drift issue #43 hit: dumpex/commands/peb.py
was deleted in the same change that retired --pid/--peb, and the CI
workflow's own coverage-gate line for it was left behind, pointing at a
file that no longer exists. Pure manual review missed it once already --
this test makes that drift a CI failure at edit time instead of a
surprise on the next push.
"""
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "tests.yml"
_INCLUDE_RE = re.compile(r'coverage report --include="([^"]+)"')


def _gated_paths() -> list[str]:
    text = _WORKFLOW.read_text(encoding="utf-8")
    return _INCLUDE_RE.findall(text)


def test_workflow_is_reachable():
    # A silently-empty match list would make the real test below
    # vacuously pass -- guard against the regex itself drifting from the
    # workflow's actual syntax.
    assert _WORKFLOW.is_file()
    assert len(_gated_paths()) > 50


def test_every_coverage_gate_path_exists():
    missing = [path for path in _gated_paths() if not (_REPO_ROOT / path).is_file()]
    assert not missing, (
        f"{len(missing)} coverage-gate --include path(s) in "
        f"{_WORKFLOW.relative_to(_REPO_ROOT)} name a file that no longer exists "
        f"(coverage report --include=<missing path> exits 1 under the workflow's "
        f"own fail-fast bash shell, failing the whole job): {missing}")


def test_no_duplicate_coverage_gate_paths():
    # A duplicate --include line is not fatal on its own, but it is
    # exactly the kind of copy-paste leftover a deleted/renamed module
    # produces (the old line kept, a new one added) -- worth catching
    # early rather than as silent redundancy.
    paths = _gated_paths()
    seen = set()
    duplicates = sorted({p for p in paths if p in seen or seen.add(p)})
    assert not duplicates, f"duplicate coverage-gate --include path(s): {duplicates}"

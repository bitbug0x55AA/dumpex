"""
Records/memory decomposition baseline.

Captures the observable behaviour of `dumpex.output.records`,
`dumpex.core.memory` and `dumpex.output.coverage` at a declared comparison
commit, so the relocations that split those modules can be shown to change
structure only. `docs/developer/decomposition_baseline.md` documents the
baseline, what each golden file contains, which parts are supported
observable contracts and which are structural metadata, and how an
approved behaviour change refreshes an expectation.

Every golden file under `golden/` is produced by
`scripts/update_decomposition_baseline.py` and compared by
`tests/integration/test_decomposition_baseline.py`; neither side writes a
golden implicitly.
"""
import os

# The commit whose behaviour the committed goldens describe.
BASELINE_COMMIT = "601dfdebcd0eae21c819ac95206f6ffa8a4c3e9e"
BASELINE_RELEASE = "v3.9.1"

# The modules whose relocation this baseline guards, by legacy import path.
RECORDS = "dumpex.output.records"
MEMORY = "dumpex.core.memory"
COVERAGE = "dumpex.output.coverage"
TARGET_MODULES = (RECORDS, MEMORY, COVERAGE)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")

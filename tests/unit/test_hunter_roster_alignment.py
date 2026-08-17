"""
Cross-artifact alignment for the hunter roster.

`dumpex.output.records.HUNTERS` is the single source of truth for which
hunters exist and in what order they are emitted. That tuple is NOT the
only place the roster is written down, though -- the JSON schema pins it
in four separate closed enums, the console summary keys two display maps
off it, region correlation keys its collector table off it, and the CLI
help plus two docs pages spell it out for humans. None of those can be
derived from HUNTERS at runtime (a JSON file and a markdown table are
static artifacts), so each is a place an 8th hunter -- or a rename --
can be forgotten.

These tests exist to make forgetting one of them a CI failure. They
deliberately assert HUNTERS against those OTHER artifacts, never against
a second literal copy of the seven names: re-typing the roster here
would only prove this file agrees with itself, and would have to be
edited in the same commit as any roster change, which is exactly the
kind of assertion that cannot fail.

Membership/order against the runtime dispatcher is covered elsewhere and
not repeated here: tests/integration/test_hunt_all_seven_collectors.py
pins `tuple(r.hunter for r in records) == HUNTERS` from a real
`--hunt all` run, and tests/integration/test_collect_hunt_single_scan.py
parametrizes every HUNTERS name through `cmd_hunt()`.
"""
import io
import json
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import dumpex.cli as cli
import dumpex.hunt as hunt
from dumpex.hunt import region_correlation, summary_presentation
from dumpex.output.records import HUNTERS
from dumpex.schemas import CURRENT_SCHEMA, schema_path

_REPO_ROOT = Path(__file__).parents[2]


def _schema():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ── the four schema enums ────────────────────────────────────────────────
# A hunter absent from these enums produces output that fails validation
# the first time that hunter actually reports something -- which, for a
# hunter whose findings are rare, may not be on any test dump at all.

@pytest.mark.parametrize("def_name,prop_path", [
    ("hunterRecord", ("hunter",)),
    ("skipRelationship", ("hunter",)),
    ("recommendedAction", ("hunters", "items")),
])
def test_schema_hunter_enums_match_hunters(def_name, prop_path):
    node = _schema()["$defs"][def_name]["properties"][prop_path[0]]
    for extra in prop_path[1:]:
        node = node[extra]
    assert set(node["enum"]) == set(HUNTERS)
    assert len(node["enum"]) == len(set(node["enum"]))


def test_schema_hunt_summary_selected_enum_is_hunters_plus_all():
    # `selected` is the only enum that carries the extra "all" value
    # (`--hunt all`); everything else names one hunter.
    node = _schema()["$defs"]["huntSummary"]["properties"]["selected"]
    assert set(node["enum"]) == set(HUNTERS) | {"all"}


# ── in-process maps keyed by hunter name ─────────────────────────────────
# Each of these is a dict literal that a new hunter has to be added to by
# hand. A missing key does not raise at import time -- it surfaces as a
# KeyError (or a silently dropped hunter) only on a run where that hunter
# is present in the results, i.e. in front of an analyst, not in CI.

@pytest.mark.parametrize("mapping_name", ["_DISPLAY_NAME", "_EVIDENCE_HUNTER_LABEL"])
def test_summary_presentation_maps_cover_exactly_hunters(mapping_name):
    mapping = getattr(summary_presentation, mapping_name)
    assert set(mapping) == set(HUNTERS)
    assert all(label.strip() for label in mapping.values())


def test_region_correlation_collectors_cover_exactly_hunters():
    assert set(region_correlation._COLLECTORS) == set(HUNTERS)


# ── cmd_hunt()'s accepted-TTP set ────────────────────────────────────────

def test_cmd_hunt_rejects_a_ttp_outside_the_roster():
    # The validation runs before `mf` is touched at all, so no dump (real
    # or fake) is needed to reach it.
    with pytest.raises(SystemExit):
        hunt.cmd_hunt(None, "not-a-hunter", verbose=False)


def test_cmd_hunt_rejects_a_hunters_internal_module_name():
    # "obfuscation" is implemented by dumpex.hunt.encoding; the module
    # name is NOT an accepted TTP, and the accepted set must not drift
    # into carrying both. This is the concrete near-miss the derived-
    # from-HUNTERS `valid` set in cmd_hunt() protects against.
    assert "encoding" not in HUNTERS
    with pytest.raises(SystemExit):
        hunt.cmd_hunt(None, "encoding", verbose=False)


# ── human-facing artifacts ───────────────────────────────────────────────

def _hunt_help_text():
    argv = sys.argv
    sys.argv = ["dumpex", "--help"]
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            cli.main()
    except SystemExit:
        pass
    finally:
        sys.argv = argv
    text = buf.getvalue()
    start = text.index("TTP detection:") + len("TTP detection:")
    # The help entry ends at the next blank line or the next option --
    # whichever comes first, so this stays correct if --hunt stops being
    # the last option in its group.
    ends = [e for e in (text.find("\n\n", start), text.find("\n  --", start)) if e != -1]
    return " ".join(text[start:min(ends)].split())


def test_cli_hunt_help_lists_exactly_the_roster_in_order():
    listed = [name.strip() for name in _hunt_help_text().split("|")]
    assert listed == list(HUNTERS) + ["all"]


def test_cli_reference_doc_lists_exactly_the_roster_in_order():
    line = next(
        line for line in (_REPO_ROOT / "docs" / "CLI_REFERENCE.md")
        .read_text(encoding="utf-8").splitlines()
        if line.startswith("| `--hunt TTP`")
    )
    listed = re.findall(r"`([a-z-]+)`", line.split("| Run ", 1)[1])
    assert listed == list(HUNTERS) + ["all"]


def test_readme_hunt_overview_table_covers_exactly_the_roster_in_order():
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    table = readme.split("## Hunt overview", 1)[1].split("\n\n")[1]
    rows = [line for line in table.splitlines() if line.startswith("| `")]
    listed = [re.match(r"\| `([a-z-]+)`", row).group(1) for row in rows]
    assert listed == list(HUNTERS)
    # every row must actually describe the hunter, not just name it
    for row in rows:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        assert len(cells) == 3 and all(cells), row

"""
Cross-hunter invariants over the score -> verdict_level tables.

Each hunter owns its own `VERDICT_LEVEL_BY_SCORE` / `MAX_SCORE` in its
own domain module, deliberately: a stomping 2 and an injection 2 are not
the same claim, so there is no shared formula (see
`dumpex.hunt._finding.verdict_level`'s docstring). "Owns its own table"
is not the same as "any table is fine", though -- a table has to satisfy
several properties to mean anything at all, and none of them is checked
by re-typing the table's literal contents into a test.

The property that matters most: `verdict_level()` looks the score up with
`level_by_score.get(score, VERDICT_POSSIBLE)`. A hunter that gains a
scoring signal -- MAX_SCORE goes 2 -> 3 -- but whose table is not
extended does not crash and does not fail a literal-echo test that was
updated alongside MAX_SCORE. It silently reports its STRONGEST evidence
(score == 3) as its WEAKEST verdict ("possible"), because 3 misses the
table and falls through to the default. `keys == {1..MAX_SCORE}` below is
what catches that.

The tables are also checked against artifacts outside the domain module:
the schema enum that closes over the values on the wire, and the severity
ranking the console's region correlation sorts by.
"""
import importlib
import json

import pytest

from dumpex.hunt._finding import (
    VERDICT_CLEAN, VERDICT_INCONCLUSIVE, VERDICT_NOT_EVALUATED, verdict_level,
)
from dumpex.hunt.region_correlation import _VERDICT_SEVERITY_RANK
from dumpex.output.records import HUNTERS
from dumpex.schemas import CURRENT_SCHEMA, schema_path

# hunter name -> the module that owns its score model. A structural map
# (which module implements which hunter), not a copy of any value in
# those modules; test_every_hunter_has_a_domain_module below pins it
# against HUNTERS so a new hunter cannot skip this file entirely.
_DOMAIN_MODULES = {
    "injection": "dumpex.hunt.injection.domain",
    "hollowing": "dumpex.hunt.hollowing.domain",
    "stomping": "dumpex.hunt.stomping.domain",
    "pipe": "dumpex.hunt.pipe.domain",
    "cs-beacon": "dumpex.hunt.cs_beacon.domain",
    "yara": "dumpex.hunt.yara_hunt.domain",
    "obfuscation": "dumpex.hunt.encoding.domain",
}

# YARA is the one hunter with no fixed ceiling: it emits max_score=None
# and derives its verdict from triggered rule severity rather than from a
# score table (dumpex/hunt/yara_hunt/report_record.py). Named here so
# that a Finding-model hunter LOSING its table is still a failure --
# without this, "no table" would silently look like "yara-style hunter".
_TABLELESS = {"yara"}


def _domain(hunter: str):
    return importlib.import_module(_DOMAIN_MODULES[hunter])


def _scored_verdicts():
    """The verdict values a SCORE can produce. clean/inconclusive/
    not_evaluated are status-driven (verdict_level() returns them before
    ever consulting the table), so a table must never contain them."""
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    enum = schema["$defs"]["hunterRecord"]["properties"]["verdict_level"]["enum"]
    return [value for value in enum
            if value not in (VERDICT_CLEAN, VERDICT_INCONCLUSIVE, VERDICT_NOT_EVALUATED)]


_TABLE_OWNERS = sorted(set(HUNTERS) - _TABLELESS)


def test_every_hunter_has_a_domain_module():
    assert set(_DOMAIN_MODULES) == set(HUNTERS)


def test_exactly_the_expected_hunters_own_a_score_table():
    with_table = {hunter for hunter in HUNTERS
                  if hasattr(_domain(hunter), "VERDICT_LEVEL_BY_SCORE")}
    assert with_table == set(HUNTERS) - _TABLELESS


def test_the_tableless_hunter_declares_no_ceiling_either():
    # A table-less hunter must also be ceiling-less; a MAX_SCORE with no
    # table to interpret it would leave `verdict_level()` defaulting to
    # "possible" for every positive score.
    for hunter in _TABLELESS:
        assert not hasattr(_domain(hunter), "MAX_SCORE")


@pytest.mark.parametrize("hunter", _TABLE_OWNERS)
def test_table_covers_every_score_up_to_the_ceiling_and_nothing_beyond(hunter):
    """The fallback bug this file exists for: a score inside 1..MAX_SCORE
    that the table does not name is reported as "possible" no matter how
    strong it is, and a key above MAX_SCORE is dead weight the record
    validation (`score <= max_score`) can never reach."""
    domain = _domain(hunter)
    assert set(domain.VERDICT_LEVEL_BY_SCORE) == set(range(1, domain.MAX_SCORE + 1))


@pytest.mark.parametrize("hunter", _TABLE_OWNERS)
def test_table_values_are_score_driven_verdicts_the_schema_accepts(hunter):
    scored = set(_scored_verdicts())
    assert set(_domain(hunter).VERDICT_LEVEL_BY_SCORE.values()) <= scored


@pytest.mark.parametrize("hunter", _TABLE_OWNERS)
def test_a_higher_score_never_means_a_weaker_verdict(hunter):
    """Ranked by the console's own severity order (region correlation
    sorts hunters by it), so a table that ranks its tiers backwards --
    or names a verdict that ranking does not know about -- fails here
    rather than showing up as a mis-sorted correlation card."""
    table = _domain(hunter).VERDICT_LEVEL_BY_SCORE
    ranks = [_VERDICT_SEVERITY_RANK[table[score]] for score in sorted(table)]
    assert all(rank > 0 for rank in ranks)
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks), "two scores share one severity tier"


@pytest.mark.parametrize("hunter", _TABLE_OWNERS)
def test_the_ceiling_score_is_the_strongest_verdict(hunter):
    domain = _domain(hunter)
    assert domain.VERDICT_LEVEL_BY_SCORE[domain.MAX_SCORE] == "high"


@pytest.mark.parametrize("hunter", _TABLE_OWNERS)
def test_every_in_range_score_resolves_through_the_table_not_the_default(hunter):
    """`verdict_level()` read back against the same table -- proving the
    `.get(score, VERDICT_POSSIBLE)` default is unreachable for any score
    a HunterRecord may actually carry, and that 0 still means clean."""
    domain = _domain(hunter)
    table = domain.VERDICT_LEVEL_BY_SCORE
    assert verdict_level(0, table, status="NOT_DETECTED_IN_SCANNED_SCOPE") == VERDICT_CLEAN
    for score in range(1, domain.MAX_SCORE + 1):
        assert verdict_level(score, table, status="DETECTED") == table[score]


@pytest.mark.parametrize("hunter", _TABLE_OWNERS)
def test_incomplete_coverage_statuses_outrank_any_table_hit(hunter):
    # A hunter that never ran, or ran over incomplete coverage, must not
    # be able to reach a score-derived verdict at all.
    domain = _domain(hunter)
    table = domain.VERDICT_LEVEL_BY_SCORE
    assert verdict_level(domain.MAX_SCORE, table, status="NOT_EVALUATED") == VERDICT_NOT_EVALUATED
    assert verdict_level(domain.MAX_SCORE, table, status="INCONCLUSIVE") == VERDICT_INCONCLUSIVE

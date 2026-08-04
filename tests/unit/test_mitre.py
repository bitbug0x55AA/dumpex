"""
Unit tests for dumpex.core.mitre.is_valid_technique_id() -- the single
shared MITRE ATT&CK id validator used by both dumpex.hunt._finding
(Finding.technique_ids) and dumpex.rules_pkg.loader (framework_pipes[].
mitre). See that module's own docstring for why it lives in its own leaf
module rather than either of those two.
"""
import pytest

from dumpex.core.mitre import is_valid_technique_id


@pytest.mark.parametrize("value", ["T1055", "T1559.001", "T1021.002", "T0001", "T9999.999"])
def test_accepts_valid_ids(value):
    assert is_valid_technique_id(value) is True


@pytest.mark.parametrize("value", [
    "not-an-attack-id",
    "1055",             # missing leading T
    "T105",              # too few digits
    "T10555",             # too many digits
    "T1055.01",            # sub-technique suffix wrong length
    "T1055.",               # trailing dot, no digits
    "t1055",                 # lowercase
    " T1055",                  # leading whitespace
    "T1055 ",                    # trailing whitespace
    "T1055\n",                     # trailing newline -- Python `$` matches
    "T1559.001\n",                   # just before a trailing newline, not
                                        # only at the true end of string
    "",
    None,
    1055,
])
def test_rejects_invalid_ids(value):
    assert is_valid_technique_id(value) is False

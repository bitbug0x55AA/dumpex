"""
MITRE ATT&CK technique/sub-technique id shape -- the ONE place this
format is defined, imported by both dumpex.hunt._finding
(Finding.technique_ids validation, at Finding-construction time) and
dumpex.rules_pkg.loader (framework_pipes[].mitre validation, at
rules.yaml/--rules-file LOAD time). Kept as its own leaf module (no
dumpex.hunt or dumpex.rules_pkg imports) specifically so neither of
those two modules has to depend on the other just to share this regex --
dumpex.rules_pkg.loader is already imported by dumpex.hunt (get_rules()),
so the reverse import (loader importing from hunt) would risk a cycle
the first time hunt's own package __init__ runs.

Validating at BOTH points matters: a malformed `mitre` string in
rules.yaml that never happens to match a pipe name in a given dump would
otherwise stay invisible forever (Finding.__post_init__ only ever raises
for a pattern that actually matched something), while a malformed
--rules-file should fail loudly at load time, before any scan runs at
all, the same way every other rules.yaml shape violation already does.
"""
import re

# No ^/$ anchors -- paired with fullmatch() below, not match()/search().
# `$` in Python's re matches "at the end of the string, or just before a
# trailing newline" (a review found this let "T1055\n"/"T1559.001\n"
# through both this validator and the v2.5 schema's own `pattern`, which
# the `jsonschema` library also checks via Python `re.search()`).
# fullmatch() requires the ENTIRE string to be consumed by the pattern,
# with no such newline exception, so a trailing "\n" is correctly
# rejected without needing a non-portable anchor like `\Z`.
TECHNIQUE_ID_RE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")


def is_valid_technique_id(value) -> bool:
    """True iff `value` is a str matching MITRE ATT&CK's own technique id
    shape ("T" + 4 digits, optionally ".003"-style sub-technique suffix
    -- e.g. "T1055", "T1559.001"), and NOTHING ELSE (no leading/trailing
    whitespace, no trailing newline -- see TECHNIQUE_ID_RE's own comment
    on why this uses fullmatch(), not match()). False for any non-str,
    including None -- never raises, so callers can use this as a plain
    predicate against untrusted/loosely-typed input (a YAML value, a
    caller-supplied kwarg) without a separate isinstance check first."""
    return isinstance(value, str) and TECHNIQUE_ID_RE.fullmatch(value) is not None

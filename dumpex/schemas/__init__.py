"""
The canonical `dumpex --json` output-contract schemas, packaged inside
dumpex so `pip install dumpex` ships them -- a bare top-level schemas/
directory next to the source checkout is never installed into a wheel
(setuptools only packages files under packages it discovers, see
pyproject.toml's [tool.setuptools.packages.find]), so a consumer with
only the installed distribution had no way to fetch these files at all.
See docs/OUTPUT_SCHEMA.md for the versioning policy.
"""
from importlib import resources

# The schema every command -- including --hunt -- now produces (see
# docs/OUTPUT_SCHEMA.md's "One JSON contract" section). Use this (or
# current_schema_path() below) in new code instead of hardcoding the
# version string; schema_path()'s own default stays pinned to v1.1 for
# backward compatibility with existing callers (see its own docstring) --
# it is NOT updated in lockstep with this constant.
CURRENT_SCHEMA = "dumpex-output-v2.8.schema.json"


def schema_path(filename: str = "dumpex-output-v1.1.schema.json"):
    """Path to a packaged schema file, usable as a context manager (works
    whether the package is on disk or inside a zipped wheel). Defaults to
    the v1.1 schema for backward compatibility with existing callers that
    already depend on that default (e.g. tests/integration/
    test_json_schema.py, which validates dumpex.ui.structured.
    StructuredOutput -- the legacy v1.1-shaped writer -- against it) --
    this default is deliberately NOT changed to track the current schema;
    use CURRENT_SCHEMA/current_schema_path() for that instead. Pass
    "dumpex-output-v2.8.schema.json" (or CURRENT_SCHEMA) for the current
    v2 contract every command, including --hunt, now produces, or
    "dumpex-output-v2.7.schema.json"/"dumpex-output-v2.6.schema.json"/
    "dumpex-output-v2.5.schema.json"/
    "dumpex-output-v2.4.schema.json"/"dumpex-output-v2.3.schema.json"/
    "dumpex-output-v2.2.schema.json"/"dumpex-output-v2.1.schema.json"/
    "dumpex-output-v2.0.schema.json" for the frozen historical
    v2.7/v2.6/v2.5/v2.4/v2.3/v2.2/v2.1/v2.0 schemas (still valid for
    validating output produced before schema_version
    2.8/2.7/2.6/2.5/2.4/2.3/2.2/2.1
    respectively -- v2.7's own `coverageLimitation` is closed
    (`additionalProperties: false`) around a field set that does NOT
    include the `targets` array v2.8 adds, so v2.8 output fails against
    it; v2.6's own `csBeaconDetails` still describes
    `configs[*].fields[*]` as numeric-ID-keyed with a `name` property, the
    shape v2.7 replaced; v2.5's own `csBeaconDetails` still describes
    `configs[*].fields[*]` as carrying the `raw` hex field v2.6 removed;
    v2.4's own `finding` $def does NOT accept the id/severity/
    technique_ids/evidence_refs/iocs/rule_id/rule_version properties v2.5
    adds; and v2.3 does NOT accept result.kind == "hunt" at all: a closed
    enum's/object's already-shipped copy must never start silently
    accepting a value or field it didn't originally define)."""
    return resources.as_file(
        resources.files(__name__).joinpath(filename)
    )


def current_schema_path():
    """Path to CURRENT_SCHEMA (the v2.8 contract every command, including
    --hunt, now produces) -- usable as a context manager, same as
    schema_path(). Prefer this over schema_path() with no arguments, whose
    default stays pinned to v1.1 for backward compatibility (see its own
    docstring)."""
    return schema_path(CURRENT_SCHEMA)

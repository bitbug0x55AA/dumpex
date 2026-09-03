"""
The canonical `dumpex --json` output-contract schemas, packaged inside
dumpex so `pip install dumpex` ships them -- a bare top-level schemas/
directory next to the source checkout is never installed into a wheel
(setuptools only packages files under packages it discovers, see
pyproject.toml's [tool.setuptools.packages.find]), so a consumer with
only the installed distribution had no way to fetch these files at all.
See docs/user/OUTPUT_MIGRATION.md for the versioning policy.
"""
from importlib import resources

# The schema every command -- including --hunt -- now produces (see
# docs/user/OUTPUT_SCHEMA.md's "Current contract" section). Use this (or
# current_schema_path() below) in new code instead of hardcoding the
# version string; schema_path()'s own default stays pinned to v1.1 for
# backward compatibility with existing callers (see its own docstring) --
# it is NOT updated in lockstep with this constant.
CURRENT_SCHEMA = "dumpex-output-v2.16.schema.json"


def schema_path(filename: str = "dumpex-output-v1.1.schema.json"):
    """Return a context manager for the requested packaged schema.

    Calling without a filename still selects v1.1 for compatibility with
    existing callers. New code should use current_schema_path() or pass
    CURRENT_SCHEMA for the current contract. Historical schema policy is
    documented in docs/user/OUTPUT_MIGRATION.md.
    """
    return resources.as_file(
        resources.files(__name__).joinpath(filename)
    )


def current_schema_path():
    """Path to CURRENT_SCHEMA (the v2.16 contract every command, including
    --hunt, now produces) -- usable as a context manager, same as
    schema_path(). Prefer this over schema_path() with no arguments, whose
    default stays pinned to v1.1 for backward compatibility (see its own
    docstring)."""
    return schema_path(CURRENT_SCHEMA)

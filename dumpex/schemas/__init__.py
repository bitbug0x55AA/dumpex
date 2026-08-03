"""
The canonical `dumpex --json` output-contract schema, packaged inside
dumpex so `pip install dumpex` ships it -- a bare top-level schemas/
directory next to the source checkout is never installed into a wheel
(setuptools only packages files under packages it discovers, see
pyproject.toml's [tool.setuptools.packages.find]), so a consumer with
only the installed distribution had no way to fetch this file at all.
See docs/OUTPUT_SCHEMA.md for the versioning policy.
"""
from importlib import resources


def schema_path(filename: str = "dumpex-output-v1.1.schema.json"):
    """Path to a packaged schema file, usable as a context manager (works
    whether the package is on disk or inside a zipped wheel). Defaults to
    the v1.1 (--hunt) schema for backward compatibility -- --hunt stays on
    v1.1 until the CLI's atomic switch onto v2 (see
    docs/hunt_migration_field_matrix.md); pass
    "dumpex-output-v2.4.schema.json" for the current v2 (recon commands,
    comparison, extract, strings, report) schema, or
    "dumpex-output-v2.3.schema.json"/"dumpex-output-v2.2.schema.json"/
    "dumpex-output-v2.1.schema.json"/"dumpex-output-v2.0.schema.json" for
    the frozen historical v2.3/v2.2/v2.1/v2.0 schemas (still valid for
    validating output produced before schema_version 2.4/2.3/2.2/2.1
    respectively -- v2.3 does NOT accept result.kind == "hunt": a closed
    enum's already-shipped copy must never start silently accepting a
    value it didn't originally define)."""
    return resources.as_file(
        resources.files(__name__).joinpath(filename)
    )

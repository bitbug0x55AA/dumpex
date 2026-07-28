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


def schema_path():
    """Path to the packaged schema file, usable as a context manager
    (works whether the package is on disk or inside a zipped wheel)."""
    return resources.as_file(
        resources.files(__name__).joinpath("dumpex-output-v1.1.schema.json")
    )

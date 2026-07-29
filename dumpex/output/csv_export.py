"""v2 CSV export.

Every v2 record is already a flat dict via its own to_dict() by the time
it reaches a dumpex.output.envelope.Result, so unlike
dumpex/ui/structured.py's `_section_to_tables` -- which special-cases
"modules"/"threads"/"sysinfo"/"pid"/"hunt" by string key and reshapes
sysinfo/pid's single dict into {field, value} rows -- most of the work
here is uniform across kinds. Two things still need real handling,
though, because `csv.DictWriter` has no concept of a nested value:

- list/dict-typed fields (ThreadRecord.flags, ModuleRecord.anomaly_flags,
  PebRecord.environment_variables) are JSON-encoded into the cell rather
  than left to csv.DictWriter's default str() behavior, which produces a
  Python repr() (`"['EXITED']"`) -- not valid JSON, not a stable format
  any other language's CSV/JSON tooling can parse back reliably.
- PEB's environment_variables is additionally broken out into its own
  "environment_variables" table (one row per variable) rather than only
  living as a JSON-encoded cell in the main "records" table -- the one
  deliberate per-kind exception in this module, kept narrow (a single
  field of a single kind) rather than the old per-section special-casing
  this design otherwise avoids.

A "summary" table (kind/execution_status/coverage/count) is always
produced, even when `records` is empty, so a directory-mode CSV export
never silently writes zero files just because a stream came back empty.
"""
import json


def _flatten_value(value):
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return value


def records_to_rows(result) -> list:
    """Flatten result.records into CSV-ready rows: every list/dict-typed
    field becomes a JSON-encoded string cell, never a Python repr()."""
    rows = []
    for record in result.records:
        row = {k: _flatten_value(v) for k, v in record.items()}
        if result.kind == "peb":
            # Broken out into its own table below instead -- see module
            # docstring.
            row.pop("environment_variables", None)
        rows.append(row)
    return rows


def environment_variables_rows(result) -> list:
    """One row per {"name", "value"} entry, across every peb record that
    has any -- in practice exactly one record, since peb is a
    single-element-array kind, but this doesn't assume that."""
    rows = []
    for record in result.records:
        env_vars = record.get("environment_variables")
        if env_vars:
            rows.extend(env_vars)
    return rows


def summary_rows(result) -> list:
    """One row summarizing the whole result. Always exactly one row,
    even when `records` is empty, so this table's file always gets
    written in directory mode."""
    return [{
        "kind":              result.kind,
        "execution_status":  result.execution_status,
        "coverage_status":   result.coverage_status,
        "coverage_reasons":  "; ".join(result.coverage_reasons),
        "count":             len(result.records),
    }]


def build_tables(result) -> dict:
    """{table_name: [row, ...]}. 'summary' and 'records' are always
    present; 'environment_variables' only for a peb result that actually
    has at least one variable to report."""
    tables = {
        "summary": summary_rows(result),
        "records": records_to_rows(result),
    }
    if result.kind == "peb":
        env_rows = environment_variables_rows(result)
        if env_rows:
            tables["environment_variables"] = env_rows
    return tables

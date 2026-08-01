"""v2 CSV export.

Every v2 record is already a flat dict via its own to_dict() by the time
it reaches a dumpex.output.envelope.Result, so unlike
dumpex/ui/structured.py's `_section_to_tables` -- which special-cases
"modules"/"threads"/"sysinfo"/"pid"/"hunt" by string key and reshapes
sysinfo/pid's single dict into {field, value} rows -- most of the work
here is uniform across kinds. A few things still need real handling,
though, because `csv.DictWriter` has no concept of a nested value or a
heterogeneous row shape:

- list/dict-typed fields (ThreadRecord.flags, ModuleRecord.anomaly_flags,
  PebRecord.environment_variables) are JSON-encoded into the cell rather
  than left to csv.DictWriter's default str() behavior, which produces a
  Python repr() (`"['EXITED']"`) -- not valid JSON, not a stable format
  any other language's CSV/JSON tooling can parse back reliably.
- PEB's environment_variables is additionally broken out into its own
  "environment_variables" table (one row per variable) rather than only
  living as a JSON-encoded cell in the main "records" table -- kept
  narrow (a single field of a single kind) rather than the old
  per-section special-casing this design otherwise avoids.
- A "comparison" result's `records` array is a tagged union
  (ModuleDiffRecord/ThreadDiffRecord/MemoryDiffRecord, discriminated by
  `entity_type`) -- entries don't share one fieldname set, so a single
  csv.DictWriter can't write them as one table the way every other kind's
  homogeneous `records` array can. The generic "records" table is skipped
  entirely for this kind; result.records is split by `entity_type` into
  up to three homogeneous tables instead (module_diffs/thread_diffs/
  memory_diffs), each written the same way every other table is.

A "summary" table (kind/execution_status/coverage/count) is always
produced, even when `records` is empty, so a directory-mode CSV export
never silently writes zero files just because a stream came back empty.
"""
import json


def _flatten_value(value):
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return value


def _flatten_row(record: dict) -> dict:
    return {k: _flatten_value(v) for k, v in record.items()}


def records_to_rows(result) -> list:
    """Flatten result.records into CSV-ready rows: every list/dict-typed
    field becomes a JSON-encoded string cell, never a Python repr()."""
    rows = []
    for record in result.records:
        row = _flatten_row(record)
        if result.kind == "peb":
            # Broken out into its own table below instead -- see module
            # docstring.
            row.pop("environment_variables", None)
        rows.append(row)
    return rows


def diff_rows_for_entity(result, entity_type: str) -> list:
    """One homogeneous table's worth of rows out of a "comparison"
    result's tagged-union `records` array -- every entry whose
    `entity_type` matches, in original order. See build_tables' kind ==
    "comparison" branch."""
    return [_flatten_row(record) for record in result.records
            if record.get("entity_type") == entity_type]


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
    """{table_name: [row, ...]}. 'summary' is always present. For every
    kind except "comparison": 'records' is always present too;
    'environment_variables' is added only for a peb result that actually
    has at least one variable to report. For "comparison": 'records' is
    never present (see module docstring) -- 'module_diffs'/'thread_diffs'/
    'memory_diffs' take its place, always present (empty tables are
    simply never written -- see collector.py's write_csv, which already
    skips any table with zero rows in both single-file and directory
    mode), exactly mirroring how 'records' itself is always present but
    silently unwritten when empty for the other six kinds."""
    if result.kind == "comparison":
        return {
            "summary":      summary_rows(result),
            "module_diffs": diff_rows_for_entity(result, "module"),
            "thread_diffs": diff_rows_for_entity(result, "thread"),
            "memory_diffs": diff_rows_for_entity(result, "memory_region"),
        }
    tables = {
        "summary": summary_rows(result),
        "records": records_to_rows(result),
    }
    if result.kind == "peb":
        env_rows = environment_variables_rows(result)
        if env_rows:
            tables["environment_variables"] = env_rows
    return tables

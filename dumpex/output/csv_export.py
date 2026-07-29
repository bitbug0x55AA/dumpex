"""v2 CSV export.

Every v2 record is already a flat dict via its own to_dict() by the time
it reaches a dumpex.output.envelope.Result (see
dumpex.output.collector.V2Output.set_result), so unlike
dumpex/ui/structured.py's `_section_to_tables` -- which special-cases
"modules"/"threads"/"sysinfo"/"pid"/"hunt" by string key and reshapes
sysinfo/pid's single dict into {field, value} rows -- this needs no
per-kind branching at all in this PR: one table, one `csv.DictWriter`
call, straight from `result.records`.
"""


def records_to_rows(result) -> list:
    """result: a dumpex.output.envelope.Result. Returns a plain list of
    row dicts ready for csv.DictWriter."""
    return list(result.records)

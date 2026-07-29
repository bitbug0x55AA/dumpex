"""dumpex v2 structured-output contract.

Kept entirely separate from dumpex/ui/structured.py (the v1.1 contract,
which --hunt still uses unchanged) so migrating a command onto v2 never
risks the existing hunt JSON/CSV shape. See docs/OUTPUT_SCHEMA.md for the
envelope layout and dumpex/schemas/dumpex-output-v2.0.schema.json for the
formal schema.

Layout:
  records.py    canonical record dataclasses (ModuleRecord, ThreadRecord,
                MemoryRegionRecord, SysInfoRecord, PidRecord, PebRecord,
                Diagnostic) -- plain dataclasses with an explicit
                to_dict(), the same house style as dumpex.hunt._finding.Finding.
  envelope.py   meta/result/envelope construction; execution_status and
                coverage-status vocabulary (the latter reused from
                dumpex.hunt._coverage, not redefined).
  serializer.py to_json(): a STRICT encoder that raises on any type it
                doesn't explicitly know, unlike structured.py's permissive
                str(obj) fallback.
  csv_export.py records -> CSV tables (summary always; records always;
                environment_variables for peb results that have any).
                List/dict-typed fields are JSON-encoded into their cell,
                never left to csv.DictWriter's default Python repr().
  collector.py  V2Output -- the per-run collector commands feed records
                into, analogous to StructuredOutput but v2-shaped.
"""
from dumpex.output.collector import V2Output

__all__ = ["V2Output"]

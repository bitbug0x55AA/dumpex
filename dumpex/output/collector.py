"""V2Output: per-run collector for commands migrated onto the v2 output
contract (see cli.py's _V2_STRUCTURED_MODES). Constructed the same way
dumpex.ui.structured.StructuredOutput is, so cli.py's existing
meta-building call sites barely change -- but produces a v2 envelope via
dumpex.output.envelope/.serializer instead of v1.1's flat section dict.
"""
import io
import os
import csv
import datetime
from pathlib import Path

from dumpex.ui.colors import DIM
from dumpex.core.safe_io import write_text_to_target, write_text_to_directory, summarize_file
from dumpex.output.envelope import build_meta_v2, Result, Envelope, EXECUTION_COMPLETED
from dumpex.output.serializer import to_json as _serialize_envelope
from dumpex.output.csv_export import records_to_rows
from dumpex.output.records import Diagnostic, SEVERITY_ERROR


class V2Output:
    def __init__(self, dump_path: str, mf=None, *, command: str = None,
                 options: dict = None, case_id: str = None, analyst: str = None,
                 redact_paths: bool = False, started_at: "datetime.datetime" = None):
        self._dump_path_abs  = os.path.abspath(dump_path)
        self._dump_file_name = os.path.basename(dump_path)
        self._command        = command
        self._options        = dict(options) if options else {}
        self._case_id        = case_id
        self._analyst        = analyst
        self._redact_paths   = redact_paths
        self._started_at     = started_at or datetime.datetime.now(datetime.timezone.utc)
        self._mf              = mf   # kept for parity with StructuredOutput; unused so far
        self._result             = None
        self._diagnostics_warnings = []
        self._diagnostics_errors   = []

    def set_result(self, kind: str, records: list, coverage_status: str,
                    coverage_reasons: list = None, summary: dict = None) -> None:
        """`records` is a list of record dataclass instances (ModuleRecord,
        ThreadRecord, ...) -- converted to plain dicts here via each
        record's own to_dict(), so every consumer downstream of this call
        (serializer, CSV export) only ever sees plain JSON-safe data."""
        record_dicts = [r.to_dict() for r in records]
        self._result = Result(
            kind=kind,
            execution_status=EXECUTION_COMPLETED,
            coverage_status=coverage_status,
            coverage_reasons=list(coverage_reasons) if coverage_reasons else [],
            summary=dict(summary) if summary is not None else {"count": len(record_dicts)},
            records=record_dicts,
        )

    def add_diagnostic(self, severity: str, message: str, code: str = None) -> None:
        d = Diagnostic(severity=severity, message=message, code=code).to_dict()
        if severity == SEVERITY_ERROR:
            self._diagnostics_errors.append(d)
        else:
            self._diagnostics_warnings.append(d)

    @property
    def has_result(self) -> bool:
        return self._result is not None

    @property
    def coverage_status(self) -> "str | None":
        return self._result.coverage_status if self._result else None

    def _build_envelope(self) -> Envelope:
        finished_at = datetime.datetime.now(datetime.timezone.utc)
        meta = build_meta_v2(
            dump_path_abs=self._dump_path_abs, dump_file_name=self._dump_file_name,
            command=self._command, options=self._options, case_id=self._case_id,
            analyst=self._analyst, redact_paths=self._redact_paths,
            started_at=self._started_at, finished_at=finished_at,
        )
        return Envelope(meta=meta, result=self._result, artifacts=[],
                         diagnostics_warnings=list(self._diagnostics_warnings),
                         diagnostics_errors=list(self._diagnostics_errors))

    def to_json(self) -> str:
        return _serialize_envelope(self._build_envelope())

    def write_json(self, path: str, cmd_label: str = "", force: bool = False) -> None:
        p = write_text_to_target(path, self.to_json(), ".json", cmd_label,
                                  self._dump_path_abs, force, "--json output")
        print(DIM(f"  [·] JSON written → {p}  ({summarize_file(p)})"))

    def write_csv(self, path: str, cmd_label: str = "", force: bool = False) -> None:
        rows = records_to_rows(self._result) if self._result else []
        p_in = Path(path)

        if p_in.suffix.lower() == ".csv":
            buf = io.StringIO()
            if rows:
                writer = csv.DictWriter(buf, fieldnames=rows[0].keys(), extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
            p = write_text_to_target(path, buf.getvalue(), ".csv", cmd_label,
                                      self._dump_path_abs, force, "--csv output")
            print(DIM(f"  [·] CSV  written → {p}  ({len(rows)} row(s), {summarize_file(p)})"))
            return

        if not rows:
            print(DIM("  [~] --csv: no rows to write."))
            return

        kind  = self._result.kind
        label = f"{cmd_label}_" if cmd_label else ""
        stem  = f"dumpex_{label}{kind}"
        buf   = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=rows[0].keys(), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        fname = write_text_to_directory(p_in, buf.getvalue(), stem, ".csv",
                                         self._dump_path_abs, force,
                                         f"CSV table output ({stem}.csv)")
        print(DIM(f"  [·] CSV  written → {fname}  ({len(rows)} row(s), {summarize_file(fname)})"))

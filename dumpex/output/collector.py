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
from dumpex.output.envelope import build_meta_v2, Result, Envelope
from dumpex.output.serializer import to_json as _serialize_envelope
from dumpex.output.csv_export import build_tables
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
        self._artifacts            = []

    def set_command_result(self, result) -> None:
        """The single way a command populates this collector's result --
        consumes every dumpex.output.command_result.CommandResult field
        (execution_status, structured coverage, diagnostics, artifacts),
        converting each nested value's own to_dict() before storing it, so
        every consumer downstream of this call (serializer, CSV export)
        only ever sees plain JSON-safe data. `result` is duck-typed (not
        type-hinted as CommandResult) to avoid this module importing
        command_result.py, which itself imports this module's sibling
        envelope.py -- without a hard import dependency between the two."""
        record_dicts = [r.to_dict() for r in result.records]
        self._result = Result(
            kind=result.kind,
            execution_status=result.execution_status,
            coverage_status=result.coverage.status,
            coverage_reasons=list(result.coverage.reasons),
            coverage_sources={name: obs.to_dict()
                               for name, obs in result.coverage.sources.items()},
            coverage_limitations=[lim.to_dict() for lim in result.coverage.limitations],
            summary=dict(result.summary) if result.summary else {"count": len(record_dicts)},
            records=record_dicts,
        )
        for d in result.diagnostics:
            d_dict = d.to_dict() if hasattr(d, "to_dict") else d
            if d_dict.get("severity") == SEVERITY_ERROR:
                self._diagnostics_errors.append(d_dict)
            else:
                self._diagnostics_warnings.append(d_dict)
        self._artifacts.extend(
            a.to_dict() if hasattr(a, "to_dict") else a for a in result.artifacts)

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
        return Envelope(meta=meta, result=self._result, artifacts=list(self._artifacts),
                         diagnostics_warnings=list(self._diagnostics_warnings),
                         diagnostics_errors=list(self._diagnostics_errors))

    def to_json(self) -> str:
        return _serialize_envelope(self._build_envelope())

    def write_json(self, path: str, cmd_label: str = "", force: bool = False) -> None:
        p = write_text_to_target(path, self.to_json(), ".json", cmd_label,
                                  self._dump_path_abs, force, "--json output")
        print(DIM(f"  [·] JSON written → {p}  ({summarize_file(p)})"))

    def write_csv(self, path: str, cmd_label: str = "", force: bool = False) -> None:
        """
        Writes every table build_tables() produces for the current result
        ('summary' always; 'records' always; 'environment_variables' only
        for a peb result that has any). 'summary' always has exactly one
        row, so a result with zero data records still writes real content
        in both modes -- a genuinely empty stream must not look like
        --csv silently did nothing.
        """
        tables = build_tables(self._result) if self._result else {}
        p_in = Path(path)

        if p_in.suffix.lower() == ".csv":
            buf = io.StringIO()
            total_rows = 0
            for table_name, rows in tables.items():
                if not rows:
                    continue
                buf.write(f"## {self._result.kind} / {table_name}\n")
                writer = csv.DictWriter(
                    buf, fieldnames=rows[0].keys(), extrasaction="ignore",
                    lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
                buf.write("\n")
                total_rows += len(rows)
            p = write_text_to_target(path, buf.getvalue(), ".csv", cmd_label,
                                      self._dump_path_abs, force, "--csv output",
                                      newline="")
            print(DIM(f"  [·] CSV  written → {p}  "
                      f"({total_rows} row(s) across all tables, {summarize_file(p)})"))
            return

        kind  = self._result.kind if self._result else "result"
        label = f"{cmd_label}_" if cmd_label else ""
        for table_name, rows in tables.items():
            if not rows:
                continue
            stem = f"dumpex_{label}{kind}_{table_name}"
            buf  = io.StringIO()
            writer = csv.DictWriter(
                buf, fieldnames=rows[0].keys(), extrasaction="ignore",
                lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            fname = write_text_to_directory(p_in, buf.getvalue(), stem, ".csv",
                                             self._dump_path_abs, force,
                                             f"CSV table output ({stem}.csv)",
                                             newline="")
            print(DIM(f"  [·] CSV  written → {fname}  ({len(rows)} row(s), {summarize_file(fname)})"))

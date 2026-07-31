# Contributing to dumpex

Contributions should preserve dumpex's DFIR evidence semantics: incomplete
coverage must not be presented as a clean result, heuristics must not be
promoted beyond their supporting evidence, and output changes must remain
reproducible.

## Development setup

Python 3.10 or newer is required.

```bash
git clone https://github.com/bitbug0x55AA/dumpex.git
cd dumpex
python -m pip install -e ".[full,dev]"
```

Run the test suite:

```bash
pytest
pytest --cov=dumpex --cov-report=term-missing
```

The default suite uses synthetic PE structures and minidump object graphs. It
requires no malware corpus, external fixture download, or network access.

## Test layout

| Path | Purpose |
|---|---|
| `tests/unit/` | Isolated parser, helper, and decision-logic tests |
| `tests/hunt/` | Hunter behavior, scoring, and coverage semantics |
| `tests/integration/` | Command/output behavior across components |
| `tests/perf/` | Bounded performance and regression benchmarks |
| `tests/fixtures/fakes.py` | Synthetic minidump and PE builders |
| `tests/corpus/` | Optional local tests against analyst-authorized real samples |

The default public CI suite intentionally has no private corpus dependency.
The separate protected `.github/workflows/corpus.yml` workflow can materialize
an authorized corpus on an isolated self-hosted runner for manual and scheduled
FP/FN regression. Follow [`tests/corpus/README.md`](tests/corpus/README.md) for
local use and runner configuration. Never commit sensitive or malicious case
evidence.

`tests/conftest.py` resets module-level thread-context monkeypatch points
before and after tests so synthetic instruction pointers do not leak between
cases.

## Expectations for changes

- Add regression coverage for changed behavior, including failure and partial
  coverage paths.
- Keep `status`, `coverage_status`, `verdict_level`, and `confidence`
  semantically distinct.
- Treat missing streams, short reads, malformed structures, and rule compile
  failures explicitly.
- Preserve evidence and rule provenance in structured output.
- Update the relevant focused document instead of expanding the README with
  implementation detail.
- Do not add real case dumps or unlicensed signatures to the repository.

## Licensing contributions

Except where a file clearly states otherwise, dumpex is licensed under the
Mozilla Public License 2.0 (`MPL-2.0`). By submitting a contribution, you agree
to license it under MPL-2.0 and represent that you have sufficient rights to
do so. Do not submit third-party code, signatures, or other material unless
its license is documented and compatible with the project; add required
attribution and license text to `CREDITS` and `THIRD_PARTY_NOTICES`.

## Rules and package data

The canonical packaged resources are:

```text
dumpex/rules_pkg/data/rules.yaml
dumpex/rules_pkg/data/yara/*.yar
```

When adding or moving rule files, keep `pyproject.toml`, resource-resolution
tests, and the PyInstaller workflow aligned with that package layout. Do not
introduce a second canonical rules tree.

## Continuous integration

`.github/workflows/tests.yml` runs tests on the minimum supported Python
version and a current Python version for pushes and pull requests. Coverage is
gated by the threshold in `pyproject.toml`.

`.github/workflows/corpus.yml` is a separate private-data boundary. It must
remain restricted to the default branch and a protected, isolated self-hosted
runner; do not expose it to fork pull-request code or upload raw corpus output.

The PyInstaller workflow should collect `dumpex.rules_pkg` package data rather
than copying an unrelated top-level rules directory. Packaging changes should
be verified against both an installed package and the generated executable.

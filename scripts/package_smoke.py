"""Standalone smoke test for a built dumpex wheel/sdist install.

Verifies that a `pip install dist/*.whl` (or the sdist equivalent) is
actually self-contained: the installed package is really being imported
from site-packages (not shadowed by a same-named source directory), its
packaged resources (rules.yaml, the YARA rule files, the JSON output
schema) are readable via importlib.resources, its MPL-2.0 metadata and
license/notice files are present, the rules loader picks up the packaged
rules.yaml rather than silently falling back to the built-in emergency
defaults, and the CLI entry point runs.

Deliberately NOT a pytest test: it must run standalone, with no pytest
and no dependency on this repository's source tree, from a fresh venv
whose only installed package is the wheel/sdist under test, invoked from
a working directory OUTSIDE the checkout -- see the "Smoke test" step in
the package-smoke CI job (.github/workflows/tests.yml), which is the
whole point of this script: `pip install dist/*.whl` followed by an
`import dumpex` run FROM THE CHECKOUT DIRECTORY is not a valid test,
because a `dumpex/` source directory sitting right next to the
interpreter can shadow the installed package entirely and no failure
would ever surface.

Usage:
    python package_smoke.py [repo_root_to_exclude]

`repo_root_to_exclude`, if given, is asserted to NOT be a prefix of the
resolved dumpex install location -- catching the exact shadowing failure
mode described above even if this script itself is (as CI does) copied
out of the checkout before running.
"""
import json
import os
import subprocess
import sys


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main() -> None:
    repo_root = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else None

    import dumpex

    install_path = os.path.abspath(dumpex.__file__)
    normalized = install_path.replace("\\", "/")
    print(f"dumpex imported from: {install_path}")

    if "site-packages" not in normalized and "dist-packages" not in normalized:
        _fail(f"dumpex.__file__ does not look like an installed package: {install_path}")

    if repo_root is not None and (install_path == repo_root
                                   or install_path.startswith(repo_root + os.sep)):
        _fail(f"dumpex imported from inside the repo checkout ({repo_root}), "
              f"not from the installed wheel/sdist: {install_path}")

    import importlib.metadata

    distribution = importlib.metadata.distribution("dumpex")
    if distribution.metadata.get("License-Expression") != "MPL-2.0":
        _fail("installed package metadata does not declare License-Expression: MPL-2.0")

    required_notice_files = {"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES", "CREDITS"}
    installed_notice_files = {
        os.path.basename(str(file))
        for file in (distribution.files or ())
        if ".dist-info/licenses/" in str(file).replace("\\", "/")
    }
    missing_notice_files = required_notice_files - installed_notice_files
    if missing_notice_files:
        _fail(f"installed package is missing license/notice files: "
              f"{sorted(missing_notice_files)}")
    print(f"packaged license/notice files: {sorted(required_notice_files)}")

    import importlib.resources

    rules_yaml = importlib.resources.files("dumpex.rules_pkg").joinpath("data", "rules.yaml")
    if not rules_yaml.is_file():
        _fail("dumpex/rules_pkg/data/rules.yaml not found via importlib.resources")
    rules_yaml.read_text(encoding="utf-8")

    # Exact filenames, not just a count -- a count-only check would still
    # pass if a rule file were accidentally dropped from packaging at the
    # same time an unrelated new one was added, which is exactly the kind
    # of packaging drift this smoke test exists to catch.
    expected_yar_files = {"cs_indicators.yar", "lateral_movement.yar", "suspicious_memory.yar"}
    yara_dir = importlib.resources.files("dumpex.rules_pkg").joinpath("data", "yara")
    if not yara_dir.is_dir():
        _fail("dumpex/rules_pkg/data/yara directory not found via importlib.resources")
    yar_files = {p.name for p in yara_dir.iterdir() if p.name.endswith((".yar", ".yara"))}
    if yar_files != expected_yar_files:
        _fail(f"packaged YARA rule files mismatch: expected {sorted(expected_yar_files)}, "
              f"found {sorted(yar_files)}")
    print(f"packaged YARA rule files: {sorted(yar_files)}")

    _schema_filenames = ("dumpex-output-v1.1.schema.json", "dumpex-output-v2.0.schema.json",
                         "dumpex-output-v2.1.schema.json", "dumpex-output-v2.2.schema.json",
                         "dumpex-output-v2.3.schema.json", "dumpex-output-v2.4.schema.json",
                         "dumpex-output-v2.5.schema.json")
    for schema_filename in _schema_filenames:
        schema_path = importlib.resources.files("dumpex.schemas").joinpath(schema_filename)
        if not schema_path.is_file():
            _fail(f"dumpex/schemas/{schema_filename} not found via importlib.resources")
        schema_text = schema_path.read_text(encoding="utf-8")
        try:
            json.loads(schema_text)
        except json.JSONDecodeError as e:
            _fail(f"packaged {schema_filename} is not valid JSON: {e}")
    print(f"packaged schemas: {', '.join(_schema_filenames)}")

    from dumpex.rules_pkg import loader

    rules = loader.get_rules()
    if not rules.get("suspicious_protections"):
        _fail("loader.get_rules() returned an empty/unusable rule set")

    info = loader.get_rules_source_info()
    if info is None:
        _fail("get_rules_source_info() returned None after get_rules() was called")
    if info["path"] is None:
        _fail("rules were loaded from the built-in fallback (path=None), not the packaged "
              "rules.yaml -- a base install must never need this fallback")
    if "rules_pkg" not in info["path"].replace("\\", "/"):
        _fail(f"rules were loaded from an unexpected path: {info['path']}")
    if info["explicit"] is not False:
        _fail(f"rules source unexpectedly marked explicit: {info}")
    sha256 = info.get("sha256")
    if not sha256 or len(sha256) != 64:
        _fail(f"unexpected sha256 in rules source info: {sha256!r}")
    print(f"rules loaded from packaged resource: {info['path']} (sha256={sha256[:16]}...)")

    result = subprocess.run([sys.executable, "-m", "dumpex", "--help"],
                             capture_output=True, text=True)
    if result.returncode != 0:
        _fail(f"'python -m dumpex --help' exited {result.returncode}\n"
              f"stdout: {result.stdout}\nstderr: {result.stderr}")

    print("OK: package smoke test passed")


if __name__ == "__main__":
    main()

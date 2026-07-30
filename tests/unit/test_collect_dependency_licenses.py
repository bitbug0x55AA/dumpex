from pathlib import Path

import pytest

from scripts import collect_dependency_licenses as collector


class _FakeDistribution:
    def __init__(self, root: Path, name: str, version: str, notice: str | None):
        self.metadata = {"Name": name}
        self.version = version
        self._root = root
        if notice is None:
            self.files = ()
        else:
            relative = Path("licenses") / notice
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_text(f"{name} license\n", encoding="utf-8")
            self.files = (relative,)

    def locate_file(self, file: Path) -> Path:
        return self._root / file


def test_collect_includes_runtime_toolchain_and_python_notices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _FakeDistribution(
        tmp_path / "runtime", "Runtime Dependency", "1.2.3", "LICENSE.txt"
    )
    pyinstaller = _FakeDistribution(
        tmp_path / "pyinstaller", "PyInstaller", "6.21.0", "COPYING.txt"
    )
    python_license = tmp_path / "python" / "LICENSE.txt"
    python_license.parent.mkdir()
    python_license.write_text("Python license\n", encoding="utf-8")

    monkeypatch.setattr(collector, "_runtime_distributions", lambda: [runtime])
    monkeypatch.setattr(
        collector.metadata,
        "distribution",
        lambda name: pyinstaller if name == "PyInstaller" else None,
    )
    monkeypatch.setattr(collector, "_python_license_path", lambda: python_license)

    output = tmp_path / "notices"
    collector.collect(
        output,
        extra_distributions=("PyInstaller",),
        include_python_license=True,
    )

    assert (output / "Runtime-Dependency-1.2.3" / "LICENSE.txt").read_text(
        encoding="utf-8"
    ) == "Runtime Dependency license\n"
    assert (output / "PyInstaller-6.21.0" / "COPYING.txt").read_text(
        encoding="utf-8"
    ) == "PyInstaller license\n"

    python_dirs = list(output.glob("Python-*"))
    assert len(python_dirs) == 1
    assert (python_dirs[0] / "LICENSE.txt").read_text(
        encoding="utf-8"
    ) == "Python license\n"

    index = (output / "INDEX.txt").read_text(encoding="utf-8")
    assert "Runtime Dependency 1.2.3" in index
    assert "PyInstaller 6.21.0" in index
    assert "Python " in index


def test_collect_rejects_distribution_without_a_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = _FakeDistribution(tmp_path / "missing", "Missing", "1.0", None)
    monkeypatch.setattr(collector, "_runtime_distributions", lambda: [missing])

    with pytest.raises(RuntimeError, match="contains no discoverable license"):
        collector.collect(tmp_path / "notices")

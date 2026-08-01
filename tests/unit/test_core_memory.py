"""Unit tests for dumpex.core.memory's cross-platform path helpers."""
from dumpex.core.memory import module_name_only


def test_module_name_only_extracts_windows_backslash_path_basename():
    # Module paths recorded in a minidump are always Windows paths (e.g.
    # "C:\\Windows\\System32\\foo.dll") regardless of the host OS this
    # tool runs on. os.path.basename only splits on "/" on a POSIX host,
    # silently returning the whole backslash-separated string unchanged
    # there -- module_name_only() must use ntpath.basename instead so
    # this extracts correctly on every host, not just Windows.
    assert module_name_only(r"C:\Windows\System32\ntdll.dll") == "ntdll.dll"


def test_module_name_only_lowercases():
    assert module_name_only(r"C:\Windows\System32\NTDLL.DLL") == "ntdll.dll"


def test_module_name_only_same_basename_different_directory_matches():
    # The exact scenario dumpex.commands.comparison.collect_module_diff
    # (and diff.py's own diff_modules) relies on: the "same" module
    # relocated to a different directory between two dumps must still
    # produce the SAME match key -- and therefore report as "rebased,"
    # not a spurious removed+added pair -- regardless of host OS.
    a = module_name_only(r"C:\Program Files\App\a.dll")
    b = module_name_only(r"C:\Windows\System32\a.dll")
    assert a == b == "a.dll"


def test_module_name_only_empty_for_none_or_empty_path():
    assert module_name_only(None) == ""
    assert module_name_only("") == ""


def test_module_name_only_forward_slash_path_still_works():
    # Not the primary case (minidump module paths are Windows paths), but
    # ntpath.basename also handles "/" -- confirms nothing regressed for
    # a path that happens to use forward slashes.
    assert module_name_only("C:/Windows/System32/ntdll.dll") == "ntdll.dll"

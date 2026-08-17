"""dumpex.hunt._console must stay a faithful re-export of
dumpex.ui.console_layout.

The primitives moved out of the hunt package when --sysinfo --verbose
needed the same width policy (issue #41). Ten hunt modules still import
them from the old path, so the shim is load-bearing: a name dropped from
its re-export list would break a hunter's console rendering at import
time, and a name that silently diverged would give two subsystems
different wrapping behaviour from what reads like one shared helper.
"""
from dumpex.hunt import _console
from dumpex.ui import console_layout


def test_shim_re_exports_every_public_name_as_the_same_object():
    # Guards against the list itself being emptied by a refactor and
    # every assertion below passing vacuously.
    assert len(console_layout.__all__) >= 8
    for name in console_layout.__all__:
        assert hasattr(_console, name), f"{name} missing from the dumpex.hunt._console shim"
        assert getattr(_console, name) is getattr(console_layout, name), (
            f"{name} is a copy, not a re-export -- the two would drift")


def test_shim_advertises_exactly_the_moved_surface():
    # Not a subset check: a name the shim advertises but the real module
    # no longer defines would raise only at the call site.
    assert sorted(_console.__all__) == sorted(console_layout.__all__)

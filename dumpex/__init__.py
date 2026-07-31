"""Dumpex — minidump triage toolkit."""

try:
    from ._version import __version__
except ImportError:  # Source checkout used without installing the project.
    __version__ = "0+unknown"

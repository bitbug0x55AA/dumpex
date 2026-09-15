"""How this process was packaged.

A dumpex installed from a wheel or a checkout can gain an optional
dependency at any time; a packaged executable ships whatever it was built
with, and `pip` cannot reach inside it. Code that tells a user what to do
about a capability that is not there asks here which of the two it is
talking to, so a frozen runtime is never handed advice it cannot act on.
"""
import sys

__all__ = ["FROZEN", "PYTHON", "is_frozen", "runtime_kind"]

#: The two packaging shapes dumpex runs as.
FROZEN = "frozen"
PYTHON = "python"


def is_frozen() -> bool:
    """Whether this process is a packaged executable. A bundled
    interpreter carries ``sys.frozen``; a wheel or source run never
    does."""
    return bool(getattr(sys, "frozen", False))


def runtime_kind() -> str:
    """:data:`FROZEN` or :data:`PYTHON` for this process."""
    return FROZEN if is_frozen() else PYTHON

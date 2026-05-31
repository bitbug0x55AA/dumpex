#!/usr/bin/env python3
"""Backwards-compatible shim — delegates to the dumpex package."""
from dumpex.cli import main
if __name__ == "__main__":
    main()

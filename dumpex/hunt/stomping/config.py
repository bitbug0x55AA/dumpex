"""Tunable constants for the module stomping hunter."""

PE_VALIDATE_READ_MAX = 4096   # bytes read from each module base to parse its
                               # own header + section table (see dumpex/hunt/injection/)

REF_FILE_MAX_READ = 64 * 1024 * 1024   # cap on a --ref-dir reference file read;
                                        # legitimate DLLs/EXEs are far smaller,
                                        # this just bounds a pathological input

IOC_SCAN_MAX = 5 * 1024 * 1024   # the unscored IOC-string region scan skips
                                  # executable MEM_IMAGE regions larger than
                                  # this (string extraction over a huge
                                  # mapping is the most expensive thing this
                                  # hunter does, and it can never score) —
                                  # every skip is RECORDED as a coverage gap
                                  # with the region's own identity, never
                                  # silently dropped: see
                                  # memory_scan.scan_ioc_strings and this
                                  # package's docstring for what an
                                  # incomplete IOC sub-scan does (and does
                                  # not) change about the hunter's verdict.

MAX_DIFF_RANGES = 20        # cap on how many differing byte ranges are KEPT
                             # for display/facts — a section with more than
                             # this many separate diffs is already
                             # unambiguously different, no need to enumerate
                             # every last one for a human to read.
MAX_DIFF_RANGES_SCAN = 200_000   # separate, much larger safety ceiling on how
                                  # many ranges are computed AT ALL (purely to
                                  # bound worst-case memory/CPU on a section
                                  # that is byte-for-byte unrelated to its
                                  # reference) — RIP-hit checking scans every
                                  # range up to THIS limit, not just the 20
                                  # kept for display, so a hit in e.g. the
                                  # 21st range is never silently missed.

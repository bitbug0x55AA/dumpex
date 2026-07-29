"""Tunable constants for the named-pipe C2 hunter."""

PIPE_SCAN_MAX = 8 * 1024 * 1024   # skip regions > 8MB; pipe names / C2 context
                                   # are short strings, no need to read huge
                                   # regions in full to find them

PIPE_CONTEXT_DISTANCE = 4096   # +/- byte window, anchored on a pipe-name
                                # string hit's own VA, for BOTH C2-context
                                # and RIP/EIP corroboration. A prior version
                                # correlated anything anywhere in the same
                                # MemoryInfo region — a single region can
                                # span megabytes, so a C2-looking string a
                                # full 1 MiB away from the pipe name (or a
                                # thread executing elsewhere in a large
                                # region for entirely unrelated reasons)
                                # was being counted as if it were adjacent
                                # to the pipe reference. 4 KiB is one page.

PIPE_MAX_MATCHES_PER_REGION = 50    # cap raw \pipe\ matches processed per region
PIPE_C2_MAX_HITS_PER_REGION = 5     # cap C2_PAT matches recorded per pipe-bearing region
PIPE_C2_CONTEXT_BYTES       = 512   # total context window (before+after) kept per match
PIPE_C2_TOKEN_PREVIEW       = 256   # bound on the match token itself — every one of
                                     # C2_PAT's own patterns (a literal "http://", an
                                     # IP:port, "submit.php", ...) already produces a
                                     # short match on its own; this is defense in depth,
                                     # not the primary bound (see patterns._iter_c2_matches)

# Two INDEPENDENT whole-hunt budgets. c2_budget only bounds Check B's C2-
# context gathering; pipe_name_budget only bounds pipe-name collection
# (Checks A/C/D's raw material). Do NOT merge these into one generic
# budget — that would let one signal's exhaustion silently cut off the
# other's coverage, changing partial-coverage reporting for whichever
# signal happened to share the merged budget.
PIPE_C2_BUDGET_MAX_HITS     = 200               # cumulative C2 hits retained, whole hunt
PIPE_C2_BUDGET_MAX_RETAINED = 2 * 1024 * 1024   # cumulative context bytes retained, whole hunt
PIPE_C2_BUDGET_TIME_SECONDS = 30.0

PIPE_NAME_MAX_CHARS   = 512     # bound on the retained pipe-name PREVIEW; the true
                                 # extent is still walked (for an accurate sha256/
                                 # original_length) but never fully decoded/kept
PIPE_NAME_BUDGET_MAX_HITS     = 500               # cumulative private+image pipe
                                                   # names retained, whole hunt
PIPE_NAME_BUDGET_MAX_RETAINED = 1 * 1024 * 1024   # cumulative preview bytes retained
PIPE_NAME_BUDGET_TIME_SECONDS = 30.0

_MIN_RUN_LEN = 6   # matches the min_len _extract_strings_from_data previously used here

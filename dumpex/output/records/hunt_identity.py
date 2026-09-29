"""The hunt wire identity: the ordered hunter roster (HUNTERS) and the
judgment vocabularies every HunterRecord is validated against.

HUNTERS is the single source of truth for which hunters exist and in what
order they are emitted. It lives in the neutral record layer and imports
no hunter implementation; dumpex.hunt's registry validates against it.
"""

HUNTERS = ("injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation")
_HUNT_STATUSES = ("DETECTED", "NOT_DETECTED_IN_SCANNED_SCOPE", "INCONCLUSIVE", "NOT_EVALUATED")
_HUNT_VERDICT_LEVELS = ("clean", "possible", "likely", "high", "inconclusive", "not_evaluated")
_HUNT_CONFIDENCES = ("none", "low", "medium", "high")
_HUNT_REVIEW_PRIORITIES = ("none", "low", "medium", "high")

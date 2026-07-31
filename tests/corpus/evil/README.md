# Evil corpus: false-negative gate

This corpus contains authorized malicious or controlled-positive process
dumps. Its purpose is to measure and block false negatives.

Each sample must declare `ground_truth.detected_hunts`. Every listed hunter is
required to return `status: DETECTED`; partial coverage does not invalidate a
positive result, but `INCONCLUSIVE`, `NOT_EVALUATED`, and scoped non-detection
all fail the FN gate.

Ground truth must be independent of dumpex. Record the controlled technique,
sandbox event, authoritative challenge evidence, or manual analysis that
supports each required hunter. Do not list a hunter merely because the current
dumpex version detects it.

Copy `manifest.example.yaml` to the ignored `manifest.yaml`, then store dumps
under the ignored `samples/` directory.

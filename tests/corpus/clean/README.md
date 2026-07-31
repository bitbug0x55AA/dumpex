# Clean corpus: false-positive gate

This corpus contains known-clean Windows process dumps. Its purpose is to
measure and block false positives.

The policy is zero tolerance: every dumpex hunter is run for every sample, and
the test fails if any result has `status: DETECTED`. A lead, partial coverage,
`INCONCLUSIVE`, or `NOT_EVALUATED` is not counted as an FP, although stable
coverage expectations may be asserted separately under `expected.hunt`.

A sample belongs here only when its clean state is supported by provenance:
for example, a verified vendor binary in a controlled clean VM, with no
injection or test payload active. Include difficult benign cases such as JIT
runtimes, browsers, packers, debuggers, security tools, and software that uses
named pipes.

Copy `manifest.example.yaml` to the ignored `manifest.yaml`, then store dumps
under the ignored `samples/` directory.

"""Makes tests/ a real package so pytest resolves test modules by their
fully-qualified dotted name (tests.hunt.test_stomping, ...) instead of a
bare basename — required for tests/fixtures/fakes.py to be importable as
tests.fixtures.fakes, and to avoid basename collisions across sibling
test directories during collection.
"""

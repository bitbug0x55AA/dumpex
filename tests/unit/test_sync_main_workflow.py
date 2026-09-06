"""Regression checks for the one-run-per-main-commit branch sync contract."""

from pathlib import Path


WORKFLOW = (
    Path(__file__).parents[2]
    / ".github"
    / "workflows"
    / "sync-main-to-all-branches.yml"
)


def test_sync_has_one_automatic_trigger_per_main_commit():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "  push:\n    branches: [main]" in workflow
    assert "workflow_run:" not in workflow


def test_sync_waits_for_required_main_push_checks():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert 'REQUIRED_WORKFLOWS: "Tests,Repository Leak Scan"' in workflow
    assert "head_sha=$sha&branch=main&event=push" in workflow
    assert 'sleep "$POLL_SECONDS"' in workflow

from pathlib import Path

from scripts import repo_privacy_scan


def test_private_corpus_and_dump_paths_are_rejected():
    private_rules = {
        finding.rule
        for finding in repo_privacy_scan.check_path(
            "tests/corpus/private/CORPUS_TESTING_GUIDE.zh-CN.md"
        )
    }
    dump_rules = {
        finding.rule
        for finding in repo_privacy_scan.check_path("tests/corpus/evil/samples/case.dmp")
    }

    assert "private-corpus-material" in private_rules
    assert "real-corpus-sample" in dump_rules
    assert "sensitive-file-type" in dump_rules


def test_real_manifest_and_local_settings_are_rejected():
    manifest_rules = {
        finding.rule
        for finding in repo_privacy_scan.check_path("tests/corpus/clean/manifest.yaml")
    }
    settings_rules = {
        finding.rule
        for finding in repo_privacy_scan.check_path(".claude/settings.local.json")
    }

    assert manifest_rules == {"real-corpus-manifest"}
    assert settings_rules == {"local-tool-settings"}


def test_credentials_are_rejected_but_templates_are_allowed():
    assert repo_privacy_scan.check_path(".env")
    assert repo_privacy_scan.check_path("config/.env.production")
    assert repo_privacy_scan.check_path("certificates/client.p12")
    assert repo_privacy_scan.check_path(".env.example") == []


def test_content_findings_do_not_render_matched_content():
    private_value = "C:" + "/Users/" + "private-user/Documents/case"
    findings = repo_privacy_scan.check_content(
        "config.json",
        f'{{"path": "{private_value}"}}'.encode(),
    )

    assert len(findings) == 1
    assert findings[0].rule == "windows-user-profile"
    assert findings[0].line == 1
    assert private_value not in findings[0].render()


def test_private_key_headers_are_rejected():
    private_key_header = "-----BEGIN " + "PRIVATE KEY-----"
    findings = repo_privacy_scan.check_content(
        "fixture.txt",
        f"{private_key_header}\nredacted\n-----END PRIVATE KEY-----\n".encode(),
    )

    assert [finding.rule for finding in findings] == ["private-key"]


def test_common_windows_examples_are_allowed():
    data = b"C:\\Windows\\System32\\ntdll.dll\nC:\\cases\\sample.dmp\n"
    assert repo_privacy_scan.check_content("docs/example.md", data) == []


def test_leak_scan_workflow_keeps_security_invariants():
    workflow = (
        Path(__file__).parents[2] / ".github" / "workflows" / "repository-leak-scan.yml"
    ).read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "fetch-depth: 0" in workflow
    assert "persist-credentials: false" in workflow
    assert "pull_request_target:" not in workflow
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "GITLEAKS_SHA256:" in workflow
    assert "--redact=100" in workflow

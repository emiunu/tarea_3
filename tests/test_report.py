

from pathlib import Path
from unittest.mock import MagicMock

import miner.report as report_module
from miner.git_ops import CloneResult
from miner.codeql_runner import CodeQLResult
from miner.models import Finding, RepoStatus, Severity


def _fake_github_client(repos):
    client = MagicMock()
    client.list_organization_repositories.return_value = repos
    return client


def test_unsupported_language_skips_clone_and_codeql(monkeypatch, tmp_path):
    repos = [{"name": "docs-only", "html_url": "https://github.com/org/docs-only", "language": None}]
    client = _fake_github_client(repos)

    clone_mock = MagicMock()
    monkeypatch.setattr(report_module, "clone_repository", clone_mock)

    result = report_module.analyze_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", db_dir=tmp_path / "db"
    )

    assert result.repositories[0].status == RepoStatus.UNSUPPORTED_LANGUAGE
    clone_mock.assert_not_called()


def test_clone_failure_does_not_stop_other_repos(monkeypatch, tmp_path):
    repos = [
        {"name": "broken", "html_url": "https://github.com/org/broken", "language": "Python"},
        {"name": "fine", "html_url": "https://github.com/org/fine", "language": "Python"},
    ]
    client = _fake_github_client(repos)

    def fake_clone(clone_url, name, workspace_dir):
        if name == "broken":
            return CloneResult(success=False, error="fatal: not found")
        return CloneResult(success=True, path=workspace_dir / name)

    monkeypatch.setattr(report_module, "clone_repository", fake_clone)
    monkeypatch.setattr(
        report_module, "create_database", lambda **kwargs: (CodeQLResult(success=True), tmp_path / "db" / "fine")
    )
    monkeypatch.setattr(report_module, "analyze_database", lambda **kwargs: CodeQLResult(success=True))
    monkeypatch.setattr(report_module, "parse_sarif_file", lambda path: [])

    result = report_module.analyze_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", db_dir=tmp_path / "db"
    )

    statuses = {r.name: r.status for r in result.repositories}
    assert statuses["broken"] == RepoStatus.CLONE_FAILED
    assert statuses["fine"] == RepoStatus.ANALYZED


def test_successful_repo_includes_findings(monkeypatch, tmp_path):
    repos = [{"name": "ok-repo", "html_url": "https://github.com/org/ok-repo", "language": "Python"}]
    client = _fake_github_client(repos)

    monkeypatch.setattr(
        report_module, "clone_repository", lambda clone_url, name, workspace_dir: CloneResult(success=True, path=workspace_dir / name)
    )
    monkeypatch.setattr(
        report_module, "create_database", lambda **kwargs: (CodeQLResult(success=True), tmp_path / "db" / "ok-repo")
    )
    monkeypatch.setattr(report_module, "analyze_database", lambda **kwargs: CodeQLResult(success=True))
    monkeypatch.setattr(
        report_module,
        "parse_sarif_file",
        lambda path: [Finding(rule_id="py/x", message="m", file="a.py", start_line=1, severity=Severity.WARNING)],
    )

    result = report_module.analyze_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", db_dir=tmp_path / "db"
    )

    repo = result.repositories[0]
    assert repo.status == RepoStatus.ANALYZED
    assert len(repo.findings) == 1
    assert result.summary.analyzed == 1
    assert result.summary.findings == 1


def test_max_repos_limits_processing(monkeypatch, tmp_path):
    repos = [
        {"name": "a", "html_url": "https://github.com/org/a", "language": None},
        {"name": "b", "html_url": "https://github.com/org/b", "language": None},
        {"name": "c", "html_url": "https://github.com/org/c", "language": None},
    ]
    client = _fake_github_client(repos)

    result = report_module.analyze_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", db_dir=tmp_path / "db", max_repos=2
    )

    assert len(result.repositories) == 2


def test_progress_callback_is_invoked(monkeypatch, tmp_path):
    repos = [{"name": "a", "html_url": "https://github.com/org/a", "language": None}]
    client = _fake_github_client(repos)
    calls = []

    report_module.analyze_organization(
        "example-org",
        client,
        workspace_dir=tmp_path / "ws",
        db_dir=tmp_path / "db",
        progress_callback=lambda name, msg: calls.append((name, msg)),
    )

    assert any(name == "a" for name, _ in calls)
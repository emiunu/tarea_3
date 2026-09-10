import json

from typer.testing import CliRunner

import miner.cli as cli_module
from miner.github_client import GitHubAuthError, GitHubOrgNotFoundError
from miner.models import OrganizationReport, RepositoryResult, RepoStatus

runner = CliRunner()


def _fake_report():
    return OrganizationReport.build(
        "pallets-eco",
        [RepositoryResult(name="flask", url="https://github.com/pallets-eco/flask", status=RepoStatus.ANALYZED)],
    )


def test_scan_writes_output_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "analyze_organization", lambda **kwargs: _fake_report())

    output_path = tmp_path / "results.json"
    result = runner.invoke(cli_module.app, ["--organization", "pallets-eco", "--output", str(output_path)])

    assert result.exit_code == 0
    assert output_path.exists()

    data = json.loads(output_path.read_text())
    assert data["organization"] == "pallets-eco"


def test_scan_passes_max_repos_through(tmp_path, monkeypatch):
    captured = {}

    def fake_analyze(**kwargs):
        captured.update(kwargs)
        return _fake_report()

    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "analyze_organization", fake_analyze)

    output_path = tmp_path / "results.json"
    runner.invoke(
        cli_module.app,
        ["--organization", "pallets-eco", "--output", str(output_path), "--max-repos", "2"],
    )

    assert captured["max_repos"] == 2


def test_scan_handles_auth_error(monkeypatch):
    def raise_auth_error():
        raise GitHubAuthError("token inválido")

    monkeypatch.setattr(cli_module, "GitHubClient", raise_auth_error)

    result = runner.invoke(cli_module.app, ["--organization", "pallets-eco"])

    assert result.exit_code == 1


def test_scan_handles_org_not_found(tmp_path, monkeypatch):
    def fake_analyze(**kwargs):
        raise GitHubOrgNotFoundError("no existe")

    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "analyze_organization", fake_analyze)

    result = runner.invoke(cli_module.app, ["--organization", "does-not-exist"])

    assert result.exit_code == 1
import json
 
from typer.testing import CliRunner
 
import miner.cli as cli_module
from miner.github_client import GitHubAuthError, GitHubOrgNotFoundError
from miner.models import (
    OrganizationReport,
    RepositoryResult,
    RepoStatus,
    SbomInfo,
    SbomOrganizationReport,
    SbomStatus,
)
 
runner = CliRunner()
 
 
def _fake_report():
    return OrganizationReport.build(
        "pallets-eco",
        [RepositoryResult(name="flask", url="https://github.com/pallets-eco/flask", status=RepoStatus.ANALYZED)],
    )
 
 
def _fake_sbom_report():
    return SbomOrganizationReport.build(
        "pallets-eco",
        [
            SbomInfo(
                repository="pallets-eco/flask",
                commit="abc123",
                generated_at="2026-09-17T12:00:00Z",
                syft_version="1.18.0",
                status=SbomStatus.SUCCESS,
                component_count=5,
                sbom_path="sboms/flask.cdx.json",
            )
        ],
    )
 
 
# --- comando scan (nota: ahora se invoca con "scan" explícito, porque al ---
# --- existir más de un comando registrado, Typer deja de tratar el único ---
# --- comando como el "default" implícito) -----------------------------------
 
 
def test_scan_writes_output_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "analyze_organization", lambda **kwargs: _fake_report())
 
    output_path = tmp_path / "results.json"
    result = runner.invoke(
        cli_module.app, ["scan", "--organization", "pallets-eco", "--output", str(output_path)]
    )
 
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
        ["scan", "--organization", "pallets-eco", "--output", str(output_path), "--max-repos", "2"],
    )
 
    assert captured["max_repos"] == 2
 
 
def test_scan_handles_auth_error(monkeypatch):
    def raise_auth_error():
        raise GitHubAuthError("token inválido")
 
    monkeypatch.setattr(cli_module, "GitHubClient", raise_auth_error)
 
    result = runner.invoke(cli_module.app, ["scan", "--organization", "pallets-eco"])
 
    assert result.exit_code == 1
 
 
def test_scan_handles_org_not_found(tmp_path, monkeypatch):
    def fake_analyze(**kwargs):
        raise GitHubOrgNotFoundError("no existe")
 
    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "analyze_organization", fake_analyze)
 
    result = runner.invoke(cli_module.app, ["scan", "--organization", "does-not-exist"])
 
    assert result.exit_code == 1
 
 
# --- comando sbom -------------------------------------------------------
 
 
def test_sbom_writes_output_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "generate_sboms_for_organization", lambda **kwargs: _fake_sbom_report())
 
    output_path = tmp_path / "sbom-results.json"
    result = runner.invoke(
        cli_module.app,
        ["sbom", "--organization", "pallets-eco", "--output", str(output_path)],
    )
 
    assert result.exit_code == 0
    assert output_path.exists()
 
    data = json.loads(output_path.read_text())
    assert data["organization"] == "pallets-eco"
    assert data["repositories"][0]["component_count"] == 5
 
 
def test_sbom_passes_sbom_dir_and_max_repos_through(tmp_path, monkeypatch):
    captured = {}
 
    def fake_generate(**kwargs):
        captured.update(kwargs)
        return _fake_sbom_report()
 
    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "generate_sboms_for_organization", fake_generate)
 
    output_path = tmp_path / "sbom-results.json"
    sbom_dir = tmp_path / "custom-sboms"
    runner.invoke(
        cli_module.app,
        [
            "sbom",
            "--organization",
            "pallets-eco",
            "--output",
            str(output_path),
            "--sbom-dir",
            str(sbom_dir),
            "--max-repos",
            "3",
        ],
    )
 
    assert captured["sbom_dir"] == sbom_dir
    assert captured["max_repos"] == 3
 
 
def test_sbom_does_not_import_codeql_analysis(monkeypatch, tmp_path):
    # El comando sbom no debe llamar a analyze_organization (CodeQL) bajo
    # ninguna circunstancia: es la forma de verificar "sin repetir CodeQL".
    analyze_mock_calls = []
    monkeypatch.setattr(
        cli_module, "analyze_organization", lambda **kwargs: analyze_mock_calls.append(kwargs)
    )
    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "generate_sboms_for_organization", lambda **kwargs: _fake_sbom_report())
 
    output_path = tmp_path / "sbom-results.json"
    runner.invoke(cli_module.app, ["sbom", "--organization", "pallets-eco", "--output", str(output_path)])
 
    assert analyze_mock_calls == []
 
 
def test_sbom_handles_auth_error(monkeypatch):
    def raise_auth_error():
        raise GitHubAuthError("token inválido")
 
    monkeypatch.setattr(cli_module, "GitHubClient", raise_auth_error)
 
    result = runner.invoke(cli_module.app, ["sbom", "--organization", "pallets-eco"])
 
    assert result.exit_code == 1
 
 
def test_sbom_handles_org_not_found(tmp_path, monkeypatch):
    def fake_generate(**kwargs):
        raise GitHubOrgNotFoundError("no existe")
 
    monkeypatch.setattr(cli_module, "GitHubClient", lambda: object())
    monkeypatch.setattr(cli_module, "generate_sboms_for_organization", fake_generate)
 
    result = runner.invoke(cli_module.app, ["sbom", "--organization", "does-not-exist"])
 
    assert result.exit_code == 1
 
from unittest.mock import MagicMock
 
import miner.sbom_report as sbom_report_module
from miner.git_ops import CloneResult
from miner.models import SbomStatus
from miner.sbom_runner import SbomRunResult
 
 
def _fake_github_client(repos):
    client = MagicMock()
    client.list_organization_repositories.return_value = repos
    return client
 
 
def test_clone_failure_does_not_stop_other_repos(monkeypatch, tmp_path):
    repos = [
        {"name": "broken", "full_name": "org/broken", "clone_url": "https://github.com/org/broken.git"},
        {"name": "fine", "full_name": "org/fine", "clone_url": "https://github.com/org/fine.git"},
    ]
    client = _fake_github_client(repos)
 
    def fake_clone(clone_url, name, workspace_dir):
        if name == "broken":
            return CloneResult(success=False, error="fatal: not found")
        return CloneResult(success=True, path=workspace_dir / name)
 
    monkeypatch.setattr(sbom_report_module, "clone_repository", fake_clone)
    monkeypatch.setattr(sbom_report_module, "get_current_commit", lambda path: "abc123")
    monkeypatch.setattr(
        sbom_report_module,
        "generate_sbom",
        lambda **kwargs: SbomRunResult(
            success=True, component_count=5, syft_version="1.18.0", sbom_path=kwargs["output_path"]
        ),
    )
 
    result = sbom_report_module.generate_sboms_for_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", sbom_dir=tmp_path / "sboms"
    )
 
    statuses = {r.repository: r.status for r in result.repositories}
    assert statuses["org/broken"] == SbomStatus.FAILED
    assert statuses["org/fine"] == SbomStatus.SUCCESS
 
 
def test_syft_failure_is_recorded_without_stopping_the_run(monkeypatch, tmp_path):
    repos = [{"name": "ok-repo", "full_name": "org/ok-repo", "clone_url": "https://github.com/org/ok-repo.git"}]
    client = _fake_github_client(repos)
 
    monkeypatch.setattr(
        sbom_report_module,
        "clone_repository",
        lambda clone_url, name, workspace_dir: CloneResult(success=True, path=workspace_dir / name),
    )
    monkeypatch.setattr(sbom_report_module, "get_current_commit", lambda path: "abc123")
    monkeypatch.setattr(
        sbom_report_module,
        "generate_sbom",
        lambda **kwargs: SbomRunResult(success=False, syft_version="1.18.0", error="unsupported source type"),
    )
 
    result = sbom_report_module.generate_sboms_for_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", sbom_dir=tmp_path / "sboms"
    )
 
    repo = result.repositories[0]
    assert repo.status == SbomStatus.FAILED
    assert repo.error == "unsupported source type"
    assert repo.component_count == 0
    assert repo.sbom_path is None
 
 
def test_successful_repo_with_zero_components_is_not_a_failure(monkeypatch, tmp_path):
    repos = [{"name": "empty-repo", "full_name": "org/empty-repo", "clone_url": "https://github.com/org/empty-repo.git"}]
    client = _fake_github_client(repos)
 
    monkeypatch.setattr(
        sbom_report_module,
        "clone_repository",
        lambda clone_url, name, workspace_dir: CloneResult(success=True, path=workspace_dir / name),
    )
    monkeypatch.setattr(sbom_report_module, "get_current_commit", lambda path: "abc123")
    monkeypatch.setattr(
        sbom_report_module,
        "generate_sbom",
        lambda **kwargs: SbomRunResult(
            success=True, component_count=0, syft_version="1.18.0", sbom_path=kwargs["output_path"]
        ),
    )
 
    result = sbom_report_module.generate_sboms_for_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", sbom_dir=tmp_path / "sboms"
    )
 
    repo = result.repositories[0]
    assert repo.status == SbomStatus.SUCCESS
    assert repo.component_count == 0
    assert result.summary.failed == 0
    assert result.summary.generated == 1
 
 
def test_sbom_info_includes_commit_and_path(monkeypatch, tmp_path):
    repos = [{"name": "ok-repo", "full_name": "org/ok-repo", "clone_url": "https://github.com/org/ok-repo.git"}]
    client = _fake_github_client(repos)
 
    monkeypatch.setattr(
        sbom_report_module,
        "clone_repository",
        lambda clone_url, name, workspace_dir: CloneResult(success=True, path=workspace_dir / name),
    )
    monkeypatch.setattr(sbom_report_module, "get_current_commit", lambda path: "deadbeef")
    monkeypatch.setattr(
        sbom_report_module,
        "generate_sbom",
        lambda **kwargs: SbomRunResult(
            success=True, component_count=3, syft_version="1.18.0", sbom_path=kwargs["output_path"]
        ),
    )
 
    result = sbom_report_module.generate_sboms_for_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", sbom_dir=tmp_path / "sboms"
    )
 
    repo = result.repositories[0]
    assert repo.commit == "deadbeef"
    assert repo.repository == "org/ok-repo"
    assert repo.sbom_path == str(tmp_path / "sboms" / "ok-repo.cdx.json")
 
 
def test_max_repos_limits_processing(monkeypatch, tmp_path):
    repos = [
        {"name": "a", "full_name": "org/a", "clone_url": "https://github.com/org/a.git"},
        {"name": "b", "full_name": "org/b", "clone_url": "https://github.com/org/b.git"},
        {"name": "c", "full_name": "org/c", "clone_url": "https://github.com/org/c.git"},
    ]
    client = _fake_github_client(repos)
 
    monkeypatch.setattr(
        sbom_report_module,
        "clone_repository",
        lambda clone_url, name, workspace_dir: CloneResult(success=True, path=workspace_dir / name),
    )
    monkeypatch.setattr(sbom_report_module, "get_current_commit", lambda path: "abc123")
    monkeypatch.setattr(
        sbom_report_module,
        "generate_sbom",
        lambda **kwargs: SbomRunResult(
            success=True, component_count=1, syft_version="1.18.0", sbom_path=kwargs["output_path"]
        ),
    )
 
    result = sbom_report_module.generate_sboms_for_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", sbom_dir=tmp_path / "sboms", max_repos=2
    )
 
    assert len(result.repositories) == 2
 
 
def test_progress_callback_is_invoked(monkeypatch, tmp_path):
    repos = [{"name": "a", "full_name": "org/a", "clone_url": "https://github.com/org/a.git"}]
    client = _fake_github_client(repos)
    calls = []
 
    monkeypatch.setattr(
        sbom_report_module,
        "clone_repository",
        lambda clone_url, name, workspace_dir: CloneResult(success=True, path=workspace_dir / name),
    )
    monkeypatch.setattr(sbom_report_module, "get_current_commit", lambda path: "abc123")
    monkeypatch.setattr(
        sbom_report_module,
        "generate_sbom",
        lambda **kwargs: SbomRunResult(
            success=True, component_count=1, syft_version="1.18.0", sbom_path=kwargs["output_path"]
        ),
    )
 
    sbom_report_module.generate_sboms_for_organization(
        "example-org",
        client,
        workspace_dir=tmp_path / "ws",
        sbom_dir=tmp_path / "sboms",
        progress_callback=lambda name, msg: calls.append((name, msg)),
    )
 
    assert any(name == "a" for name, _ in calls)
 
 
def test_unexpected_exception_is_recorded_and_run_continues(monkeypatch, tmp_path):
    repos = [
        {"name": "weird", "full_name": "org/weird", "clone_url": "https://github.com/org/weird.git"},
        {"name": "fine", "full_name": "org/fine", "clone_url": "https://github.com/org/fine.git"},
    ]
    client = _fake_github_client(repos)
 
    def fake_clone(clone_url, name, workspace_dir):
        if name == "weird":
            raise RuntimeError("algo inesperado")
        return CloneResult(success=True, path=workspace_dir / name)
 
    monkeypatch.setattr(sbom_report_module, "clone_repository", fake_clone)
    monkeypatch.setattr(sbom_report_module, "get_current_commit", lambda path: "abc123")
    monkeypatch.setattr(
        sbom_report_module,
        "generate_sbom",
        lambda **kwargs: SbomRunResult(
            success=True, component_count=1, syft_version="1.18.0", sbom_path=kwargs["output_path"]
        ),
    )
 
    result = sbom_report_module.generate_sboms_for_organization(
        "example-org", client, workspace_dir=tmp_path / "ws", sbom_dir=tmp_path / "sboms"
    )
 
    statuses = {r.repository: r.status for r in result.repositories}
    assert statuses["org/weird"] == SbomStatus.FAILED
    assert statuses["org/fine"] == SbomStatus.SUCCESS
 
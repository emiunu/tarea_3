from __future__ import annotations
 
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
 
from miner.git_ops import clone_repository, get_current_commit
from miner.github_client import GitHubClient
from miner.models import SbomInfo, SbomOrganizationReport, SbomStatus
from miner.sbom_runner import generate_sbom
 
ProgressCallback = Callable[[str, str], None]
 
 
def _noop_progress(repo_name: str, message: str) -> None:
    return None
 
 
def generate_sboms_for_organization(
    organization: str,
    github_client: GitHubClient,
    workspace_dir: Path = Path("workspace"),
    sbom_dir: Path = Path("sboms"),
    max_repos: int | None = None,
    progress_callback: ProgressCallback = _noop_progress,
) -> SbomOrganizationReport:
    repos_metadata = github_client.list_organization_repositories(organization)
    if max_repos is not None:
        repos_metadata = repos_metadata[:max_repos]
 
    results: list[SbomInfo] = []
    for repo_meta in repos_metadata:
        repo_name = repo_meta.get("name", "unknown")
        try:
            results.append(
                _generate_sbom_for_repository(
                    repo_meta,
                    workspace_dir=workspace_dir,
                    sbom_dir=sbom_dir,
                    progress_callback=progress_callback,
                )
            )
        except Exception as exc:  # noqa: BLE001 - no debe abortar la corrida completa
            progress_callback(repo_name, f"error inesperado: {exc}")
            results.append(
                SbomInfo(
                    repository=repo_meta.get("full_name", repo_name),
                    commit=None,
                    generated_at=datetime.now(timezone.utc),
                    syft_version=None,
                    status=SbomStatus.FAILED,
                    component_count=0,
                    sbom_path=None,
                    error=str(exc),
                )
            )
 
    return SbomOrganizationReport.build(organization, results)
 
 
def _generate_sbom_for_repository(
    repo_meta: dict,
    workspace_dir: Path,
    sbom_dir: Path,
    progress_callback: ProgressCallback,
) -> SbomInfo:
    name = repo_meta["name"]
    full_name = repo_meta.get("full_name", name)
    clone_url = repo_meta.get("clone_url", f"https://github.com/{full_name}.git")
 
    progress_callback(name, "clonando repositorio (o reutilizando clon existente)")
    clone_result = clone_repository(clone_url, name, workspace_dir=workspace_dir)
    if not clone_result.success:
        progress_callback(name, f"error al clonar: {clone_result.error}")
        return SbomInfo(
            repository=full_name,
            commit=None,
            generated_at=datetime.now(timezone.utc),
            syft_version=None,
            status=SbomStatus.FAILED,
            component_count=0,
            sbom_path=None,
            error=clone_result.error,
        )
 
    commit = get_current_commit(clone_result.path)
 
    progress_callback(name, "generando SBOM con Syft")
    output_path = sbom_dir / f"{name}.cdx.json"
    sbom_result = generate_sbom(
        source_root=clone_result.path,
        output_path=output_path,
        repo_name=name,
    )
 
    if not sbom_result.success:
        progress_callback(name, f"error generando SBOM: {sbom_result.error}")
        return SbomInfo(
            repository=full_name,
            commit=commit,
            generated_at=datetime.now(timezone.utc),
            syft_version=sbom_result.syft_version,
            status=SbomStatus.FAILED,
            component_count=0,
            sbom_path=None,
            error=sbom_result.error,
        )
 
    progress_callback(name, f"SBOM generado: {sbom_result.component_count} componente(s)")
    return SbomInfo(
        repository=full_name,
        commit=commit,
        generated_at=datetime.now(timezone.utc),
        syft_version=sbom_result.syft_version,
        status=SbomStatus.SUCCESS,
        component_count=sbom_result.component_count,
        sbom_path=str(sbom_result.sbom_path),
        error=None,
    )
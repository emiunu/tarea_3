

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from miner.codeql_runner import analyze_database, create_database
from miner.git_ops import clone_repository
from miner.github_client import GitHubClient
from miner.language import detect_codeql_language
from miner.models import OrganizationReport, RepositoryResult, RepoStatus
from miner.sarif_parser import parse_sarif_file

ProgressCallback = Callable[[str, str], None]


class RepoDict(Protocol):

    name: str


def _noop_progress(repo_name: str, message: str) -> None:
    return None


def analyze_organization(
    organization: str,
    github_client: GitHubClient,
    workspace_dir: Path = Path("workspace"),
    db_dir: Path = Path("db"),
    sarif_dir: Path = Path("db") / "_sarif",
    max_repos: int | None = None,
    progress_callback: ProgressCallback = _noop_progress,
) -> OrganizationReport:
   
    repos_metadata = github_client.list_organization_repositories(organization)
    if max_repos is not None:
        repos_metadata = repos_metadata[:max_repos]

    results: list[RepositoryResult] = []
    for repo_meta in repos_metadata:
        results.append(
            _analyze_single_repository(
                repo_meta,
                workspace_dir=workspace_dir,
                db_dir=db_dir,
                sarif_dir=sarif_dir,
                progress_callback=progress_callback,
            )
        )

    return OrganizationReport.build(organization, results)


def _analyze_single_repository(
    repo_meta: dict,
    workspace_dir: Path,
    db_dir: Path,
    sarif_dir: Path,
    progress_callback: ProgressCallback,
) -> RepositoryResult:
    name = repo_meta["name"]
    url = repo_meta.get("html_url", f"https://github.com/{repo_meta.get('full_name', name)}")
    clone_url = repo_meta.get("clone_url", url + ".git")
    github_language = repo_meta.get("language")

    progress_callback(name, "iniciando análisis")

    codeql_language = detect_codeql_language(github_language)
    if codeql_language is None:
        progress_callback(name, f"lenguaje no soportado ({github_language!r}), se omite")
        return RepositoryResult(
            name=name,
            url=url,
            status=RepoStatus.UNSUPPORTED_LANGUAGE,
            languages=[github_language.lower()] if github_language else [],
            error=f"Lenguaje no soportado por el miner: {github_language!r}",
        )

    progress_callback(name, "clonando repositorio")
    clone_result = clone_repository(clone_url, name, workspace_dir=workspace_dir)
    if not clone_result.success:
        progress_callback(name, f"error al clonar: {clone_result.error}")
        return RepositoryResult(
            name=name,
            url=url,
            status=RepoStatus.CLONE_FAILED,
            languages=[codeql_language],
            error=clone_result.error,
        )

    progress_callback(name, "creando base de datos CodeQL")
    db_result, database_path = create_database(
        source_root=clone_result.path,
        language=codeql_language,
        db_dir=db_dir,
        repo_name=name,
    )
    if not db_result.success:
        progress_callback(name, f"error creando base de datos: {db_result.error}")
        return RepositoryResult(
            name=name,
            url=url,
            status=RepoStatus.DATABASE_FAILED,
            languages=[codeql_language],
            error=db_result.error,
        )

    progress_callback(name, "ejecutando consultas de seguridad de CodeQL")
    sarif_path = sarif_dir / f"{name}.sarif"
    analyze_result = analyze_database(
        database_path=database_path,
        language=codeql_language,
        sarif_output_path=sarif_path,
    )
    if not analyze_result.success:
        progress_callback(name, f"error en el análisis: {analyze_result.error}")
        return RepositoryResult(
            name=name,
            url=url,
            status=RepoStatus.ANALYSIS_FAILED,
            languages=[codeql_language],
            error=analyze_result.error,
        )

    findings = parse_sarif_file(sarif_path)
    progress_callback(name, f"análisis completo: {len(findings)} hallazgo(s)")

    return RepositoryResult(
        name=name,
        url=url,
        status=RepoStatus.ANALYZED,
        languages=[codeql_language],
        findings=findings,
    )
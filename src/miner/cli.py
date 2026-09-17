from __future__ import annotations
 
import sys
from pathlib import Path
 
import typer
 
from miner.github_client import GitHubAuthError, GitHubClient, GitHubOrgNotFoundError
from miner.report import analyze_organization
from miner.sbom_report import generate_sboms_for_organization
 
app = typer.Typer(help="Miner de vulnerabilidades para organizaciones de GitHub, usando CodeQL y Syft.")
 
 
def _print_progress(repo_name: str, message: str) -> None:
    typer.echo(f"[{repo_name}] {message}", err=True)
 
 
@app.command()
def scan(
    organization: str = typer.Option(..., "--organization", "-o", help="Nombre de la organización de GitHub a analizar."),
    output: Path = typer.Option(Path("results.json"), "--output", help="Archivo donde se guardará el JSON final."),
    max_repos: int | None = typer.Option(
        None,
        "--max-repos",
        help="Límite de repositorios a procesar, útil para pruebas rápidas antes de correr la organización completa.",
    ),
    workspace_dir: Path = typer.Option(Path("workspace"), "--workspace-dir", help="Carpeta donde se clonan los repos."),
    db_dir: Path = typer.Option(Path("db"), "--db-dir", help="Carpeta donde se crean las bases de datos de CodeQL."),
) -> None:
    typer.echo(f"Consultando repositorios de la organización '{organization}'...", err=True)
 
    try:
        client = GitHubClient()
    except GitHubAuthError as exc:
        typer.echo(f"Error de autenticación: {exc}", err=True)
        raise typer.Exit(code=1) from exc
 
    try:
        report = analyze_organization(
            organization=organization,
            github_client=client,
            workspace_dir=workspace_dir,
            db_dir=db_dir,
            sarif_dir=db_dir / "_sarif",
            max_repos=max_repos,
            progress_callback=_print_progress,
        )
    except GitHubOrgNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
 
    output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
 
    typer.echo(
        f"Listo. {report.summary.analyzed} analizados, {report.summary.failed} fallidos, "
        f"{report.summary.unsupported} no soportados, {report.summary.findings} hallazgos totales.",
        err=True,
    )
    typer.echo(f"Resultado guardado en: {output}", err=True)
 
 
@app.command()
def sbom(
    organization: str = typer.Option(..., "--organization", "-o", help="Nombre de la organización de GitHub a analizar."),
    output: Path = typer.Option(
        Path("sbom-results.json"), "--output", help="Archivo JSON consolidado con los resultados de todos los repos."
    ),
    sbom_dir: Path = typer.Option(
        Path("sboms"), "--sbom-dir", help="Carpeta donde se guarda un SBOM CycloneDX JSON por repositorio."
    ),
    max_repos: int | None = typer.Option(
        None,
        "--max-repos",
        help="Límite de repositorios a procesar, útil para pruebas rápidas antes de correr la organización completa.",
    ),
    workspace_dir: Path = typer.Option(
        Path("workspace"),
        "--workspace-dir",
        help="Carpeta donde se clonan (o reutilizan, si ya fueron clonados con 'scan') los repos.",
    ),
) -> None:
    """Genera un SBOM por repositorio con Syft, sin repetir el análisis de CodeQL."""
    typer.echo(f"Consultando repositorios de la organización '{organization}'...", err=True)
 
    try:
        client = GitHubClient()
    except GitHubAuthError as exc:
        typer.echo(f"Error de autenticación: {exc}", err=True)
        raise typer.Exit(code=1) from exc
 
    try:
        report = generate_sboms_for_organization(
            organization=organization,
            github_client=client,
            workspace_dir=workspace_dir,
            sbom_dir=sbom_dir,
            max_repos=max_repos,
            progress_callback=_print_progress,
        )
    except GitHubOrgNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
 
    output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
 
    typer.echo(
        f"Listo. {report.summary.generated} SBOM(s) generados, {report.summary.failed} fallidos, "
        f"{report.summary.total_components} componentes identificados en total.",
        err=True,
    )
    typer.echo(f"SBOMs individuales guardados en: {sbom_dir}", err=True)
    typer.echo(f"Resultado consolidado guardado en: {output}", err=True)
 
 
def main() -> None:
    app()
 
 
if __name__ == "__main__":
    main()
 
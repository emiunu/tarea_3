
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DB_DIR = Path("db")


DEFAULT_QUERY_SUITE = {
    "python": "python-security-and-quality.qls",
    "javascript": "javascript-security-and-quality.qls",
    "java": "java-security-and-quality.qls",
    "cpp": "cpp-security-and-quality.qls",
    "csharp": "csharp-security-and-quality.qls",
    "go": "go-security-and-quality.qls",
    "ruby": "ruby-security-and-quality.qls",
}


@dataclass
class CodeQLResult:

    success: bool
    error: str | None = None


def create_database(
    source_root: Path,
    language: str,
    db_dir: Path = DEFAULT_DB_DIR,
    repo_name: str = "",
    timeout_seconds: int = 600,
) -> tuple[CodeQLResult, Path]:
    
    database_path = db_dir / (repo_name or source_root.name)

    if database_path.exists():
        
        return CodeQLResult(success=True), database_path

    db_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                "codeql",
                "database",
                "create",
                str(database_path),
                f"--language={language}",
                f"--source-root={source_root}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.CalledProcessError as exc:
        return CodeQLResult(success=False, error=exc.stderr.strip() or str(exc)), database_path
    except subprocess.TimeoutExpired as exc:
        return CodeQLResult(success=False, error=f"Timeout creando la base de datos: {exc}"), database_path
    except OSError as exc:
        return CodeQLResult(success=False, error=f"Error de sistema ejecutando codeql: {exc}"), database_path

    return CodeQLResult(success=True), database_path


def analyze_database(
    database_path: Path,
    language: str,
    sarif_output_path: Path,
    query_suite: str | None = None,
    timeout_seconds: int = 900,
) -> CodeQLResult:
    
    suite = query_suite or DEFAULT_QUERY_SUITE.get(language)
    if suite is None:
        return CodeQLResult(success=False, error=f"No hay query suite definida para el lenguaje '{language}'")

    sarif_output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                "codeql",
                "database",
                "analyze",
                str(database_path),
                suite,
                "--format=sarif-latest",
                f"--output={sarif_output_path}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.CalledProcessError as exc:
        return CodeQLResult(success=False, error=exc.stderr.strip() or str(exc))
    except subprocess.TimeoutExpired as exc:
        return CodeQLResult(success=False, error=f"Timeout analizando la base de datos: {exc}")
    except OSError as exc:
        return CodeQLResult(success=False, error=f"Error de sistema ejecutando codeql: {exc}")

    return CodeQLResult(success=True)
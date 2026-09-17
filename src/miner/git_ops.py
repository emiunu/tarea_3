

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_WORKSPACE_DIR = Path("workspace")


@dataclass
class CloneResult:
    """Resultado de intentar clonar un repositorio."""

    success: bool
    path: Path | None = None
    error: str | None = None


def clone_repository(
    clone_url: str,
    repo_name: str,
    workspace_dir: Path = DEFAULT_WORKSPACE_DIR,
    timeout_seconds: int = 120,
) -> CloneResult:
    
    destination = workspace_dir / repo_name

    if destination.exists():
        # Repo ya clonado en una corrida anterior (útil mientras pruebas
        # con pocos repos): lo reusamos en vez de fallar o re-clonar.
        return CloneResult(success=True, path=destination)

    workspace_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, str(destination)],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.CalledProcessError as exc:
        return CloneResult(success=False, error=exc.stderr.strip() or str(exc))
    except subprocess.TimeoutExpired as exc:
        return CloneResult(success=False, error=f"Timeout clonando {repo_name}: {exc}")
    except OSError as exc:
        # git no instalado, permisos, etc.
        return CloneResult(success=False, error=f"Error de sistema al clonar {repo_name}: {exc}")

    return CloneResult(success=True, path=destination)

def get_current_commit(repo_path: Path) -> str | None:
    #Retorna el hash del commit actual (HEAD) de un repo ya clonado.
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
 
    return result.stdout.strip() or None
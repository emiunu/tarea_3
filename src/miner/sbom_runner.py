from __future__ import annotations
 
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
 
DEFAULT_SBOM_DIR = Path("sboms")
 
 
@dataclass
class SbomRunResult:
    #Resultado de intentar generar el SBOM de un repositorio.
 
    success: bool
    component_count: int = 0
    syft_version: str | None = None
    sbom_path: Path | None = None
    error: str | None = None
 
 
def get_syft_version(timeout_seconds: int = 10) -> str | None:
    try:
        result = subprocess.run(
            ["syft", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
 
    # La salida típica es algo como: "syft 1.18.0"
    match = re.search(r"(\d+\.\d+\.\d+\S*)", result.stdout)
    if match:
        return match.group(1)
    return result.stdout.strip() or None
 
 
def _count_components(sbom_path: Path) -> int:
    try:
        content = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    return len(content.get("components", []))
 
 
def generate_sbom(
    source_root: Path,
    output_path: Path,
    repo_name: str = "",
    timeout_seconds: int = 300,
) -> SbomRunResult:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    syft_version = get_syft_version()
 
    try:
        subprocess.run(
            [
                "syft",
                str(source_root),
                "-o",
                f"cyclonedx-json={output_path}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.CalledProcessError as exc:
        return SbomRunResult(
            success=False,
            syft_version=syft_version,
            error=exc.stderr.strip() or str(exc),
        )
    except subprocess.TimeoutExpired as exc:
        return SbomRunResult(
            success=False,
            syft_version=syft_version,
            error=f"Timeout generando SBOM para {repo_name or source_root}: {exc}",
        )
    except OSError as exc:
        return SbomRunResult(
            success=False,
            syft_version=syft_version,
            error=f"Error de sistema ejecutando syft: {exc}",
        )
 
    if not output_path.exists():
        return SbomRunResult(
            success=False,
            syft_version=syft_version,
            error="Syft finalizó sin errores pero no generó el archivo de SBOM esperado.",
        )
 
    component_count = _count_components(output_path)
 
    return SbomRunResult(
        success=True,
        component_count=component_count,
        syft_version=syft_version,
        sbom_path=output_path,
    )
 
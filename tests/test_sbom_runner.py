import json
import subprocess
 
import pytest
 
from miner.sbom_runner import generate_sbom, get_syft_version
 
 
def _fake_run_factory(version_stdout="syft 1.18.0\n", sbom_content=None, raise_on_generate=None):
    """Crea un fake_run que responde distinto según si se invoca
    `syft --version` o `syft <path> -o cyclonedx-json=...`.
    """
 
    def fake_run(cmd, *args, **kwargs):
        if "--version" in cmd:
            return subprocess.CompletedProcess(cmd, returncode=0, stdout=version_stdout)
 
        if raise_on_generate is not None:
            raise raise_on_generate
 
        if sbom_content is not None:
            output_arg = next(part for part in cmd if part.startswith("cyclonedx-json="))
            output_path = output_arg.split("=", 1)[1]
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(sbom_content, fh)
 
        return subprocess.CompletedProcess(cmd, returncode=0)
 
    return fake_run
 
 
def test_get_syft_version_parses_version(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(version_stdout="syft 1.18.0\n"))
 
    version = get_syft_version()
 
    assert version == "1.18.0"
 
 
def test_get_syft_version_returns_none_on_missing_binary(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("syft no encontrado")
 
    monkeypatch.setattr(subprocess, "run", fake_run)
 
    version = get_syft_version()
 
    assert version is None
 
 
def test_generate_sbom_success_counts_components(tmp_path, monkeypatch):
    sbom_content = {"components": [{"name": "requests"}, {"name": "flask"}]}
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(sbom_content=sbom_content))
 
    output_path = tmp_path / "sboms" / "repo.cdx.json"
    result = generate_sbom(
        source_root=tmp_path / "workspace" / "repo",
        output_path=output_path,
        repo_name="repo",
    )
 
    assert result.success is True
    assert result.component_count == 2
    assert result.syft_version == "1.18.0"
    assert result.sbom_path == output_path
    assert result.error is None
 
 
def test_generate_sbom_success_with_zero_components(tmp_path, monkeypatch):
    sbom_content = {"components": []}
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(sbom_content=sbom_content))
 
    output_path = tmp_path / "sboms" / "repo.cdx.json"
    result = generate_sbom(
        source_root=tmp_path / "workspace" / "repo",
        output_path=output_path,
        repo_name="repo",
    )
 
    assert result.success is True
    assert result.component_count == 0
    assert result.error is None
 
 
def test_generate_sbom_failure_records_stderr(tmp_path, monkeypatch):
    error = subprocess.CalledProcessError(returncode=1, cmd="syft", stderr="unsupported source type")
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(raise_on_generate=error))
 
    result = generate_sbom(
        source_root=tmp_path / "workspace" / "repo",
        output_path=tmp_path / "sboms" / "repo.cdx.json",
        repo_name="repo",
    )
 
    assert result.success is False
    assert "unsupported source type" in result.error
 
 
def test_generate_sbom_timeout_is_reported(tmp_path, monkeypatch):
    error = subprocess.TimeoutExpired(cmd="syft", timeout=1)
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(raise_on_generate=error))
 
    result = generate_sbom(
        source_root=tmp_path / "workspace" / "repo",
        output_path=tmp_path / "sboms" / "repo.cdx.json",
        repo_name="repo",
        timeout_seconds=1,
    )
 
    assert result.success is False
    assert "Timeout" in result.error
 
 
def test_generate_sbom_missing_binary(tmp_path, monkeypatch):
    error = FileNotFoundError("syft no encontrado")
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(raise_on_generate=error))
 
    result = generate_sbom(
        source_root=tmp_path / "workspace" / "repo",
        output_path=tmp_path / "sboms" / "repo.cdx.json",
        repo_name="repo",
    )
 
    assert result.success is False
    assert "Error de sistema" in result.error
 
 
def test_generate_sbom_reports_failure_when_output_file_missing(tmp_path, monkeypatch):
    # Syft termina sin error pero, por algún motivo, no escribe el archivo esperado.
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(sbom_content=None))
 
    result = generate_sbom(
        source_root=tmp_path / "workspace" / "repo",
        output_path=tmp_path / "sboms" / "repo.cdx.json",
        repo_name="repo",
    )
 
    assert result.success is False
    assert "no generó el archivo" in result.error
 
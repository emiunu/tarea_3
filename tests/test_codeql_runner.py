

import subprocess
from pathlib import Path

import pytest

from miner.codeql_runner import analyze_database, create_database


def test_create_database_success(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result, db_path = create_database(
        source_root=tmp_path / "workspace" / "repo",
        language="python",
        db_dir=tmp_path / "db",
        repo_name="repo",
    )

    assert result.success is True
    assert db_path == tmp_path / "db" / "repo"


def test_create_database_reuses_existing(tmp_path):
    existing_db = tmp_path / "db" / "repo"
    existing_db.mkdir(parents=True)

    result, db_path = create_database(
        source_root=tmp_path / "workspace" / "repo",
        language="python",
        db_dir=tmp_path / "db",
        repo_name="repo",
    )

    assert result.success is True
    assert db_path == existing_db


def test_create_database_failure_records_stderr(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd="codeql", stderr="no source code found")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result, _ = create_database(
        source_root=tmp_path / "workspace" / "repo",
        language="python",
        db_dir=tmp_path / "db",
        repo_name="repo",
    )

    assert result.success is False
    assert "no source code found" in result.error


def test_create_database_missing_binary(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("codeql no encontrado")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result, _ = create_database(
        source_root=tmp_path / "workspace" / "repo",
        language="python",
        db_dir=tmp_path / "db",
        repo_name="repo",
    )

    assert result.success is False
    assert "Error de sistema" in result.error


def test_analyze_database_success(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = analyze_database(
        database_path=tmp_path / "db" / "repo",
        language="python",
        sarif_output_path=tmp_path / "results" / "repo.sarif",
    )

    assert result.success is True


def test_analyze_database_unknown_language_without_suite(tmp_path):
    result = analyze_database(
        database_path=tmp_path / "db" / "repo",
        language="cobol",
        sarif_output_path=tmp_path / "results" / "repo.sarif",
    )

    assert result.success is False
    assert "query suite" in result.error


def test_analyze_database_failure_records_stderr(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd="codeql", stderr="analysis failed")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = analyze_database(
        database_path=tmp_path / "db" / "repo",
        language="python",
        sarif_output_path=tmp_path / "results" / "repo.sarif",
    )

    assert result.success is False
    assert "analysis failed" in result.error
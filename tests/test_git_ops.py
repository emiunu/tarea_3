

import subprocess

import pytest

from miner.git_ops import clone_repository


def test_clone_success(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = clone_repository("https://github.com/example/repo.git", "repo", workspace_dir=tmp_path)

    assert result.success is True
    assert result.path == tmp_path / "repo"
    assert result.error is None


def test_clone_reuses_existing_directory(tmp_path):
    existing = tmp_path / "repo"
    existing.mkdir()

    result = clone_repository("https://github.com/example/repo.git", "repo", workspace_dir=tmp_path)

    assert result.success is True
    assert result.path == existing


def test_clone_failure_records_stderr(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=128, cmd="git clone", stderr="fatal: repository not found"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = clone_repository("https://github.com/example/broken.git", "broken", workspace_dir=tmp_path)

    assert result.success is False
    assert "not found" in result.error
    assert result.path is None


def test_clone_timeout_is_reported(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git clone", timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = clone_repository("https://github.com/example/slow.git", "slow", workspace_dir=tmp_path, timeout_seconds=1)

    assert result.success is False
    assert "Timeout" in result.error
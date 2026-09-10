

import pytest

from miner.github_client import (
    GitHubAuthError,
    GitHubClient,
    GitHubOrgNotFoundError,
)


class FakeResponse:
    def __init__(self, status_code, json_data=None, links=None, text=""):
        self.status_code = status_code
        self._json_data = json_data or []
        self.links = links or {}
        self.text = text

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Sustituye requests.Session, devolviendo respuestas predefinidas en orden."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.headers = {}
        self.calls = []

    def get(self, url, params=None):
        self.calls.append((url, params))
        return self._responses.pop(0)


def test_list_repositories_follows_pagination_link():
    page1 = FakeResponse(
        status_code=200,
        json_data=[{"name": "repo-a"}, {"name": "repo-b"}],
        links={"next": {"url": "https://api.github.com/orgs/example-org/repos?page=2"}},
    )
    page2 = FakeResponse(status_code=200, json_data=[{"name": "repo-c"}], links={})

    session = FakeSession([page1, page2])
    client = GitHubClient(token="fake-token", session=session)

    repos = client.list_organization_repositories("example-org")

    assert [r["name"] for r in repos] == ["repo-a", "repo-b", "repo-c"]
    assert len(session.calls) == 2


def test_list_repositories_stops_when_no_next_link():
    only_page = FakeResponse(status_code=200, json_data=[{"name": "solo-repo"}], links={})
    session = FakeSession([only_page])
    client = GitHubClient(token="fake-token", session=session)

    repos = client.list_organization_repositories("example-org")

    assert [r["name"] for r in repos] == ["solo-repo"]


def test_missing_organization_raises_not_found():
    response = FakeResponse(status_code=404, text="Not Found")
    session = FakeSession([response])
    client = GitHubClient(token="fake-token", session=session)

    with pytest.raises(GitHubOrgNotFoundError):
        client.list_organization_repositories("does-not-exist")


def test_bad_credentials_raises_auth_error():
    response = FakeResponse(status_code=401, text="Bad credentials")
    session = FakeSession([response])
    client = GitHubClient(token="fake-token", session=session)

    with pytest.raises(GitHubAuthError):
        client.list_organization_repositories("example-org")


def test_missing_token_raises_auth_error(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    with pytest.raises(GitHubAuthError):
        GitHubClient(token=None)
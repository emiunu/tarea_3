

from __future__ import annotations

import os

import requests

GITHUB_API_URL = "https://api.github.com"


class GitHubAuthError(RuntimeError):
    """El token no existe o fue rechazado por la API (401/403)."""


class GitHubOrgNotFoundError(RuntimeError):
    """La organización indicada no existe (404)."""


class GitHubClient:
    """Cliente delgado sobre la GitHub REST API para listar repos de una org."""

    def __init__(self, token: str | None = None, session: requests.Session | None = None):
        self._token = token or os.environ.get("GITHUB_TOKEN")
        if not self._token:
            raise GitHubAuthError(
                "No se encontró GITHUB_TOKEN. Define la variable de entorno "
                "antes de ejecutar el miner (ver .env.example)."
            )
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def list_organization_repositories(self, organization: str) -> list[dict]:
        
        repos: list[dict] = []
        url: str | None = f"{GITHUB_API_URL}/orgs/{organization}/repos"
        params = {"per_page": 100, "type": "all"}

        while url:
            response = self._session.get(url, params=params)

            if response.status_code == 404:
                raise GitHubOrgNotFoundError(f"La organización '{organization}' no existe o no es accesible.")
            if response.status_code in (401, 403):
                raise GitHubAuthError(
                    f"GitHub rechazó las credenciales (status {response.status_code}): {response.text}"
                )
            response.raise_for_status()

            repos.extend(response.json())

            
            url = response.links.get("next", {}).get("url")
            params = None

        return repos
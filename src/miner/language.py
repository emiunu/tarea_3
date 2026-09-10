"""Detección de lenguaje soportado por CodeQL."""

from __future__ import annotations

GITHUB_TO_CODEQL_LANGUAGE = {
    "Python": "python",
    "JavaScript": "javascript",
    "TypeScript": "javascript",  
    "Java": "java",
    "Kotlin": "java",
    "C": "cpp",
    "C++": "cpp",
    "C#": "csharp",
    "Go": "go",
    "Ruby": "ruby",
}


def detect_codeql_language(github_language: str | None) -> str | None:
    """Retorna el identificador de lenguaje de CodeQL, o None si no es soportado."""
    if not github_language:
        return None
    return GITHUB_TO_CODEQL_LANGUAGE.get(github_language)


def is_supported(github_language: str | None) -> bool:
    """Azúcar sintáctico sobre detect_codeql_language para chequeos rápidos."""
    return detect_codeql_language(github_language) is not None
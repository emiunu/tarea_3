from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class RepoStatus(str, Enum):

    ANALYZED = "analyzed"
    CLONE_FAILED = "clone_failed"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    DATABASE_FAILED = "database_failed"
    ANALYSIS_FAILED = "analysis_failed"


class Severity(str, Enum):

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    UNKNOWN = "unknown"


class Finding(BaseModel):

    rule_id: str
    message: str
    file: str
    start_line: int | None = None
    severity: Severity = Severity.UNKNOWN


class RepositoryResult(BaseModel):

    name: str
    url: str
    status: RepoStatus
    languages: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None

class Summary(BaseModel):

    repositories: int
    analyzed: int
    failed: int
    unsupported: int
    findings: int


class OrganizationReport(BaseModel):

    organization: str
    summary: Summary
    repositories: list[RepositoryResult]

    @classmethod
    def build(cls, organization: str, repositories: list[RepositoryResult]) -> "OrganizationReport":
        
        ordered_repos = sorted(repositories, key=lambda r: r.name)
        for repo in ordered_repos:
            repo.findings.sort(key=lambda f: (f.file, f.start_line or 0, f.rule_id))

        analyzed = sum(1 for r in ordered_repos if r.status == RepoStatus.ANALYZED)
        failed = sum(
            1
            for r in ordered_repos
            if r.status in (RepoStatus.DATABASE_FAILED, RepoStatus.ANALYSIS_FAILED, RepoStatus.CLONE_FAILED)
        )
        unsupported = sum(1 for r in ordered_repos if r.status == RepoStatus.UNSUPPORTED_LANGUAGE)
        total_findings = sum(len(r.findings) for r in ordered_repos)

        summary = Summary(
            repositories=len(ordered_repos),
            analyzed=analyzed,
            failed=failed,
            unsupported=unsupported,
            findings=total_findings,
        )

        return cls(organization=organization, summary=summary, repositories=ordered_repos)

class SbomStatus(str, Enum):
 
    SUCCESS = "success"
    FAILED = "failed"
 
 
class SbomInfo(BaseModel):
 
    repository: str
    commit: str | None = None
    generated_at: datetime
    syft_version: str | None = None
    status: SbomStatus
    component_count: int = 0
    sbom_path: str | None = None
    error: str | None = None
 
 
class SbomSummary(BaseModel):
 
    repositories: int
    generated: int
    failed: int
    total_components: int
 
 
class SbomOrganizationReport(BaseModel):
 
    organization: str
    summary: SbomSummary
    repositories: list[SbomInfo]
 
    @classmethod
    def build(cls, organization: str, repositories: list[SbomInfo]) -> "SbomOrganizationReport":
 
        ordered_repos = sorted(repositories, key=lambda r: r.repository)
 
        generated = sum(1 for r in ordered_repos if r.status == SbomStatus.SUCCESS)
        failed = sum(1 for r in ordered_repos if r.status == SbomStatus.FAILED)
        total_components = sum(r.component_count for r in ordered_repos)
 
        summary = SbomSummary(
            repositories=len(ordered_repos),
            generated=generated,
            failed=failed,
            total_components=total_components,
        )
 
        return cls(organization=organization, summary=summary, repositories=ordered_repos)
 
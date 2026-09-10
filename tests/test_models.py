 
from miner.models import (
    Finding,
    OrganizationReport,
    RepositoryResult,
    RepoStatus,
    Severity,
)
 
 
def test_finding_defaults_to_unknown_severity():
    finding = Finding(rule_id="py/example", message="msg", file="a.py", start_line=10)
    assert finding.severity == Severity.UNKNOWN
 
 
def test_repository_result_analyzed_with_findings():
    repo = RepositoryResult(
        name="example-project",
        url="https://github.com/example-org/example-project",
        status=RepoStatus.ANALYZED,
        languages=["python"],
        findings=[
            Finding(rule_id="py/example-rule", message="desc", file="src/example.py", start_line=42)
        ],
    )
    assert repo.status == RepoStatus.ANALYZED
    assert repo.error is None
    assert len(repo.findings) == 1
 
 
def test_repository_result_failed_records_error():
    repo = RepositoryResult(
        name="broken-repo",
        url="https://github.com/example-org/broken-repo",
        status=RepoStatus.CLONE_FAILED,
        error="fatal: repository not found",
    )
    assert repo.status == RepoStatus.CLONE_FAILED
    assert repo.error == "fatal: repository not found"
    assert repo.findings == []
 
 
def test_organization_report_orders_repositories_alphabetically():
    repos = [
        RepositoryResult(name="zeta", url="https://x/zeta", status=RepoStatus.ANALYZED),
        RepositoryResult(name="alpha", url="https://x/alpha", status=RepoStatus.ANALYZED),
        RepositoryResult(name="mid", url="https://x/mid", status=RepoStatus.UNSUPPORTED_LANGUAGE),
    ]
 
    report = OrganizationReport.build("example-org", repos)
 
    assert [r.name for r in report.repositories] == ["alpha", "mid", "zeta"]
 
 
def test_organization_report_orders_findings_by_file_line_rule():
    findings = [
        Finding(rule_id="py/b-rule", message="m", file="b.py", start_line=5),
        Finding(rule_id="py/a-rule", message="m", file="a.py", start_line=20),
        Finding(rule_id="py/a-rule", message="m", file="a.py", start_line=5),
    ]
    repo = RepositoryResult(
        name="example",
        url="https://x/example",
        status=RepoStatus.ANALYZED,
        findings=findings,
    )
 
    report = OrganizationReport.build("example-org", [repo])
 
    ordered = report.repositories[0].findings
    assert [(f.file, f.start_line) for f in ordered] == [
        ("a.py", 5),
        ("a.py", 20),
        ("b.py", 5),
    ]
 
 
def test_organization_report_summary_counts():
    repos = [
        RepositoryResult(name="ok1", url="https://x/ok1", status=RepoStatus.ANALYZED,
                          findings=[Finding(rule_id="r", message="m", file="a.py", start_line=1)]),
        RepositoryResult(name="ok2", url="https://x/ok2", status=RepoStatus.ANALYZED),
        RepositoryResult(name="bad", url="https://x/bad", status=RepoStatus.ANALYSIS_FAILED, error="boom"),
        RepositoryResult(name="skip", url="https://x/skip", status=RepoStatus.UNSUPPORTED_LANGUAGE),
    ]
 
    report = OrganizationReport.build("example-org", repos)
 
    assert report.summary.repositories == 4
    assert report.summary.analyzed == 2
    assert report.summary.failed == 1
    assert report.summary.unsupported == 1
    assert report.summary.findings == 1
 
 
def test_report_serializes_to_valid_json():
    repo = RepositoryResult(name="a", url="https://x/a", status=RepoStatus.ANALYZED)
    report = OrganizationReport.build("example-org", [repo])
 
    payload = report.model_dump_json(indent=2)
 
    assert '"organization": "example-org"' in payload
 
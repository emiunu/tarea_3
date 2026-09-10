

from __future__ import annotations

import json
from pathlib import Path

from miner.models import Finding, Severity

SARIF_LEVEL_TO_SEVERITY = {
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "note": Severity.NOTE,
}


def parse_sarif_file(sarif_path: Path) -> list[Finding]:
    
    try:
        content = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []

    for run in content.get("runs", []):
        rule_severities = _extract_rule_severities(run)

        for result in run.get("results", []):
            finding = _result_to_finding(result, rule_severities)
            if finding is not None:
                findings.append(finding)

    return findings


def _extract_rule_severities(run: dict) -> dict[str, Severity]:
   
    severities: dict[str, Severity] = {}
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    for rule in rules:
        rule_id = rule.get("id")
        level = rule.get("defaultConfiguration", {}).get("level")
        if rule_id and level in SARIF_LEVEL_TO_SEVERITY:
            severities[rule_id] = SARIF_LEVEL_TO_SEVERITY[level]
    return severities


def _result_to_finding(result: dict, rule_severities: dict[str, Severity]) -> Finding | None:
    rule_id = result.get("ruleId")
    message = result.get("message", {}).get("text")

    locations = result.get("locations", [])
    if not locations:
        # Un resultado sin ubicación no es útil para el reporte del miner.
        return None

    physical_location = locations[0].get("physicalLocation", {})
    file_path = physical_location.get("artifactLocation", {}).get("uri")
    start_line = physical_location.get("region", {}).get("startLine")

    if not rule_id or not message or not file_path:
        return None

    
    result_level = result.get("level")
    severity = (
        SARIF_LEVEL_TO_SEVERITY.get(result_level)
        or rule_severities.get(rule_id)
        or Severity.UNKNOWN
    )

    return Finding(
        rule_id=rule_id,
        message=message,
        file=file_path,
        start_line=start_line,
        severity=severity,
    )
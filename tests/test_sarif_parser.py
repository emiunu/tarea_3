

import json

from miner.models import Severity
from miner.sarif_parser import parse_sarif_file


def _write_sarif(tmp_path, content):
    path = tmp_path / "results.sarif"
    path.write_text(json.dumps(content))
    return path


def test_parses_findings_with_rule_level_severity(tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "defaultConfiguration": {"level": "error"},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "message": {"text": "Posible inyección SQL"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    sarif_path = _write_sarif(tmp_path, sarif)

    findings = parse_sarif_file(sarif_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "py/sql-injection"
    assert finding.message == "Posible inyección SQL"
    assert finding.file == "src/db.py"
    assert finding.start_line == 42
    assert finding.severity == Severity.ERROR


def test_result_level_overrides_rule_default(tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "py/example", "defaultConfiguration": {"level": "warning"}}
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "py/example",
                        "level": "error",
                        "message": {"text": "msg"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    sarif_path = _write_sarif(tmp_path, sarif)

    findings = parse_sarif_file(sarif_path)

    assert findings[0].severity == Severity.ERROR


def test_missing_severity_defaults_to_unknown(tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "py/example",
                        "message": {"text": "msg"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    sarif_path = _write_sarif(tmp_path, sarif)

    findings = parse_sarif_file(sarif_path)

    assert findings[0].severity == Severity.UNKNOWN


def test_result_without_location_is_skipped(tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {"ruleId": "py/example", "message": {"text": "msg"}, "locations": []}
                ],
            }
        ]
    }
    sarif_path = _write_sarif(tmp_path, sarif)

    findings = parse_sarif_file(sarif_path)

    assert findings == []


def test_missing_file_returns_empty_list(tmp_path):
    missing_path = tmp_path / "does_not_exist.sarif"

    findings = parse_sarif_file(missing_path)

    assert findings == []


def test_multiple_runs_are_all_parsed(tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "py/a",
                        "message": {"text": "msg a"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            },
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "py/b",
                        "message": {"text": "msg b"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "b.py"},
                                    "region": {"startLine": 2},
                                }
                            }
                        ],
                    }
                ],
            },
        ]
    }
    sarif_path = _write_sarif(tmp_path, sarif)

    findings = parse_sarif_file(sarif_path)

    assert {f.rule_id for f in findings} == {"py/a", "py/b"}